#!/usr/bin/env python3
# mapper.py
#
# Purpose:
#   Map fully-qualified Java methods (e.g., `java.lang.System.nanoTime`) to their
#   native implementations by combining three sources of truth:
#     1) Exported symbols in ELF libraries (via nm) for standard JNI `Java_*` and
#        library-specific conventions (e.g., Netty `netty_*`).
#     2) OpenJDK source `JNINativeMethod` tables (optional; when `JVM_SRC` is set),
#        which link Java methods to C targets (e.g., `JVM_*` or custom functions).
#     3) Symbol resolution across transitive runtime dependencies (via ldd) to
#        identify which `.so` actually defines a target symbol.
#
# Key environment inputs:
#   - LIB_DIRS: os.pathsep-separated directories to scan for ELF `.so` files. If unset,
#               a sensible default set is used (project libs, JDK libs, system libs).
#   - JVM_SRC:  Path to the OpenJDK source tree. When set, we parse native registration
#               tables to learn mappings like `java.lang.System.nanoTime -> JVM_NanoTime`.
#               If unset, source-based mappings are skipped and such methods may appear
#               as NOT_FOUND.
#   - JVM_SO:   Explicit path to `libjvm.so`. If unset, we try to discover it from
#               `LIB_DIRS`, `JAVA_HOME`, and common system locations.
#   - METHODS_FILE: File listing Java methods (one per line) to classify.
#
# Outputs (in project root):
#   - method_syscalls.txt: Per-method resolution details and classification tags.
#   - found_jni_methods.txt: Unique set of JNI/Netty-like native symbols found.
#   - found_jvm_methods.txt: Unique set of `JVM_*` symbols validated in `libjvm.so`.
#   - found_registered_methods.txt: Unique set of registered (non-JVM) native symbols.
#
# High-level workflow:
#   - Discover candidate libraries (from `LIB_DIRS`) and optionally `libjvm.so`.
#   - Extract `Java_*` symbols and map to `pkg.Class.method` (direct JNI hits).
#   - Parse Netty libs for `netty_*` symbols and construct best-effort mappings.
#   - If `JVM_SRC` is available, scan source for `JNINativeMethod` entries to learn
#     `JVM_*` and other registered native targets and associate them with Java methods.
#   - Validate `JVM_*` targets against `libjvm.so` exports and resolve non-JVM targets
#     to an owning `.so` by scanning transitive dependencies (via `ldd`).
import os
import re
import sys
import glob
import subprocess

# ----------------------------
# Config / Inputs
# ----------------------------
env_lib_dirs = os.environ.get("LIB_DIRS")
if env_lib_dirs:
    LIB_DIRS = [p for p in env_lib_dirs.split(os.pathsep) if p]
else:
    # Prefer explicit image-scoped variable first, then LIBS_DIR
    lib_base = os.environ.get("LIBS_IMAGE") or os.environ.get("LIBS_DIR")
    if lib_base:
        LIB_DIRS = [lib_base]
    else:
        sys.stderr.write(
            "ERROR: No library directories configured.\n"
            "Please set one of the following environment variables:\n"
            "  - LIB_DIRS: colon-separated list of directories to scan for .so files\n"
            "  - LIBS_IMAGE: single directory containing libraries for a specific container image\n"
            "  - LIBS_DIR: single directory containing libraries\n"
        )
        sys.exit(1)

if not LIB_DIRS:
    sys.stderr.write("ERROR: LIB_DIRS is empty after configuration.\n")
    sys.exit(1)

print("DEBUG: Using LIB_DIRS:")
for d in LIB_DIRS:
    print("  -", d)

# Optional: OpenJDK native source root to learn JNINativeMethod tables (no hardcoding).
# If absent, we skip source-based mapping.
JVM_SRC = os.environ.get("JVM_SRC", "")

# Optional: explicit path to libjvm.so. If not set, we discover it (preferring LIB_DIRS).
JVM_SO = os.environ.get("JVM_SO", "")

# Output directory (use OUTPUTS_DIR if set, otherwise current directory)
output_dir = os.environ.get("OUTPUTS_DIR", ".").strip() or "."


def resolve_methods_file():
    env_methods = os.environ.get("METHODS_FILE")
    if env_methods:
        return env_methods
    if output_dir not in (".", ""):
        return os.path.join(output_dir, "native_methods.txt")
    return "native_methods.txt"


def ensure_methods_file(path: str):
    if os.path.exists(path):
        return
    sys.stderr.write(
        f"ERROR: Methods file not found: {path}\n"
        "Set METHODS_FILE or OUTPUTS_DIR to point to an existing native_methods.txt.\n"
    )
    sys.exit(1)


# Input list of Java methods (one per line): e.g., "java.lang.System.nanoTime"
methods_file = resolve_methods_file()
ensure_methods_file(methods_file)

# Outputs
detailed_output_file = os.path.join(output_dir, "mapped_method_syscalls.txt")

# ----------------------------
# Helpers
# ----------------------------
def is_elf(path: str) -> bool:
    """
    Purpose:
        Check if a file is an ELF (Executable and Linkable Format) binary by examining
        its magic number. ELF files include executables, shared libraries (.so), and
        object files that may contain native symbols we need to scan.

    Input:
        path (str): File system path to the file to check.

    Output:
        bool: True if the file is an ELF binary (starts with 0x7fELF magic bytes),
              False otherwise (file doesn't exist, can't be read, or isn't ELF).

    Description:
        Reads the first 4 bytes of the file and checks for the ELF magic signature
        (0x7f followed by "ELF"). Returns False on any I/O errors or if the magic
        bytes don't match.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def jni_to_java_method(jni_name: str):
    """
    Purpose:
        Convert a JNI (Java Native Interface) symbol name to its corresponding
        fully-qualified Java method name. JNI uses underscores to represent dots
        in package and class names, with special escaping for literal underscores.

        WHY CONVERT JNI → JAVA (not the other way)?

        Example scenario:
        - Input file has: "java.lang.System.nanoTime"
        - Binary library has: "Java_java_lang_System_nanoTime"

        APPROACH 1 (What we do - FAST):
        Step 1: Scan ALL binaries → find ["Java_java_lang_System_nanoTime", ...]
        Step 2: Convert JNI→Java → {"java.lang.System.nanoTime": ("Java_java_lang_System_nanoTime", "lib.so")}
        Step 3: For each input method, do fast dict lookup: if "java.lang.System.nanoTime" in dict → FOUND!
        Result: O(1) lookup per method = FAST

        APPROACH 2 (Alternative - SLOW):
        Step 1: For each input method "java.lang.System.nanoTime"
        Step 2: Convert Java→JNI → "Java_java_lang_System_nanoTime"
        Step 3: Search ALL binaries for this symbol (run nm on each .so file)
        Result: O(n*m) where n=methods, m=libraries = SLOW!

        We choose Approach 1 because we scan binaries ONCE, then do fast lookups.

    Input:
        jni_name (str): JNI symbol name (e.g., "Java_java_lang_System_nanoTime",
                        "Java_java_util_Map_00024Entry_getKey",
                        "Java_com_sun_GTKEngine_native_1get_1gtk_1setting").

    Output:
        str | None: The fully-qualified Java method name (e.g., "java.lang.System.nanoTime")
                    if the input is a valid JNI symbol starting with "Java_", otherwise None.

    Description:
        JNI symbols follow the pattern "Java_<package>_<class>_<method>" where:
        - Underscores represent dots in package/class names
        - "_1" is the escape sequence for a literal underscore character
        - "_00024" is the escape for '$' (inner classes like Map$Entry)
        - "_0xxxx" are Unicode escapes
        - "_2" and "_3" are signature escapes for ';' and '['

        The function properly handles the order of operations to preserve literal underscores
        in method names while converting package separators to dots.

        Examples:
            Java_java_lang_System_nanoTime → java.lang.System.nanoTime
            Java_java_util_Map_00024Entry_getKey → java.util.Map$Entry.getKey
            Java_com_sun_GTKEngine_native_1get_1gtk_1setting → com.sun.GTKEngine.native_get_gtk_setting
    """
    if not jni_name.startswith("Java_"):
        return None

    # Remove "Java_" prefix
    mangled = jni_name[5:]

    # Step 1: Handle Unicode escapes (_0xxxx -> Unicode character)
    # Must be done BEFORE other replacements
    def unescape_unicode(match):
        hex_str = match.group(1)
        code_point = int(hex_str, 16)
        return chr(code_point)

    mangled = re.sub(r'_0([0-9a-fA-F]{4})', unescape_unicode, mangled)

    # Step 2: Handle escape sequences with temporary placeholders
    # CRITICAL: Must do this BEFORE replacing _ with .
    mangled = mangled.replace("_1", "\x00UNDERSCORE\x00")
    mangled = mangled.replace("_2", ";")
    mangled = mangled.replace("_3", "[")

    # Step 3: Replace remaining underscores with dots (package/class separators)
    mangled = mangled.replace("_", ".")

    # Step 4: Restore literal underscores
    mangled = mangled.replace("\x00UNDERSCORE\x00", "_")

    return mangled

def load_defined_symbols(so_path: str, pattern: str):
    """
    Purpose:
        Extract symbol names from an ELF shared library that match a given regex pattern.
        Only returns symbols that are actually defined in the library (not external references),
        which is essential for identifying which library owns a particular native function.

    Input:
        so_path (str): Path to the ELF shared library (.so file) to scan.
        pattern (str): Regular expression pattern to match against symbol names.
                      Examples: r"\\bJava_[A-Za-z0-9_]+\\b" for JNI symbols,
                               r"\\bJVM_[A-Za-z0-9_]+\\b" for JVM internal symbols.

    Output:
        set[str]: Set of symbol names that match the pattern and are defined in the library.
                  Returns an empty set if the library can't be read or nm fails.

    Description:
        Uses the `nm` (name list) tool with flags:
        - `-D`: Only show dynamic symbols (exported symbols used at runtime)
        - `--defined-only`: Exclude undefined references (only symbols defined in this library)
        The regex pattern is applied to each line of nm output, and matching symbol names
        are collected into a set. This is used to discover JNI functions, JVM_* functions,
        and other native symbols exported by libraries.
    """
    try:
        out = subprocess.check_output(
            ["nm", "-D", "--defined-only", so_path],
            universal_newlines=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"WARN: nm failed on {so_path}: {e}", file=sys.stderr)
        return set()
    symset = set()
    rx = re.compile(pattern)
    for line in out.splitlines():
        m = rx.search(line)
        if m:
            symset.add(m.group(0))
    return symset

def ldd_paths(binary_path: str) -> list[str]:
    """
    Purpose:
        Discover all shared library dependencies of a binary by running `ldd` (list dynamic
        dependencies). This is crucial because many native symbols are defined in transitive
        dependencies rather than the main library, and we need to expand our search scope
        to find symbol owners.

    Input:
        binary_path (str): Path to an ELF binary (executable or shared library) whose
                          dependencies should be discovered.

    Output:
        list[str]: List of absolute file paths to dependency libraries (.so files) that
                   the binary depends on. Returns an empty list if ldd fails or the binary
                   doesn't exist.

    Description:
        Executes `ldd` to list dynamic library dependencies. Parses the output to extract
        absolute paths to dependency libraries. Handles two output formats:
        - "lib => /path/to/lib.so" (with arrow)
        - "/path/to/lib.so" (direct path)
        Only includes paths that exist, are absolute (start with "/"), and are valid ELF files.
        This transitive dependency discovery is essential because symbols registered in source
        code may be implemented in any dependency, not just the main library.
    """
    try:
        out = subprocess.check_output(["ldd", binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    paths = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            right = line.split("=>", 1)[1].strip()
            cand = right.split(" ", 1)[0].strip()
            if cand.startswith("/") and os.path.exists(cand) and is_elf(cand):
                paths.append(cand)
        else:
            tok = line.split(" ", 1)[0]
            if tok.startswith("/") and os.path.exists(tok) and is_elf(tok):
                paths.append(tok)
    return paths

def collect_search_libs(seed_libs: list[str], extra_dirs: list[str]) -> list[str]:
    """
    Purpose:
        Build a comprehensive list of ELF libraries to search for symbol definitions.
        Combines seed libraries with all their transitive dependencies (via ldd) and
        all libraries found in additional directories. This ensures symbol resolution
        covers both direct libraries and all their runtime dependencies.

    Input:
        seed_libs (list[str]): List of key library paths to start with (e.g., libjvm.so,
                              libjava.so). These and all their dependencies will be included.
        extra_dirs (list[str]): Additional directories to scan for libraries matching
                               the pattern "lib*.so*".

    Output:
        list[str]: Complete list of unique ELF library paths to search, including:
                  - All seed libraries (if they're ELF files)
                  - All transitive dependencies of seed libraries (via ldd)
                  - All libraries found in extra_dirs matching "lib*.so*"

    Description:
        Uses a queue-based breadth-first traversal to collect libraries:
        1. Starts with seed_libs (e.g., libjvm.so) and adds them to the search set
        2. For each library, uses `ldd_paths()` to discover its dependencies
        3. Recursively adds dependencies to the queue until all are discovered
        4. Scans extra_dirs for any additional libraries matching "lib*.so*"
        5. Returns a deduplicated list of all ELF libraries found
        This comprehensive search set is used by `resolve_symbol_in_libs()` to locate
        which library actually defines a given symbol.
    """
    seen = set()
    out = []

    queue = [p for p in seed_libs if p and os.path.exists(p)]
    while queue:
        cur = queue.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if is_elf(cur):
            out.append(cur)
            for dep in ldd_paths(cur):
                if dep not in seen:
                    queue.append(dep)

    for d in extra_dirs:
        for p in glob.glob(os.path.join(d, "lib*.so*")):
            if p not in seen and is_elf(p):
                out.append(p)
                seen.add(p)

    return out

def resolve_symbol_in_libs(symbol: str, libs: list[str]) -> str | None:
    """
    Purpose:
        Find which library in a collection actually defines a given symbol. This is
        used to resolve registered native functions (discovered from source code) to
        their actual implementation library, since the source code tells us the function
        name but not which .so file contains it.

    Input:
        symbol (str): The name of the symbol to search for (e.g., "JVM_NanoTime",
                     "RegisterNatives", or any C function name).
        libs (list[str]): List of library paths to search through. Typically this is
                         the comprehensive list from `collect_search_libs()`.

    Output:
        str | None: The path to the first library that defines the symbol, or None
                   if the symbol is not found in any of the provided libraries.

    Description:
        Searches through the provided libraries using `nm -D --defined-only` to check
        if each library defines the target symbol. Uses word-boundary regex matching
        to avoid false positives (e.g., matching "JVM_Time" when searching for "JVM_T").
        Returns the first library that contains the symbol definition. This is critical
        for methods discovered from OpenJDK source code JNINativeMethod tables, which
        reference C functions that may be in libjvm.so, libjava.so, or other dependencies.
    """
    rx = re.compile(rf"\b{re.escape(symbol)}\b")
    for so in libs:
        try:
            out = subprocess.check_output(["nm", "-D", "--defined-only", so],
                                          universal_newlines=True, stderr=subprocess.DEVNULL)
        except Exception:
            continue
        if rx.search(out):
            return so
    return None

def build_netty_map(lib_paths):
    """
    Purpose:
        Build a mapping from Java Netty methods to their native symbol names.
        Netty uses custom `netty_*` symbol naming conventions instead of standard
        JNI `Java_*` naming, so we need special parsing logic to connect Java methods
        to their native implementations.

    Input:
        lib_paths (list[str]): List of library file paths to scan for Netty symbols.
                              Only libraries with "netty" in their filename are processed.

    Output:
        dict[str, tuple[str, str]]: Dictionary mapping fully-qualified Java method names
                                    to tuples of (native_symbol, library_path).
                                    Example: {"io.netty.channel.unix.Socket.getOption":
                                             ("netty_unix_socket_getOption", "/path/to/lib.so")}

    Description:
        Scans Netty libraries for symbols starting with "netty_" and attempts to
        reconstruct the corresponding Java method name using pattern matching:
        - netty_unix_socket_getOption -> io.netty.channel.unix.Socket.getOption
        - netty_epoll_linuxsocket_bindVSock -> io.netty.channel.epoll.LinuxSocket.bindVSock
        Uses regular `nm` (not `-D`) to include local symbols that may not be exported.
        Handles special cases like "linuxsocket" -> "LinuxSocket" for proper class naming.
        This mapping is used later to match Java methods from the input list to their
        native Netty implementations.
    """
    netty_map = {}
    
    # Find netty libraries
    netty_libs = []
    for path in lib_paths:
        if 'netty' in os.path.basename(path).lower():
            netty_libs.append(path)
    
    for lib in netty_libs:
        try:
            # Get all netty_* symbols (use regular nm instead of -D --defined-only)
            out = subprocess.check_output(
                ["nm", lib],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            # Parse netty symbols
            for line in out.splitlines():
                # Look for netty_ prefixed symbols
                if 'netty_' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        symbol_type = parts[1]
                        symbol = parts[2]
                        
                        # Accept both 't' (text) and 'T' (text) symbols
                        if symbol_type in ['t', 'T'] and symbol.startswith('netty_'):
                            # Extract components
                            components = symbol[6:].split('_')  # Remove 'netty_' prefix
                            
                            if len(components) >= 2:
                                # Handle different patterns
                                if components[0] == 'internal' and len(components) >= 4 and components[1] == 'tcnative':
                                    # netty_internal_tcnative_Buffer_address -> io.netty.internal.tcnative.Buffer.address
                                    # netty_internal_tcnative_SSLSession_JNI_OnLoad -> io.netty.internal.tcnative.SSLSession.JNI_OnLoad
                                    # netty_internal_tcnative_NativeStaticallyReferencedJniMethods_sslErrorNone
                                    #   -> io.netty.internal.tcnative.NativeStaticallyReferencedJniMethods.sslErrorNone
                                    # Preserve original case from symbol (don't use .title())
                                    class_name = components[2]
                                    method_name = '_'.join(components[3:])  # Handle multi-part method names like JNI_OnLoad
                                    java_method = f"io.netty.internal.tcnative.{class_name}.{method_name}"
                                    netty_map[java_method] = (symbol, lib)
                                    # Also add variant with "org.apache" prefix for shaded versions
                                    java_method_shaded = f"org.apache.storm.shade.io.netty.internal.tcnative.{class_name}.{method_name}"
                                    netty_map[java_method_shaded] = (symbol, lib)
                                elif components[0] == 'unix' and len(components) >= 3:
                                    # netty_unix_socket_getOption -> io.netty.channel.unix.Socket.getOption
                                    java_method = f"io.netty.channel.unix.{components[1].title()}.{components[-1]}"
                                    netty_map[java_method] = (symbol, lib)
                                elif components[0] == 'epoll' and len(components) >= 3:
                                    # netty_epoll_linuxsocket_bindVSock -> io.netty.channel.epoll.LinuxSocket.bindVSock
                                    # Fix: Convert linuxsocket to LinuxSocket properly
                                    class_name = components[1]
                                    if class_name == 'linuxsocket':
                                        class_name = 'LinuxSocket'
                                    else:
                                        class_name = class_name.title()
                                    java_method = f"io.netty.channel.epoll.{class_name}.{components[-1]}"
                                    netty_map[java_method] = (symbol, lib)
                                elif len(components) >= 2:
                                    # Generic case
                                    java_method = f"io.netty.channel.{components[0]}.{components[-1]}"
                                    netty_map[java_method] = (symbol, lib)
                        
        except Exception as e:
            print(f"WARN: Failed to process netty lib {lib}: {e}", file=sys.stderr)
    
    return netty_map

def match_netty_method(method, netty_symbols):
    """
    Purpose:
        Perform fuzzy matching to associate a Java Netty method with a native `netty_*`
        symbol when an exact mapping wasn't found in `build_netty_map()`. This handles
        cases where the symbol naming pattern doesn't perfectly match our reconstruction
        logic, or when methods have slightly different naming conventions.

    Input:
        method (str): Fully-qualified Java method name (e.g., "io.netty.channel.epoll.LinuxSocket.bind").
        netty_symbols (dict): Dictionary from `build_netty_map()` mapping Java methods to
                             (symbol, library_path) tuples.

    Output:
        tuple[str, str] | None: Tuple of (native_symbol, library_path) if a match is found,
                               None if no plausible match can be determined.

    Description:
        Uses heuristics to find matching symbols:
        1. Extracts package context (epoll, unix) and class/method names from the Java method
        2. Constructs candidate symbol patterns (e.g., "netty_epoll_linuxsocket_bind")
        3. Searches for symbols containing these patterns (case-insensitive)
        4. Falls back to suffix matching (matches if symbol ends with the method name)
        This helps catch Netty methods that don't follow the exact patterns handled by
        `build_netty_map()`, improving the coverage of native method resolution.
    """
    if not method.startswith("io.netty"):
        return None
    
    # Extract class and method name
    parts = method.split('.')
    if len(parts) < 4:
        return None
    
    # Get the last parts (class.method)
    class_name = parts[-2].lower()
    method_name = parts[-1]
    
    # Extract package context
    if 'epoll' in method:
        package_type = 'epoll'
    elif 'unix' in method:
        package_type = 'unix'
    else:
        package_type = None
    
    # Try different symbol patterns
    patterns = []
    if package_type:
        patterns.append(f"netty_{package_type}_{class_name}_{method_name}")
    patterns.append(f"netty_{class_name}_{method_name}")
    
    for pattern in patterns:
        for java_method, (symbol, lib_path) in netty_symbols.items():
            if pattern.lower() in symbol.lower():
                return (symbol, lib_path)
    
    # Try suffix matching as fallback
    method_suffix = method_name.lower()
    for java_method, (symbol, lib_path) in netty_symbols.items():
        if symbol.lower().endswith(method_suffix):
            return (symbol, lib_path)
    
    return None

# ----------------------------
# Discover libraries (.so) — filter to ELF only
# ----------------------------
so_paths: list[str] = []
for lib_dir in LIB_DIRS:
    for p in glob.glob(os.path.join(lib_dir, "lib*.so*")):
        if is_elf(p):
            so_paths.append(p)

def find_libjvm() -> str | None:
    """
    Purpose:
        Locate the libjvm.so library file, which contains the Java Virtual Machine
        implementation and many core native methods (JVM_* functions). This library
        is essential for validating JVM_* symbols discovered from source code.

    Input:
        None (uses module-level variables JVM_SO and LIB_DIRS, and environment variables).

    Output:
        str | None: Absolute path to libjvm.so if found, None if the library cannot
                   be located. The library must exist and be a valid ELF file.

    Description:
        Searches for libjvm.so in the following order (first match wins):
        1. Explicit override: If JVM_SO environment variable is set and points to a valid file
        2. LIB_DIRS: Search recursively in directories specified in LIB_DIRS
        3. JAVA_HOME: Search in JAVA_HOME/lib/server/libjvm.so and recursively
        4. System paths: Search in /usr/lib/jvm/**/lib/server/libjvm.so and variants
        All candidates are validated to ensure they exist and are ELF binaries.
        This library is critical because it contains JVM_* functions that many core
        Java methods (like System.nanoTime) map to, and we need to validate these
        symbols actually exist in the library.
    """
    # 1) explicit override
    if JVM_SO and os.path.isfile(JVM_SO):
        return JVM_SO
    # 2) search inside LIB_DIRS first
    for d in LIB_DIRS:
        for p in glob.glob(os.path.join(d, "**", "libjvm.so"), recursive=True):
            if os.path.isfile(p) and is_elf(p):
                return p
    # 3) fallback to JAVA_HOME and system
    java_home = os.environ.get("JAVA_HOME")
    candidates = []
    if java_home:
        candidates += glob.glob(os.path.join(java_home, "lib", "server", "libjvm.so"))
        candidates += glob.glob(os.path.join(java_home, "**", "libjvm.so"), recursive=True)
    candidates += glob.glob("/usr/lib/jvm/**/lib/server/libjvm.so", recursive=True)
    candidates += glob.glob("/usr/lib/jvm/**/libjvm.so", recursive=True)
    candidates = [c for c in candidates if os.path.isfile(c) and is_elf(c)]
    return candidates[0] if candidates else None

libjvm_so = find_libjvm()

if not so_paths and not libjvm_so:
    print("ERROR: No ELF .so files found. Check LIB_DIRS/JAVA_HOME.", file=sys.stderr)
    sys.exit(1)

print("DEBUG: ELF libraries:")
for p in so_paths:
    print(" -", p)
if libjvm_so:
    print(" - (JVM) ", libjvm_so)
else:
    print("WARN: libjvm.so not found; JVM_* validation will be skipped")

# ----------------------------
# Step 1: JNI mapping (Java_*)
# ----------------------------
# WORKFLOW EXPLANATION:
# 1. We scan binary libraries (.so files) and find JNI symbols like:
#    - "Java_java_lang_System_nanoTime"  (found in lib.so)
#    - "Java_java_lang_String_length"    (found in lib.so)
#
# 2. We convert these JNI symbols → Java method names:
#    - "Java_java_lang_System_nanoTime" → "java.lang.System.nanoTime"
#    - "Java_java_lang_String_length" → "java.lang.String.length"
#
# 3. We build a dictionary: method_to_jni["java.lang.System.nanoTime"] = ("Java_java_lang_System_nanoTime", "/path/to/lib.so")
#
# 4. Later, when we read methods from input file (like "java.lang.System.nanoTime"),
#    we can do a FAST dictionary lookup: if method in method_to_jni → found it!
#
# Why not convert Java→JNI? Because we'd need to search ALL binaries for EACH method
# in the input file, which is slow. This way we scan binaries once, then do fast lookups.
method_to_jni: dict[str, tuple[str, str]] = {}
for so_path in so_paths:
    out_syms = load_defined_symbols(so_path, r"\bJava_[A-Za-z0-9_]+\b")
    for jni in out_syms:
        m = jni_to_java_method(jni)  # Convert: "Java_java_lang_System_nanoTime" → "java.lang.System.nanoTime"
        if m and m not in method_to_jni:
            method_to_jni[m] = (jni, so_path)  # Store: "java.lang.System.nanoTime" → ("Java_java_lang_System_nanoTime", "/path/lib.so")

# ----------------------------
# Step 1.5: Netty mapping (netty_*)
# ----------------------------
netty_method_map = build_netty_map(so_paths)
if netty_method_map:
    print(f"INFO: Found {len(netty_method_map)} Netty native methods.")
    # Debug: Show some examples
    for i, (method, (symbol, lib)) in enumerate(netty_method_map.items()):
        if i < 5:  # Show first 5 examples
            print(f"  {method} -> {symbol} ({os.path.basename(lib)})")
        elif i == 5:
            print("  ...")
            break
else:
    print("INFO: No Netty libraries found or no netty_* symbols detected.")

# ----------------------------
# Step 2: Source-based scan of JNINativeMethod tables (optional)
#   - capture &JVM_* targets -> jvm_method_map
#   - capture &NonJVM targets -> registered_method_map
# ----------------------------
def infer_java_class_from_path(filepath: str) -> str | None:
    """
    Purpose:
        Infer the fully-qualified Java class name from a native source file path.
        OpenJDK native files use naming conventions that reflect the Java package structure,
        and we need to map these back to Java class names to associate native methods
        with their Java counterparts.

    Input:
        filepath (str): Path to a native source file (e.g., "java_lang_Class.c" or
                       "/path/to/java/lang/Class.c" or "jdk_internal_misc_Unsafe.c").

    Output:
        str | None: Fully-qualified Java class name (e.g., "java.lang.Class",
                   "jdk.internal.misc.Unsafe") if the pattern can be inferred,
                   None if the filename doesn't match known conventions.

    Description:
        Tries multiple strategies to infer the class name:
        1. Filename pattern: "java_lang_Class.c" -> "java.lang.Class"
           Uses regex to match "java|jdk" prefix, package part (underscores), and class name
        2. Directory structure: ".../java/lang/Class.c" -> "java.lang.Class"
           Extracts package and class from directory path components
        3. Content-based: Searches file content for Java class references
        This is used when parsing OpenJDK source files to associate JNINativeMethod
        table entries with their corresponding Java classes, since the source files
        don't always explicitly name the class.
    """
    path = filepath.replace("\\", "/")
    base = os.path.splitext(os.path.basename(path))[0]

    m = re.match(r'^(java|jdk)_([A-Za-z0-9_]+)_([A-Za-z0-9_$]+)$', base)
    if m:
        root, pkg_part, cls = m.groups()
        pkg = pkg_part.replace('_', '.')
        return f"{root}.{pkg}.{cls}"

    parts = path.split("/")
    if "java" in parts:
        try:
            i = parts.index("java")
            if i + 2 < len(parts):
                pkg = parts[i + 1]
                cls = os.path.splitext(parts[i + 2])[0]
                if re.match(r"^[a-z][a-z0-9_]*$", pkg) and re.match(r"^[A-Z][A-Za-z0-9_$]*$", cls):
                    return f"java.{pkg}.{cls}"
        except ValueError:
            pass

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(4096)
        m2 = re.search(r'\b((java|jdk)\.[a-z0-9_.]+\.[A-Za-z0-9_$]+)\b', text)
        if m2:
            return m2.group(1)
    except Exception:
        pass

    return None

def scan_native_tables(src_root: str):
    """
    Purpose:
        Parse OpenJDK source code to extract JNINativeMethod registration tables that
        map Java methods to their native C function implementations. This is essential
        because many core Java methods (like System.nanoTime) don't use standard JNI
        naming and instead register at runtime with C functions like JVM_* or custom names.

    Input:
        src_root (str): Root directory of the OpenJDK source tree to scan. Should contain
                       native source files (.c, .cc, .cpp, .cxx) with JNINativeMethod tables.

    Output:
        tuple[dict, dict]: Two dictionaries:
          - jvm_map (dict[str, str]): Maps "pkg.Class.method" -> "JVM_*" symbol name
                                     (e.g., "java.lang.System.nanoTime" -> "JVM_NanoTime")
          - reg_map (dict[str, str]): Maps "pkg.Class.method" -> non-JVM_* C function name
                                     (e.g., registered natives that use custom function names)

    Description:
        Recursively walks through the source tree, scanning all C/C++ files for
        JNINativeMethod table entries. These tables have the format:
          { "methodName", "signature", (void*)&FunctionName }
        Uses `infer_java_class_from_path()` to determine which Java class each file
        corresponds to. Separates JVM_* functions (implemented in libjvm.so) from
        other registered natives (which may be in libjava.so or other libraries).
        This source-based mapping complements binary symbol scanning by revealing
        methods that are registered at runtime and not visible through static analysis.
    """
    jvm_map, reg_map = {}, {}
    if not src_root or not os.path.isdir(src_root):
        return jvm_map, reg_map

    # FIXED: More flexible regex that allows C macros in signatures (e.g., OBJ, JSTRING)
    # The signature part (?P<sig>[^,]+?) matches anything up to the next comma,
    # which allows for string concatenation like "(" OBJ "I" OBJ "II)V"
    entry_rx = re.compile(
        r'''\{\s*
            "(?P<name>[A-Za-z0-9_]+)"\s*,\s*           # Method name
            (?P<sig>[^,]+?)\s*,\s*                      # Signature (can include macros)
            \(void\s*\*\)\s*&(?P<target>[A-Za-z0-9_]+) # Target function
            \s*\}''',
        re.VERBOSE
    )

    for root, _, files in os.walk(src_root):
        for fn in files:
            if not fn.endswith((".c", ".cc", ".cpp", ".cxx")):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue

            clazz = infer_java_class_from_path(path)

            for m in entry_rx.finditer(text):
                name = m.group("name")
                target = m.group("target")
                use_class = clazz
                if not use_class:
                    base = os.path.splitext(fn)[0]
                    # Common java.lang classes
                    if base in ("Class", "System", "Thread", "ClassLoader", "Runtime", "Object",
                                "String", "Throwable", "StackTraceElement", "ProcessEnvironment",
                                "Package", "Module", "Float", "Double", "StrictMath"):
                        use_class = f"java.lang.{base}"
                    # jdk.internal.misc classes
                    elif base in ("VM", "Signal", "Unsafe"):
                        use_class = f"jdk.internal.misc.{base}"
                    else:
                        continue
                key = f"{use_class}.{name}"
                if target.startswith("JVM_"):
                    jvm_map.setdefault(key, target)
                else:
                    reg_map.setdefault(key, target)

    return jvm_map, reg_map

try:
    jvm_method_map, registered_method_map = scan_native_tables(JVM_SRC)
    if JVM_SRC and os.path.isdir(JVM_SRC):
        print(f"INFO: Source scan found {len(jvm_method_map)} JVM_* entries and {len(registered_method_map)} registered entries.")
    else:
        # Without `JVM_SRC`, core methods like `java.lang.System.nanoTime` may
        # remain unresolved because their mapping (e.g., to `JVM_NanoTime`) is
        # learned exclusively from registration tables in the source tree.
        print("INFO: JVM_SRC not set (or missing). Skipping source-based mapping.")
except Exception as e:
    print(f"WARN: JVM source scan failed: {e}", file=sys.stderr)
    jvm_method_map, registered_method_map = {}, {}

# ----------------------------
# Step 3: Validate JVM_* symbols in libjvm.so and prepare symbol resolution
# ----------------------------
available_jvm_symbols = set()
if libjvm_so:
    available_jvm_symbols = load_defined_symbols(libjvm_so, r"\bJVM_[A-Za-z0-9_]+\b")

seed_libs = []
if libjvm_so:
    seed_libs.append(libjvm_so)
# include any libjava.so we already loaded
for p in so_paths:
    if os.path.basename(p).startswith("libjava.so"):
        seed_libs.append(p)

search_libs = collect_search_libs(seed_libs, LIB_DIRS)

# ----------------------------
# Step 4: Read methods list
# ----------------------------
if not os.path.isfile(methods_file):
    print(f"ERROR: methods file not found: {methods_file}", file=sys.stderr)
    sys.exit(1)

with open(methods_file, "r", encoding="utf-8") as f:
    methods = [line.strip() for line in f if line.strip()]

# ----------------------------
# Step 4.5: Platform-exclusion keywords
# ----------------------------
# Methods containing these substrings are for non-Linux platforms and will
# never execute inside a Linux container.  Tag them early so we skip the
# expensive symbol lookups and keep them out of the "NOT_FOUND" bucket.
PLATFORM_EXCLUDE_KEYWORDS = [
    ".kqueue.",          # macOS/BSD kqueue API  (io.netty.channel.kqueue.*)
    ".win32.",           # Windows APIs          (org.hyperic.sigar.win32.*)
    "NativeLibraryDarwin",  # macOS Cassandra   (o.a.c.utils.NativeLibraryDarwin.*)
    "BsdSocket.",        # BSD-specific Netty    (io.netty.channel.kqueue.BsdSocket.*)
]

def is_platform_excluded(method: str) -> str | None:
    """Return the matched keyword if `method` is platform-specific, else None."""
    for kw in PLATFORM_EXCLUDE_KEYWORDS:
        if kw in method:
            return kw
    return None

# ----------------------------
# Step 5: Classify each method
# ----------------------------
with open(detailed_output_file, "w", encoding="utf-8") as out:
    for method in methods:  # e.g., "java.lang.System.nanoTime" from input file
        # 0) Platform-excluded methods (win32, kqueue, Darwin)
        excl_kw = is_platform_excluded(method)
        if excl_kw:
            out.write(f"{method}: PLATFORM_EXCLUDED ({excl_kw})\n")
            continue

        # 1) JNI (Java_*) direct hits from binaries
        # FAST LOOKUP: Check if this Java method exists in our dictionary
        # (which we built by converting JNI symbols → Java method names)
        if method in method_to_jni:  # Dictionary lookup: O(1) - very fast!
            jni_sym, so_path = method_to_jni[method]  # Get: ("Java_java_lang_System_nanoTime", "/path/lib.so")
            out.write(f"{os.path.basename(so_path)}:{method} -> {jni_sym} [JNI]\n")
            continue

        # 1.5) Check Netty-specific mappings
        if method in netty_method_map:
            netty_sym, so_path = netty_method_map[method]
            out.write(f"{os.path.basename(so_path)}:{method} -> {netty_sym} [NETTY]\n")
            continue

        # 1.6) Try fuzzy Netty matching
        if method.startswith("io.netty"):
            result = match_netty_method(method, netty_method_map)
            if result:
                netty_sym, so_path = result
                out.write(f"{os.path.basename(so_path)}:{method} -> {netty_sym} [NETTY_FUZZY]\n")
                continue

        # 2) JVM_* via source tables
        # Method format is "pkg.ClassmethodName()descriptor"
        # jvm_method_map keys are "pkg.Class.methodName"
        # Extract class and method name to build lookup key
        jvm_sym = jvm_method_map.get(method)
        if not jvm_sym:
            # Try to parse method string to extract class.methodName
            # Find the last capital letter followed by a lowercase letter before '('
            match = re.match(r'^(.+?)([a-z][a-zA-Z0-9_]*)\(', method)
            if match:
                class_part = match.group(1)  # e.g., "java.lang.System"
                method_name = match.group(2)  # e.g., "nanoTime"
                lookup_key = f"{class_part}.{method_name}"
                jvm_sym = jvm_method_map.get(lookup_key)

        if jvm_sym:
            tag = "JVM"
            if libjvm_so and (jvm_sym not in available_jvm_symbols):
                tag = "JVM? NOT_IN_THIS_LIB"
            out.write(f"libjvm.so:{method} -> {jvm_sym} [{tag}]\n")
            continue

        # 3) Registered natives (non-JVM target) via source tables -> resolve to a library
        reg_sym = registered_method_map.get(method)
        if reg_sym:
            owner = resolve_symbol_in_libs(reg_sym, search_libs)
            if owner:
                out.write(f"{os.path.basename(owner)}:{method} -> {reg_sym} [REGISTERED]\n")
            else:
                out.write(f"{method} -> {reg_sym} [REGISTERED? UNRESOLVED]\n")
            continue

        # 4) Unknown (pure Java or unobserved registration)
        out.write(f"{method}: NOT_FOUND_IN_LIBS\n")

print(f"Done!")
print(f"- Detailed results: {detailed_output_file}")
