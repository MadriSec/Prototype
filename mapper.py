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
    LIB_DIRS = [
        "/home/rupesh.punna/Prototype/LIBS",
        "/home/rupesh.punna/SWAT4J/",
        "/home/rupesh.punna/SWAT4J/JNI_thirdparty/",
        "/usr/lib/jvm/java-17-openjdk-amd64/lib",
        "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/",
        "/usr/lib/x86_64-linux-gnu/",
    ]

# Optional: OpenJDK native source root to learn JNINativeMethod tables (no hardcoding).
# If absent, we skip source-based mapping.
JVM_SRC = os.environ.get("JVM_SRC", "")

# Optional: explicit path to libjvm.so. If not set, we discover it (preferring LIB_DIRS).
JVM_SO = os.environ.get("JVM_SO", "")

# Input list of Java methods (one per line): e.g., "java.lang.System.nanoTime"
methods_file = os.environ.get("METHODS_FILE", "formatted_methods.txt")

# Outputs
detailed_output_file = "method_syscalls.txt"
jni_only_output_file = "found_jni_methods.txt"
jvm_only_output_file = "found_jvm_methods.txt"
registered_only_output_file = "found_registered_methods.txt"

# ----------------------------
# Helpers
# ----------------------------
def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def jni_to_java_method(jni_name: str):
    """
    Convert JNI symbol "Java_pkg_Class_method" to "pkg.Class.method".
    Handles _1 => '_' unescape.
    """
    if not jni_name.startswith("Java_"):
        return None
    core = jni_name[5:].replace("_1", "_")
    return core.replace("_", ".")

def load_defined_symbols(so_path: str, pattern: str):
    """
    Return a set of symbol names matching `pattern` from `nm -D --defined-only so_path`.
    Notes:
      - `-D` limits to dynamic symbols; `--defined-only` excludes undefined refs.
      - `pattern` is a regex applied to each nm output line.
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
    Return absolute dependency library paths reported by `ldd binary_path`.
    Why:
      - Many target symbols live in transitive deps; we expand the search set so
        `resolve_symbol_in_libs` can locate owners reliably.
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
    Build a list of ELF libraries to scan for symbols by combining:
      - seed_libs and all of their transitive ldd-discovered dependencies; and
      - every `lib*.so*` ELF in `extra_dirs`.
    This ensures symbol resolution covers direct and indirect runtime libs.
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
    Find the library that DEFINES `symbol` by invoking `nm -D --defined-only` on
    each candidate. Returns the path of the owning `.so`, or None if not found.
    Typical usage: resolve registered (non-`JVM_*`) targets discovered from source
    tables to a concrete library for reporting.
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
    Build a best-effort mapping for Netty native methods which use custom
    `netty_*` symbol names instead of standard `Java_*` JNI names. Examples:
      - netty_unix_socket_getOption   -> io.netty.channel.unix.Socket.getOption
      - netty_epoll_linuxsocket_bindVSock -> io.netty.channel.epoll.LinuxSocket.bindVSock
    Implementation detail: uses plain `nm` (not `-D`) to include local symbols too.
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
                                if components[0] == 'unix' and len(components) >= 3:
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
    Fuzzy matcher to associate a Java Netty method with a plausible `netty_*`
    symbol when an exact entry is not constructed in `build_netty_map`.
    Tries context-aware and suffix-based heuristics.
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
method_to_jni: dict[str, tuple[str, str]] = {}
for so_path in so_paths:
    out_syms = load_defined_symbols(so_path, r"\bJava_[A-Za-z0-9_]+\b")
    for jni in out_syms:
        m = jni_to_java_method(jni)
        if m and m not in method_to_jni:
            method_to_jni[m] = (jni, so_path)

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
    Map native filenames to fully-qualified classes:
      java_lang_Class.c                -> java.lang.Class
      java_lang_reflect_Array.c        -> java.lang.reflect.Array
      jdk_internal_misc_Unsafe.c       -> jdk.internal.misc.Unsafe
      .../java/lang/Class.c            -> java.lang.Class
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
    Parse OpenJDK native sources to reconstruct `JNINativeMethod` table mappings.
    Returns two dicts:
      - jvm_map: "pkg.Class.method" -> "JVM_*" target
      - reg_map: "pkg.Class.method" -> non-`JVM_*` C function (registered native)
    Rationale: not all natives use `Java_*`; many core methods register to `JVM_*`
    or other C functions at startup and are invisible to pure binary scanning.
    """
    jvm_map, reg_map = {}, {}
    if not src_root or not os.path.isdir(src_root):
        return jvm_map, reg_map

    entry_rx = re.compile(
        r'\{\s*"(?P<name>[A-Za-z0-9_]+)"\s*,\s*"(?:[^"]+)"\s*,\s*\(void\*\)\s*&(?P<target>[A-Za-z0-9_]+)\s*\}'
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
                    if base in ("Class", "System", "Thread"):
                        use_class = f"java.lang.{base}"
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
# Step 5: Classify each method
# ----------------------------
found_jni_symbols = set()
found_jvm_symbols = set()
found_registered_symbols = set()

with open(detailed_output_file, "w", encoding="utf-8") as out:
    for method in methods:
        # 1) JNI (Java_*) direct hits from binaries
        if method in method_to_jni:
            jni_sym, so_path = method_to_jni[method]
            out.write(f"{os.path.basename(so_path)}:{method} -> {jni_sym} [JNI]\n")
            found_jni_symbols.add(jni_sym)
            continue

        # 1.5) Check Netty-specific mappings
        if method in netty_method_map:
            netty_sym, so_path = netty_method_map[method]
            out.write(f"{os.path.basename(so_path)}:{method} -> {netty_sym} [NETTY]\n")
            found_jni_symbols.add(netty_sym)  # Add to JNI symbols for simplicity
            continue

        # 1.6) Try fuzzy Netty matching
        if method.startswith("io.netty"):
            result = match_netty_method(method, netty_method_map)
            if result:
                netty_sym, so_path = result
                out.write(f"{os.path.basename(so_path)}:{method} -> {netty_sym} [NETTY_FUZZY]\n")
                found_jni_symbols.add(netty_sym)
                continue

        # 2) JVM_* via source tables
        jvm_sym = jvm_method_map.get(method)
        if jvm_sym:
            tag = "JVM"
            if libjvm_so and (jvm_sym not in available_jvm_symbols):
                tag = "JVM? NOT_IN_THIS_LIB"
            else:
                found_jvm_symbols.add(jvm_sym)
            out.write(f"libjvm.so:{method} -> {jvm_sym} [{tag}]\n")
            continue

        # 3) Registered natives (non-JVM target) via source tables -> resolve to a library
        reg_sym = registered_method_map.get(method)
        if reg_sym:
            owner = resolve_symbol_in_libs(reg_sym, search_libs)
            if owner:
                out.write(f"{os.path.basename(owner)}:{method} -> {reg_sym} [REGISTERED]\n")
                found_registered_symbols.add(reg_sym)
            else:
                out.write(f"{method} -> {reg_sym} [REGISTERED? UNRESOLVED]\n")
            continue

        # 4) Unknown (pure Java or unobserved registration)
        out.write(f"{method}: NOT_FOUND_IN_LIBS\n")

# ----------------------------
# Step 6: Write symbol lists
# ----------------------------
with open(jni_only_output_file, "w", encoding="utf-8") as jf:
    for sym in sorted(found_jni_symbols):
        jf.write(sym + "\n")

with open(jvm_only_output_file, "w", encoding="utf-8") as jf:
    for sym in sorted(found_jvm_symbols):
        jf.write(sym + "\n")

with open(registered_only_output_file, "w", encoding="utf-8") as jf:
    for sym in sorted(found_registered_symbols):
        jf.write(sym + "\n")

print(f"Done!")
print(f"- Detailed results: {detailed_output_file}")
print(f"- JNI-only list:   {jni_only_output_file}")
print(f"- JVM-only list:   {jvm_only_output_file}")
print(f"- Registered list: {registered_only_output_file}")
