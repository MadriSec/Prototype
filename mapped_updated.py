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
#   - LIB_DIRS: os.pathsep-separated directories to scan for ELF `.so` files.
#   - JVM_SRC:  Path to the OpenJDK source tree (optional).
#   - JVM_SO:   Explicit path to `libjvm.so` (optional, auto-discovered if unset).
#   - METHODS_FILE: File listing Java methods (one per line) to classify.
#   - OUTPUTS_DIR: Directory for output files (default: current directory).
#
# Outputs (in OUTPUTS_DIR):
#   - mapped_method_syscalls.txt: Per-method resolution details and classification tags.

import os
import re
import sys
import glob
import subprocess
import json
import time

# ----------------------------
# Config / Inputs
# ----------------------------
env_lib_dirs = os.environ.get("LIB_DIRS")
if env_lib_dirs:
    LIB_DIRS = [p for p in env_lib_dirs.split(os.pathsep) if p]
else:
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


def normalize_lib_dirs(lib_dirs: list) -> list:
    """
    Normalize known LIB_DIRS path variants.
    If a configured path does not exist and there is a sibling Extracted_Data/LIBS_* path,
    use the existing Extracted_Data path automatically.
    """
    normalized = []
    for lib_dir in lib_dirs:
        if os.path.isdir(lib_dir):
            normalized.append(lib_dir)
            continue
        alt = os.path.join(os.path.dirname(lib_dir), "Extracted_Data", os.path.basename(lib_dir))
        if os.path.isdir(alt):
            normalized.append(alt)
        else:
            normalized.append(lib_dir)
    return normalized

JVM_SRC = os.environ.get("JVM_SRC", "")
JVM_SRC_NORM = os.path.expanduser((JVM_SRC or "").strip().strip('"').strip("'"))
JVM_SO  = os.environ.get("JVM_SO", "")
output_dir = os.environ.get("OUTPUTS_DIR", ".").strip() or "."

DEBUG_LOG_PATH = "/home/rupesh.punna/Prototype/.cursor/debug-2d3c38.log"
DEBUG_SESSION_ID = "2d3c38"


def debug_log(run_id: str, hypothesis_id: str, message: str, data: dict):
    payload = {
        "sessionId": DEBUG_SESSION_ID,
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": "mapped_updated.py",
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass

# #region agent log
debug_log("cassandra-netty-tcnative", "H0", "mapped_updated.py module loaded", {
    "pythonExecutable": sys.executable,
    "cwd": os.getcwd(),
})
# #endregion

LIB_DIRS = normalize_lib_dirs(LIB_DIRS)

# ----------------------------
# Add supplemental JDK library directories for multi-version symbol resolution
# ----------------------------
# When analyzing JRuby (JDK 8) bytecode that references JDK 9+ methods,
# we need to search multiple JDK versions to resolve symbols correctly.
supplemental_jdk_dirs = [
    "/home/rupesh.punna/Prototype/LIBS_jdk8_temurin",   # Standard JDK 8 (for debugging tools)
    "/home/rupesh.punna/Prototype/LIBS_jdk11_temurin",  # JDK 11 (JDK 9+ features)
    "/home/rupesh.punna/Prototype/LIBS_jdk17_temurin",  # JDK 17 LTS (sealed classes, FFM incubating)
    "/home/rupesh.punna/Prototype/LIBS_jdk21_temurin",  # JDK 21 LTS (virtual threads, FFM preview)
    "/home/rupesh.punna/Prototype/netty_libs",          # Netty native transport libraries
    "/home/rupesh.punna/Prototype/netty_libs_all",      # Multiple Netty versions (4.1.50-4.1.113)
    "/home/rupesh.punna/Prototype/hawtjni_libs",        # Eclipse SWT (for HawtJNI)
    "/home/rupesh.punna/Prototype/hadoop_libs",         # Apache Hadoop 3.2.0 native libraries
    "/home/rupesh.punna/Prototype/hadoop_ec_downloads",
]

for jdk_dir in supplemental_jdk_dirs:
    if os.path.isdir(jdk_dir) and jdk_dir not in LIB_DIRS:
        LIB_DIRS.append(jdk_dir)
        print(f"INFO: Added supplemental JDK library directory: {jdk_dir}")

print("DEBUG: Using LIB_DIRS:")
for d in LIB_DIRS:
    print("  -", d)


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


methods_file = resolve_methods_file()
ensure_methods_file(methods_file)


def load_methods(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        methods = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Skip malformed entries from previous analysis runs (output classifications that got into input)
            if line in ("NOT_FOUND_IN_LIBS", "PLATFORM_EXCLUDED"):
                continue
            if line.startswith("NATIVE_METHOD_NOT_IN_THIS_BUILD"):
                continue
            if line.startswith("PLATFORM_EXCLUDED ("):
                continue
            methods.append(line)
        return methods


methods = load_methods(methods_file)

detailed_output_file = os.path.join(output_dir, "mapped_method_syscalls.txt")


def load_intrinsic_whitelist() -> set:
    """
    Load the JVM intrinsic whitelist — methods inlined by the JIT compiler
    that have no corresponding symbol in any .so file.
    Searches: INTRINSICS_FILE env var, then OUTPUTS_DIR, then cwd.
    """
    candidates = []
    env_path = os.environ.get("INTRINSICS_FILE")
    if env_path:
        candidates.append(env_path)
    if output_dir not in (".", ""):
        candidates.append(os.path.join(output_dir, "intrinsic_whitelist_all_jdks.txt"))
    candidates.append("intrinsic_whitelist_all_jdks.txt")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Bounded fallbacks to avoid expensive recursive directory traversal.
    candidates.append(os.path.join(script_dir, "intrinsic_whitelist_all_jdks.txt"))
    candidates.extend(
        glob.glob(os.path.join(script_dir, "outputs_*", "intrinsic_whitelist_all_jdks.txt"))
    )

    seen = set()
    ordered_candidates = []
    for path in candidates:
        if path and path not in seen:
            ordered_candidates.append(path)
            seen.add(path)

    for path in ordered_candidates:
        if os.path.isfile(path):
            entries = set()
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line)
            print(f"INFO: Loaded {len(entries)} intrinsic methods from {path}")
            return entries

    print("INFO: No intrinsic whitelist found (optional). Skipping intrinsic classification.")
    return set()


intrinsic_methods = load_intrinsic_whitelist()

# ----------------------------
# JVM built-in native mappings
# ----------------------------
# Methods resolved by the JVM's internal NativeLookup rather than through
# JNI symbol export or JNINativeMethod registration tables.
# These are well-known in the JVM spec and unlikely to change.
JVM_BUILTIN_NATIVES = {
    "java.lang.Object.wait":            "JVM_MonitorWait",
    "java.lang.Object.notify":          "JVM_MonitorNotify",
    "java.lang.Object.notifyAll":       "JVM_MonitorNotifyAll",
    "java.lang.Object.hashCode":        "JVM_IHashCode",
    "java.lang.Object.clone":           "JVM_Clone",
}

# Some Unsafe natives exist as local (non-exported) libjvm symbols and are not
# present in our current intrinsic/registered source tables for a given JDK build.
UNSAFE_LOCAL_FALLBACKS = {
    "jdk.internal.misc.Unsafe.allocateMemory0": "Unsafe_AllocateMemory0",
    "jdk.internal.misc.Unsafe.objectFieldOffset0": "Unsafe_ObjectFieldOffset0",
    "jdk.internal.misc.Unsafe.shouldBeInitialized0": "Unsafe_ShouldBeInitialized0",
}

# ----------------------------
# Unsafe legacy name aliases  (JDK <14 names → JDK 17+ names)
# ----------------------------
# Methods renamed in JDK 14 (JDK-8220793): Object→Reference.
# Bytecode compiled against older JDKs still references the old names.
# Map old name → new name so the source-scan and intrinsic lookups succeed.
UNSAFE_RENAMED = {
    "jdk.internal.misc.Unsafe.compareAndSetObject":      "jdk.internal.misc.Unsafe.compareAndSetReference",
    "jdk.internal.misc.Unsafe.compareAndExchangeObject":  "jdk.internal.misc.Unsafe.compareAndExchangeReference",
    "jdk.internal.misc.Unsafe.getObject":                "jdk.internal.misc.Unsafe.getReference",
    "jdk.internal.misc.Unsafe.putObject":                "jdk.internal.misc.Unsafe.putReference",
    "jdk.internal.misc.Unsafe.getObjectVolatile":        "jdk.internal.misc.Unsafe.getReferenceVolatile",
    "jdk.internal.misc.Unsafe.putObjectVolatile":        "jdk.internal.misc.Unsafe.putReferenceVolatile",
    "jdk.internal.misc.Unsafe.getObjectOpaque":          "jdk.internal.misc.Unsafe.getReferenceOpaque",
    "jdk.internal.misc.Unsafe.putObjectOpaque":          "jdk.internal.misc.Unsafe.putReferenceOpaque",
    "jdk.internal.misc.Unsafe.getObjectAcquire":         "jdk.internal.misc.Unsafe.getReferenceAcquire",
    "jdk.internal.misc.Unsafe.putObjectRelease":         "jdk.internal.misc.Unsafe.putReferenceRelease",
    "jdk.internal.misc.Unsafe.getAndSetObject":          "jdk.internal.misc.Unsafe.getAndSetReference",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectPlain":   "jdk.internal.misc.Unsafe.weakCompareAndSetReferencePlain",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObject":        "jdk.internal.misc.Unsafe.weakCompareAndSetReference",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectAcquire": "jdk.internal.misc.Unsafe.weakCompareAndSetReferenceAcquire",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectRelease": "jdk.internal.misc.Unsafe.weakCompareAndSetReferenceRelease",
}

# Deterministic JNI name aliases observed in bundled native libs.
METHOD_ALIASES = {
    "com.github.luben.zstd.Zstd.searchLengthMax": "com.github.luben.zstd.Zstd.searchLogMax",
    "com.github.luben.zstd.Zstd.searchLengthMin": "com.github.luben.zstd.Zstd.searchLogMin",
}

# ----------------------------
# JDK 8 ↔ JDK 9+ Package Renames
# ----------------------------
# In JDK 9, many internal APIs were moved from sun.* to jdk.internal.* (JEP 260)
# Bytecode compiled against JDK 9+ references jdk.internal.*, but JDK 8
# runtime only has sun.* symbols.
# This dictionary maps JDK 9+ names → JDK 8 names (verified against libjava.so)
JDK8_JDK9_PACKAGE_RENAMES = {
    # jdk.internal.misc.* → sun.misc.* (JEP 260)
    "jdk.internal.misc.Signal.handle0": "sun.misc.Signal.handle0",
    "jdk.internal.misc.Signal.raise0": "sun.misc.Signal.raise0",
    "jdk.internal.misc.VM.latestUserDefinedLoader0": "sun.misc.VM.latestUserDefinedLoader0",
    # Note: VM.getuid/geteuid/getgid/getegid are JDK 9+ only, no JDK 8 equivalent

    # jdk.internal.reflect.* → sun.reflect.* (JEP 260)
    "jdk.internal.reflect.ConstantPool.getUTF8At0": "sun.reflect.ConstantPool.getUTF8At0",
    "jdk.internal.reflect.ConstantPool.getIntAt0": "sun.reflect.ConstantPool.getIntAt0",
    "jdk.internal.reflect.ConstantPool.getLongAt0": "sun.reflect.ConstantPool.getLongAt0",
    "jdk.internal.reflect.ConstantPool.getFloatAt0": "sun.reflect.ConstantPool.getFloatAt0",
    "jdk.internal.reflect.ConstantPool.getDoubleAt0": "sun.reflect.ConstantPool.getDoubleAt0",
    "jdk.internal.reflect.ConstantPool.getClassAt0": "sun.reflect.ConstantPool.getClassAt0",
    "jdk.internal.reflect.ConstantPool.getStringAt0": "sun.reflect.ConstantPool.getStringAt0",
    # Note: areNestMates is JDK 11+ only, no JDK 8 equivalent
}

# ----------------------------
# JDK 8 ↔ JDK 9+ Method Name Changes
# ----------------------------
# Some methods were renamed in JDK 9+ (usually adding a "0" suffix for consistency)
# This maps JDK 9+ method names → JDK 8 method names
JDK8_JDK9_METHOD_RENAMES = {
    # Signal.findSignal0 (JDK 9+) → Signal.findSignal (JDK 8)
    "jdk.internal.misc.Signal.findSignal0": "sun.misc.Signal.findSignal",
}

# ----------------------------
# ZIP/NIO Method Name Variants
# ----------------------------
# Some JDK 9+ bytecode uses method names that don't match the actual JNI symbols
# (e.g., inflateBufferBytes vs inflateBytes)
METHOD_NAME_VARIANTS = {
    # Inflater methods - BufferBytes variant → Bytes
    "java.util.zip.Inflater.inflateBufferBytes": "java.util.zip.Inflater.inflateBytes",
    "java.util.zip.Inflater.inflateBytesBytes": "java.util.zip.Inflater.inflateBytes",

    # Deflater methods - BufferBytes variant → Bytes
    "java.util.zip.Deflater.deflateBufferBytes": "java.util.zip.Deflater.deflateBytes",
    "java.util.zip.Deflater.deflateBytesBytes": "java.util.zip.Deflater.deflateBytes",
}

# ----------------------------
# HawtJNI → Eclipse SWT Callback Mapping
# ----------------------------
# HawtJNI (org.fusesource.hawtjni.runtime) uses Eclipse SWT's Callback class internally.
# The Java package is org.fusesource.hawtjni.runtime.Callback, but the JNI symbols
# are Java_org_eclipse_swt_internal_Callback_*.
HAWTJNI_SWT_CALLBACK_MAPPING = {
    "org.fusesource.hawtjni.runtime.Callback.bind": "org.eclipse.swt.internal.Callback.bind",
    "org.fusesource.hawtjni.runtime.Callback.getEnabled": "org.eclipse.swt.internal.Callback.getEnabled",
    "org.fusesource.hawtjni.runtime.Callback.getEntryCount": "org.eclipse.swt.internal.Callback.getEntryCount",
    "org.fusesource.hawtjni.runtime.Callback.getPlatform": "org.eclipse.swt.internal.Callback.getPlatform",
    "org.fusesource.hawtjni.runtime.Callback.reset": "org.eclipse.swt.internal.Callback.reset",
    "org.fusesource.hawtjni.runtime.Callback.setEnabled": "org.eclipse.swt.internal.Callback.setEnabled",
    "org.fusesource.hawtjni.runtime.Callback.unbind": "org.eclipse.swt.internal.Callback.unbind",
}

# Known JNA/JFFI-style wrappers that directly bridge to libc symbols.
# These methods generally do not expose Java_* JNI symbols with matching names.
DIRECT_LIBC_METHODS = {
    "org.apache.cassandra.utils.NativeLibraryLinux.getpid": "getpid",
    "org.apache.cassandra.utils.NativeLibraryLinux.close": "close",
    "org.apache.cassandra.utils.NativeLibraryLinux.mlockall": "mlockall",
    "org.apache.cassandra.utils.NativeLibraryLinux.fcntl": "fcntl",
    "org.apache.cassandra.utils.NativeLibraryLinux.fsync": "fsync",
    "org.apache.cassandra.utils.NativeLibraryLinux.strerror": "strerror",
    "org.apache.cassandra.utils.NativeLibraryLinux.posix_fadvise": "posix_fadvise",
    "org.apache.cassandra.utils.NativeLibraryLinux.open": "open",
    "org.apache.cassandra.utils.NativeLibraryLinux.munlockall": "munlockall",
    "net.openhft.posix.internal.jna.JNAPosixInterface.mmap": "mmap",
    "org.fusesource.jansi.internal.CLibrary.openpty": "openpty",  # PTY allocation (Jansi terminal)
}

DIRECT_JNI_BRIDGES = {
    # JDK I/O wrappers invoke private native *0 methods.
    "java.io.RandomAccessFile.length": "Java_java_io_RandomAccessFile_length0",
    "java.io.RandomAccessFile.readBytes": "Java_java_io_RandomAccessFile_readBytes0",
    "java.io.RandomAccessFile.writeBytes": "Java_java_io_RandomAccessFile_writeBytes0",
    "java.io.RandomAccessFile.setLength": "Java_java_io_RandomAccessFile_setLength0",
}

SOURCE_JNI_BRIDGES = {
    # Implemented in OpenJDK libjava native sources; symbols may be hidden.
    "java.lang.StrictMath.log": "Java_java_lang_StrictMath_log",
    "java.security.AccessController.getStackAccessControlContext": "Java_java_security_AccessController_getStackAccessControlContext",
    "java.security.AccessController.getInheritedAccessControlContext": "Java_java_security_AccessController_getInheritedAccessControlContext",
}


# Netty tcnative SSL.java native methods -> documented OpenSSL function names.
# Source: https://netty.io/4.0/xref/io/netty/internal/tcnative/SSL.html
# Only methods whose javadoc explicitly names an OpenSSL function are included;
# methods without a documented C counterpart are intentionally omitted.
TCNATIVE_SSL_OPENSSL = {
    "newSSL":                 "SSL_new",
    "getError":               "SSL_get_error",
    "bioWrite":               "BIO_write",
    "bioFlushByteBuffer":     "BIO_flush",
    "sslPending":             "SSL_pending",
    "writeToSSL":             "SSL_write",
    "readFromSSL":            "SSL_read",
    "getShutdown":            "SSL_get_shutdown",
    "setShutdown":            "SSL_set_shutdown",
    "freeSSL":                "SSL_free",
    "freeBIO":                "BIO_free",
    "shutdownSSL":            "SSL_shutdown",
    "getCipherForSSL":        "SSL_get_cipher",
    "getVersion":             "SSL_get_version",
    "doHandshake":            "SSL_do_handshake",
    "isInInit":               "SSL_in_init",
    "getNextProtoNegotiated": "SSL_get0_next_proto_negotiated",
    "getAlpnSelected":        "SSL_get0_alpn_selected",
    "getTime":                "SSL_get_time",
    "getTimeout":             "SSL_get_timeout",
    "setTimeout":             "SSL_set_timeout",
    "setMode":                "SSL_set_mode",
    "getMode":                "SSL_get_mode",
    "getMaxWrapOverhead":     "SSL_max_seal_overhead",
    "renegotiate":            "SSL_renegotiate",
    "setState":               "SSL_set_state",
    "setTlsExtHostName":      "SSL_set_tlsext_host_name",
    "setHostNameValidation":  "X509_check_host",
    "enableOcsp":             "SSL_set_tlsext_status_type",
    # --- Additional documented mappings (high-confidence from javadoc evidence) ---
    "version":                "OpenSSL_version_num",
    "versionString":          "OpenSSL_version",
    "getLastErrorNumber":     "ERR_peek_last_error",
    "getErrorString":         "ERR_error_string",
    "getPeerCertChain":       "SSL_get_peer_cert_chain",
    "getPeerCertificate":     "SSL_get_peer_certificate",
    "setVerify":              "SSL_set_verify",
    "setOptions":             "SSL_set_options",
    "clearOptions":           "SSL_clear_options",
    "getOptions":             "SSL_get_options",
    "getCiphers":             "SSL_get_ciphers",
    "setCipherSuites":        "SSL_set_cipher_list",
    "getSessionId":           "SSL_SESSION_get_id",
    "clearError":             "ERR_clear_error",
    "parsePrivateKey":        "PEM_read_bio_PrivateKey",
    "freePrivateKey":         "EVP_PKEY_free",
    # OCSP payload setter/getter: javadoc links to SSL_set_tlsext_status_type
    # (the enabler), but that's what enableOcsp already maps to. The semantically
    # correct symbols for setting/getting the OCSP response payload are:
    "setOcspResponse":        "SSL_set_tlsext_status_ocsp_resp",
    "getOcspResponse":        "SSL_get_tlsext_status_ocsp_resp",
}

# Netty tcnative SSLContext.java native methods -> documented OpenSSL function names.
# Source: https://chromium.googlesource.com/external/netty-tcnative/+/refs/heads/master/java/io/netty/internal/tcnative/SSLContext.java
# Only methods with explicit javadoc evidence or an unambiguous SSL_CTX_* naming
# convention are included. tcnative-internal helpers (e.g., sessionTicketKey*
# stats counters) and multi-call wrappers are intentionally omitted.
TCNATIVE_SSLCONTEXT_OPENSSL = {
    "make":                      "SSL_CTX_new",
    "free":                      "SSL_CTX_new",
    "setOptions":                "SSL_CTX_set_options",
    "getOptions":                "SSL_CTX_get_options",
    "clearOptions":              "SSL_CTX_clear_options",
    "setCipherSuite":            "SSL_CTX_set_cipher_list",
    "setCertificate":            "SSL_CTX_use_certificate",
    "setCertificateBio":         "SSL_CTX_use_certificate",
    "setCertificateChainBio":    "tcn_SSL_CTX_use_certificate_chain_bio",
    "setCACertificateBio":       "tcn_SSL_CTX_use_client_CA_bio",
    "setCertificateChainFile":   "SSL_CTX_use_certificate_chain_file",
    "setSessionCacheSize":       "SSL_CTX_sess_set_cache_size",
    "getSessionCacheSize":       "SSL_CTX_sess_get_cache_size",
    "setSessionCacheTimeout":    "SSL_CTX_set_timeout",
    "getSessionCacheTimeout":    "SSL_CTX_get_timeout",
    "setSessionCacheMode":       "SSL_CTX_set_session_cache_mode",
    "getSessionCacheMode":       "SSL_CTX_get_session_cache_mode",
    "sessionAccept":             "SSL_CTX_sess_accept",
    "sessionAcceptGood":         "SSL_CTX_sess_accept_good",
    "sessionAcceptRenegotiate":  "SSL_CTX_sess_accept_renegotiate",
    "sessionCacheFull":          "SSL_CTX_sess_cache_full",
    "sessionCbHits":             "SSL_CTX_sess_cb_hits",
    "sessionConnect":            "SSL_CTX_sess_connect",
    "sessionConnectGood":        "SSL_CTX_sess_connect_good",
    "sessionConnectRenegotiate": "SSL_CTX_sess_connect_renegotiate",
    "sessionHits":               "SSL_CTX_sess_hits",
    "sessionMisses":             "SSL_CTX_sess_misses",
    "sessionNumber":             "SSL_CTX_sess_number",
    "sessionTimeouts":           "SSL_CTX_sess_timeouts",
    # Ticket key stats are exposed by SSLContext.java as native counters.
    "sessionTicketKeyNew":       "SSL_CTX_sess_ticket_key_new",
    "sessionTicketKeyResume":    "SSL_CTX_sess_ticket_key_resume",
    "sessionTicketKeyRenew":     "SSL_CTX_sess_ticket_key_renew",
    "sessionTicketKeyFail":      "SSL_CTX_sess_ticket_key_fail",
    "setVerify":                 "SSL_CTX_set_verify",
    "setCertVerifyCallback":     "SSL_CTX_set_cert_verify_callback",
    "setCertRequestedCallback":  "SSL_CTX_set_client_cert_cb",
    "setSniHostnameMatcher":     "SSL_CTX_set_tlsext_servername_callback",
    "setTmpDHLength":            "SSL_CTX_set_tmp_dh_callback",
    "setSessionTicketKeys":      "SSL_CTX_set_tlsext_ticket_key_cb",
    "enableOcsp":                "SSL_CTX_set_tlsext_status_cb",
    "disableOcsp":               "SSL_CTX_set_tlsext_status_cb",
    "setAlpnProtos":             "SSL_CTX_set_alpn_protos",
    # setContextId hashes its String arg then calls SSL_CTX_set_session_id_context;
    # same underlying OpenSSL symbol as setSessionIdContext (intentional collision).
    "setContextId":              "SSL_CTX_set_session_id_context",
    "setSessionIdContext":       "SSL_CTX_set_session_id_context",
    "setMode":                   "SSL_CTX_set_mode",
    "getMode":                   "SSL_CTX_get_mode",
}

# Dispatch tuple for stage 1.4: (fully-qualified class prefix, per-class map).
# Prefixes include the trailing dot so "SSL." and "SSLContext." never overlap.
TCNATIVE_CLASS_MAPS = (
    ("io.netty.internal.tcnative.SSLContext.", TCNATIVE_SSLCONTEXT_OPENSSL),
    ("io.netty.internal.tcnative.SSL.",        TCNATIVE_SSL_OPENSSL),
)

# Sigar high-level gather methods that map to native "Sigar_get*List" entrypoints.
SIGAR_LIST_BRIDGES = {
    "org.hyperic.sigar.FileSystem.gather": "Java_org_hyperic_sigar_Sigar_getFileSystemListNative",
    "org.hyperic.sigar.Who.gather": "Java_org_hyperic_sigar_Sigar_getWhoList",
    "org.hyperic.sigar.CpuInfo.gather": "Java_org_hyperic_sigar_Sigar_getCpuInfoList",
    "org.hyperic.sigar.NetRoute.gather": "Java_org_hyperic_sigar_Sigar_getNetRouteList",
    "org.hyperic.sigar.NetConnection.gather": "Java_org_hyperic_sigar_Sigar_getNetConnectionList",
}

UNSAFE_FENCE_METHODS = {
    "jdk.internal.misc.Unsafe.loadFence",
    "jdk.internal.misc.Unsafe.storeFence",
}

# ----------------------------
# Helpers
# ----------------------------

def is_elf(path: str) -> bool:
    """Return True if the file starts with the ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def jni_to_java_method(jni_name: str):
    """
    Convert a JNI symbol name to its fully-qualified Java method name.

    KEY FIX: Strip the overload disambiguation suffix before processing.
    The JNI spec uses double-underscore (__) to separate the method name from
    the encoded argument signature when overloaded methods exist.

    Examples:
        Java_com_kenai_jffi_Foreign_getZeroTerminatedByteArrayChecked__J
            -> com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked
        Java_com_kenai_jffi_Foreign_getZeroTerminatedByteArrayChecked__JI
            -> com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked
        Java_java_lang_System_nanoTime
            -> java.lang.System.nanoTime
        Java_java_util_Map_00024Entry_getKey
            -> java.util.Map$Entry.getKey
        Java_com_sun_GTKEngine_native_1get_1gtk_1setting
            -> com.sun.GTKEngine.native_get_gtk_setting
        Java_com_kenai_jffi_Foreign_defineClass__Ljava_lang_String_2Ljava_lang_Object_2_3BII
            -> com.kenai.jffi.Foreign.defineClass
        Java_com_sun_jna_Native__1getPointer
            -> com.sun.jna.Native._getPointer     (__1 = separator + underscore escape, NOT overload)
        Java_com_sun_jna_Native__1getDirectBufferPointer
            -> com.sun.jna.Native._getDirectBufferPointer
    """
    if not jni_name.startswith("Java_"):
        return None

    mangled = jni_name[5:]

    # CRITICAL FIX: Strip overload suffix — double underscore marks the start of
    # the encoded argument type signature (e.g., __J, __JI, __Ljava_lang_String_2).
    # This suffix is NOT part of the Java method name and must be removed before
    # any other processing, otherwise __ becomes .. in the final output.
    #
    # BUG FIX: Must NOT strip at "__" when followed by JNI escape digits (0-3).
    # JNI escape sequences: _1 (underscore), _2 (semicolon), _3 (bracket), _0xxxx (unicode).
    # So "__1" is actually "_" (separator) + "_1" (literal underscore), NOT an overload
    # delimiter.  Example: Java_com_sun_jna_Native__1getPointer → _getPointer (not stripped).
    # We use a negative lookahead (?![0-3]) to skip these escape sequences.
    overload_match = re.search(r'__(?![0-3])', mangled)
    if overload_match:
        mangled = mangled[:overload_match.start()]

    # Step 1: Handle Unicode escapes (_0xxxx -> Unicode character)
    # Must be done BEFORE other replacements
    def unescape_unicode(match):
        return chr(int(match.group(1), 16))

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


def load_defined_symbols(so_path: str, pattern: str) -> set:
    """
    Extract defined symbol names from an ELF shared library matching a regex pattern.
    Uses nm -D --defined-only to get only exported, defined symbols.
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


def ldd_paths(binary_path: str) -> list:
    """Discover all shared library dependencies of a binary via ldd."""
    try:
        out = subprocess.check_output(
            ["ldd", binary_path],
            universal_newlines=True,
            stderr=subprocess.DEVNULL,
        )
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


def collect_search_libs(seed_libs: list, extra_dirs: list) -> list:
    """
    Build a comprehensive list of ELF libraries to search for symbol definitions.
    Combines seed libraries with all their transitive dependencies (via ldd) and
    all libraries found in additional directories.
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

def build_class_maps(methods: list) -> tuple:
    """
    Derive netty class name maps dynamically from the methods file.
    Reads actual Java class names and maps their lowercase token
    (as it appears in nm symbols) to the correct CamelCase class name.
    
    e.g. com.datastax.shaded.netty.channel.unix.FileDescriptor.close
         -> 'filedescriptor' -> 'FileDescriptor'
    """
    unix_map  = {}
    epoll_map = {}

    # Match any netty package (canonical or shaded) — no hardcoded vendor prefixes.
    # Captures the class name from e.g. "*.netty.channel.unix.FileDescriptor.close"
    unix_rx = re.compile(r'\.netty\.channel\.unix\.([A-Za-z]+)\.')
    epoll_rx = re.compile(r'\.netty\.channel\.epoll\.([A-Za-z]+)\.')

    try:
        for line in methods:
            m = unix_rx.search(line)
            if m:
                class_name = m.group(1)
                unix_map[class_name.lower()] = class_name

            m = epoll_rx.search(line)
            if m:
                class_name = m.group(1)
                epoll_map[class_name.lower()] = class_name

    except Exception as e:
        print(f"WARN: Could not build class maps from methods file: {e}", file=sys.stderr)

    print(f"INFO: Derived unix class map:  {unix_map}")
    print(f"INFO: Derived epoll class map: {epoll_map}")
    return unix_map, epoll_map


def discover_shaded_netty_prefixes(methods: list) -> list:
    """
    Scan the methods file to discover all shaded/relocated netty package prefixes.
    Returns a list of prefix strings (e.g., 'com.datastax.shaded.netty',
    'org.apache.storm.shade.io.netty') that are aliases for 'io.netty'.
    Detected dynamically from the methods present in the input — no hardcoded vendors.
    """
    prefixes = set()
    # Match methods in known netty subpackages: channel.unix, channel.epoll,
    # channel.kqueue, internal.tcnative — and extract the prefix before them.
    # Only match valid Java package names (letters, digits, dots, underscores, $).
    netty_pkg_rx = re.compile(
        r'^([a-zA-Z][a-zA-Z0-9_$.]*\.netty)\.(channel\.(unix|epoll|kqueue)|internal\.tcnative)\.'
    )
    try:
        for line in methods:
            m = netty_pkg_rx.match(line)
            if m:
                prefix = m.group(1)
                if prefix != "io.netty":
                    prefixes.add(prefix)
    except Exception as e:
        print(f"WARN: Could not discover shaded netty prefixes: {e}", file=sys.stderr)

    result = sorted(prefixes)
    if result:
        print(f"INFO: Discovered shaded netty prefixes: {result}")
    return result


def resolve_symbol_in_libs(symbol: str, libs: list):
    """
    Find which library in a collection actually defines a given symbol.
    Returns the path to the first library that defines it, or None.
    """
    global RESOLVE_SYMBOL_CALLS
    RESOLVE_SYMBOL_CALLS += 1
    for so in libs:
        symbols = get_library_symbol_index(so, require_full=False)
        if symbol in symbols:
            return so
        # Fallback to local/non-exported symbol index only if needed.
        symbols_full = get_library_symbol_index(so, require_full=True)
        if symbol in symbols_full:
            return so
    return None


LIB_SYMBOL_INDEX = {}
LIB_SYMBOL_INDEX_FULL = set()
NM_SUBPROCESS_CALLS = 0
RESOLVE_SYMBOL_CALLS = 0


def _add_symbol_and_alias(symbols: set, sym: str):
    symbols.add(sym)
    if "@" in sym:
        symbols.add(sym.split("@", 1)[0])


def get_library_symbol_index(so: str, require_full: bool = False) -> set:
    global NM_SUBPROCESS_CALLS
    cached = LIB_SYMBOL_INDEX.get(so)
    if cached is not None and (not require_full or so in LIB_SYMBOL_INDEX_FULL):
        return cached

    symbols = cached if cached is not None else set()
    commands = (
        [
            ["nm", "--defined-only", so],  # include local defined symbols
            ["nm", so],                    # broad fallback (handles stripped oddities)
        ]
        if cached is not None
        else [
            ["nm", "-D", "--defined-only", so],  # exported dynamic symbols first
        ]
    )

    for cmd in commands:
        try:
            NM_SUBPROCESS_CALLS += 1
            out = subprocess.check_output(
                cmd,
                universal_newlines=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if parts:
                _add_symbol_and_alias(symbols, parts[-1])
        if cached is None and symbols and not require_full:
            break

    LIB_SYMBOL_INDEX[so] = symbols
    if require_full:
        LIB_SYMBOL_INDEX_FULL.add(so)
    return symbols


def build_netty_map(lib_paths: list, methods: list, shaded_prefixes: list = None) -> dict:
    netty_map = {}

    # Derive class name maps and method sets from the methods file — no hardcoding
    UNIX_CLASS_MAP, EPOLL_CLASS_MAP = build_class_maps(methods)

    netty_libs = [p for p in lib_paths if 'netty' in os.path.basename(p).lower()]

    for lib in netty_libs:
        try:
            out = subprocess.check_output(
                ["nm", lib],
                universal_newlines=True,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if 'netty_' not in line:
                    continue
                parts = line.split()

                # Handle both:
                #   "addr t symbol"  (3 parts)
                #   "t symbol"       (2 parts — local symbols, no address)
                if len(parts) == 3:
                    symbol_type = parts[1]
                    symbol      = parts[2]
                elif len(parts) == 2:
                    symbol_type = parts[0]
                    symbol      = parts[1]
                else:
                    continue

                if symbol_type not in ('t', 'T') or not symbol.startswith('netty_'):
                    continue

                # Skip JNI lifecycle symbols — not Java native methods
                if symbol.endswith(('JNI_OnLoad', 'JNI_OnUnLoad', 'JNI_OnUnload')):
                    continue

                components = symbol[6:].split('_')
                if len(components) < 3:
                    continue

                if components[0] == 'internal' and len(components) >= 4 and components[1] == 'tcnative':
                    class_name  = components[2]
                    method_name = '_'.join(components[3:])
                    java_method = "io.netty.internal.tcnative.{class_name}.{method_name}"
                    netty_map[java_method] = (symbol, lib)
                    for prefix in (shaded_prefixes or []):
                        netty_map[java_method.replace("io.netty", prefix, 1)] = (symbol, lib)

                elif components[0] == 'unix' and len(components) >= 3:
                    class_token = components[1]
                    class_name  = UNIX_CLASS_MAP.get(class_token, class_token.title())
                    # Join ALL remaining components as method name
                    # handles multi-word methods: netty_unix_errors_strError -> strError
                    method_name = '_'.join(components[2:])
                    java_method = f"io.netty.channel.unix.{class_name}.{method_name}"
                    netty_map[java_method] = (symbol, lib)
                    for prefix in (shaded_prefixes or []):
                        netty_map[java_method.replace("io.netty", prefix, 1)] = (symbol, lib)

                elif components[0] == 'epoll' and len(components) >= 3:
                    class_token = components[1]
                    class_name  = EPOLL_CLASS_MAP.get(class_token, class_token.title())
                    method_name = '_'.join(components[2:])
                    java_method = f"io.netty.channel.epoll.{class_name}.{method_name}"
                    netty_map[java_method] = (symbol, lib)
                    for prefix in (shaded_prefixes or []):
                        netty_map[java_method.replace("io.netty", prefix, 1)] = (symbol, lib)

                elif len(components) >= 2:
                    java_method = f"io.netty.channel.{components[0]}.{'_'.join(components[1:])}"
                    netty_map[java_method] = (symbol, lib)
                    for prefix in (shaded_prefixes or []):
                        netty_map[java_method.replace("io.netty", prefix, 1)] = (symbol, lib)

        except Exception as e:
            print(f"WARN: Failed to process netty lib {lib}: {e}", file=sys.stderr)

    return netty_map

def match_netty_method(method: str, netty_symbols: dict, shaded_prefixes: list = None):
    """
    Fuzzy matching to associate a Java Netty method with a native netty_* symbol
    when exact mapping wasn't found in build_netty_map().
    Handles shaded netty packages by normalizing to canonical 'io.netty' form.
    """
    # Normalize shaded method to canonical io.netty form for matching
    canonical = method
    if not method.startswith("io.netty"):
        for prefix in (shaded_prefixes or []):
            if method.startswith(prefix):
                canonical = "io.netty" + method[len(prefix):]
                break
        if not canonical.startswith("io.netty"):
            return None

    parts = canonical.split('.')
    if len(parts) < 4:
        return None

    class_name  = parts[-2].lower()
    method_name = parts[-1]
    package_type = 'epoll' if 'epoll' in canonical else ('unix' if 'unix' in canonical else None)

    patterns = []
    if package_type:
        patterns.append(f"netty_{package_type}_{class_name}_{method_name}")
    patterns.append(f"netty_{class_name}_{method_name}")

    for pattern in patterns:
        for java_method, (symbol, lib_path) in netty_symbols.items():
            if pattern.lower() in symbol.lower():
                return (symbol, lib_path)

    method_suffix = method_name.lower()
    for java_method, (symbol, lib_path) in netty_symbols.items():
        if symbol.lower().endswith(method_suffix):
            return (symbol, lib_path)

    return None

# ----------------------------
# Discover libraries (.so) — filter to ELF only
# ----------------------------
so_paths: list = []
for lib_dir in LIB_DIRS:
    matched = glob.glob(os.path.join(lib_dir, "lib*.so*"))
    for p in matched:
        if is_elf(p):
            so_paths.append(p)

so_basenames_lower = [os.path.basename(p).lower() for p in so_paths]
has_chronicle_native_lib = any(
    ("chronicle" in b) or ("affinity" in b) or ("ticker" in b)
    for b in so_basenames_lower
)
has_commons_daemon_lib = any("daemon" in b for b in so_basenames_lower)


def find_libjvm():
    """
    Locate libjvm.so, preferring LIB_DIRS, then JAVA_HOME, then system paths.
    Returns path string or None.
    """
    if JVM_SO and os.path.isfile(JVM_SO):
        return JVM_SO
    for d in LIB_DIRS:
        for p in glob.glob(os.path.join(d, "**", "libjvm.so"), recursive=True):
            if os.path.isfile(p) and is_elf(p):
                return p
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

print("DEBUG: ELF libraries found:")
for p in so_paths:
    print(" -", p)
if libjvm_so:
    print(" - (JVM) ", libjvm_so)
else:
    print("WARN: libjvm.so not found; JVM_* validation will be skipped")

# ----------------------------
# Step 1: Build JNI mapping (Java_* symbols)
#
# KEY FIX: Use dict[str, list[tuple]] instead of dict[str, tuple] to handle
# overloaded methods. Multiple JNI symbols can map to the same Java method name
# (e.g., Java_*_getZeroTerminatedByteArrayChecked__J and __JI both map to
# com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked). We store all of them
# and use the first one for output (they all live in the same .so).
# ----------------------------
method_to_jni: dict = {}  # str -> list[tuple[str, str]]

for so_path in so_paths:
    out_syms = load_defined_symbols(so_path, r"\bJava_[A-Za-z0-9_]+\b")
    for jni in out_syms:
        java_method = jni_to_java_method(jni)
        if java_method:
            if java_method not in method_to_jni:
                method_to_jni[java_method] = []
            method_to_jni[java_method].append((jni, so_path))

print(f"INFO: Built JNI map with {len(method_to_jni)} unique Java method entries")

# Show a few examples including overloaded ones
overloaded = {k: v for k, v in method_to_jni.items() if len(v) > 1}
print(f"INFO: {len(overloaded)} methods have overloaded JNI variants")
for method, variants in list(overloaded.items())[:5]:
    print(f"  {method}:")
    for sym, lib in variants:
        print(f"    {sym} ({os.path.basename(lib)})")

# ----------------------------
# Step 1.5: Netty mapping (netty_* symbols)
# ----------------------------
shaded_netty_prefixes = discover_shaded_netty_prefixes(methods)
netty_method_map = build_netty_map(so_paths, methods, shaded_netty_prefixes)
# Tuple of all netty-related prefixes for fast startswith() checks
_all_netty_prefixes = tuple(["io.netty"] + shaded_netty_prefixes)
if netty_method_map:
    print(f"INFO: Found {len(netty_method_map)} Netty native methods.")
    for i, (method, (symbol, lib)) in enumerate(netty_method_map.items()):
        if i < 5:
            print(f"  {method} -> {symbol} ({os.path.basename(lib)})")
        elif i == 5:
            print("  ...")
            break
else:
    print("INFO: No Netty libraries found or no netty_* symbols detected.")

# ----------------------------
# Step 1.7: JNI Dynamic Bindings (extracted via bytecode analysis)
# ----------------------------
def load_jni_dynamic_bindings(output_dir_path: str) -> dict:
    """
    Load JNI dynamic bindings extracted via bytecode analysis from JnaDynDetector/Mode4.
    File format: libfoo.so|com.example.Class.method|(I)V|native_symbol|HIGH_CONF
    Returns: dict[java_method] -> (jni_symbol, library_path)
    """
    candidates = [
        os.path.join(output_dir_path, "jni_dynamic_bindings.txt"),
        "jni_dynamic_bindings.txt",
    ]

    for path in candidates:
        if os.path.isfile(path):
            bindings = {}
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) >= 4:
                        lib_name, java_method, signature, jni_symbol = parts[:4]
                        # Find full path to this library
                        lib_path = None
                        for so in so_paths:
                            if os.path.basename(so) == lib_name:
                                lib_path = so
                                break
                        if lib_path:
                            bindings[java_method] = (jni_symbol, lib_path)
            print(f"INFO: Loaded {len(bindings)} JNI dynamic bindings from {path}")
            return bindings

    print("INFO: No JNI dynamic bindings file found (optional).")
    return {}

jni_dynamic_map = load_jni_dynamic_bindings(output_dir)

# ----------------------------
# Step 1.8: JFR RegisterNatives bindings (extracted via jfr_registernative_mapping.sh)
# ----------------------------
def load_jfr_registernatives(output_dir_path: str) -> dict:
    """
    Load JFR RegisterNatives mappings extracted from libjvm.so.
    File format (from jfr_registernative_mapping.sh output):
        N. jdk.jfr.internal.JVM.methodName(signature) → native_symbol
    Returns: dict[java_method_without_sig] -> native_symbol
        e.g. "jdk.jfr.internal.JVM.beginRecording" -> "jfr_begin_recording"
    """
    candidates = [
        os.path.join(output_dir_path, "jfr_extracted_methods.txt"),
        "jfr_extracted_methods.txt",
    ]

    # Pattern: " N. jdk.jfr.internal.JVM.methodName(sig) → native_symbol"
    entry_rx = re.compile(
        r'^\s*\d+\.\s+([A-Za-z0-9_.]+\.[A-Za-z_][A-Za-z0-9_]*)\(.*?\)\s*→\s*(\S+)'
    )

    for path in candidates:
        if os.path.isfile(path):
            bindings = {}
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = entry_rx.match(line)
                    if m:
                        java_method = m.group(1)  # e.g. jdk.jfr.internal.JVM.beginRecording
                        native_sym = m.group(2)   # e.g. jfr_begin_recording
                        bindings[java_method] = native_sym
            print(f"INFO: Loaded {len(bindings)} JFR RegisterNatives bindings from {path}")
            return bindings

    print("INFO: No JFR RegisterNatives file found (optional). Run jfr_registernative_mapping.sh to generate.")
    return {}


jfr_registernatives_map = load_jfr_registernatives(output_dir)

# ----------------------------
# Step 2: Source-based scan of JNINativeMethod tables (optional)
# ----------------------------


# Map of well-known HotSpot/libjava source file basenames (CASE-INSENSITIVE)
# to their corresponding fully-qualified Java class names.
# Needed because HotSpot filenames (e.g., unsafe.cpp, methodHandles.cpp) don't
# follow the standard Java_pkg_Class naming convention.
_HOTSPOT_FILE_CLASS_MAP = {
    # hotspot/share/prims/
    "unsafe":           "jdk.internal.misc.Unsafe",
    "methodhandles":    "java.lang.invoke.MethodHandleNatives",
    "perf":             "jdk.internal.perf.Perf",
    "scopedmemoryaccess": "jdk.internal.misc.ScopedMemoryAccess",
    # libjava files
    "class":            "java.lang.Class",
    "system":           "java.lang.System",
    "thread":           "java.lang.Thread",
    "classloader":      "java.lang.ClassLoader",
    "runtime":          "java.lang.Runtime",
    "object":           "java.lang.Object",
    "string":           "java.lang.String",
    "throwable":        "java.lang.Throwable",
    "stacktraceelement": "java.lang.StackTraceElement",
    "processenvironment": "java.lang.ProcessEnvironment",
    "package":          "java.lang.Package",
    "module":           "java.lang.Module",
    "float":            "java.lang.Float",
    "double":           "java.lang.Double",
    "strictmath":       "java.lang.StrictMath",
    "vm":               "jdk.internal.misc.VM",
    "signal":           "jdk.internal.misc.Signal",
    "accesscontroller": "java.security.AccessController",
    "objectoutputstream": "java.io.ObjectOutputStream",
    "objectinputstream":  "java.io.ObjectInputStream",
    "mappedbytebuffer":   "java.nio.MappedByteBuffer",
}


def infer_java_class_from_path(filepath: str):
    """
    Infer the fully-qualified Java class name from a native source file path.
    Uses filename pattern, directory structure, HotSpot file map, and file
    content as fallbacks.
    """
    path = filepath.replace("\\", "/")
    base = os.path.splitext(os.path.basename(path))[0]

    # Pattern 1: Standard libjava naming — e.g., java_lang_Thread_isAlive.c
    m = re.match(r'^(java|jdk)_([A-Za-z0-9_]+)_([A-Za-z0-9_$]+)$', base)
    if m:
        root, pkg_part, cls = m.groups()
        pkg = pkg_part.replace('_', '.')
        return f"{root}.{pkg}.{cls}"

    # Pattern 2: Directory-based — e.g., .../native/libjava/Thread.c
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

    # Pattern 3: Well-known HotSpot/libjava file names (case-insensitive)
    mapped = _HOTSPOT_FILE_CLASS_MAP.get(base.lower())
    if mapped:
        return mapped

    # Pattern 4: Content-based fallback — scan first 4K for a FQCN
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
    Parse OpenJDK source code to extract JNINativeMethod registration tables.
    Returns two dicts:
      - jvm_map:  method -> JVM_* symbol
      - reg_map:  method -> non-JVM C function name
    """
    jvm_map, reg_map = {}, {}
    if not src_root or not os.path.isdir(src_root):
        return jvm_map, reg_map

    # Match JNINativeMethod table entries in three common cast styles:
    #   1)  (void *)&JVM_StartThread           — libjava C files (Thread.c, etc.)
    #   2)  FN_PTR(Unsafe_AllocateMemory0)     — HotSpot C++ files (unsafe.cpp, methodHandles.cpp)
    #   3)  CAST_FROM_FN_PTR(void*, &target)   — rare, but FN_PTR expands to this
    entry_rx = re.compile(
        r'''\{\s*
            (?:CC\s*)?"(?P<name>[A-Za-z0-9_]+)"\s*,\s*
            (?P<sig>[^,]+?)\s*,\s*
            (?:
                \(void\s*\*\)\s*&?(?P<target1>[A-Za-z0-9_]+)
              | FN_PTR\((?P<target2>[A-Za-z0-9_]+)\)
              | CAST_FROM_FN_PTR\([^,]+,\s*&?(?P<target3>[A-Za-z0-9_]+)\)
            )
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
                name   = m.group("name")
                target = m.group("target1") or m.group("target2") or m.group("target3")
                use_class = clazz
                if not use_class:
                    # infer_java_class_from_path handles HotSpot files via
                    # _HOTSPOT_FILE_CLASS_MAP; if it still returns None, skip.
                    continue
                key = f"{use_class}.{name}"
                if target.startswith("JVM_"):
                    jvm_map.setdefault(key, target)
                else:
                    reg_map.setdefault(key, target)

    return jvm_map, reg_map


try:
    jvm_method_map, registered_method_map = scan_native_tables(JVM_SRC_NORM)
    if JVM_SRC_NORM and os.path.isdir(JVM_SRC_NORM):
        print(f"INFO: Source scan found {len(jvm_method_map)} JVM_* entries "
              f"and {len(registered_method_map)} registered entries.")
    else:
        shown = JVM_SRC_NORM or JVM_SRC or "<empty>"
        print(f"INFO: JVM_SRC not set (or missing). Skipping source-based mapping. ({shown})")
except Exception as e:
    print(f"WARN: JVM source scan failed: {e}", file=sys.stderr)
    jvm_method_map, registered_method_map = {}, {}

# ----------------------------
# Step 3: Validate JVM_* symbols and prepare search library list
# ----------------------------
available_jvm_symbols = set()
if libjvm_so:
    available_jvm_symbols = load_defined_symbols(libjvm_so, r"\bJVM_[A-Za-z0-9_]+\b")

seed_libs = []
if libjvm_so:
    seed_libs.append(libjvm_so)
for p in so_paths:
    if os.path.basename(p).startswith("libjava.so"):
        seed_libs.append(p)

search_libs = collect_search_libs(seed_libs, LIB_DIRS)

print(f"INFO: Classifying {len(methods)} methods...")

# ----------------------------
# Step 4.5: Platform-exclusion keywords
# ----------------------------
# Methods containing these substrings target non-Linux platforms and will
# never execute inside a Linux container.  Tag them early so we skip the
# expensive symbol lookups and keep them out of the "NOT_FOUND" bucket.
PLATFORM_EXCLUDE_KEYWORDS = [
    ".kqueue.",             # macOS/BSD kqueue API  (io.netty.channel.kqueue.*)
    ".win32.",              # Windows APIs          (org.hyperic.sigar.win32.*)
    "NativeLibraryDarwin",  # macOS Cassandra       (o.a.c.utils.NativeLibraryDarwin.*)
    "BsdSocket.",           # BSD-specific Netty    (io.netty.channel.kqueue.BsdSocket.*)
    "Foreign.VirtualAlloc", # Windows VirtualAlloc  (com.kenai.jffi.Foreign.VirtualAlloc)
    "Foreign.VirtualFree",  # Windows VirtualFree   (com.kenai.jffi.Foreign.VirtualFree)
    "Foreign.VirtualProtect",# Windows VirtualProtect(com.kenai.jffi.Foreign.VirtualProtect)
    "jansi.internal.Kernel32", # Windows console APIs  (org.fusesource.jansi.internal.Kernel32.*)
    "jline.nativ.Kernel32",  # Windows JLine terminal (org.jline.nativ.Kernel32.*)
    "getWindowsDirectory",  # Windows Kerberos      (sun.security.krb5.Config.getWindowsDirectory)
    "SCDynamicStoreConfig", # macOS Kerberos        (sun.security.krb5.SCDynamicStoreConfig.*)
    "WindowsDirectory.",    # Windows Lucene native (org.apache.lucene.store.WindowsDirectory.*)
    "_getGlyphImageFromWindows", # Windows font rendering (sun.font.FileFontStrike.*)
]


def is_platform_excluded(method: str):
    """Return the matched keyword if *method* is platform-specific, else None."""
    for kw in PLATFORM_EXCLUDE_KEYWORDS:
        if kw in method:
            return kw
    return None


# ----------------------------
# Step 5: Classify each method
# ----------------------------
found_builtin    = 0
found_aliased    = 0
found_platform   = 0
found_unavailable = 0
not_found_count  = 0
count_jni = 0
count_jvm = 0
count_registered = 0
count_intrinsic = 0

bitshuffle_available = any(k.startswith("org.xerial.snappy.BitShuffleNative.") for k in method_to_jni.keys())
zstd_generate_available = "com.github.luben.zstd.Zstd.generateSequences" in method_to_jni

def try_bridge_resolve(original: str, sym: str, tag: str, libs: list, out_file):
    owner = resolve_symbol_in_libs(sym, libs)
    if tag == "SIGAR_LIST_BRIDGE":
        # #region agent log
        debug_log("sigar-bridge-resolve", "H1", "evaluated SIGAR bridge symbol owner", {
            "original": original,
            "symbol": sym,
            "owner": owner,
            "libsCount": len(libs),
        })
        # #endregion
    if owner:
        emit_result(out_file, owner, original, original, sym, tag)
        return True
    out_file.write(f"{original} -> {sym} [{tag}? UNRESOLVED]\n")
    return False


def alias_tag(original: str, lookup: str) -> str:
    return f" (alias of {lookup})" if lookup != original else ""


def emit_result(out_file, owner: str, original: str, lookup: str, sym: str, tag: str, note: str = ""):
    owner_base = os.path.basename(owner) if owner else "libjvm.so"
    if sym:
        out_file.write(f"{owner_base}:{original} -> {sym} [{tag}]{note}{alias_tag(original, lookup)}\n")
    else:
        out_file.write(f"{owner_base}:{original} [{tag}]{note}{alias_tag(original, lookup)}\n")
    return 1 if lookup != original else 0


def resolve_fence_fallback(lookup: str, libs: list):
    if lookup not in UNSAFE_FENCE_METHODS:
        return None
    owner = resolve_symbol_in_libs("Unsafe_FullFence", libs)
    if not owner:
        return None
    return owner, "Unsafe_FullFence"

with open(detailed_output_file, "w", encoding="utf-8") as out:
    for method in methods:

        # ----- 0) Handle [INTRINSIC] tag in input -----
        if method.endswith(" [INTRINSIC]"):
            clean_method = method.replace(" [INTRINSIC]", "")
            out.write(f"{clean_method} [INTRINSIC]\n")
            count_intrinsic += 1
            continue

        # ----- 0) Platform-excluded (win32, kqueue, Darwin) -----
        excl_kw = is_platform_excluded(method)
        if excl_kw:
            out.write(f"{method}: PLATFORM_EXCLUDED ({excl_kw})\n")
            found_platform += 1
            continue

        # ----- 0.5) Unsafe legacy-name alias resolution -----
        # If this is a renamed Unsafe method (JDK <14 name), resolve via the
        # new name.  We keep 'original' for output and use 'lookup' for all
        # subsequent lookups.
        original = method
        lookup = UNSAFE_RENAMED.get(method, method)
        lookup = METHOD_ALIASES.get(lookup, lookup)

        # Apply JDK 8 ↔ JDK 9+ compatibility mappings in priority order:
        # 1. Method name variants (bytecode-level differences)
        # 2. JDK method renames (package + method name changes)
        # 3. JDK package renames (package-only changes)
        # 4. HawtJNI → Eclipse SWT Callback mapping
        lookup = METHOD_NAME_VARIANTS.get(lookup, lookup)
        lookup = JDK8_JDK9_METHOD_RENAMES.get(lookup, lookup)
        lookup = JDK8_JDK9_PACKAGE_RENAMES.get(lookup, lookup)
        lookup = HAWTJNI_SWT_CALLBACK_MAPPING.get(lookup, lookup)

        # ----- 1) JNI direct hit (Java_* symbols) -----
        if lookup in method_to_jni:
            jni_sym, so_path = method_to_jni[lookup][0]
            if lookup == "org.hyperic.sigar.Sigar.getFileSystemListNative":
                # #region agent log
                debug_log("sigar-jni-direct", "H2", "direct JNI mapping found for Sigar.getFileSystemListNative", {
                    "lookup": lookup,
                    "jniSymbol": jni_sym,
                    "owner": so_path,
                })
                # #endregion
            found_aliased += emit_result(out, so_path, original, lookup, jni_sym, "JNI")
            count_jni += 1
            continue

        # ----- 1.4) tcnative SSL/SSLContext -> documented OpenSSL function name -----
        # Source: netty.io xref + chromium netty-tcnative mirror. Only fires when
        # the javadoc explicitly names an OpenSSL function; unmapped methods fall
        # through to the existing paths unchanged.
        tcnative_hit = None
        for _prefix, _class_map in TCNATIVE_CLASS_MAPS:
            if original.startswith(_prefix):
                method_name = original.rsplit(".", 1)[-1]
                # #region agent log
                debug_log("cassandra-netty-tcnative", "H1", "entered tcnative lookup branch", {
                    "original": original,
                    "classPrefix": _prefix,
                    "methodName": method_name,
                    "dictHasExact": method_name in _class_map,
                })
                # #endregion
                tcnative_hit = _class_map.get(method_name)
                # Netty tcnative wrappers commonly suffix native entrypoints with "0"
                # while docs/mapping keys use names without the suffix.
                if tcnative_hit is None and method_name.endswith("0"):
                    tcnative_hit = _class_map.get(method_name[:-1])
                    # #region agent log
                    debug_log("cassandra-netty-tcnative", "H2", "applied trailing-zero fallback", {
                        "original": original,
                        "methodName": method_name,
                        "fallbackMethodName": method_name[:-1],
                        "fallbackHit": tcnative_hit,
                    })
                    # #endregion
                break
        if tcnative_hit:
            # #region agent log
            debug_log("cassandra-netty-tcnative", "H3", "resolved via tcnative openssl map", {
                "original": original,
                "resolvedSymbol": tcnative_hit,
            })
            # #endregion
            out.write(f"{original} -> {tcnative_hit} [TCNATIVE_OPENSSL]\n")
            count_jni += 1
            continue
        elif original.startswith("io.netty.internal.tcnative."):
            # #region agent log
            debug_log("cassandra-netty-tcnative", "H4", "tcnative method unresolved in dictionary", {
                "original": original,
                "methodName": original.rsplit(".", 1)[-1],
            })
            # #endregion

        # ----- 1.5) Netty exact mapping -----
        if original in netty_method_map:
            netty_sym, so_path = netty_method_map[original]
            emit_result(out, so_path, original, original, netty_sym, "NETTY")
            count_jni += 1
            continue

        # ----- 1.6) Netty fuzzy matching -----
        if original.startswith(_all_netty_prefixes):
            result = match_netty_method(original, netty_method_map, shaded_netty_prefixes)
            if result:
                netty_sym, so_path = result
                emit_result(out, so_path, original, original, netty_sym, "NETTY_FUZZY")
                count_jni += 1
                continue

        # ----- 1.7) JNI Dynamic Bindings (bytecode-extracted) -----
        if original in jni_dynamic_map or lookup in jni_dynamic_map:
            # Try both original and lookup (for aliased methods)
            jni_dyn_key = original if original in jni_dynamic_map else lookup
            jni_dyn_sym, so_path = jni_dynamic_map[jni_dyn_key]
            found_aliased += emit_result(out, so_path, original, jni_dyn_key, jni_dyn_sym, "JNI_DYNAMIC")
            count_jni += 1
            continue

        # ----- 2) JVM_* via source tables -----
        jvm_sym = jvm_method_map.get(lookup)
        if not jvm_sym:
            match = re.match(r'^(.+?)([a-z][a-zA-Z0-9_]*)\(', lookup)
            if match:
                lookup_key = f"{match.group(1)}.{match.group(2)}"
                jvm_sym = jvm_method_map.get(lookup_key)

        if jvm_sym:
            tag = "JVM"
            if libjvm_so and (jvm_sym not in available_jvm_symbols):
                tag = "JVM? NOT_IN_THIS_LIB"
            found_aliased += emit_result(out, None, original, lookup, jvm_sym, tag)
            count_jvm += 1
            continue

        # ----- 2.5) JVM built-in natives (well-known JVM_* functions) -----
        builtin_sym = JVM_BUILTIN_NATIVES.get(lookup)
        if builtin_sym:
            tag = "JVM_BUILTIN"
            if libjvm_so and (builtin_sym not in available_jvm_symbols):
                tag = "JVM_BUILTIN? NOT_IN_THIS_LIB"
            found_aliased += emit_result(out, None, original, lookup, builtin_sym, tag)
            count_jvm += 1
            found_builtin += 1
            continue

        # ----- 3) Registered natives (non-JVM) via source tables -----
        reg_sym = registered_method_map.get(lookup)
        if reg_sym:
            owner = resolve_symbol_in_libs(reg_sym, search_libs)
            if owner:
                found_aliased += emit_result(out, owner, original, lookup, reg_sym, "REGISTERED")
            else:
                fence_result = resolve_fence_fallback(lookup, search_libs)
                if fence_result:
                    full_owner, full_sym = fence_result
                    found_aliased += emit_result(
                        out,
                        full_owner,
                        original,
                        lookup,
                        full_sym,
                        "REGISTERED_FENCE_FALLBACK",
                        note=f" (registered as {reg_sym})",
                    )
                    count_registered += 1
                    continue
                out.write(f"{original} -> {reg_sym} [REGISTERED? UNRESOLVED]{alias_tag(original, lookup)}\n")
            count_registered += 1
            continue



        # ----- 4) JVM intrinsic (inlined by JIT, no .so symbol) -----
        if lookup in intrinsic_methods:
            found_aliased += emit_result(out, None, original, lookup, None, "INTRINSIC")
            count_intrinsic += 1
            continue

        # ----- 4.2) Unsafe local-symbol fallback in libjvm -----
        unsafe_local_sym = UNSAFE_LOCAL_FALLBACKS.get(lookup)
        if unsafe_local_sym:
            owner = resolve_symbol_in_libs(unsafe_local_sym, [libjvm_so] if libjvm_so else search_libs)
            if owner:
                found_aliased += emit_result(out, owner, original, lookup, unsafe_local_sym, "UNSAFE_LOCAL_SYMBOL")
                count_registered += 1
                continue

        # ----- 4.5) Direct libc bridge wrappers (JNA/JFFI-style) -----
        libc_sym = DIRECT_LIBC_METHODS.get(original)
        if libc_sym:
            resolved = try_bridge_resolve(original, libc_sym, "DIRECT_LIBC_BRIDGE", search_libs, out)
            if resolved:
                count_registered += 1
            continue

        # ----- 4.55) Direct JNI bridge wrappers (JDK public->private native indirection) -----
        jni_bridge_sym = DIRECT_JNI_BRIDGES.get(original)
        if jni_bridge_sym:
            resolved = try_bridge_resolve(original, jni_bridge_sym, "DIRECT_JNI_BRIDGE", search_libs, out)
            if resolved:
                count_registered += 1
            continue

        # ----- 4.56) Source-backed JNI wrappers (hidden-symbol fallback) -----
        source_jni_sym = SOURCE_JNI_BRIDGES.get(original)
        if source_jni_sym:
            owner = resolve_symbol_in_libs(source_jni_sym, search_libs)
            if owner:
                emit_result(out, owner, original, original, source_jni_sym, "SOURCE_JNI_BRIDGE")
                count_registered += 1
            elif any(os.path.basename(p) == "libjava.so" for p in search_libs):
                emit_result(out, "libjava.so", original, original, source_jni_sym, "SOURCE_JNI_BRIDGE? SYMBOL_NOT_EXPORTED")
                count_registered += 1
            else:
                out.write(f"{original} -> {source_jni_sym} [SOURCE_JNI_BRIDGE? UNRESOLVED]\n")
            continue

        # ----- 4.57) HotSpot JFR RegisterNatives bridge (jdk.jfr.internal.JVM -> jfr_*) -----
        jfr_sym = jfr_registernatives_map.get(lookup) or jfr_registernatives_map.get(original)
        if jfr_sym:
            owner = resolve_symbol_in_libs(jfr_sym, [libjvm_so] if libjvm_so else search_libs)
            if owner:
                found_aliased += emit_result(out, owner, original, lookup, jfr_sym, "JFR_REGISTERED")
            else:
                # jfr_* symbols are local in libjvm.so, libjvm always owns them
                emit_result(out, libjvm_so or "libjvm.so", original, lookup, jfr_sym, "JFR_REGISTERED")
            count_registered += 1
            continue

        # ----- 4.6) Sigar gather/list bridge mapping -----
        sigar_sym = SIGAR_LIST_BRIDGES.get(original)
        if sigar_sym:
            # #region agent log
            debug_log("sigar-bridge-entry", "H1", "entered SIGAR list bridge path", {
                "original": original,
                "bridgeSymbol": sigar_sym,
            })
            # #endregion
            resolved = try_bridge_resolve(original, sigar_sym, "SIGAR_LIST_BRIDGE", search_libs, out)
            # #region agent log
            debug_log("sigar-bridge-result", "H1", "SIGAR list bridge resolution result", {
                "original": original,
                "bridgeSymbol": sigar_sym,
                "resolved": resolved,
            })
            # #endregion
            if resolved:
                count_registered += 1
            continue

        # ----- 4.7) Deterministic unavailable-in-build classifications -----
        if original.startswith("software.chronicle.enterprise.internals.impl.NativeAffinity.") or original == "net.openhft.ticker.impl.JNIClock.rdtsc0":
            if not has_chronicle_native_lib:
                out.write(f"{original}: LIB_NOT_PRESENT_IN_SCAN [CHRONICLE_NATIVE]\n")
                found_unavailable += 1
                continue

        if original.startswith("org.apache.commons.daemon.support.DaemonLoader.") and not has_commons_daemon_lib:
            out.write(f"{original}: LIB_NOT_PRESENT_IN_SCAN [COMMONS_DAEMON_NATIVE]\n")
            found_unavailable += 1
            continue

        if original.startswith("org.xerial.snappy.BitShuffleNative.") and not bitshuffle_available:
            out.write(f"{original}: NATIVE_METHOD_NOT_IN_THIS_BUILD [SNAPPY_BITSHUFFLE]\n")
            found_unavailable += 1
            continue

        if original == "com.github.luben.zstd.Zstd.generateSequences" and not zstd_generate_available:
            out.write(f"{original}: NATIVE_METHOD_NOT_IN_THIS_BUILD [ZSTD_JNI]\n")
            found_unavailable += 1
            continue

        # ----- 5) Not found -----
        if original == "org.hyperic.sigar.FileSystem.gather":
            # #region agent log
            debug_log("sigar-not-found", "H3", "FileSystem.gather reached NOT_FOUND_IN_LIBS", {
                "original": original,
                "lookup": lookup,
            })
            # #endregion
        out.write(f"{original}: NOT_FOUND_IN_LIBS\n")
        not_found_count += 1

# ----------------------------
# Summary
# ----------------------------
total = len(methods)
found_total = total - not_found_count - found_platform

print(f"\n=== Classification Summary ===")
print(f"Total methods:        {total}")
print(f"Resolved:             {found_total}  ({100*found_total//total}%)")
print(f"  JNI / Netty:        {count_jni}")
print(f"  JVM_* (source):     {count_jvm}")
print(f"  Registered:         {count_registered}")
print(f"  Intrinsic (JIT):    {count_intrinsic}")
if found_unavailable:
    print(f"  Unavailable build:  {found_unavailable}")
if found_builtin:
    print(f"  (incl. builtins):   {found_builtin}")
if found_aliased:
    print(f"  (via Unsafe alias): {found_aliased}")
print(f"Platform-excluded:    {found_platform}")
print(f"NOT_FOUND_IN_LIBS:    {not_found_count}")
print(f"\nOutput: {detailed_output_file}")
