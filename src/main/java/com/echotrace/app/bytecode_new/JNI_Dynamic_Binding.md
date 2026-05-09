# JNI dynamic binding extraction

This note describes **one** way EchoTrace recovers **JNI dynamic registrations**: bindings established with `RegisterNatives` and encoded as `JNINativeMethod[]` tables (method name, JNI type signature, native function pointer). That surface is **not** the same as scanning bytecode for `native` declarations—see [JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md) for `ACC_NATIVE` and cross-JDK coverage.

The work is implemented today as several Python helpers at the **repository root** (`extract_jni_bindings.py`, `extract_jvm_native_tables.py`, `extract_jfr_methods.py`, `extract_netty_epoll_native_methods.py`). They share the same **idea**; we plan to **merge** them into a single tool later. Until then, treat the following as **one pipeline** described once.

---

## What we are recovering

At runtime, the JVM can attach native implementations to Java methods in two broad ways:

- **Static naming** — the VM looks for `Java_<mangled_pkg_class>_<method>` in loaded `.so` files.
- **Explicit registration** — native code calls `RegisterNatives(env, jclass, JNINativeMethod *methods, jint nMethods)`.

Our extractors target the second: each row is logically **`(name, signature, fn_ptr)`**. On 64-bit LP64 ELFs, that row is **24 bytes**: three little-endian pointers. We **decode** those pointers into:

1. A **Java method name** (C string in read-only or relocated data).
2. A **JNI type signature** (another C string, normally starting with `(`).
3. A **native code address** resolved to a **symbol** where possible (`nm`, or trust the source label).

From that we can relate **Java FQCN + method + signature** to **ELF / HotSpot symbols**, which downstream mapping (seccomp, syscall tagging, `mapped_updated.py`, and friends) can consume alongside bytecode-derived `native_methods.txt`.

---

## How we do it (unified workflow)

**1. Choose an artifact**

- **Vendor or app shared libraries** (Netty transport, Hadoop, etc.) — scan the `.so`.
- **The JVM itself** (`libjvm.so`) — same binary layout for registration tables that live in **data** or **RELRO** segments.
- **OpenJDK source** — when the table is static C/C++ initializer syntax rather than something we want to hunt only in the binary.

**2. Find a table (or many candidates)**

We need the **address or file offset** of something that looks like a contiguous array of `JNINativeMethod` rows. Depending on the build:

- **Generic ELF scan** — look for relocated pointer triples in **read-only RELRO** (`.data.rel.ro`, …) that cluster into valid(name, sig, fn) patterns, optionally scoped to libraries that export `JNI_OnLoad`.
- **Anchored scan** — use **`nm`** (or the symbol table) to locate a known static array symbol (for example Netty’s `fixed_method_table` / `statically_referenced_fixed_method_table`, or a JFR array whose VMA was determined for a given `libjvm.so` build), then convert **virtual address → file offset** with section layouts (`readelf`, or `pyelftools` where available).

**3. Validate each row**

For every 24-byte slot:

- Follow `name_ptr` and `sig_ptr` through the section map and read **null-terminated UTF-8 strings**.
- Check the name looks like a **Java identifier** and the signature looks like a **JNI descriptor** (parameters in parentheses, return type after).
- Follow `fn_ptr` into **executable text** (or a plausible PLT target) and resolve a **symbol name** when the binary is not fully stripped.

Invalid or sentinel rows end the scan (or mark the boundary between tables).

**4. Attach the Java class**

Bytecode alone does not always tell you which `RegisterNatives` call owns a row; we **infer** the declaring class by context:

- **Source path and table literals** — OpenJDK maps known HotSpot / libjava filenames to `java.lang.Thread`, `jdk.internal.misc.Unsafe`, `jdk.jfr.internal.JVM`, and similar.
- **C symbol naming** — many third-party libraries encode package stems (`netty_epoll_*`, `netty_unix_*`, …) in the native symbol; rules map those stems back to a Java FQN with a **confidence** tag where the binary also contains a corroborating string.

**5. Emit bindings**

Output is **one registration per line** (exact formatting varies slightly today; the merge will normalize this). Conceptually each line answers: **which Java method (class.name(signature)) is implemented by which native symbol, from which library or OpenJDK component**, with a note on how we **proved** the link (high-confidence string match, symbol inference, or source scan).

---

## What this is not

- **Not a substitute for running the JVM** — we do not execute `JNI_OnLoad` or follow dynamic `malloc`’d tables built at runtime.
- **Not guaranteed on odd ABIs** — the tools assume LP64 triples and sensible RELRO / section metadata; fully relocated or pathological binaries may not yield tables.
- **Not identical to HotSpot’s `JVM_*` catalog** — that catalog is partly maintained in C++ source; source extraction aligns with it, while generic `.so` mining discovers **vendor** registrations the VM never lists.

---

## Related files

| Topic | Location |
|------|----------|
| Bytecode `native` scan + cross-JDK tests | [JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md) |
| Implementation (to be merged) | `extract_jni_bindings.py`, `extract_jvm_native_tables.py`, `extract_jfr_methods.py`, `extract_netty_epoll_native_methods.py` (repository root) |
| Design notes for the ELF miner | `JNI_DYNAMIC_EXTRACTOR_PLAN` (referenced from `extract_jni_bindings.py` docstring) |

---

## Summary

**JNI dynamic binding** extraction means: **locate `JNINativeMethod[]`-shaped data**, **decode pointers into Java names and JNI signatures**, **resolve function pointers to symbols**, and **label the owning Java class**—whether the evidence comes from **RELRO in a `.so`**, **a known array anchor in `libjvm.so`**, **Netty’s transport tables**, or **OpenJDK C++ sources**. The current scripts are **split for historical reasons**; operationally they implement **one** recovery strategy with different **inputs and anchors**.

