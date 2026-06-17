# EchoTrace

**Static and dynamic analysis framework for generating container-specific seccomp allowlists for Java applications.**

EchoTrace analyzes how a Java container reaches native code and, from there, Linux system calls. It combines runtime observation of the container with static analysis of Java bytecode and native ELF binaries. The output is a JSON syscall allowlist that can be used as the basis for a Docker seccomp profile.

```
Dynamic Capture -> Bytecode Analysis -> Native Mapping
-> Syscall Reachability -> JSON Allowlist
```

---

## Table of Contents

- [Architecture Overview](#architecture-overview) — **[ARCHITECTURE.md](ARCHITECTURE.md)** (diagram only)
- [Dynamic Analysis (Sysdig / eBPF)](#dynamic-analysis-sysdig--ebpf)
- [Container Artifact Extraction](#container-artifact-extraction)
- [Finding Native Methods (Bytecode Analysis)](#finding-native-methods-bytecode-analysis)
  - [Detector Documentation](src/main/java/com/echotrace/app/bytecode_new/README.md)
- [Mapping Native Methods to Libraries](#mapping-native-methods-to-libraries)
- [Binary Analysis with SysPart (VFA)](#binary-analysis-with-syspart-vfa)
- [Seccomp Profile Generation](#seccomp-profile-generation)
- [End-to-End Pipeline](#end-to-end-pipeline)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)

---

## Architecture Overview

EchoTrace has four stages:

1. **Dynamic capture:** observe the running container and identify the JARs, native libraries, and binaries it uses.
2. **Bytecode analysis:** scan application and container-JDK runtime JARs for Java methods and APIs that can enter native code.
3. **Native mapping:** map Java native methods and binding sites to concrete native symbols in container-extracted `.so` files.
4. **Syscall reachability:** run SysPart from the recovered native start functions and merge reachable syscalls into a JSON allowlist.

The key design choice is that EchoTrace analyzes the container's own artifacts rather than the host environment. Java native methods and their implementations differ across JDK versions and distributions, so using the host JDK can produce incorrect mappings.

| Stage | Tool | Input | Output |
|-------|------|-------|--------|
| 1. Dynamic capture | Sysdig (eBPF) | Running container | Lists of loaded libraries, JARs, executables |
| 2. Extraction | `docker cp` | Container filesystem | `LIBS/`, `JARFILES/`, `BINARIES/` directories |
| 3. Bytecode analysis | ASM + SootUp | Application and runtime JARs | Native method and native binding records |
| 4. Native mapping | Mapper + ELF tools | Native records + `.so` files | Java method -> native symbol -> library |
| 5. Binary analysis | SysPart VFA | `.so` files + mapper starts; executables + entry/import starts | Syscall summaries per ELF |
| 6. Profile generation | Seccomp profile generator | Aggregated syscalls | JSON allowlist |

---

## Dynamic Analysis (Sysdig / eBPF)

### What We Monitor
<img width="960" height="540" alt="sysdig" src="https://github.com/user-attachments/assets/8dec74d9-0557-4efd-810e-a07d03d61e94" />


EchoTrace uses [Sysdig](https://github.com/draios/sysdig) with the modern eBPF backend (`--modern-bpf`) to observe container activity without modifying the application. The unified capture is a clean-start run:

```
stop container -> start Sysdig -> wait for probes -> start container
```

This ordering captures JVM startup, where most JARs, runtime modules, and native libraries are loaded.

The unified capture monitors:

```
open, openat, openat2  -> JAR files and native libraries opened by the JVM
mmap                   -> mapped artifacts, included for completeness
execve                 -> native binaries launched inside the container
```

Events are scoped to the target container using Docker metadata resolved through `docker inspect`:

```
container.name = <name> OR container.id = <container-id>
```

Using both fields avoids missing JVM startup events when name attribution is incomplete.

### Running a Capture

```bash
# Capture a container clean-start run (120s default)
./sysdig_unified_scoped.sh <container_name_or_id> [duration_seconds]
```

**Outputs** (in `sysdig_outputs_<IMG_SAFE>/`):

- `jni_libs_opened.txt` -- deduplicated `.so` file paths
- `jars_unique_<IMG_SAFE>.txt` -- deduplicated `.jar` file paths
- `binaries_unique_<IMG_SAFE>.txt` -- deduplicated executable paths
- `libs_by_pid.txt` -- PID/process/library attribution

`mmap` is monitored for completeness, but in the final evaluation captures the observed `.so` artifacts were discovered through `open`/`openat` events.

---

## Container Artifact Extraction

Once Sysdig identifies which files the container uses, EchoTrace extracts those paths from the container filesystem for offline analysis:

```
JARFILES_<image>/    # Application and dependency JARs
LIBS_<image>/        # Native shared libraries (.so files)
BINARIES_<image>/    # Executed native binaries
RUNTIME_<image>/     # Runtime JARs/modules from the container JDK
```

The runtime extraction is important: EchoTrace analyzes the JDK that actually runs inside the container, not the host JDK.

---

## Finding Native Methods (Bytecode Analysis)

### The Problem

Dynamic capture tells EchoTrace what files were loaded; bytecode analysis tells it which Java code can enter native code. Java applications may cross into native code through ordinary JNI declarations, dynamically registered JNI methods, JNA, JNR/JFFI, or FFI/FFM APIs.

### How We Find Them

EchoTrace analyzes:

```
Application JARs observed during dynamic capture
Runtime JARs/modules extracted from the container JDK
```

The scanners use ASM and SootUp. Each native interface type has a dedicated detector:

| Type | Detector | Detection strategy |
|------|----------|-------------------|
| JNI native declarations | `PrototypeFinal` | Scan for `ACC_NATIVE` methods |
| JNA Interface | `JnaIfaceDetector` | Find interfaces extending `com.sun.jna.Library` |
| JNA Dynamic | `JnaDynDetector` | Track `NativeLibrary.getInstance()` -> `getFunction()` -> `invoke()` |
| JNA Direct | `JnaDirectMapDetector` | Find `Native.register()` and enumerate native methods |
| FFI/FFM | `FfiDetector` | Track `SymbolLookup` -> `find()` -> `downcallHandle()` |
| JNR/JFFI | `JnrFfiDetector` | Find JNR/JFFI library-loader and interface patterns |

> For detailed documentation of each detector (Java patterns, output formats, limitations), see [`src/main/java/com/echotrace/app/bytecode_new/README.md`](src/main/java/com/echotrace/app/bytecode_new/README.md)

### Unified Detector

```bash
mvn -f pom.xml exec:java \
  -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
  -Dexec.args="<JARFILES_dir> <outputs_dir> <RUNTIME_dir>"
```

Important outputs:

- `native_methods.txt` -- Java native method declarations
- `jna_hits.txt` -- merged JNA/JNR/FFI native binding hits
- `ffi_all_hits.txt` -- FFI/JNR-family hits
- `analyzed_jars.txt` -- application and runtime archives scanned by the detector

---


## Mapping Native Methods to Libraries

After bytecode analysis, EchoTrace maps Java native methods and binding sites to native functions in the `.so` files extracted from the same container.

### How Mapping Works

`mapped_updated.py` combines several sources of evidence.

**1. Standard JNI symbol matching**

EchoTrace scans container-extracted `.so` files for exported JNI symbols:

```text
Java_<package>_<class>_<method>
```

It also handles overloaded JNI names and common JNI mangling variants such as `_1`.

**2. RegisterNatives binary extraction**

Many native methods are not exported as `Java_*` symbols. They are registered at runtime through `RegisterNatives`. EchoTrace recovers these mappings directly from the container's native binaries, including libraries such as:

```text
libjvm.so
libjava.so
libnetty*.so
libjffi*.so
```

For example, a native table may contain:

```c
static JNINativeMethod methods[] = {
  { "start0", "()V", (void *)&JVM_StartThread }
};
```

EchoTrace recovers:

```text
java.lang.Thread.start0()V -> JVM_StartThread -> libjvm.so
```

This binary-level recovery is preferred over source-code assumptions. OpenJDK source scanning through `JVM_SRC` is only a fallback when binary extraction is unavailable.

**3. JNA, JNR/JFFI, and FFI mappings**

EchoTrace also resolves non-JNI native binding mechanisms:

- JNA direct mappings map Java native method names to C symbols in the registered library.
- JNA interface mappings treat interface methods as native symbols.
- JNA dynamic mappings recover library and function names from dynamic lookup patterns.
- JNR/JFFI and FFI/FFM mappings identify bridge-based native calls and downcall targets.

**Output:** `mapped_method_syscalls.txt`

```text
libjvm.so:java.lang.Thread.start0 -> JVM_StartThread [JVM_REGISTERED]
libjava.so:java.io.FileInputStream.readBytes -> Java_java_io_FileInputStream_readBytes [JNI]
libc.so.6:org.example.Native.getpid -> getpid [JNA]
```

Each line gives:

```text
library:java.method -> c_symbol [resolution_type]
```

### Post-Processing

- `filter.sh` -- removes `NOT_FOUND_IN_LIBS` entries (methods with no library match)
- `change_format.py` -- groups C symbols by library, producing per-library start-function files for SysPart

---

## Binary Analysis with SysPart (VFA)

### What SysPart Does

[SysPart](https://arxiv.org/abs/2309.05169) ([CCS ’23](https://doi.org/10.1145/3576915.3623207)) is a research system for **binary-only** syscall surface reduction; at its core it builds **sound (conservative) control- and call-graph views** of x86-64 Linux ELF code and uses **value-flow analysis (VFA)** together with other static techniques to **refine the function-call graph (FCG)**—especially around **indirect calls** and **dynamically resolved targets**—before reasoning about which **syscall** sites are reachable.

EchoTrace plugs into SysPart's **static syscall computation** pipeline: we supply **ELF paths** (mirrored `.so` files and extracted executables) and **explicit start functions**. For shared libraries, these starts normally come from the Java-to-native mapper. If bytecode mapping is unavailable, EchoTrace can fall back to exported dynamic symbols. For binaries observed through `execve`, EchoTrace uses `_start` when available and otherwise falls back to imported dynamic functions. SysPart then answers: *starting from those addresses, which syscall instructions can this binary reach?*

### What SysPart Does Internally (per ELF)

When analysis runs (via **`compute_syscalls.sh`** under your **`SysPartCode/analysis/app`** checkout, as invoked by **`automate_syscall_analysis.sh`**), the workflow is roughly:

1. **Load & configure the binary.** The target ELF is loaded for analysis; **`USER_LIBRARY_PATH`** points SysPart at EchoTrace’s extracted **`LIBS_*`** tree so dependent shared objects resolve the same way as in the offline mirror.

2. **Lift machine code to analyzable CFGs.** Functions are disassembled/lifted into **control-flow graphs (CFGs)** over basic blocks—the usual prerequisite for sound whole-program reasoning on stripped or partially stripped ELFs.

3. **Resolve start addresses.** Each name in the start-function list is bound to an entry address (see **`startfuncs_with_addr.txt`** in the output bundle).

4. **Explore an interprocedural call graph.** Analysis walks **reachable functions** outward from those starts: **direct calls** give precise edges; **indirect calls**, PLT/GOT behavior, and similar patterns are handled with conservative models that SysPart **tightens using VFA** (and related heuristics described in the paper) so the **FCG** is not blindly “every possible target.”

5. **Collect syscall sites.** Along reachable paths SysPart identifies instructions that actually issue Linux syscalls—on x86-64 typically the **`syscall`** instruction once the syscall number is determined—and records those syscall numbers/names into **`syscalls.txt`**.

6. **Emit diagnostics.** **`callgraph.json`** captures the explored call structure; **`allfunctions.txt`** lists reachable symbols encountered during the walk; **`logfile.txt`** captures warnings (unresolved jumps, missing symbols, etc.).

This is **static** analysis: it does not require running the container during SysPart itself. Precision is bounded by reverse-engineering realities such as opaque indirect jumps, hand-written assembly, stripped symbols, and unusual loaders. EchoTrace keeps the analysis container-specific by analyzing the exact libraries and binaries extracted from the image.

### EchoTrace vs the Full SysPart Paper

The published SysPart system also targets **temporal** syscall filtering for servers (initialization vs serving phases), combines analysis passes built on **Egalito**, and may use **dynamic** observations where static resolution of **`dlopen` / `dlsym`** is incomplete. EchoTrace's integration focuses on the **same static backbone**--CFG/FCG construction with **VFA-informed** reachability--but drives it with **EchoTrace-derived start functions** and merges results into a **single Docker seccomp profile** over libraries *and* helper binaries. Treat the paper as the authoritative reference for algorithmic detail; treat this repo's scripts as the **wiring** from Java bytecode -> ELF mirrors -> **`syscalls.txt`** -> **`seccomp.json`**.

### How We Use It

EchoTrace runs SysPart **once per analyzed ELF**: **`automate_syscall_analysis.sh`** prepares start-function files, sets **`USER_LIBRARY_PATH`** to the extracted library tree, and invokes **`SysPartCode/analysis/app/src/scripts/compute_syscalls.sh`** with the binary path, output directory, and start list. In the normal Java path, start functions come from the native-method mapper; in fallback modes they come from library exports or executable starts/imports.

```bash
./automate_syscall_analysis.sh \
  --binary-dir LIBS_cassandra/ \
  --startfunc-dir outputs_cassandra/ \
  --output-dir syscalls_output_cassandra/ \
  --img-safe cassandra
```

### SysPart Output (per library)

```
syscalls_output_cassandra/
  libjvm.so/
    allfunctions.txt          # All reachable functions
    callgraph.json            # Full call graph
    syscalls.txt              # Reachable syscall numbers/names
    startfuncs_with_addr.txt  # Start functions with addresses
    logfile.txt               # Analysis log
```

### Analysis Modes

`run_analysis.sh` supports three modes:

| Mode | Start Functions | Use Case |
|------|-----------------|----------|
| `FULL_BYTECODE` | C symbols from the native-method mapper | Standard: bytecode analysis -> mapper -> SysPart |
| `LIBRARY_SYMBOLS` | Exported dynamic symbols from `nm -D` | Library fallback when Java mapping is unavailable |
| `BINARY_ONLY` | `_start` when available; otherwise imported `UND` functions from `objdump -T` | Native binaries observed through `execve` |

### Handling Stripped Binaries

When symbol information is limited, EchoTrace uses the best start functions available for the artifact type. For libraries, the preferred source is still the Java-to-native mapping; exported dynamic symbols are a fallback mode. For executed binaries, EchoTrace uses `_start` if it can resolve it and otherwise falls back to imported dynamic functions. Optional debug-symbol extraction can improve names and coverage when separate debug packages are available.

### dlopen/dlsym Analysis

Some native targets are resolved through `dlopen()` and `dlsym()` rather than ordinary JNI naming. EchoTrace primarily accounts for these paths through bytecode-level JNA/JNR/JFFI/FFI detection and by analyzing the libraries observed during dynamic capture. The repository also contains helper code for inspecting explicit `dlopen`/`dlsym` behavior:

**Static helpers** (`analysis/app/src/dlanalysis/static/`):
- Finds `dlopen()` and `dlsym()` call sites in binaries
- Recovers string arguments when they are compile-time constants

**Dynamic helpers** (`analysis/app/src/dlanalysis/dynamic/`):
- Uses `LD_PRELOAD` function interposition to intercept `dlopen()`/`dlsym()` at runtime
- Captures actual library paths and symbol names

**JNI dynamic binding**:
- `scripts/extract_registernatives_binary.py` recovers `JNINativeMethod[]` registrations from container libraries when methods are registered through `RegisterNatives` instead of exported as `Java_*` symbols

---

## Seccomp Profile Generation

### From Syscalls to Seccomp

After all libraries are analyzed by SysPart, the syscall lists are aggregated and converted into a Docker-compatible seccomp profile:

```bash
python3 generate_seccomp.py \
  --input syscalls_output_cassandra/ \
  --output seccomp_cassandra.json
```

**Output format:**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": ["accept4", "bind", "clone", "close", "epoll_create1", "..."],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Everything not explicitly allowed is denied (`SCMP_ACT_ERRNO`). The generated profile is a restrictive, container-specific allowlist derived from observed artifacts and static reachability; it should be validated with the workload before deployment.

### Using the Profile

```bash
docker run --security-opt seccomp=seccomp_cassandra.json cassandra:latest
```

---


## Quick Start

### Prerequisites

- Docker CLI + `jq`
- Java 11+ (for building the agent and running SootUp analysis)
- Maven 3.6+
- Python 3.8+
- Sysdig (with `--modern-bpf` support) for dynamic capture
- SysPart (in `../SysPartCode/`) for binary analysis

### Build

```bash
# Build the main analysis tool
mvn clean package -DskipTests
```

### Run

```bash
# Start your target container
docker run -d --name my-app my-image:latest

# Run the full analysis
IMG_SAFE=my_app bash final_tool.sh my-app

# Result: seccomp.json in the project root
docker run --security-opt seccomp=seccomp.json my-image:latest
```

### Tested Applications

EchoTrace has been tested against:

| Application | JDK | Native Interfaces Used |
|-------------|-----|----------------------|
| Apache Cassandra 3.0, 5.0 | JDK 11, 17 | JNI, JNA (interface + dynamic) |
| Apache Tomcat 7, 9, 11 | JDK 8-25 | JNI (Tomcat Native / tcnative) |
| Apache Solr 8.7 | JDK 11 | JNI |
| Apache Storm 2.8 | JDK 11 | JNI |
| Apache ZooKeeper 3.4, 3.8 | JDK 8, 11 | JNI |
| Elasticsearch 7.17 | JDK 17 | JNA (interface) |
| SonarQube | JDK 17 | JNI |
| Groovy 5.0 | JDK 25 | JNA (interface + dynamic), jnr-ffi |
| JRuby 9.4 | JDK 11 | jnr-ffi |
| Apache Spark 4.1 | JDK 21 | JNI |
| OrientDB 3.2 | JDK 11 | JNI |
| JBoss/WildFly | JDK 11 | JNI |
| Jetty 9.4 | JDK 8 | JNI |
