# EchoTrace - Java Native Method Reachability Analyzer

This prototype is a Java static analysis tool built using the SootUp framework that analyzes Java bytecode to find paths from main methods to native methods. It provides comprehensive dependency analysis and call graph traversal to understand how Java applications interact with native code.

## Overview

EchoTrace performs a three-phase analysis:
1. **Main Method Discovery** - Identifies all `public static void main(String[])` methods in target classes
2. **Dependency Analysis** - Analyzes dependency JARs and builds a dependency tree
3. **Call Graph Traversal** - Uses Breadth-First Search (BFS) to find paths from main methods to native methods

## Prerequisites

- Java 8 or higher
- Maven 3.6 or higher
- SootUp framework dependencies (automatically managed by Maven)

## Building the Project

### Quick Build
```bash
# Navigate to the project directory
cd Prototype/

# Run the build script
./build.sh
```

### Manual Build
```bash
# Clean and package
mvn clean package
```

## Running EchoTrace

### Basic Usage
```bash
# Analyze the example application
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.MainApp" -Dexec.args="example/app.jar example/deps"

# Analyze a different application
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.MainApp" -Dexec.args="/path/to/your/app.jar /path/to/dependencies"
```

### Individual Components
```bash
# Find main methods only
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.Findmain" -Dexec.args="<target-jar> <deps-dir>"

# Analyze dependencies only
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.Dependencytree" -Dexec.args="<deps-dir>"

# Call graph analysis only
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.Printpath" -Dexec.args="<target-jar> <deps-dir>"
```

## Input Requirements

### Target JAR
- Must be a valid JAR file containing Java bytecode
- Should contain classes with `public static void main(String[])` methods
- Will be analyzed for main methods and call graph traversal

### Dependencies Directory
- Must be a directory containing JAR files
- All files with `.jar` extension will be scanned
- Used to distinguish between target and dependency classes

## Output Files

### Generated Files
- `found_main_methods_target.txt` - List of classes containing main methods
- `call_to_native_deps_incl.txt` - Complete call paths to native methods
- `unique_native_methods.txt` - List of unique native methods found

## Example Output

```
==== Main Methods Found in Target JAR ====
Found main method: <com.example.app.MainApp: void main(java.lang.String[])>
=== Summary ===
Total classes with main methods: 1
Total main methods found: 1

==== Dependency Tree ====
JAR: helper.jar
Classes:
  com.example.util.HelperClass
  Total classes: 1

==== Call Path from Main to Dependency ====
Main class: com.example.app.MainApp
  Main method: <com.example.app.MainApp: void main(java.lang.String[])>
  [NATIVE] Found native method: <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
  [NATIVE] Path: <com.example.app.MainApp: void main(java.lang.String[])> -> <java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)> -> <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
  [INFO] BFS analysis completed. Processed 58 methods total.
  [INFO] Found 13 paths to 4 unique native methods.
```

## Project Structure

```
Prototype/
├── src/main/java/com/echotrace/app/bytecode_new/
│   ├── MainApp.java          # Main orchestrator
│   ├── Findmain.java         # Main method discovery
│   ├── Dependencytree.java   # Dependency analysis
│   └── Printpath.java        # Call graph analysis
├── example/
│   ├── app.jar              # Example target application
│   └── deps/                # Example dependencies
├── target/                  # Build output
├── pom.xml                  # Maven configuration
└── build.sh                 # Build script
```

## Configuration

### MAX_DEPTH Configuration
The maximum depth for BFS traversal can be configured in `Printpath.java`:
```java
private static final int MAX_DEPTH = 30;  // Adjust based on project size
```

## Understanding Analysis Results

The [results/](results/) directory contains comprehensive analysis data for Java-based Docker containers. Each container analysis generates several subdirectories organized into three main analysis categories.

### Directory Structure

For each analyzed container (e.g., `cassandra`, `tomcat:8.5.56-jdk14-openjdk-oracle`), the following structure is created:

#### Captured Artifacts (Boot Time)

##### `BINARIES_<container>`
Executables extracted during container boot time via `execve` system calls. These are the actual binaries that were executed during the container startup and runtime.

##### `JARFILES_<container>`
JAR files opened via `open`/`openat2` system calls during container execution. These represent Java archives that were accessed by the application.

##### `LIBS_<container>`
Shared libraries (`.so` files) opened via `open`/`openat2` system calls. These are the native libraries loaded by the JVM and application during runtime.

#### Analysis Directories

##### `Dynamic_Analysis/`
Contains runtime data captured using sysdig eBPF monitoring. This includes:
- `raw_capture.txt` - Complete sysdig trace output
- `binaries_*.txt` - Binary execution traces (host, resolved, unique)
- `jars_*.txt` - JAR file access logs
- `libs_*.txt` - Library loading information
- `jni_libs_opened.txt` - JNI native libraries opened during execution

##### `Bytecode_Analysis/`
Contains native method analysis results from bytecode analysis. This directory includes:
- `filtered_method_syscalls.txt` - Filtered system calls from native methods
- `mapped_method_syscalls.txt` - Native methods extracted from JARFILES and mapped to LIBS
- `lib*.so.txt` - Individual library native method mappings (e.g., `libjava.so.txt`, `libjvm.so.txt`)

Native methods found in the JAR files are analyzed and mapped to their corresponding shared libraries.

##### `Static_Analysis/`
Contains system call analysis using Syspart binary analysis tool. Each subdirectory (named after a binary or library) contains:
- `allfunctions.txt` - Complete list of functions found via static analysis
- `callgraph.json` - Call graph representation in JSON format
- `startfuncs_with_addr.txt` - Entry point functions with their memory addresses
- `syscalls.txt` - List of system calls identified in the binary/library
- `syscalls_with_callsites.txt` - System calls with their invocation locations in the code
- `binary_syscalls.txt` - Summary of all binary system calls found

### Analysis Workflow

1. **Boot Time Capture**: Container starts and artifacts (binaries, JARs, libraries) are captured via system call monitoring
2. **Dynamic Analysis**: Runtime behavior is captured using sysdig eBPF to track executions and file operations
3. **Bytecode Analysis**: JAR files are analyzed to extract native method calls and map them to loaded native libraries
4. **Static Analysis**: Syspart performs binary analysis on executables and libraries to identify system calls and generate call graphs
