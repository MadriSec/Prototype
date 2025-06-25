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
cd EchoTrace/echotrace

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
