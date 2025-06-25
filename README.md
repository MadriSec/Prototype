# EchoTrace - Java Native Method Reachability Analyzer

This Prototype is a Java static analysis tool built using the SootUp framework that analyzes Java bytecode to find paths from main methods to native methods. It provides comprehensive dependency analysis and call graph traversal to understand how Java applications interact with native code.

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


## Running EchoTrace

# Analyze the example application
mvn exec:java -Dexec.mainClass="com.echotrace.app.bytecode_new.MainApp" -Dexec.args="example/app.jar example/deps"


## Input Requirements

### Target JAR
- Must be a valid JAR file containing Java bytecode
- Should contain classes with `public static void main(String[])` methods
- Will be analyzed for main methods and call graph traversal


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






