package com.echotrace.app.bytecode_new;

/**
 * /// MainApp
 *
 * This is the main entry point for the EchoTrace Java static analysis tool. It orchestrates
 * the complete analysis workflow by calling three specialized components in sequence:
 * 1. Finding main methods in the target JAR
 * 2. Analyzing dependency JAR structure
 * 3. Performing call graph analysis from main methods to native methods
 * This provides a comprehensive view of the application's entry points and their
 * reachability to native code.
 *
 * /// Function Arguments
 * - args[0]: The path to the target JAR file to analyze.
 *   This should be a valid JAR file containing the application classes to be analyzed.
 * - args[1]: The path to the directory containing dependency JAR files.
 *   This should be a valid directory path where dependency JAR files are stored.
 *   The tool will scan all files with `.jar` extension in this directory.
 *
 * /// Returns
 * - Prints comprehensive analysis results to stdout showing:
 *   - Main methods found in target JAR
 *   - Dependency tree structure from dependency JARs
 *   - Call paths from main methods to native methods
 *   - Summary statistics for each analysis phase
 *
 * /// Errors
 * - IllegalArgumentException: If insufficient arguments are provided.
 * - FileNotFoundException: If the target JAR or dependency directory does not exist.
 * - IOException: If JAR files cannot be read due to permission issues or corruption.
 * - ZipException: If any JAR file is corrupted or cannot be opened as a ZIP archive.
 * - RuntimeException: If any of the sub-components fail during analysis.
 *
 * /// Behavior
 * 1. Validates input arguments and file existence
 * 2. Calls Findmain.main() to identify main methods in target JAR
 * 3. Calls Dependencytree.main() to analyze dependency JAR structure
 * 4. Calls Printpath.main() to perform call graph analysis
 * 5. Outputs results from all three analysis phases
 *
 * /// Analysis Phases
 * - Phase 1 (Findmain): Identifies public static void main(String[]) methods
 *   in target classes (excluding dependency classes)
 * - Phase 2 (Dependencytree): Scans dependency JARs and lists all classes
 *   contained within each JAR file
 * - Phase 3 (Printpath): Performs BFS call graph traversal from main methods
 *   to find paths leading to native method calls
 *
 * /// Output Sections
 * - "Main Methods Found in Target JAR": List of main method signatures
 * - "Dependency Tree": Hierarchical view of dependency JAR contents
 * - "Call Path from Main to Dependency": Call graph paths to native methods
 *
 * /// Example Output
 * ==== Main Methods Found in Target JAR ====
 * Found main method: <com.example.app.MainApp: void main(java.lang.String[])>
 * === Summary ===
 * Total classes with main methods: 1
 * 
 * ==== Dependency Tree ====
 * JAR: helper.jar
 * Classes:
 *   com.example.util.HelperClass
 * 
 * ==== Call Path from Main to Dependency ====
 * [NATIVE] Found native method: <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
 * [NATIVE] Path: <com.example.app.MainApp: void main(java.lang.String[])> -> ... -> <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
 */
public class MainApp {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java com.echotrace.app.bytecode_new.MainApp <target-jar> <deps-dir>");
            return;
        }
        String targetJar = args[0];
        String depsDir = args[1];

        System.out.println("==== Main Methods Found in Target JAR ====");
        Findmain.main(new String[]{targetJar, depsDir});
        System.out.println("\n==== Dependency Tree ====");
        Dependencytree.main(new String[]{depsDir});
        System.out.println("\n==== Call Path from Main to Dependency ====");
        //Printpath.main(new String[]{targetJar, depsDir});
	PrintpathDFS.main(new String[]{targetJar, depsDir});

    }
} 
