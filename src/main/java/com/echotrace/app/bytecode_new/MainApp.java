// package com.echotrace.app.bytecode_new;

// import com.echotrace.app.bytecode_new.utils.DependencyTreeUtil;
// import com.echotrace.app.bytecode_new.utils.MainFinderUtil;
// import sootup.callgraph.CallGraph;
// import sootup.callgraph.CallGraphAlgorithm;
// import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
// import sootup.core.inputlocation.AnalysisInputLocation;
// import sootup.core.jimple.common.stmt.InvokableStmt;
// import sootup.core.model.Body;
// import sootup.core.model.Method;
// import sootup.core.model.MethodModifier;
// import sootup.core.signatures.MethodSignature;
// import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
// import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
// import sootup.java.core.JavaSootClass;
// import sootup.java.core.JavaSootMethod;
// import sootup.java.core.views.JavaView;

// import java.io.*;
// import java.util.*;
// import java.util.concurrent.atomic.AtomicInteger;
// import java.util.zip.ZipEntry;
// import java.util.zip.ZipFile;

// /**
//  * /// MainApp
//  *
//  * This is the main entry point for the EchoTrace Java static analysis tool. It orchestrates
//  * the complete analysis workflow by calling three specialized components in sequence:
//  * 1. Finding main methods in the target JAR
//  * 2. Analyzing dependency JAR structure
//  * 3. Performing call graph analysis from main methods to native methods
//  * This provides a comprehensive view of the application's entry points and their
//  * reachability to native code.
//  *
//  * /// Function Arguments
//  * - args[0]: The path to the target JAR file to analyze.
//  *   This should be a valid JAR file containing the application classes to be analyzed.
//  * - args[1]: The path to the directory containing dependency JAR files.
//  *   This should be a valid directory path where dependency JAR files are stored.
//  *   The tool will scan all files with `.jar` extension in this directory.
//  *
//  * /// Returns
//  * - Prints comprehensive analysis results to stdout showing:
//  *   - Main methods found in target JAR
//  *   - Dependency tree structure from dependency JARs
//  *   - Call paths from main methods to native methods
//  *   - Summary statistics for each analysis phase
//  *
//  * /// Errors
//  * - IllegalArgumentException: If insufficient arguments are provided.
//  * - FileNotFoundException: If the target JAR or dependency directory does not exist.
//  * - IOException: If JAR files cannot be read due to permission issues or corruption.
//  * - ZipException: If any JAR file is corrupted or cannot be opened as a ZIP archive.
//  * - RuntimeException: If any of the sub-components fail during analysis.
//  *
//  * /// Behavior
//  * 1. Validates input arguments and file existence
//  * 2. Calls Findmain.main() to identify main methods in target JAR
//  * 3. Calls Dependencytree.main() to analyze dependency JAR structure
//  * 4. Calls Printpath.main() to perform call graph analysis
//  * 5. Outputs results from all three analysis phases
//  *
//  * /// Analysis Phases
//  * - Phase 1 (Findmain): Identifies public static void main(String[]) methods
//  *   in target classes (excluding dependency classes)
//  * - Phase 2 (Dependencytree): Scans dependency JARs and lists all classes
//  *   contained within each JAR file
//  * - Phase 3 (Printpath): Performs BFS call graph traversal from main methods
//  *   to find paths leading to native method calls
//  *
//  * /// Output Sections
//  * - "Main Methods Found in Target JAR": List of main method signatures
//  * - "Dependency Tree": Hierarchical view of dependency JAR contents
//  * - "Call Path from Main to Dependency": Call graph paths to native methods
//  *
//  * /// Example Output
//  * ==== Main Methods Found in Target JAR ====
//  * Found main method: <com.example.app.MainApp: void main(java.lang.String[])>
//  * === Summary ===
//  * Total classes with main methods: 1
//  * 
//  * ==== Dependency Tree ====
//  * JAR: helper.jar
//  * Classes:
//  *   com.example.util.HelperClass
//  * 
//  * ==== Call Path from Main to Dependency ====
//  * [NATIVE] Found native method: <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
//  * [NATIVE] Path: <com.example.app.MainApp: void main(java.lang.String[])> -> ... -> <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
//  */
// public class MainApp {

//     private static final int MAX_DEPTH = 30;

//     private static Set<String> targetJarClasses = new HashSet<>();
//     private static Set<String> dependencyClasses = new HashSet<>();

//     private static void loadTargetJarClasses(String jarPath) {
//         try (ZipFile zipFile = new ZipFile(jarPath)) {
//             Enumeration<? extends ZipEntry> entries = zipFile.entries();
//             while (entries.hasMoreElements()) {
//                 ZipEntry entry = entries.nextElement();
//                 String name = entry.getName();
//                 if (name.endsWith(".class") && !name.contains("$")) {
//                     String className = name.replace('/', '.').substring(0, name.length() - 6);
//                     targetJarClasses.add(className);
//                 }
//             }
//         } catch (IOException e) {
//             System.err.println("Error reading target JAR: " + e.getMessage());
//         }
//     }

//     private static List<String> loadDependencyJars(String depsDir) {
//         List<String> depJars = new ArrayList<>();
//         File depDir = new File(depsDir);
//         File[] jars = depDir.listFiles((d, name) -> name.endsWith(".jar"));
//         if (jars != null) {
//             for (File jar : jars) {
//                 depJars.add(jar.getAbsolutePath());
//                 try (ZipFile zipFile = new ZipFile(jar)) {
//                     Enumeration<? extends ZipEntry> entries = zipFile.entries();
//                     while (entries.hasMoreElements()) {
//                         ZipEntry entry = entries.nextElement();
//                         String name = entry.getName();
//                         if (name.endsWith(".class") && !name.contains("$")) {
//                             String className = name.replace('/', '.').substring(0, name.length() - 6);
//                             dependencyClasses.add(className);
//                         }
//                     }
//                 } catch (IOException e) {
//                     System.err.println("Error reading dependency JAR: " + jar.getName());
//                 }
//             }
//         }
//         return depJars;
//     }


//     /**
//      * Initialize the SootUp Java view with the target JAR and its dependencies.
//      */
//     private static JavaView initializeView(String targetJar, List<String> depJars) {
//         List<AnalysisInputLocation> inputs = new ArrayList<>();
//         inputs.add(new JavaClassPathAnalysisInputLocation(targetJar));
//         for (String depJar : depJars) {
//             inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
//         }
//         inputs.add(new DefaultRuntimeAnalysisInputLocation()); // Include JRE classes
//         return new JavaView(inputs);
//     }

//     public static void main(String[] args) {
//         if (args.length < 2) {
//             System.out.println("Usage: java com.echotrace.app.bytecode_new.MainApp <target-jar> <deps-dir>");
//             return;
//         }
//         String jarPath = args[0];
//         String depsDir = args[1];

//         loadTargetJarClasses(jarPath);
//         List<String> depJars = loadDependencyJars(depsDir);

//         JavaView view = initializeView(jarPath, depJars);

//         System.out.println("==== Main Methods Found in Target JAR ====");
//         List<JavaSootMethod> mainMethods = MainFinderUtil.findMainMethods(view, targetJarClasses);
//         if (mainMethods.isEmpty()) {
//             System.out.println("No main methods found in the target JAR.");
//             return;
//         }
//         System.out.println("Total main methods found: " + mainMethods.size());

//         System.out.println("\n==== Start Analysis ====");
//         //Printpath.main(new String[]{targetJar, depsDir});
//         processAllMainMethods(mainMethods, view);
//     }

//     /**
//      * Process all classes with main methods and analyze their call paths to dependencies.
//      * This method will print the main methods found and their call paths to native methods.
//      */
//     private static void processAllMainMethods(List<JavaSootMethod> mainMethods, JavaView view) {

//         // For each main method, analyze and find calls to dependencies
//         for (JavaSootMethod main : mainMethods) {
//             System.out.println("\n=== Processing Main Method: " + main + " ===");

//             MethodSignature mainMethodSig = main.getSignature();

//             //nativeMethodsBFS(mainMethod, view);
//             nativeMethodsDFS(mainMethodSig, view);
//             //nativeMethodsCHA(mainMethod, view);
//         }
//     }


//     private static void nativeMethodsCHA(MethodSignature mainMethod, JavaView view) {
//         // Initialize call graph with CHA
//         CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
//         CallGraph cg = cha.initialize(Collections.singletonList(mainMethod));

//         List<MethodSignature> currentPath = new ArrayList<>();
//         currentPath.add(mainMethod);
//         Set<MethodSignature> visitedMethods = new HashSet<>();
//         visitedMethods.add(mainMethod);
//         List<List<MethodSignature>> nativePaths = new ArrayList<>();
//         Set<MethodSignature> uniqueNativeMethods = new HashSet<>();

//         nativeMethodsCHA(cg, view, mainMethod, currentPath, visitedMethods, nativePaths, uniqueNativeMethods);

//         analysisSummary(nativePaths, uniqueNativeMethods);
//     }

//     private static void nativeMethodsCHA(CallGraph cg, JavaView view, MethodSignature currentMethod, List<MethodSignature> currentPath, Set<MethodSignature> visitedMethods, List<List<MethodSignature>> nativePaths, Set<MethodSignature> uniqueNativeMethods) {
//         cg.callsFrom(currentMethod).stream().forEach(tgt -> {
//             System.out.println(" [INFO] " + currentMethod + " may call " + tgt);
//             MethodSignature targetMethod = tgt.getTargetMethodSignature();
//             view.getMethod(targetMethod).ifPresent(method -> {
//                 // Check if this is a native method
//                 if (method.isNative()) {
//                     List<MethodSignature> newPath = new ArrayList<>(currentPath);
//                     nativePaths.add(newPath);
//                     uniqueNativeMethods.add(targetMethod); // Add to unique set
//                     System.out.println("  [NATIVE] Found native method: " + targetMethod);
//                     System.out.println("  [NATIVE] Path: " + buildPathString(newPath));
//                     return; // Don't continue from native methods
//                 }
//                 // Only proceed if this method has not been visited yet
//                 if (visitedMethods.add(targetMethod)) {
//                     List<MethodSignature> newPath = new ArrayList<>(currentPath);
//                     newPath.add(targetMethod);
//                     nativeMethodsCHA(cg, view, targetMethod, newPath, visitedMethods, nativePaths, uniqueNativeMethods);
//                 }
//             });
//         });
//     }

//     private static void nativeMethodsDFS(MethodSignature mainMethod, JavaView view) {
//         List<MethodSignature> currentPath = new ArrayList<>();
//         currentPath.add(mainMethod);
//         Set<MethodSignature> visitedMethods = new HashSet<>();
//         visitedMethods.add(mainMethod);
//         List<List<MethodSignature>> nativePaths = new ArrayList<>();
//         Set<MethodSignature> uniqueNativeMethods = new HashSet<>();

//         nativeMethodsDFS(view, mainMethod, currentPath, visitedMethods, nativePaths, uniqueNativeMethods);

//         analysisSummary(nativePaths, uniqueNativeMethods);
//     }

//     private static void nativeMethodsDFS(JavaView view, MethodSignature targetMethod, List<MethodSignature> currentPath, Set<MethodSignature> visitedMethods, List<List<MethodSignature>> nativePaths, Set<MethodSignature> uniqueNativeMethods) {
//         view.getMethod(targetMethod).ifPresent(method -> {
//             // Check if this is a native method
//             if (method.isNative()) {
//                 List<MethodSignature> newPath = new ArrayList<>(currentPath);
//                 nativePaths.add(newPath);
//                 uniqueNativeMethods.add(targetMethod); // Add to unique set
//                 System.out.println("  [NATIVE] Found native method: " + targetMethod);
//                 System.out.println("  [NATIVE] Path: " + buildPathString(newPath));
//                 return; // Don't continue from native methods
//             }

//             if (method.hasBody()) {
//                 try {
//                     Body body = method.getBody();
//                     for (Object stmtObj : body.getStmts()) {
//                         if (stmtObj instanceof InvokableStmt) {
//                             ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
//                                 MethodSignature callee = invokeExpr.getMethodSignature();

//                                 if (visitedMethods.add(callee)) {
//                                     List<MethodSignature> newPath = new ArrayList<>(currentPath);
//                                     newPath.add(callee);
//                                     nativeMethodsDFS(view, callee, newPath, visitedMethods, nativePaths, uniqueNativeMethods);
//                                 }
//                             });
//                         }
//                     }
//                 } catch (Throwable t) {
//                     // Better error handling - log but continue analysis
//                     System.err.println("  [WARNING] Could not analyze method " + targetMethod + ": " + t.getMessage());
//                     // Don't stop the analysis, just skip this method
//                 }
//             } else {
//                 System.out.println("  [DEBUG] Method " + targetMethod + " has no body (abstract/native)");
//             }
//         });

//     }

//     /**
//      * Perform a comprehensive BFS analysis from the main method to find all paths
//      * leading to native methods, including detailed debug output.
//      */
//     private static void nativeMethodsBFS(MethodSignature mainMethod, JavaView view) {
//         // Perform BFS to find paths to native methods
//         Queue<List<MethodSignature>> worklist = new ArrayDeque<>();
//         List<MethodSignature> startPath = new ArrayList<>();
//         startPath.add(mainMethod);
//         worklist.add(startPath);
//         List<List<MethodSignature>> nativePaths = new ArrayList<>();
//         Set<MethodSignature> uniqueNativeMethods = new HashSet<>(); // Track unique native methods
//         Set<MethodSignature> processedMethods = new HashSet<>(); // Track processed methods for progress

//         System.out.println("  [DEBUG] Starting comprehensive BFS analysis from main method...");

//         int maxDepth = MAX_DEPTH; // Use the appropriate depth based on project size
//         int processedCount = 0;

//         while (!worklist.isEmpty()) {
//             List<MethodSignature> path = worklist.poll();
//             MethodSignature current = path.get(path.size() - 1);

//             // Check for recursion in current path (path-based visited tracking)
//             if (path.size() > 1 && path.subList(0, path.size() - 1).contains(current)) {
//                 continue; // Skip if this method already appears in the current path
//             }

//             // Skip if path is too deep
//             if (path.size() > maxDepth) {
//                 continue;
//             }

//             // Progress tracking
//             if (processedMethods.add(current)) {
//                 processedCount++;

//             }

//             view.getMethod(current).ifPresent(method -> {
//                 // Check if this is a native method
//                 if (method.isNative()) {
//                     List<MethodSignature> newPath = new ArrayList<>(path);
//                     nativePaths.add(newPath);
//                     uniqueNativeMethods.add(current); // Add to unique set
//                     System.out.println("  [NATIVE] Found native method: " + current);
//                     System.out.println("  [NATIVE] Path: " + buildPathString(newPath));
//                     return; // Don't continue from native methods
//                 }

//                 if (method.hasBody()) {
//                     try {
//                         Body body = method.getBody();
//                         AtomicInteger invokeCount = new AtomicInteger(0);
//                         for (Object stmtObj : body.getStmts()) {
//                             if (stmtObj instanceof InvokableStmt) {
//                                 ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
//                                     MethodSignature callee = invokeExpr.getMethodSignature();
//                                     invokeCount.incrementAndGet();

//                                     // Continue BFS if not too deep
//                                     if (path.size() < maxDepth) {
//                                         List<MethodSignature> newPath = new ArrayList<>(path);
//                                         newPath.add(callee);
//                                         worklist.add(newPath);
//                                     }
//                                 });
//                             }
//                         }
//                         if (invokeCount.get() > 0) {
//                             System.out.println("  [DEBUG] Method " + current + " has " + invokeCount.get() + " invocations");
//                         }
//                     } catch (Throwable t) {
//                         // Better error handling - log but continue analysis
//                         System.err.println("  [WARNING] Could not analyze method " + current + ": " + t.getMessage());
//                         // Don't stop the analysis, just skip this method
//                     }
//                 } else {
//                     System.out.println("  [DEBUG] Method " + current + " has no body (abstract/native)");
//                 }
//             });
//         }

//         System.out.println("  [INFO] BFS analysis completed. Processed " + processedCount + " methods total.");

//         analysisSummary(nativePaths, uniqueNativeMethods);
//     }

//     private static String buildPathString(List<MethodSignature> path) {
//         StringBuilder sb = new StringBuilder();
//         for (int i = 0; i < path.size(); i++) {
//             if (i > 0) sb.append(" -> ");
//             sb.append(path.get(i).toString());
//         }
//         return sb.toString();
//     }

//     /**
//      * Print a summary of the analysis results, including paths to native methods
//      * and unique native methods found.
//      */
//     private static void analysisSummary(List<List<MethodSignature>> nativePaths, Set<MethodSignature> uniqueNativeMethods) {
//         System.out.println("  [INFO] Found " + nativePaths.size() + " paths to " + uniqueNativeMethods.size() + " unique native methods.");

//         // Write paths to file
//         try (PrintWriter writer = new PrintWriter("call_to_native_deps_incl.txt")) {
//             for (List<MethodSignature> path : nativePaths) {
//                 writer.println(buildPathString(path));
//             }
//             writer.println("\nTotal paths found: " + nativePaths.size());
//             System.out.println("  [INFO] Native paths written to call_to_native_deps_incl.txt");
//         } catch (IOException e) {
//             System.err.println("  [ERROR] Failed to write native paths to file: " + e.getMessage());
//         }

//         // Write unique native methods to separate file
//         try (PrintWriter writer = new PrintWriter("unique_native_methods.txt")) {
//             if (uniqueNativeMethods.isEmpty()) {
//                 writer.println("No unique native methods found.");
//             } else {
//                 writer.println("Total unique native methods: " + uniqueNativeMethods.size());
//                 writer.println();
//                 int count = 1;
//                 for (MethodSignature nativeMethod : uniqueNativeMethods) {
//                     writer.println(count + ". " + nativeMethod);
//                     count++;
//                 }
//             }
//             System.out.println("  [INFO] Unique native methods written to unique_native_methods.txt");
//         } catch (IOException e) {
//             System.err.println("  [ERROR] Failed to write unique native methods to file: " + e.getMessage());
//         }

//         // Print unique native methods list
//         System.out.println("  ==== UNIQUE NATIVE METHODS FOUND ====");
//         if (uniqueNativeMethods.isEmpty()) {
//             System.out.println("  No unique native methods found.");
//         } else {
//             System.out.println("  Total unique native methods: " + uniqueNativeMethods.size());
//             int count = 1;
//             for (MethodSignature nativeMethod : uniqueNativeMethods) {
//                 System.out.println("  " + count + ". " + nativeMethod);
//                 count++;
//             }
//         }
//         System.out.println();

//         // Print summary
//         if (nativePaths.isEmpty()) {
//             System.out.println("  No paths to native methods found.");
//         } else {
//             System.out.println("  Summary of paths to native methods:");
//             for (int i = 0; i < nativePaths.size(); i++) {
//                 List<MethodSignature> path = nativePaths.get(i);
//                 System.out.println("  Path " + (i + 1) + ": " + buildPathString(path));
//             }
//         }
//         System.out.println();
//     }

// } 