package com.echotrace.app.bytecode_new;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * /// Printpath
 *
 * This utility performs comprehensive call graph analysis to find paths from main methods
 * to native methods in Java applications. It uses Breadth-First Search (BFS) to traverse
 * the call graph starting from main methods, identifying all possible paths that lead
 * to native method calls. This is essential for understanding how Java applications
 * interact with native code and identifying potential security or performance implications.
 *
 * /// Function Arguments
 * - args[0]: The path to the target JAR file to analyze.
 *   This should be a valid JAR file containing the application classes to be analyzed.
 * - args[1]: The path to the directory containing dependency JAR files.
 *   This should be a valid directory path where dependency JAR files are stored.
 *   The tool will scan all files with `.jar` extension in this directory.
 *
 * /// Returns
 * - Prints detailed analysis results to stdout showing:
 *   - Main method signatures found in target classes
 *   - BFS traversal progress and statistics
 *   - Native method discoveries with full call paths
 *   - Summary of unique native methods and total paths
 * - Writes call paths to call_to_native_deps_incl.txt file
 * - Writes unique native methods to unique_native_methods.txt file
 *
 * /// Errors
 * - IllegalArgumentException: If insufficient arguments are provided.
 * - FileNotFoundException: If the target JAR, dependency directory, or found_main_methods_target.txt does not exist.
 * - IOException: If JAR files cannot be read due to permission issues or corruption.
 * - ZipException: If any JAR file is corrupted or cannot be opened as a ZIP archive.
 * - RuntimeException: If SootUp analysis fails or method resolution errors occur.
 *
 * /// Behavior
 * 1. Reads main classes from found_main_methods_target.txt file
 * 2. Scans dependency JARs to build set of dependency classes
 * 3. Filters out dependency classes from main classes list
 * 4. Initializes SootUp view with target and dependency JARs
 * 5. For each main class, finds the main method signature
 * 6. Performs BFS call graph traversal from main methods
 * 7. Identifies native methods and records call paths
 * 8. Outputs results to console and files
 *
 * /// BFS Analysis Details
 * - Uses Breadth-First Search to explore call graph systematically
 * - Tracks visited methods to avoid infinite loops
 * - Implements path-based recursion detection
 * - Configurable maximum depth (MAX_DEPTH = 30)
 * - Processes all method invocations: virtual, static, special, and interface calls
 * - Handles abstract and native methods gracefully
 *
 * /// Native Method Detection
 * - Identifies methods marked as native in bytecode
 * - Records complete call paths from main methods to native methods
 * - Tracks unique native methods to avoid duplicates
 * - Provides path information for each discovery
 *
 * /// Output Files
 * - call_to_native_deps_incl.txt: Complete call paths to native methods
 * - unique_native_methods.txt: List of unique native methods found
 * - Console output: Real-time analysis progress and summary
 *
 *
 * /// Example Output
 * Main class: com.example.app.MainApp
 *   Main method: <com.example.app.MainApp: void main(java.lang.String[])>
 *   [DEBUG] Starting comprehensive BFS analysis from main method...
 *   [NATIVE] Found native method: <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
 *   [NATIVE] Path: <com.example.app.MainApp: void main(java.lang.String[])> -> <java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)> -> <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
 *   [INFO] BFS analysis completed. Processed 58 methods total.
 *   [INFO] Found 13 paths to 4 unique native methods.
 *   ==== UNIQUE NATIVE METHODS FOUND ====
 *   Total unique native methods: 4
 *   1. <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>
 *   2. <java.lang.Thread: java.lang.Thread currentThread()>
 *   3. <java.lang.Thread: void interrupt0()>
 *   4. <java.lang.StrictMath: double sqrt(double)>
 */
public class Printpath {
    // Configuration for different project sizes
    private static final int MAX_DEPTH = 30;    
    
    public static void main(String[] args) {
        if (args.length < 2) {
            return;
        }
        String targetJar = args[0];
        String depsDir = args[1];

        // Read main classes from file
        List<String> mainClasses = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("found_main_methods_target.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                mainClasses.add(line.trim());
            }
        } catch (IOException e) {
            System.err.println("[ERROR] Could not read found_main_methods_target.txt: " + e.getMessage());
            return;
        }

        // Get dependency classes
        Set<String> dependencyClasses = new HashSet<>();
        List<String> depJars = new ArrayList<>();
        File depDir = new File(depsDir);
        File[] jars = depDir.listFiles((d, name) -> name.endsWith(".jar"));
        if (jars != null) {
            for (File jar : jars) {
                depJars.add(jar.getAbsolutePath());
                try (ZipFile zipFile = new ZipFile(jar)) {
                    Enumeration<? extends ZipEntry> entries = zipFile.entries();
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();
                        String name = entry.getName();
                        if (name.endsWith(".class") && !name.contains("$")) {
                            String className = name.replace('/', '.').substring(0, name.length() - 6);
                            dependencyClasses.add(className);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[ERROR] Could not read JAR: " + jar.getName());
                }
            }
        }

        // Filter out dependency classes from main classes
        List<String> targetMainClasses = new ArrayList<>();
        for (String className : mainClasses) {
            if (!dependencyClasses.contains(className)) {
                targetMainClasses.add(className);
            } else {
                System.out.println("[INFO] Skipping dependency class: " + className);
            }
        }

        if (targetMainClasses.isEmpty()) {
            System.out.println("[WARNING] No target classes with main methods found after filtering dependencies.");
            return;
        }

        // Initialize SootUp view with target and dependency JARs
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(targetJar));
        for (String depJar : depJars) {
            inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        }
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        JavaView view = new JavaView(inputs);

        // For each main class, analyze and find calls to dependencies
        for (String mainClassName : targetMainClasses) {
            System.out.println("Main class: " + mainClassName);
            
            // Find the main method in this class
            Optional<JavaSootClass> mainClassOpt = view.getClasses()
                .filter(clazz -> clazz.getType().getFullyQualifiedName().equals(mainClassName))
                .findFirst();
            
            if (!mainClassOpt.isPresent()) {
                System.out.println("  [WARNING] Class not found in view: " + mainClassName);
                continue;
            }
            
            JavaSootClass mainClass = mainClassOpt.get();
            Optional<JavaSootMethod> mainMethodOpt = mainClass.getMethods().stream()
                .filter(method -> method.getName().equals("main")
                    && method.getModifiers().contains(MethodModifier.PUBLIC)
                    && method.getModifiers().contains(MethodModifier.STATIC)
                    && method.getParameterTypes().size() == 1
                    && method.getParameterTypes().get(0).toString().equals("java.lang.String[]")
                    && method.getReturnType().toString().equals("void"))
                .findFirst();
            
            if (!mainMethodOpt.isPresent()) {
                System.out.println("  [WARNING] No main method found in class: " + mainClassName);
                continue;
            }
            
            MethodSignature mainMethod = mainMethodOpt.get().getSignature();
            System.out.println("  Main method: " + mainMethod);
            
            // Perform BFS to find paths to native methods
            Queue<List<MethodSignature>> worklist = new ArrayDeque<>();
            List<MethodSignature> startPath = new ArrayList<>();
            startPath.add(mainMethod);
            worklist.add(startPath);
            List<List<MethodSignature>> nativePaths = new ArrayList<>();
            Set<MethodSignature> uniqueNativeMethods = new HashSet<>(); // Track unique native methods
            Set<MethodSignature> processedMethods = new HashSet<>(); // Track processed methods for progress
            
            System.out.println("  [DEBUG] Starting comprehensive BFS analysis from main method...");
            System.out.println("  [DEBUG] Dependency classes: " + dependencyClasses);
            
            int maxDepth = MAX_DEPTH; // Use the appropriate depth based on project size
            int processedCount = 0;
            
            while (!worklist.isEmpty()) {
                List<MethodSignature> path = worklist.poll();
                MethodSignature current = path.get(path.size() - 1);
                
                // Check for recursion in current path (path-based visited tracking)
                if (path.size() > 1 && path.subList(0, path.size() - 1).contains(current)) {
                    continue; // Skip if this method already appears in the current path
                }
                
                // Skip if path is too deep
                if (path.size() > maxDepth) {
                    continue;
                }
                
                // Progress tracking
                if (processedMethods.add(current)) {
                    processedCount++;

                }
                
                view.getMethod(current).ifPresent(method -> {
                    // Check if this is a native method
                    if (method.isNative()) {
                        List<MethodSignature> newPath = new ArrayList<>(path);
                        nativePaths.add(newPath);
                        uniqueNativeMethods.add(current); // Add to unique set
                        System.out.println("  [NATIVE] Found native method: " + current);
                        System.out.println("  [NATIVE] Path: " + buildPathString(newPath));
                        return; // Don't continue from native methods
                    }
                    
                    if (method.hasBody()) {
                        try {
                            Body body = method.getBody();
                            AtomicInteger invokeCount = new AtomicInteger(0);
                            for (Object stmtObj : body.getStmts()) {
                                if (stmtObj instanceof InvokableStmt) {
                                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                                        MethodSignature callee = invokeExpr.getMethodSignature();
                                        invokeCount.incrementAndGet();
                                        
                                        // Continue BFS if not too deep
                                        if (path.size() < maxDepth) {
                                            List<MethodSignature> newPath = new ArrayList<>(path);
                                            newPath.add(callee);
                                            worklist.add(newPath);
                                        }
                                    });
                                }
                            }
                            if (invokeCount.get() > 0) {
                                System.out.println("  [DEBUG] Method " + current + " has " + invokeCount.get() + " invocations");
                            }
                        } catch (Throwable t) {
                            // Better error handling - log but continue analysis
                            System.err.println("  [WARNING] Could not analyze method " + current + ": " + t.getMessage());
                            // Don't stop the analysis, just skip this method
                        }
                    } else {
                        System.out.println("  [DEBUG] Method " + current + " has no body (abstract/native)");
                    }
                });
            }
            
            System.out.println("  [INFO] BFS analysis completed. Processed " + processedCount + " methods total.");
            System.out.println("  [INFO] Found " + nativePaths.size() + " paths to " + uniqueNativeMethods.size() + " unique native methods.");
            
            // Write paths to file
            try (PrintWriter writer = new PrintWriter("call_to_native_deps_incl.txt")) {
                for (List<MethodSignature> path : nativePaths) {
                    writer.println(buildPathString(path));
                }
                writer.println("\nTotal paths found: " + nativePaths.size());
                System.out.println("  [INFO] Native paths written to call_to_native_deps_incl.txt");
            } catch (IOException e) {
                System.err.println("  [ERROR] Failed to write native paths to file: " + e.getMessage());
            }
            
            // Write unique native methods to separate file
            try (PrintWriter writer = new PrintWriter("unique_native_methods.txt")) {
                if (uniqueNativeMethods.isEmpty()) {
                    writer.println("No unique native methods found.");
                } else {
                    writer.println("Total unique native methods: " + uniqueNativeMethods.size());
                    writer.println();
                    int count = 1;
                    for (MethodSignature nativeMethod : uniqueNativeMethods) {
                        writer.println(count + ". " + nativeMethod);
                        count++;
                    }
                }
                System.out.println("  [INFO] Unique native methods written to unique_native_methods.txt");
            } catch (IOException e) {
                System.err.println("  [ERROR] Failed to write unique native methods to file: " + e.getMessage());
            }
            
            // Print unique native methods list
            System.out.println("  ==== UNIQUE NATIVE METHODS FOUND ====");
            if (uniqueNativeMethods.isEmpty()) {
                System.out.println("  No unique native methods found.");
            } else {
                System.out.println("  Total unique native methods: " + uniqueNativeMethods.size());
                int count = 1;
                for (MethodSignature nativeMethod : uniqueNativeMethods) {
                    System.out.println("  " + count + ". " + nativeMethod);
                    count++;
                }
            }
            System.out.println();
            
            // Print summary
            if (nativePaths.isEmpty()) {
                System.out.println("  No paths to native methods found.");
            } else {
                System.out.println("  Summary of paths to native methods:");
                for (int i = 0; i < nativePaths.size(); i++) {
                    List<MethodSignature> path = nativePaths.get(i);
                    System.out.println("  Path " + (i + 1) + ": " + buildPathString(path));
                }
            }
            System.out.println();
        }
    }

    private static String buildPathString(List<MethodSignature> path) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append(path.get(i).toString());
        }
        return sb.toString();
    }
} 
