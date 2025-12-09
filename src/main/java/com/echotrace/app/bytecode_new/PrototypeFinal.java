package com.echotrace.app.bytecode_new;
// sootup imports
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

// ASM imports
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.jar.JarFile;
import java.util.jar.JarEntry;

/**
 * Native Method Tracer - ASM and SootUp Based Analysis
 *
 * This class provides comprehensive analysis of native method usage in Java applications.
 * It provides two analysis approaches: ASM-based bytecode analysis and SootUp-based
 * Jimple analysis to trace native method calls and their execution paths.
 *
 * USAGE:
 *   java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2]
 *
 * INPUT REQUIREMENTS:
 *   - target-directory: Directory containing application JAR files to analyze
 *   - dependencies-directory: Directory containing dependency JAR files
 *   - mode: Analysis mode selector (--1 or --2)
 *
 * ANALYSIS MODES:
 *   --1: Use HybridByteCodeTracer approach (ASM-based native method detection).
 *        Use case: Bytecode-level analysis using ASM framework
 *   --2 (default): SootUp Visitor Pattern (Worklist-based, using Jimple instead of ASM).
 *        Use case: Jimple-based analysis with comprehensive call chain tracking
 *
 * OUTPUT FILES:
 *   - native_methods.txt: Results from hybrid bytecode tracer (mode 1)
 *   - sootup_visitor_natives.txt: Results from SootUp visitor pattern (mode 2)
 *   - mode2_callgraph.txt: Call graph with native method callers (mode 2)
 *   - mode2_callchains.txt: Complete call chains to natives (mode 2)
 */
public class PrototypeFinal {
    // Shared fields
    private static final Map<String, String> classToJar = new HashMap<>();
    private static Set<String> targetJarClasses = new HashSet<>();
    private static Set<String> dependencyClasses = new HashSet<>();

    // HybridByteCodeTracer fields (Mode 1)
    private static String pathPrefix = "/home/rupesh.punna/Prototype/JARFILES/";
    private static final String NATIVE_METHODS_FILE = "/home/rupesh.punna/Prototype/native_methods.txt";

    /**
     * Main entry point for the Native Method Tracer
     *
     * FUNCTION NAME: main
     *
     * USAGE:
     *   java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2]
     *
     * INPUT REQUIRED:
     *   - args[0]: target-directory - Directory containing application JAR files
     *   - args[1]: dependencies-directory - Directory containing dependency JAR files
     *   - args[2]: mode (optional) - Analysis mode selector (--1 or --2, default: --2)
     *
     * WHAT IT'S USED FOR:
     *   - Orchestrates the native method analysis workflow
     *   - Parses command line arguments and validates input
     *   - Selects appropriate analysis mode based on user input
     *   - Executes the chosen analysis strategy
     *   - Generates comprehensive output files with results
     *
     * PROCESS FLOW:
     *   1. Parse and validate command line arguments
     *   2. Determine analysis mode (--1 or --2)
     *   3. Execute mode-specific analysis logic
     *   4. Generate output files with results
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2]");
            System.err.println("  --1: Use HybridByteCodeTracer approach (ASM-based native detection)");
            System.err.println("  --2: SootUp Visitor Pattern (Worklist-based, Jimple analysis) [DEFAULT]");
            return;
        }

        String targetDir = args[0];
        String depsDir = args[1];

        // Parse mode argument
        boolean hybridByteCodeTracer = false;
        boolean sootupVisitorPattern = false;

        if (args.length >= 3) {
            if ("--1".equals(args[2])) {
                hybridByteCodeTracer = true;
                System.out.println("Mode 1: HybridByteCodeTracer approach (ASM-based)");
            } else if ("--2".equals(args[2])) {
                sootupVisitorPattern = true;
                System.out.println("Mode 2: SootUp Visitor Pattern (Worklist-based)");
            } else {
                System.err.println("Invalid mode. Use --1 or --2");
                return;
            }
        } else {
            sootupVisitorPattern = true;
            System.out.println("Mode 2: SootUp Visitor Pattern (Worklist-based) [DEFAULT]");
        }

        System.out.println("=== PrototypeFinal: Native Method Tracer ===");
        System.out.println("Analyzing target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);

        // Mode 1: HybridByteCodeTracer approach
        if (hybridByteCodeTracer) {
            System.out.println("\n=== Mode 1: HybridByteCodeTracer Approach ===");
            try {
                runHybridByteCodeTracer(targetDir, depsDir);
            } catch (Exception e) {
                System.err.println("Error running HybridByteCodeTracer: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }

        // Mode 2: SootUp Visitor Pattern (Worklist-based)
        if (sootupVisitorPattern) {
            System.out.println("\n=== Mode 2: SootUp Visitor Pattern (Worklist) ===");
            try {
                runSootUpVisitorPattern(targetDir, depsDir);
            } catch (Exception e) {
                System.err.println("Error running SootUp Visitor Pattern: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }
    }
    private static void writeStringToFile(String content, File file) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        try (FileWriter fw = new FileWriter(file)) {
            fw.write(content);
        }
    }


    /**
     * Executes HybridByteCodeTracer analysis (Mode 1)
     *
     * FUNCTION NAME: runHybridByteCodeTracer
     *
     * USAGE:
     *   Called internally when --1 mode is selected
     * 
     * INPUT REQUIRED:
     *   - targetDir: Directory containing target application JAR files
     *   - depsDir: Directory containing dependency JAR files
     * 
     * WHAT IT'S USED FOR:
     *   - Performs ASM-based bytecode analysis for native method detection
     *   - Scans JAR files using ASM ClassReader to find native methods
     *   - Traces method calls through bytecode instructions
     *   - Generates comprehensive native method usage report
     *   - Provides performance timing information
     * 
     * PROCESS:
     *   1. Set up path prefix for dependency directory
     *   2. Get list of JAR files to analyze
     *   3. Extract class files from each JAR
     *   4. Use ASM to analyze bytecode for native method calls
     *   5. Trace method invocation chains
     *   6. Write results to output file
     *   7. Display performance metrics
     */
    private static void runHybridByteCodeTracer(String targetDir, String depsDir) throws IOException {
        System.out.println("Starting HybridByteCodeTracer analysis...");
        
        // Set the path prefix to the dependencies directory
        pathPrefix = depsDir;
        if (!pathPrefix.endsWith("/")) {
            pathPrefix += "/";
        }

        long startTime = System.currentTimeMillis();
        List<String> jarPathResult = new ArrayList<>();
        Set<String> nativeMethodResult = new HashSet<>();
        GetJarPaths getJarPaths = new GetJarPaths();

        List<String> classPathResult = new ArrayList<>();
        FindJarClass findJarClass = new FindJarClass();

        FindNativeMethods findNativeMethods = new FindNativeMethods();
        
        try {
            jarPathResult = getJarPaths.getJarPaths();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        for(String jarPath : jarPathResult){
            jarPath = pathPrefix + jarPath;
            File file = new File(jarPath);
            if (!file.exists() || !file.isFile()){
                System.out.println("JAR file not found: " + jarPath);
                continue;
            }
            classPathResult.addAll(findJarClass.findClass(jarPath));
            nativeMethodResult.addAll(findNativeMethods.findNativeMethods(jarPath));
        }
        
        System.out.println("DEBUG: classpath: " + classPathResult);
        System.out.println(classPathResult.size());
        System.out.println("There are " + classPathResult.size() + " classes over all\n");
        
        System.out.println("Now we start to analyze called native methods!");
        Util.println();
        PrototypeFinal bct = new PrototypeFinal();
        bct.traceJarFiles(jarPathResult);
        bct.prettyPrint();
        bct.writeToFile();
        
        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("Time taken: " + totalTimeInSeconds + " seconds");
    }

    /**
     * Executes SootUp Visitor Pattern analysis (Mode 2)
     *
     * FUNCTION NAME: runSootUpVisitorPattern
     *
     * USAGE:
     *   Called internally when --2 mode is selected
     *
     * INPUT REQUIRED:
     *   - targetDir: Directory containing target application JAR files
     *   - depsDir: Directory containing dependency JAR files
     *
     * WHAT IT'S USED FOR:
     *   - Performs SootUp-based Jimple analysis using visitor pattern
     *   - Similar to Mode 1 but uses SootUp/Jimple instead of ASM/bytecode
     *   - Worklist-based traversal without explicit DFS/BFS
     *   - Traces method calls through Jimple statements
     *   - Generates comprehensive native method usage report
     *
     * PROCESS:
     *   1. Load JARs and build SootUp view
     *   2. Get all classes from target and dependencies
     *   3. Visit each class and analyze methods
     *   4. Use visitor pattern to process Jimple statements
     *   5. Track visited methods to avoid duplicates
     *   6. Write results to output file
     *   7. Display performance metrics
     */
    private static void runSootUpVisitorPattern(String targetDir, String depsDir) throws IOException {
        System.out.println("Starting SootUp Visitor Pattern analysis (Method-based worklist)...");

        long startTime = System.currentTimeMillis();

        // ========== DATA STRUCTURES FOR ANALYSIS ==========

        // Track visited methods to prevent duplicate analysis and infinite loops
        // Contains method signatures in SootUp format: "<ClassName: ReturnType methodName(ParamTypes)>"
        Set<String> visitedMethods = new HashSet<>();

        // Store all discovered native methods (final output)
        // Simple format: "ClassName.methodName" (e.g., "java.lang.System.currentTimeMillis")
        Set<String> nativeMethods = new HashSet<>();

        // BUILD CALL GRAPH - Maps each method to the set of methods it calls
        // Key: Method signature (caller) - the method doing the calling
        // Value: Set of method signatures this method invokes (callees)
        // Example: "<com.example.App: void main(String[])>" ->
        //          {"<com.example.Utils: String helper()>", "<java.io.PrintStream: void println(String)>"}
        // This creates a directed graph where edges represent "calls" relationships
        Map<String, Set<String>> callGraph = new HashMap<>();

        // Maps each native method to the set of methods that directly call it
        // Key: Native method name (simple format: "ClassName.methodName")
        // Value: Set of method signatures that invoke this native
        // This helps us identify which application methods depend on which natives
        // Example: "java.lang.System.currentTimeMillis" ->
        //          {"<com.example.Timer: long getTime()>", "<com.example.Logger: void log()>"}
        Map<String, Set<String>> nativeCallersMap = new HashMap<>();

        // ========== LOAD JAR FILES ==========

        // Recursively scan target and dependency directories for JAR files
        // This also populates:
        //   - targetJarClasses: Set of all class names found in target JARs
        //   - dependencyClasses: Set of all class names found in dependency JARs
        //   - classToJar: Map from class name to the JAR file containing it
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        System.out.println("Target JARs contain " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // ========== BUILD SOOTUP VIEW ==========

        // SootUp's "view" is the core abstraction for analyzing Java code
        // It provides:
        //   1. Method resolution: Look up method signatures and get their implementations
        //   2. Jimple access: Convert bytecode to Jimple intermediate representation
        //   3. Class hierarchy: Understand inheritance and interface relationships
        //
        // We add three types of input locations:
        //   1. Target JARs: The application we're analyzing
        //   2. Dependency JARs: Libraries the application uses
        //   3. JRE runtime: Standard Java libraries (java.lang.*, java.util.*, etc.)
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());  // Adds JRE classes
        JavaView view = new JavaView(inputs);

        System.out.println("\nStarting method-based worklist analysis..");

        // ========== INITIALIZE METHOD WORKLIST ==========

        // METHOD-BASED WORKLIST (not class-based!)
        // This is the key approach: we follow method calls transitively, just like Mode 1
        //
        // The worklist algorithm:
        //   1. Start with all methods from the target application
        //   2. Process each method to find what it calls
        //   3. Add called methods to the worklist
        //   4. Repeat until worklist is empty (fixed-point)
        //
        // This creates a TRANSITIVE CLOSURE of all reachable methods from the application
        Queue<MethodSignature> methodWorklist = new LinkedList<>();

        // Initialize worklist with all methods from target classes
        // (Similar to Mode 1 starting from classes in the target JARs)
        for (String className : targetJarClasses) {
            Optional<JavaSootClass> classOpt = view.getClass(
                view.getIdentifierFactory().getClassType(className)
            );
            if (classOpt.isPresent()) {
                for (JavaSootMethod method : classOpt.get().getMethods()) {
                    methodWorklist.add(method.getSignature());
                }
            }
        }

        // Also add dependency methods (if you want to be comprehensive)
        for (String className : dependencyClasses) {
            Optional<JavaSootClass> classOpt = view.getClass(
                view.getIdentifierFactory().getClassType(className)
            );
            if (classOpt.isPresent()) {
                for (JavaSootMethod method : classOpt.get().getMethods()) {
                    methodWorklist.add(method.getSignature());
                }
            }
        }

        System.out.println("Initial worklist size: " + methodWorklist.size() + " methods");

        int processedMethods = 0;
        int progressInterval = 100;

        // ========== MAIN WORKLIST PROCESSING LOOP ==========
        // Process methods one by one, following calls transitively
        // This implements a worklist-based fixed-point algorithm
        while (!methodWorklist.isEmpty()) {
            // STEP 1: Dequeue the next method from the worklist
            MethodSignature methodSig = methodWorklist.poll();
            String methodId = methodSig.toString();

            // STEP 2: Skip if already visited (prevents infinite loops and duplicate work)
            if (visitedMethods.contains(methodId)) {
                continue;
            }
            visitedMethods.add(methodId);

            // STEP 3: Progress reporting (shows analysis is progressing)
            processedMethods++;
            if (processedMethods % progressInterval == 0) {
                System.out.println("  Processed " + processedMethods + " methods, found " +
                                 nativeMethods.size() + " natives...");
            }

            // STEP 4: Try to get the method implementation from SootUp view
            // This may fail if the method is from a missing dependency
            Optional<JavaSootMethod> methodOpt = view.getMethod(methodSig);
            if (!methodOpt.isPresent()) {
                continue;
            }

            JavaSootMethod method = methodOpt.get();
            String className = methodSig.getDeclClassType().getFullyQualifiedName();

            // STEP 5: Check if this method is native
            // This is equivalent to checking the ACC_NATIVE flag in bytecode (Mode 1)
            // If native, record it in our results set
            if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                String nativeName = className + "." + method.getName();
                nativeMethods.add(nativeName);
                System.out.println("[ * Found native method * ] " + nativeName);
            }

            // STEP 6: Skip methods without a body (abstract, native, interface methods)
            // We can't analyze calls from these methods since there's no implementation
            if (!method.hasBody()) {
                continue;
            }

            // STEP 7: Analyze method body to find all method calls (KEY STEP!)
            // This is where we build the call graph and find natives transitively
            try {
                // Get the method's Jimple IR (intermediate representation)
                // Jimple is a 3-address code format that's easier to analyze than bytecode
                Body body = method.getBody();

                // Process all statements in the method to find method invocations
                // Jimple statements include assignments, calls, conditionals, etc.
                for (Object stmtObj : body.getStmts()) {
                    // Check if this statement is a method invocation
                    // InvokableStmt represents method calls (virtual, static, special, interface, dynamic)
                    if (stmtObj instanceof InvokableStmt) {
                        ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                            // Extract the signature of the method being called
                            MethodSignature callee = invokeExpr.getMethodSignature();
                            String calleeId = callee.toString();
                            String calleeClassName = callee.getDeclClassType().getFullyQualifiedName();

                            // BUILD CALL GRAPH EDGE: Add "methodId calls calleeId" relationship
                            // This creates a directed edge in our call graph
                            callGraph.computeIfAbsent(methodId, k -> new HashSet<>()).add(calleeId);

                            // Check if the called method is native
                            // If so, track that this method (methodId) calls a native
                            try {
                                Optional<JavaSootMethod> calleeMethodOpt = view.getMethod(callee);
                                if (calleeMethodOpt.isPresent() &&
                                    calleeMethodOpt.get().getModifiers().contains(MethodModifier.NATIVE)) {
                                    String nativeName = calleeClassName + "." + callee.getName();
                                    // Record that methodId directly calls this native method
                                    nativeCallersMap.computeIfAbsent(nativeName, k -> new HashSet<>()).add(methodId);
                                }
                            } catch (Exception ignored) {}

                            // Add the called method to the worklist if not already visited
                            // This is the TRANSITIVE part - we follow calls into JRE, libraries, etc.
                            // Eventually we'll reach all methods reachable from the application
                            if (!visitedMethods.contains(calleeId)) {
                                methodWorklist.add(callee);
                            }
                        });
                    }
                }
            } catch (VerifyError | Exception e) {
                // Skip methods that can't be analyzed due to verification errors
                // This can happen with malformed bytecode or SootUp limitations
                // Same defensive error handling approach as Mode 1
            }
        }

        // Write results
        String outputFile = "sootup_visitor_natives.txt";
        writeMode2Results(outputFile, nativeMethods, visitedMethods.size());

        // Write call graph
        String callGraphFile = "mode2_callgraph.txt";
        writeMode2CallGraph(callGraphFile, callGraph, nativeCallersMap, nativeMethods);

        // Write call chains (full paths from entry points to natives)
        System.out.println("\nBuilding call chains to native methods...");
        String callChainsFile = "mode2_callchains.txt";
        Set<String> allEntryPoints = new HashSet<>(visitedMethods);
        writeMode2CallChains(callChainsFile, callGraph, nativeMethods, nativeCallersMap, allEntryPoints, targetJarClasses);

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("\nAnalysis complete!");
        System.out.println("Time taken: " + totalTimeInSeconds + " seconds");
        System.out.println("Total methods visited: " + visitedMethods.size());
        System.out.println("Native methods found: " + nativeMethods.size());
        System.out.println("Call graph edges: " + callGraph.size());
    }

    /**
     * Writes Mode 2 results to file
     */
    private static void writeMode2Results(String filename, Set<String> nativeMethods, int totalVisited) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Visitor Pattern Analysis Results ===\n\n");
            content.append("Total methods visited: ").append(totalVisited).append("\n");
            content.append("Total native methods found: ").append(nativeMethods.size()).append("\n\n");
            content.append("Native Methods:\n");
            content.append("===============\n");

            List<String> sortedNatives = new ArrayList<>(nativeMethods);
            Collections.sort(sortedNatives);

            for (String nativeMethod : sortedNatives) {
                content.append(nativeMethod).append("\n");
            }

            File file = new File(filename);
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content.toString());
            fw.close();

            System.out.println("\nResults written to: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Writes Mode 2 call graph to file
     */
    private static void writeMode2CallGraph(String filename, Map<String, Set<String>> callGraph,
                                           Map<String, Set<String>> nativeCallersMap,
                                           Set<String> nativeMethods) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Mode 2 Call Graph Analysis ===\n\n");

            // Section 1: Summary statistics
            content.append("SUMMARY:\n");
            content.append("========\n");
            content.append("Total call graph edges: ").append(callGraph.size()).append("\n");
            content.append("Total native methods found: ").append(nativeMethods.size()).append("\n");
            content.append("Native methods with known callers: ").append(nativeCallersMap.size()).append("\n\n");

            // Section 2: Native methods with their direct callers
            content.append("\nNATIVE METHODS WITH CALLERS:\n");
            content.append("============================\n\n");

            List<String> sortedNatives = new ArrayList<>(nativeMethods);
            Collections.sort(sortedNatives);

            for (String nativeMethod : sortedNatives) {
                content.append("NATIVE: ").append(nativeMethod).append("\n");

                Set<String> callers = nativeCallersMap.get(nativeMethod);
                if (callers != null && !callers.isEmpty()) {
                    content.append("  Called by ").append(callers.size()).append(" method(s):\n");
                    List<String> sortedCallers = new ArrayList<>(callers);
                    Collections.sort(sortedCallers);

                    // Limit to first 20 callers to avoid huge files
                    int count = 0;
                    for (String caller : sortedCallers) {
                        content.append("    - ").append(caller).append("\n");
                        count++;
                        if (count >= 20) {
                            if (sortedCallers.size() > 20) {
                                content.append("    ... and ").append(sortedCallers.size() - 20)
                                       .append(" more callers\n");
                            }
                            break;
                        }
                    }
                } else {
                    content.append("  No direct callers found (may be called via reflection or unreachable)\n");
                }
                content.append("\n");
            }

            // Section 3: Call graph statistics
            content.append("\n\nCALL GRAPH STATISTICS:\n");
            content.append("=====================\n\n");

            // Count methods by number of callees
            Map<Integer, Integer> calleeDistribution = new HashMap<>();
            for (Set<String> callees : callGraph.values()) {
                int size = callees.size();
                calleeDistribution.put(size, calleeDistribution.getOrDefault(size, 0) + 1);
            }

            content.append("Methods by number of callees:\n");
            List<Integer> sizes = new ArrayList<>(calleeDistribution.keySet());
            Collections.sort(sizes);
            for (int size : sizes) {
                content.append(String.format("  %d callees: %d methods\n", size, calleeDistribution.get(size)));
            }

            File file = new File(filename);
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content.toString());
            fw.close();

            System.out.println("Call graph written to: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing call graph: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Writes call chains showing complete paths from entry points to native methods
     */
    private static void writeMode2CallChains(String filename,
                                            Map<String, Set<String>> callGraph,
                                            Set<String> nativeMethods,
                                            Map<String, Set<String>> nativeCallersMap,
                                            Set<String> allMethods,
                                            Set<String> targetClasses) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Mode 2 Call Chains Analysis ===\n\n");
            content.append("This shows example execution paths from entry points to native methods\n\n");

            // Build reverse call graph (callee -> callers)
            System.out.println("  Building reverse call graph...");
            Map<String, Set<String>> reverseCallGraph = new HashMap<>();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    reverseCallGraph.computeIfAbsent(callee, k -> new HashSet<>()).add(caller);
                }
            }
            System.out.println("  Reverse call graph has " + reverseCallGraph.size() + " entries");

            // Find potential entry points (methods in target classes)
            // We'll identify them during the search, not pre-filter
            content.append("Searching for call chains from target class methods to native methods...\n");
            content.append("Target classes: ").append(targetClasses).append("\n");
            content.append("This traces backward from each native through the call graph.\n\n");

            // Analyze each native method
            List<String> sortedNatives = new ArrayList<>(nativeMethods);
            Collections.sort(sortedNatives);

            int nativesWithChains = 0;
            int maxNativesToShow = 100; // Show first 100 natives with chains
            int nativesProcessed = 0;

            for (String nativeMethod : sortedNatives) {
                if (nativesWithChains >= maxNativesToShow) {
                    content.append("\n... (showing first ").append(maxNativesToShow)
                           .append(" natives with chains, more not shown for brevity)\n");
                    break;
                }

                // Find the full method signature(s) in the call graph that match this native
                // nativeMethod is like "java.lang.Class.forName0"
                // but call graph has "<java.lang.Class: java.lang.Class forName0(...)>"
                // So we need to search for the method name part (after last dot)
                String className = nativeMethod.substring(0, nativeMethod.lastIndexOf('.'));
                String methodName = nativeMethod.substring(nativeMethod.lastIndexOf('.') + 1);

                List<String> matchingSignatures = new ArrayList<>();
                for (String sig : reverseCallGraph.keySet()) {
                    // Check if signature contains the class and method name
                    // Format: "<className: ... methodName(...)>"
                    if (sig.contains("<" + className + ":") && sig.contains(" " + methodName + "(")) {
                        matchingSignatures.add(sig);
                    }
                }


                List<List<String>> allChains = new ArrayList<>();
                for (String fullSig : matchingSignatures) {
                    // Find call chains to this native (using BFS backward from native)
                    // We'll search until we find methods in target classes
                    List<List<String>> chains = findCallChainsBackward(
                        fullSig, reverseCallGraph, targetClasses, 15, 3);
                    allChains.addAll(chains);
                    if (allChains.size() >= 3) break; // Limit to 3 chains total
                }

                nativesProcessed++;
                if (nativesProcessed % 50 == 0) {
                    System.out.println("  Analyzed " + nativesProcessed + "/" + nativeMethods.size() + " natives...");
                }

                if (!allChains.isEmpty()) {
                    content.append("\n").append("=".repeat(80)).append("\n");
                    content.append("NATIVE: ").append(nativeMethod).append("\n");
                    content.append("Found ").append(allChains.size()).append(" example call chain(s):\n\n");

                    int chainNum = 1;
                    for (List<String> chain : allChains) {
                        // Reverse the chain to show entry point first
                        Collections.reverse(chain);

                        content.append("  Chain ").append(chainNum++).append(" (depth: ")
                               .append(chain.size()).append("):\n");

                        for (int i = 0; i < chain.size(); i++) {
                            String indent = "    ";
                            String arrow = i < chain.size() - 1 ? "  ├─→ " : "  └─→ ";
                            String prefix = "  ".repeat(i);

                            content.append(indent).append(prefix).append(arrow).append(chain.get(i));

                            if (i == chain.size() - 1) {
                                content.append(" [NATIVE]");
                            } else if (i == 0) {
                                content.append(" [ENTRY POINT]");
                            }
                            content.append("\n");
                        }
                        content.append("\n");
                    }
                    nativesWithChains++;
                }
            }

            // Analyze natives without chains for reflection usage
            System.out.println("  Checking for reflection usage in natives without chains...");
            Set<String> reflectionNatives = new HashSet<>();
            Set<String> unreachableNatives = new HashSet<>();

            for (String nativeMethod : sortedNatives) {
                boolean hasChain = false;

                // Check if this native had chains
                String className = nativeMethod.substring(0, nativeMethod.lastIndexOf('.'));
                String methodName = nativeMethod.substring(nativeMethod.lastIndexOf('.') + 1);

                List<String> matchingSignatures = new ArrayList<>();
                for (String sig : reverseCallGraph.keySet()) {
                    if (sig.contains("<" + className + ":") && sig.contains(" " + methodName + "(")) {
                        matchingSignatures.add(sig);
                    }
                }

                for (String fullSig : matchingSignatures) {
                    List<List<String>> chains = findCallChainsBackward(
                        fullSig, reverseCallGraph, targetClasses, 15, 1);
                    if (!chains.isEmpty()) {
                        hasChain = true;
                        break;
                    }
                }

                if (!hasChain) {
                    // Check if it's likely called via reflection
                    boolean isReflection = isLikelyReflectionCall(nativeMethod, nativeCallersMap, callGraph);
                    if (isReflection) {
                        reflectionNatives.add(nativeMethod);
                    } else {
                        unreachableNatives.add(nativeMethod);
                    }
                }
            }

            content.append("\n\nSUMMARY:\n");
            content.append("========\n");
            content.append("Total natives analyzed: ").append(nativesProcessed).append("\n");
            content.append("Natives with direct call chains: ").append(nativesWithChains).append("\n");
            content.append("Natives likely called via reflection: ").append(reflectionNatives.size()).append("\n");
            content.append("Natives that appear unreachable: ").append(unreachableNatives.size()).append("\n");

            if (!reflectionNatives.isEmpty()) {
                content.append("\n\nNATIVES LIKELY CALLED VIA REFLECTION:\n");
                content.append("=====================================\n");
                for (String nativeMethod : reflectionNatives) {
                    content.append("  - ").append(nativeMethod).append("\n");
                }
            }

            if (!unreachableNatives.isEmpty()) {
                content.append("\n\nNATIVES THAT APPEAR UNREACHABLE:\n");
                content.append("================================\n");
                for (String nativeMethod : unreachableNatives) {
                    content.append("  - ").append(nativeMethod).append("\n");
                }
            }

            File file = new File(filename);
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content.toString());
            fw.close();

            System.out.println("Call chains written to: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing call chains: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Checks if a native method is likely called via reflection or is part of reflection API
     *
     * FUNCTION NAME: isLikelyReflectionCall
     *
     * PURPOSE:
     *   Heuristically determines if a native method is invoked through Java reflection
     *   or is itself part of the reflection API implementation.
     *
     * WHY THIS IS NEEDED:
     *   Static analysis cannot see through reflection - when code uses Method.invoke() or
     *   Class.forName(), the actual methods called are determined at runtime, not statically.
     *   This means some natives won't have visible call chains in our call graph.
     *   This function helps categorize those "unreachable" natives as likely reflection-based.
     *
     * DETECTION STRATEGY:
     *   Two-part heuristic:
     *   1. DIRECT: Is the native itself part of the reflection API?
     *   2. INDIRECT: Do any callers (up to 5 levels) use reflection methods?
     *
     * PARAMETERS:
     *   - nativeMethod: Simple name of native method (e.g., "java.lang.Class.forName0")
     *   - nativeCallersMap: Map of native -> direct callers
     *   - callGraph: Map of caller -> callees (for traversing up the call chain)
     *
     * RETURNS:
     *   true if likely called via reflection, false otherwise
     */
    private static boolean isLikelyReflectionCall(String nativeMethod,
                                                  Map<String, Set<String>> nativeCallersMap,
                                                  Map<String, Set<String>> callGraph) {
        // ========== DIRECT CHECK: IS THE NATIVE ITSELF REFLECTION API? ==========
        // Many natives in the reflection API are themselves invoked reflectively
        // Examples:
        //   - java.lang.reflect.Method.invoke0 (the actual native behind Method.invoke)
        //   - java.lang.Class.forName0 (the native behind Class.forName)
        //   - java.lang.Class.getDeclaredMethods0
        if (nativeMethod.contains("java.lang.reflect.") ||
            nativeMethod.contains("java.lang.Class.forName") ||
            nativeMethod.contains("java.lang.Class.getDeclared") ||
            nativeMethod.contains("java.lang.Class.getConstructor") ||
            nativeMethod.contains("java.lang.Class.getMethod") ||
            nativeMethod.contains("java.lang.Class.getField") ||
            nativeMethod.contains("java.lang.Class.newInstance") ||
            nativeMethod.contains("jdk.internal.reflect.") ||
            nativeMethod.contains("sun.reflect.")) {
            return true;
        }

        // ========== INDIRECT CHECK: DO CALLERS USE REFLECTION? ==========

        // Get the methods that directly call this native
        Set<String> directCallers = nativeCallersMap.get(nativeMethod);
        if (directCallers == null || directCallers.isEmpty()) {
            return false;  // No callers means we can't determine reflection usage
        }

        // Define reflection API methods that indicate reflection is being used
        // If any caller invokes these, the native is likely reached through reflection
        Set<String> reflectionMethods = new HashSet<>();
        reflectionMethods.add("java.lang.reflect.Method.invoke");
        reflectionMethods.add("java.lang.reflect.Constructor.newInstance");
        reflectionMethods.add("java.lang.Class.newInstance");
        reflectionMethods.add("java.lang.Class.forName");
        reflectionMethods.add("java.lang.reflect.Field.get");
        reflectionMethods.add("java.lang.reflect.Field.set");
        reflectionMethods.add("java.lang.invoke.MethodHandle.invoke");

        // BFS up to 5 levels of callers to check for reflection usage
        // We traverse UP the call chain (from callee to caller)
        Queue<String> toCheck = new LinkedList<>(directCallers);
        Set<String> visited = new HashSet<>();
        int depth = 0;
        int maxDepth = 5;  // Don't go too far - trades recall for precision

        // Level-by-level BFS (guarantees we check closer callers first)
        while (!toCheck.isEmpty() && depth < maxDepth) {
            int levelSize = toCheck.size();  // Process one level at a time

            for (int i = 0; i < levelSize; i++) {
                String method = toCheck.poll();

                // Skip if already visited (avoid redundant checks)
                if (visited.contains(method)) {
                    continue;
                }
                visited.add(method);

                // CHECK 1: Is this caller itself a reflection method?
                for (String reflectionMethod : reflectionMethods) {
                    if (method.contains(reflectionMethod)) {
                        return true;  // Found reflection usage!
                    }
                }

                // CHECK 2: Does this caller invoke any reflection methods?
                Set<String> callees = callGraph.get(method);
                if (callees != null) {
                    for (String callee : callees) {
                        for (String reflectionMethod : reflectionMethods) {
                            if (callee.contains(reflectionMethod)) {
                                return true;  // Found reflection usage!
                            }
                        }
                    }
                }

                // Add this method's callers to the next level of BFS
                // This is a reverse lookup: who calls this method?
                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    if (entry.getValue().contains(method)) {
                        toCheck.add(entry.getKey());
                    }
                }
            }
            depth++;  // Move to next level
        }

        return false;  // No reflection detected within search depth
    }

    /**
     * Find call chains backward from a native method to methods in target classes using BFS
     *
     * FUNCTION NAME: findCallChainsBackward
     *
     * PURPOSE:
     *   Searches BACKWARD through the call graph from a native method to find execution
     *   paths that start in the target application code.
     *
     * ALGORITHM:
     *   Uses Breadth-First Search (BFS) on the reverse call graph
     *   - Start from the native method
     *   - Follow callers (who calls this method?)
     *   - Continue until we reach a method in the target application
     *   - Each path represents a possible execution flow from app to native
     *
     * PARAMETERS:
     *   - targetMethod: The native method to search from (full signature)
     *   - reverseCallGraph: Map of callee -> callers (backward edges)
     *   - targetClasses: Set of application class names (entry points)
     *   - maxDepth: Maximum chain length (prevents infinite search)
     *   - maxChains: Maximum number of chains to find (stops early)
     *
     * RETURNS:
     *   List of call chains, where each chain is a list of method signatures
     *   from native (index 0) to entry point (last index)
     *
     * EXAMPLE OUTPUT:
     *   Chain: [
     *     "<java.lang.System: long currentTimeMillis()>",      // native
     *     "<com.example.Timer: long getTime()>",              // calls native
     *     "<com.example.App: void main(String[])>"            // entry point
     *   ]
     */
    private static List<List<String>> findCallChainsBackward(
            String targetMethod,
            Map<String, Set<String>> reverseCallGraph,
            Set<String> targetClasses,
            int maxDepth,
            int maxChains) {

        // Store all found call chains (result)
        List<List<String>> foundChains = new ArrayList<>();

        // BFS queue: each element is a partial path from native to current method
        Queue<List<String>> queue = new LinkedList<>();

        // Initialize BFS: start from the target (native) method
        List<String> initialPath = new ArrayList<>();
        initialPath.add(targetMethod);
        queue.add(initialPath);

        // Track visited edges to avoid redundant exploration
        // We use "method1->method2" keys to remember which transitions we've tried
        Set<String> visitedInSearch = new HashSet<>();

        // Safety counter to prevent infinite loops
        int iterations = 0;
        int maxIterations = 100000;

        // ========== BFS MAIN LOOP ==========
        // Continue until:
        //   1. Queue is empty (explored all paths)
        //   2. Found enough chains (maxChains)
        //   3. Safety limit reached
        while (!queue.isEmpty() && foundChains.size() < maxChains && iterations < maxIterations) {
            iterations++;

            // Dequeue the next path to explore
            List<String> currentPath = queue.poll();

            // Get the method at the end of this path (most recent caller)
            String currentMethod = currentPath.get(currentPath.size() - 1);

            // CHECK IF REACHED ENTRY POINT: Is this method in the target application?
            // If yes, we've found a complete chain from app to native
            boolean isInTargetClass = false;
            for (String targetClass : targetClasses) {
                // Check if method signature contains the target class name
                // Format: "<com.example.App: void main(...)>"
                if (currentMethod.contains("<" + targetClass + ":")) {
                    isInTargetClass = true;
                    break;
                }
            }

            if (isInTargetClass) {
                // Found a complete chain! Save it and continue searching for more
                foundChains.add(new ArrayList<>(currentPath));
                continue;
            }

            // DEPTH LIMIT: Don't explore paths that are too long
            // This prevents exponential explosion in large call graphs
            if (currentPath.size() >= maxDepth) {
                continue;
            }

            // EXPAND PATH: Get all methods that call the current method
            Set<String> callers = reverseCallGraph.get(currentMethod);
            if (callers != null) {
                for (String caller : callers) {
                    // CYCLE DETECTION: Don't revisit methods already in this path
                    // Prevents: A -> B -> A -> B -> ...
                    if (!currentPath.contains(caller)) {
                        // REDUNDANCY ELIMINATION: Don't explore the same edge twice
                        // This is an optimization - different paths might converge
                        String pathKey = currentMethod + "->" + caller;
                        if (!visitedInSearch.contains(pathKey)) {
                            visitedInSearch.add(pathKey);

                            // Create new path by appending this caller
                            List<String> newPath = new ArrayList<>(currentPath);
                            newPath.add(caller);

                            // Add to queue for BFS exploration
                            queue.add(newPath);
                        }
                    }
                }
            }
        }

        return foundChains;
    }

    /**
     * Traces all classes within JAR files for native method calls
     * 
     * FUNCTION NAME: traceJarFiles
     * 
     * USAGE:
     *   Called internally to process JAR files and extract class analysis
     * 
     * INPUT REQUIRED:
     *   - jarPaths: List of JAR file paths (relative to pathPrefix)
     * 
     * WHAT IT'S USED FOR:
     *   - Opens JAR files and extracts all .class files
     *   - Analyzes each class file using ASM ClassReader
     *   - Detects native methods and method calls within JAR contents
     *   - Handles JAR file I/O and error recovery
     * 
     * PROCESS:
     *   1. Iterate through each JAR file path
     *   2. Construct full path using pathPrefix
     *   3. Open JAR file and enumerate entries
     *   4. Process each .class file using ASM
     *   5. Handle errors gracefully and continue processing
     */
    public void traceJarFiles(List<String> jarPaths) throws IOException {
        for (String jarPath : jarPaths) {
            String fullJarPath = pathPrefix + jarPath;
            File file = new File(fullJarPath);
            if (!file.exists() || !file.isFile()) {
                System.out.println("JAR file not found: " + fullJarPath);
                continue;
            }

            try (JarFile jarFile = new JarFile(fullJarPath)) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.getName().endsWith(".class")) {
                        try (InputStream inputStream = jarFile.getInputStream(entry)) {
                            ClassReader cr = new ClassReader(inputStream);
                            ClassPrinter cp = new ClassPrinter();
                            cr.accept(cp, 0);
                        } catch (Exception e) {
                            System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing JAR " + fullJarPath + ": " + e.getMessage());
            }
        }
    }

    /**
     * Writes discovered native methods to output file
     * 
     * FUNCTION NAME: writeToFile
     * 
     * USAGE:
     *   Called internally after analysis completion to save results
     * 
     * INPUT REQUIRED:
     *   - None (uses static Util.visitedNative set)
     * 
     * WHAT IT'S USED FOR:
     *   - Saves all discovered native methods to elasticsearch_hybrid.txt
     *   - Creates output file if it doesn't exist
     *   - Provides summary of total native methods found
     *   - Handles file I/O operations safely
     * 
     * PROCESS:
     *   1. Collect all native methods from Util.visitedNative
     *   2. Create or open output file
     *   3. Write each native method on a separate line
     *   4. Close file and display summary
     */
    public void writeToFile() {
        try {
            // Build native methods content
            StringBuilder nativeContentBuilder = new StringBuilder();
            for (String m : Util.visitedNative) {
                nativeContentBuilder.append(m).append("\n");
            }
            String nativeContent = nativeContentBuilder.toString();

            // Write to files
            File nativeOutput = new File(NATIVE_METHODS_FILE);

            writeStringToFile(nativeContent, nativeOutput);

            // Print single consolidated output message
            System.out.println("Analysis results written to:");
            System.out.println("  - Native methods (" + Util.visitedNative.size() + "): " + nativeOutput.getAbsolutePath());
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Displays analysis summary statistics
     * 
     * FUNCTION NAME: prettyPrint
     * 
     * USAGE:
     *   Called internally to display analysis results summary
     * 
     * INPUT REQUIRED:
     *   - None (uses static Util sets for statistics)
     * 
     * WHAT IT'S USED FOR:
     *   - Displays count of visited methods during analysis
     *   - Shows count of discovered native methods
     *   - Provides visual separator for output formatting
     *   - Informs user about file output location
     * 
     * PROCESS:
     *   1. Print visual separator line
     *   2. Display visited method count
     *   3. Display native method count
     *   4. Inform about file output destination
     */
    public void prettyPrint() {
        Util.println();
        System.out.println("Count of visited methods: " + Util.visitedMethod.size() +
                "\n\nCount of called native methods: " + Util.visitedNative.size());
        Util.println();
    }


    /**
     * Loads JAR files from a directory and indexes their class contents
     * 
     * FUNCTION NAME: loadJarsFromDirectory
     * 
     * USAGE:
     *   Called internally to load target and dependency JAR files
     * 
     * INPUT REQUIRED:
     *   - dirPath: Directory path containing JAR files
     *   - classSet: Set to store discovered class names
     *   - classToJarMap: Map to store class name to JAR file mapping
     *   - type: String identifier for logging ("target" or "dependency")
     * 
     * WHAT IT'S USED FOR:
     *   - Recursively scans directory for JAR files
     *   - Extracts class names from each JAR file
     *   - Builds mapping between class names and their source JAR files
     *   - Populates class sets for analysis
     *   - Provides detailed logging of discovered JARs and classes
     * 
     * PROCESS:
     *   1. Validate directory exists and is accessible
     *   2. Use stack-based traversal to find all JAR files recursively
     *   3. Open each JAR file and enumerate entries
     *   4. Extract .class files and convert to class names
     *   5. Update class sets and mappings
     *   6. Handle I/O errors gracefully
     *   7. Return list of discovered JAR file paths
     */
    private static List<String> loadJarsFromDirectory(
            String dirPath,
            Set<String> classSet,
            Map<String, String> classToJarMap,
            String type
    ) {
        List<String> jarList = new ArrayList<>();
        File root = new File(dirPath);
        if (!root.exists() || !root.isDirectory()) {
            System.err.println(type + " directory does not exist or is not a directory: " + dirPath);
            return jarList;
        }
        Deque<File> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            File dir = stack.pop();
            File[] files = dir.listFiles();
            if (files == null) continue;
            for (File f : files) {
                if (f.isDirectory()) {
                    stack.push(f);
                } else if (f.getName().endsWith(".jar")) {
                    System.out.println("Processing " + type + " JAR: " + f.getAbsolutePath());
                    jarList.add(f.getAbsolutePath());
                    try (ZipFile zipFile = new ZipFile(f)) {
                        Enumeration<? extends ZipEntry> entries = zipFile.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry entry = entries.nextElement();
                            String name = entry.getName();
                            if (name.endsWith(".class")) {
                                String className = name.replace('/', '.').substring(0, name.length() - 6);
                                classSet.add(className);
                                classToJarMap.put(className, f.getAbsolutePath());
                            }
                        }
                    } catch (IOException e) {
                        System.err.println("Error reading " + type + " JAR: " + f.getName() + " - " + e.getMessage());
                    }
                }
            }
        }
        System.out.println("Total " + type + " JARs found: " + jarList.size());
        System.out.println(type + " classes indexed: " + classSet.size());
        return jarList;
    }


    /**
     * Utility class for HybridByteCodeTracer functionality
     * 
     * CLASS NAME: Util
     * 
     * USAGE:
     *   Used internally by HybridByteCodeTracer methods for data storage and utilities
     * 
     * WHAT IT'S USED FOR:
     *   - Stores visited methods and native methods during analysis
     *   - Provides utility methods for file operations
     *   - Manages static collections for analysis state
     *   - Provides formatting utilities for output
     */
    static class Util {
        public static Set<String> visitedMethod = new HashSet<>();
        public static Set<String> visitedNative = new HashSet<>();

        /**
         * Prints visual separator line for output formatting
         *
         * FUNCTION NAME: println
         *
         * USAGE:
         *   Called internally for output formatting
         *
         * WHAT IT'S USED FOR:
         *   - Provides visual separation in console output
         *   - Improves readability of analysis results
         */
        public static void println() {
            System.out.println(" ");
        }
    }

    /**
     * ASM ClassVisitor for filtering specific methods in classes
     * 
     * CLASS NAME: ClassFilter
     * 
     * USAGE:
     *   Used internally by ASM to filter and analyze specific methods
     * 
     * WHAT IT'S USED FOR:
     *   - Filters classes to find specific method signatures
     *   - Detects native methods during bytecode analysis
     *   - Processes only methods matching specific identifier
     *   - Integrates with ASM framework for bytecode analysis
     */
    static class ClassFilter extends ClassVisitor {
        private String identifier;
        private String className;

        public ClassFilter(String identifier) {
            super(Opcodes.ASM9);
            this.identifier = identifier;
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (!this.identifier.equals(name+descriptor)) {
                return null;
            }
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    /**
     * ASM ClassVisitor for printing class information and detecting native methods
     * 
     * CLASS NAME: ClassPrinter
     * 
     * USAGE:
     *   Used internally by ASM to analyze class bytecode and detect native methods
     * 
     * WHAT IT'S USED FOR:
     *   - Visits class bytecode during ASM analysis
     *   - Detects and records native methods found in classes
     *   - Provides class information logging
     *   - Creates MethodPrinter for method-level analysis
     *   - Integrates with ASM framework for comprehensive analysis
     */
    static class ClassPrinter extends ClassVisitor {
        private String className;

        public ClassPrinter() {
            super(Opcodes.ASM9);
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    /**
     * ASM MethodVisitor for analyzing method bytecode and tracing method calls
     * 
     * CLASS NAME: MethodPrinter
     * 
     * USAGE:
     *   Used internally by ASM to analyze method bytecode and trace calls
     * 
     * WHAT IT'S USED FOR:
     *   - Visits method bytecode during ASM analysis
     *   - Detects method invocation instructions (INVOKEVIRTUAL, INVOKESTATIC, etc.)
     *   - Traces method calls to find native methods
     *   - Prevents duplicate analysis of same methods
     *   - Recursively analyzes called methods using ClassReader
     *   - Integrates with ASM framework for method-level analysis
     */
    static class MethodPrinter extends MethodVisitor {
        public MethodPrinter() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String className = owner.replace('/', '.');
            if (Util.visitedMethod.contains(className+name+descriptor)) {
                return;
            }

            Util.visitedMethod.add(className+name+descriptor);
            try {
                ClassReader cr = new ClassReader(className);
                ClassFilter cf = new ClassFilter(name+descriptor);
                cr.accept(cf, 0);
            } catch (IOException e) {
                // System.out.println("oops exception.. " + className + " " + name + " " + descriptor);
            }

            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }

    /**
     * Utility class for extracting class names from JAR files
     * 
     * CLASS NAME: FindJarClass
     * 
     * USAGE:
     *   Used internally to extract class file names from JAR archives
     * 
     * WHAT IT'S USED FOR:
     *   - Opens JAR files and enumerates entries
     *   - Extracts .class file names from JAR contents
     *   - Converts JAR entry names to fully qualified class names
     *   - Provides list of classes for further analysis
     *   - Handles JAR file I/O operations
     */
    static class FindJarClass {
        public List<String> findClass(String jarFileName) throws IOException {
            List<String> classPaths = new ArrayList<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    classPaths.add(entry.getName().replace(".class", "")
                            .replace("/", "."));
                }
            }

            jarFile.close();
            return classPaths;
        }
    }

    /**
     * Utility class for discovering JAR files in a directory
     * 
     * CLASS NAME: GetJarPaths
     * 
     * USAGE:
     *   Used internally to find all JAR files in a specified directory
     * 
     * WHAT IT'S USED FOR:
     *   - Scans directory for .jar files
     *   - Returns list of JAR file names (not full paths)
     *   - Validates directory existence and accessibility
     *   - Provides JAR file discovery for analysis pipeline
     *   - Handles directory I/O operations
     */
    static class GetJarPaths {
        public List<String> getJarPaths() throws IOException {
            ArrayList<String> result = new ArrayList<>();

            String jarDir = pathPrefix;
            File jarFolder = new File(jarDir);

            if (!jarFolder.exists() || !jarFolder.isDirectory()) {
                System.out.println("JAR directory not found: " + jarDir);
                return result;
            }

            File[] jarFiles = jarFolder.listFiles((dir, name) -> name.endsWith(".jar"));
            if (jarFiles != null) {
                for (File jarFile : jarFiles) {
                    result.add(jarFile.getName());
                    System.out.println("Found JAR: " + jarFile.getName());
                }
            }

            return result;
        }
    }

    /**
     * Utility class for finding native methods in JAR files using ASM
     * 
     * CLASS NAME: FindNativeMethods
     * 
     * USAGE:
     *   Used internally to scan JAR files for native method declarations
     * 
     * WHAT IT'S USED FOR:
     *   - Scans JAR files for classes containing native methods
     *   - Uses ASM to analyze class bytecode for native method flags
     *   - Extracts native method signatures and names
     *   - Provides comprehensive native method discovery
     *   - Handles JAR file processing and error recovery
     */
    static class FindNativeMethods {
        public Set<String> findNativeMethods(String jarFileName) throws IOException {
            Set<String> nativeMethods = new HashSet<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        ClassReader classReader = new ClassReader(inputStream);
                        classReader.accept(new NativeMethodVisitor(entry.getName(), nativeMethods), 0);
                    } catch (Exception e) {
                        System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                    }
                }
            }

            jarFile.close();
            return nativeMethods;
        }

        /**
         * ASM ClassVisitor for detecting native methods in class bytecode
         * 
         * CLASS NAME: NativeMethodVisitor
         * 
         * USAGE:
         *   Used internally by FindNativeMethods to analyze individual classes
         * 
         * WHAT IT'S USED FOR:
         *   - Visits class bytecode to detect native method declarations
         *   - Checks method access flags for native modifier
         *   - Records native method signatures in specified format
         *   - Integrates with ASM framework for bytecode analysis
         *   - Handles class name conversion and formatting
         */
        private static class NativeMethodVisitor extends ClassVisitor {
            private final String className;
            private final Set<String> nativeMethods;

            public NativeMethodVisitor(String className, Set<String> nativeMethods) {
                super(Opcodes.ASM9);
                this.className = className;
                this.nativeMethods = nativeMethods;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0) {
                    String jniFunction = className.replace(".class", "")
                            .replace("/", ".")+ "." + name + "---" + descriptor;
                    nativeMethods.add(jniFunction);
                }
                return null;
            }
        }
    }
}
