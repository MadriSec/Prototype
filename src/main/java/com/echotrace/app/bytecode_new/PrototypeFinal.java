package com.echotrace.app.bytecode_new;

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
import java.util.stream.Collectors;
import java.util.Comparator;

/**
 * Unified Native Method Tracer - Merges PrintpathDFS and HybridByteCodeTracer
 * 
 * This class provides comprehensive analysis of native method usage in Java applications.
 * It combines static analysis techniques using Soot framework and ASM bytecode analysis
 * to trace native method calls and their execution paths.
 * 
 * USAGE:
 *   java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2|--3|--5|--6]
 *
 * INPUT REQUIREMENTS:
 *   - target-directory: Directory containing application JAR files to analyze
 *   - dependencies-directory: Directory containing dependency JAR files
 *   - mode (optional): Analysis mode selector (--1 to --3, --5, --6)
 *
 * ANALYSIS MODES:
 *   --1 (default): Trace from main methods only; emit paths to reachable native methods.
 *                  Use case: Find native methods called during application startup
 *   --2: Scan all classes to list every native method in target+deps, and separately
 *        identify JRE natives reachable from main.
 *        Use case: Comprehensive inventory of all native methods in codebase
 *   --3: Use ALL methods in target JARs as entry points (not just main) and trace.
 *        Use case: Find all possible native method calls from any target method
 *   --4: Use HybridByteCodeTracer approach (ASM-based native method detection).
 *        Use case: Bytecode-level analysis using ASM framework
 *   --5: SootUp Visitor Pattern (Worklist-based like Mode 4, using Jimple instead of ASM).
 *
 * 
 * OUTPUT FILES:
 *   - unique_native_methods.txt: List of unique native methods found
 *   - native_methods_with_paths.txt: Native methods with call paths
 *   - deps_called_by_target.txt: Dependency classes called by target code
 *   - all_target_dep_natives.txt: All native methods in target and dependencies
 *   - jre_used_natives.txt: JRE native methods actually used
 *   - native_methods_by_package.txt: Native methods organized by package
 *   - elasticsearch_hybrid.txt: Results from hybrid bytecode tracer (mode 4)
 *   - sootup_visitor_natives.txt: Results from SootUp visitor pattern (mode 5)
 */
public class PrototypeFinal {
    // PrintpathDFS fields
    private static final Map<String, String> classToJar = new HashMap<>();
    private static final Set<String> usedDepClasses = new HashSet<>();
    private static final Set<MethodSignature> allTargetDepNativeMethods = new HashSet<>();
    private static final Set<MethodSignature> jreUsedNativeMethods = new HashSet<>();
    private static final Set<MethodSignature> visited = new HashSet<>();
    private static final List<List<MethodSignature>> nativePaths = new ArrayList<>();
    private static final Set<MethodSignature> foundNative = new HashSet<>();
    private static JavaView view;
    private static Set<String> targetJarClasses = new HashSet<>();
    private static Set<String> dependencyClasses = new HashSet<>();
    private static final Set<MethodSignature> allUniqueNativeMethods = new HashSet<>();

    // Call graph structure: caller -> set of callees
    private static final Map<String, Set<String>> callGraph = new HashMap<>();

    // HybridByteCodeTracer fields
    private static String pathPrefix = "/home/rupesh.punna/Prototype/JARFILES/";
    private static final String FALLBACK_NATIVE_FILE = "/home/rupesh.punna/Prototype/elasticsearch_hybrid.txt";
    private static final String FALLBACK_FORMATTED_METHODS_FILE = "/home/rupesh.punna/Prototype/formatted_methods.txt";

    /**
     * Main entry point for the Unified Native Method Tracer
     * 
     * FUNCTION NAME: main
     * 
     * USAGE:
     *   java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2|--3|--4|--5]
     *
     * INPUT REQUIRED:
     *   - args[0]: target-directory - Directory containing application JAR files
     *   - args[1]: dependencies-directory - Directory containing dependency JAR files
     *   - args[2]: mode (optional) - Analysis mode selector (--1 to --5)
     * 
     * WHAT IT'S USED FOR:
     *   - Orchestrates the entire native method analysis workflow
     *   - Parses command line arguments and validates input
     *   - Selects appropriate analysis mode based on user input
     *   - Loads JAR files and builds classpath for analysis
     *   - Executes the chosen analysis strategy
     *   - Generates comprehensive output files with results
     * 
     * PROCESS FLOW:
     *   1. Parse and validate command line arguments
     *   2. Determine analysis mode (--1 to --5)
     *   3. Load JAR files from target and dependencies directories
     *   4. Build Soot analysis environment with classpath
     *   5. Execute mode-specific analysis logic
     *   6. Generate output files with results
     */
    public static void main(String[] args) {
        // Parse CLI, configure analysis inputs (target + deps + runtime), then run
        // either DFS-based tracing (modes 1/3), combined scanning (mode 2),
        // HybridByteCodeTracer approach (mode 4), or SootUp Visitor Pattern (mode 5).
        if (args.length < 2) {
            System.err.println("Usage: java PrototypeFinal <target-directory> <dependencies-directory> [--1|--2|--3|--4|--5]");
            System.err.println("  --1: Only include native methods called by main methods (with paths)");
            System.err.println("  --2: Include all native methods present in target+deps JARs + JRE natives from main");
            System.err.println("  --3: Use all target methods as entry points (not just main)");
            System.err.println("  --4: Use HybridByteCodeTracer approach (ASM-based native detection)");
            System.err.println("  --5: SootUp Visitor Pattern (Worklist-based, Jimple analysis)");
            return;
        }

        String targetDir = args[0];
        String depsDir = args[1];

        // Parse mode argument
        boolean onlyMainCalled = false;
        boolean includeAllNative = false;
        boolean allTargetMethods = false;
        boolean hybridByteCodeTracer = false;
        boolean sootupVisitorPattern = false;
        boolean generateDetailedLogs = false;

        if (args.length >= 3) {
            if ("--1".equals(args[2])) {
                onlyMainCalled = true;
                System.out.println("Mode: Only native methods called by main methods");
            } else if ("--2".equals(args[2])) {
                includeAllNative = true;
                System.out.println("Mode: All native methods in target+deps JARs + JRE natives from main");
            } else if ("--3".equals(args[2])) {
                allTargetMethods = true;
                System.out.println("Mode: All methods in target JARs as entry points");
            } else if ("--4".equals(args[2])) {
                hybridByteCodeTracer = true;
                System.out.println("Mode: HybridByteCodeTracer approach (ASM-based)");
            } else if ("--5".equals(args[2])) {
                sootupVisitorPattern = true;
                System.out.println("Mode: SootUp Visitor Pattern (Worklist-based)");
            } else {
                System.err.println("Invalid mode. Use --1, --2, --3, --4, or --5");
                return;
            }
        } else {
            onlyMainCalled = true;
            System.out.println("Mode: Only native methods called by main methods (default)");
        }

        // Check for --log flag (can be args[3] or args[4])
        for (int i = 2; i < args.length; i++) {
            if ("--log".equals(args[i])) {
                generateDetailedLogs = true;
                System.out.println("Detailed logging enabled: Will generate call graph and call chains");
                break;
            }
        }

        System.out.println("=== PrototypeFinal: Unified Native Method Tracer ===");
        System.out.println("Analyzing target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);

        ensureFormattedMethodsFile();

        // Mode 4: HybridByteCodeTracer approach
        if (hybridByteCodeTracer) {
            System.out.println("\n=== Mode 4: HybridByteCodeTracer Approach ===");
            try {
                runHybridByteCodeTracer(targetDir, depsDir);
            } catch (Exception e) {
                System.err.println("Error running HybridByteCodeTracer: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }

        // Mode 5: SootUp Visitor Pattern (Worklist-based)
        if (sootupVisitorPattern) {
            System.out.println("\n=== Mode 5: SootUp Visitor Pattern (Worklist) ===");
            try {
                runSootUpVisitorPattern(targetDir, depsDir);
            } catch (Exception e) {
                System.err.println("Error running SootUp Visitor Pattern: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }

        // Modes 1, 2, 3: Original PrintpathDFS logic
        // 1) Load JARs from target and dependencies; index class -> jar path
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        view = new JavaView(inputs);

        System.out.println("Target JARs contain " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // 3) Find entry point methods in target JARs (main only for mode 1, all methods for mode 3)
        List<JavaSootMethod> entryPointMethods = new ArrayList<>();
        int totalTargetMethods = 0;
        
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    totalTargetMethods++;
                    
                    if (allTargetMethods) {
                        // Mode 3: Add ALL methods from target classes
                        entryPointMethods.add(method);
                    } else if (isMainMethod(method)) {
                        // Mode 1: Only main methods
                        entryPointMethods.add(method);
                        System.out.println("Found main method: " + method.getSignature());
                    }
                }
            }
        }

        if (allTargetMethods) {
            System.out.println("Total target methods found: " + totalTargetMethods);
            System.out.println("Using all " + entryPointMethods.size() + " target methods as entry points");
        }

        if ((onlyMainCalled || allTargetMethods) && entryPointMethods.isEmpty()) {
            System.out.println("No entry point methods found in the target JARs.");
            writeUniqueNativeMethodsToFile("unique_native_methods.txt", allUniqueNativeMethods);
            writeMainCalledNativeMethods("native_methods_with_paths.txt", entryPointMethods, allTargetMethods);
            writeDepsCalledByTarget("deps_called_by_target.txt", entryPointMethods, allTargetMethods);
            return;
        }

        // 4) In --1 or --3 mode, DFS from each entry point to collect reachable natives
        if (onlyMainCalled || allTargetMethods) {
            int processedCount = 0;

            // For Mode 3, share visited set across all entry points for performance
            // For Mode 1, clear visited for each main method to get individual paths
            if (onlyMainCalled) {
                visited.clear();
            }

            for (JavaSootMethod entryPoint : entryPointMethods) {
                if (onlyMainCalled) {
                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();
                }

                List<MethodSignature> startPath = new ArrayList<>();
                startPath.add(entryPoint.getSignature());
                dfs(entryPoint.getSignature(), startPath);

                allUniqueNativeMethods.addAll(foundNative);

                processedCount++;
                if (allTargetMethods && processedCount % 100 == 0) {
                    System.out.println("  Processed " + processedCount + "/" + entryPointMethods.size() + " methods...");
                }
            }
            
            writeDepsCalledByTarget("deps_called_by_target.txt", entryPointMethods, allTargetMethods);
        }

        // 5) Write results based on mode
        if (onlyMainCalled || allTargetMethods) {
            writeMainCalledNativeMethods("native_methods_with_paths.txt", entryPointMethods, allTargetMethods);
            writeUniqueNativeMethodsToFile("unique_native_methods.txt", allUniqueNativeMethods);
        } else if (includeAllNative) {
            System.out.println("\n=== Scanning All Classes for Native Methods ===");
            scanAllNativeMethods();
            System.out.println("Total native methods found in entire codebase: " + allUniqueNativeMethods.size());

            scanTargetAndDependencyNatives();

            Set<MethodSignature> reachableNatives = new HashSet<>();
            List<JavaSootMethod> mainMethods = entryPointMethods.stream()
                .filter(PrototypeFinal::isMainMethod)
                .collect(Collectors.toList());
                
            if (!mainMethods.isEmpty()) {
                for (JavaSootMethod main : mainMethods) {
                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();

                    List<MethodSignature> startPath = new ArrayList<>();
                    startPath.add(main.getSignature());
                    dfs(main.getSignature(), startPath);

                    reachableNatives.addAll(foundNative);
                }
            } else {
                System.out.println("[WARN] No main methods found; cannot determine JRE natives used.");
            }

            for (MethodSignature sig : reachableNatives) {
                String className = sig.getDeclClassType().getFullyQualifiedName();
                if (!targetJarClasses.contains(className) && !dependencyClasses.contains(className)) {
                    jreUsedNativeMethods.add(sig);
                }
            }

            writeAllTargetDepFlat("all_target_dep_natives.txt", allTargetDepNativeMethods);
            writeJreUsedSignatures("jre_used_natives.txt", jreUsedNativeMethods);
            writeAllTargetDepSignatures("all_target_dep_natives_signatures.txt", allTargetDepNativeMethods);
            writeDepsCalledByTarget_AllTargets("deps_called_by_target.txt");
            writeNativeMethodsByPackage("native_methods_by_package.txt", allUniqueNativeMethods);
            writeCallGraph("callgraph.json");
        }
    }
    /**
     * Ensures formatted_methods.txt exists so downstream tooling can read/write it safely.
     */
    private static void ensureFormattedMethodsFile() {
        File formattedFile = new File(resolveFormattedMethodsPath());
        if (formattedFile.exists()) {
            return;
        }
        try {
            File parent = formattedFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (formattedFile.createNewFile()) {
                System.out.println("[INFO] Created formatted_methods.txt");
            }
        } catch (IOException e) {
            System.err.println("[WARN] Could not create formatted_methods.txt: " + e.getMessage());
        }
    }

    private static String resolveFormattedMethodsPath() {
        String outputsDir = System.getenv("OUTPUTS_DIR");
        if (outputsDir != null && !outputsDir.isBlank()) {
            if (outputsDir.endsWith(File.separator)) {
                return outputsDir + "formatted_methods.txt";
            }
            return outputsDir + File.separator + "formatted_methods.txt";
        }
        return FALLBACK_FORMATTED_METHODS_FILE;
    }

    private static String resolveNativeFilePath() {
        String outputsDir = System.getenv("OUTPUTS_DIR");
        if (outputsDir != null && !outputsDir.isBlank()) {
            if (outputsDir.endsWith(File.separator)) {
                return outputsDir + "native_methods.txt";
            }
            return outputsDir + File.separator + "native_methods.txt";
        }
        return FALLBACK_NATIVE_FILE;
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
     * Executes HybridByteCodeTracer analysis (Mode 4)
     *
     * FUNCTION NAME: runHybridByteCodeTracer
     *
     * USAGE:
     *   Called internally when --4 mode is selected
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
     * Executes SootUp Visitor Pattern analysis (Mode 5)
     *
     * FUNCTION NAME: runSootUpVisitorPattern
     *
     * USAGE:
     *   Called internally when --5 mode is selected
     *
     * INPUT REQUIRED:
     *   - targetDir: Directory containing target application JAR files
     *   - depsDir: Directory containing dependency JAR files
     *
     * WHAT IT'S USED FOR:
     *   - Performs SootUp-based Jimple analysis using visitor pattern
     *   - Similar to Mode 4 but uses SootUp/Jimple instead of ASM/bytecode
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
        System.out.println("Starting SootUp Visitor Pattern analysis (FIXED - Method-based worklist)...");

        long startTime = System.currentTimeMillis();

        // Track visited methods and found natives
        Set<String> visitedMethodsMode6 = new HashSet<>();
        Set<String> nativeMethodsMode6 = new HashSet<>();

        // BUILD CALL GRAPH! (caller -> list of callees)
        Map<String, Set<String>> callGraphMode6 = new HashMap<>();
        Map<String, Set<String>> nativeCallersMap = new HashMap<>(); // native -> callers

        // Load JARs
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        System.out.println("Target JARs contain " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // Build SootUp view (needed for method resolution)
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        JavaView mode6View = new JavaView(inputs);

        System.out.println("\nStarting method-based worklist analysis..");

        // METHOD-BASED WORKLIST (not class-based!)
        // This is the key fix: we follow method calls transitively, just like Mode 4
        Queue<MethodSignature> methodWorklist = new LinkedList<>();

        // Initialize worklist with all methods from target classes
        // (Similar to Mode 4 starting from classes in the target JARs)
        for (String className : targetJarClasses) {
            Optional<JavaSootClass> classOpt = mode6View.getClass(
                mode6View.getIdentifierFactory().getClassType(className)
            );
            if (classOpt.isPresent()) {
                for (JavaSootMethod method : classOpt.get().getMethods()) {
                    methodWorklist.add(method.getSignature());
                }
            }
        }

        // Also add dependency methods (if you want to be comprehensive)
        for (String className : dependencyClasses) {
            Optional<JavaSootClass> classOpt = mode6View.getClass(
                mode6View.getIdentifierFactory().getClassType(className)
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

        // Process methods one by one, following calls transitively
        while (!methodWorklist.isEmpty()) {
            MethodSignature methodSig = methodWorklist.poll();
            String methodId = methodSig.toString();

            // Skip if already visited
            if (visitedMethodsMode6.contains(methodId)) {
                continue;
            }
            visitedMethodsMode6.add(methodId);

            processedMethods++;
            if (processedMethods % progressInterval == 0) {
                System.out.println("  Processed " + processedMethods + " methods, found " +
                                 nativeMethodsMode6.size() + " natives...");
            }

            // Try to get the method
            Optional<JavaSootMethod> methodOpt = mode6View.getMethod(methodSig);
            if (!methodOpt.isPresent()) {
                continue;
            }

            JavaSootMethod method = methodOpt.get();
            String className = methodSig.getDeclClassType().getFullyQualifiedName();

            // Check if native (like Mode 4's ACC_NATIVE check)
            if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                String nativeName = className + "." + method.getName();
                nativeMethodsMode6.add(nativeName);
                System.out.println("[ * Found native method * ] " + nativeName);
            }

            // If method has no body, we can't follow calls from it
            if (!method.hasBody()) {
                continue;
            }

            // Follow method calls (THIS IS THE KEY FIX!)
            try {
                Body body = method.getBody();

                // Process statements to find method calls
                for (Object stmtObj : body.getStmts()) {
                    if (stmtObj instanceof InvokableStmt) {
                        ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                            MethodSignature callee = invokeExpr.getMethodSignature();
                            String calleeId = callee.toString();
                            String calleeClassName = callee.getDeclClassType().getFullyQualifiedName();

                            // BUILD CALL GRAPH EDGE: methodId -> calleeId
                            callGraphMode6.computeIfAbsent(methodId, k -> new HashSet<>()).add(calleeId);

                            // Check if callee is native and track caller
                            try {
                                Optional<JavaSootMethod> calleeMethodOpt = mode6View.getMethod(callee);
                                if (calleeMethodOpt.isPresent() &&
                                    calleeMethodOpt.get().getModifiers().contains(MethodModifier.NATIVE)) {
                                    String nativeName = calleeClassName + "." + callee.getName();
                                    nativeCallersMap.computeIfAbsent(nativeName, k -> new HashSet<>()).add(methodId);
                                }
                            } catch (Exception ignored) {}

                            // Add called method to worklist if not already visited
                            // This will naturally follow calls into JRE, dependencies, etc.
                            if (!visitedMethodsMode6.contains(calleeId)) {
                                methodWorklist.add(callee);
                            }
                        });
                    }
                }
            } catch (VerifyError | Exception e) {
                // Skip methods that can't be analyzed
                // (Same error handling as Mode 4)
            }
        }

        // Write results
        String outputFile = "sootup_visitor_natives.txt";
        writeMode5Results(outputFile, nativeMethodsMode6, visitedMethodsMode6.size());

        // Write call graph
        String callGraphFile = "mode5_callgraph.txt";
        writeMode5CallGraph(callGraphFile, callGraphMode6, nativeCallersMap, nativeMethodsMode6);

        // Write call chains (full paths from entry points to natives)
        System.out.println("\nBuilding call chains to native methods...");
        String callChainsFile = "mode5_callchains.txt";
        Set<String> allEntryPoints = new HashSet<>(visitedMethodsMode6);
        writeMode5CallChains(callChainsFile, callGraphMode6, nativeMethodsMode6, nativeCallersMap, allEntryPoints, targetJarClasses);

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("\nAnalysis complete!");
        System.out.println("Time taken: " + totalTimeInSeconds + " seconds");
        System.out.println("Total methods visited: " + visitedMethodsMode6.size());
        System.out.println("Native methods found: " + nativeMethodsMode6.size());
        System.out.println("Call graph edges: " + callGraphMode6.size());
    }

    /**
     * Writes Mode 5 results to file
     */
    private static void writeMode5Results(String filename, Set<String> nativeMethods, int totalVisited) {
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
     * Writes Mode 5 call graph to file
     */
    private static void writeMode5CallGraph(String filename, Map<String, Set<String>> callGraph,
                                           Map<String, Set<String>> nativeCallersMap,
                                           Set<String> nativeMethods) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Mode 5 Call Graph Analysis ===\n\n");

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
    private static void writeMode5CallChains(String filename,
                                            Map<String, Set<String>> callGraph,
                                            Set<String> nativeMethods,
                                            Map<String, Set<String>> nativeCallersMap,
                                            Set<String> allMethods,
                                            Set<String> targetClasses) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Mode 5 Call Chains Analysis ===\n\n");
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
     */
    private static boolean isLikelyReflectionCall(String nativeMethod,
                                                  Map<String, Set<String>> nativeCallersMap,
                                                  Map<String, Set<String>> callGraph) {
        // Check if the native itself is part of the reflection API
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

        // Get direct callers of this native
        Set<String> directCallers = nativeCallersMap.get(nativeMethod);
        if (directCallers == null || directCallers.isEmpty()) {
            return false;
        }

        // Reflection API methods that indicate reflection usage
        Set<String> reflectionMethods = new HashSet<>();
        reflectionMethods.add("java.lang.reflect.Method.invoke");
        reflectionMethods.add("java.lang.reflect.Constructor.newInstance");
        reflectionMethods.add("java.lang.Class.newInstance");
        reflectionMethods.add("java.lang.Class.forName");
        reflectionMethods.add("java.lang.reflect.Field.get");
        reflectionMethods.add("java.lang.reflect.Field.set");
        reflectionMethods.add("java.lang.invoke.MethodHandle.invoke");

        // Check if any caller or their callers use reflection
        Queue<String> toCheck = new LinkedList<>(directCallers);
        Set<String> visited = new HashSet<>();
        int depth = 0;
        int maxDepth = 5; // Check up to 5 levels of callers

        while (!toCheck.isEmpty() && depth < maxDepth) {
            int levelSize = toCheck.size();
            for (int i = 0; i < levelSize; i++) {
                String method = toCheck.poll();

                if (visited.contains(method)) {
                    continue;
                }
                visited.add(method);

                // Check if this method is a reflection method
                for (String reflectionMethod : reflectionMethods) {
                    if (method.contains(reflectionMethod)) {
                        return true;
                    }
                }

                // Check if this method's callees include reflection methods
                Set<String> callees = callGraph.get(method);
                if (callees != null) {
                    for (String callee : callees) {
                        for (String reflectionMethod : reflectionMethods) {
                            if (callee.contains(reflectionMethod)) {
                                return true;
                            }
                        }
                    }
                }

                // Add callers to check next level (reverse lookup)
                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    if (entry.getValue().contains(method)) {
                        toCheck.add(entry.getKey());
                    }
                }
            }
            depth++;
        }

        return false;
    }

    /**
     * Find call chains backward from a native method to methods in target classes using BFS
     */
    private static List<List<String>> findCallChainsBackward(
            String targetMethod,
            Map<String, Set<String>> reverseCallGraph,
            Set<String> targetClasses,
            int maxDepth,
            int maxChains) {

        List<List<String>> foundChains = new ArrayList<>();
        Queue<List<String>> queue = new LinkedList<>();

        // Start from the target (native) method
        List<String> initialPath = new ArrayList<>();
        initialPath.add(targetMethod);
        queue.add(initialPath);

        Set<String> visitedInSearch = new HashSet<>();
        int iterations = 0;
        int maxIterations = 100000; // Safety limit

        while (!queue.isEmpty() && foundChains.size() < maxChains && iterations < maxIterations) {
            iterations++;
            List<String> currentPath = queue.poll();
            String currentMethod = currentPath.get(currentPath.size() - 1);

            // Check if we've reached a method in target classes (entry point)
            boolean isInTargetClass = false;
            for (String targetClass : targetClasses) {
                if (currentMethod.contains("<" + targetClass + ":")) {
                    isInTargetClass = true;
                    break;
                }
            }

            if (isInTargetClass) {
                foundChains.add(new ArrayList<>(currentPath));
                continue; // Found a chain, keep looking for more
            }

            // Don't go too deep
            if (currentPath.size() >= maxDepth) {
                continue;
            }

            // Get callers of current method
            Set<String> callers = reverseCallGraph.get(currentMethod);
            if (callers != null) {
                for (String caller : callers) {
                    // Avoid cycles
                    if (!currentPath.contains(caller)) {
                        // Avoid revisiting same method from different paths (optimization)
                        String pathKey = currentMethod + "->" + caller;
                        if (!visitedInSearch.contains(pathKey)) {
                            visitedInSearch.add(pathKey);

                            List<String> newPath = new ArrayList<>(currentPath);
                            newPath.add(caller);
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

            // Build formatted methods content (non-native methods only)
            StringBuilder formattedContentBuilder = new StringBuilder();
            for (String m : Util.visitedMethod) {
                // Only add methods that are NOT in the native set
                if (!Util.visitedNative.contains(m)) {
                    formattedContentBuilder.append(m).append("\n");
                }
            }
            String formattedContent = formattedContentBuilder.toString();

            // Write to files
            File nativeOutput = new File(resolveNativeFilePath());
            File formattedOutput = new File(resolveFormattedMethodsPath());

            writeStringToFile(nativeContent, nativeOutput);
            writeStringToFile(formattedContent, formattedOutput);

            // Print single consolidated output message
            System.out.println("Analysis results written to:");
            System.out.println("  - Native methods (" + Util.visitedNative.size() + "): " + nativeOutput.getAbsolutePath());
            System.out.println("  - Formatted methods (" + (Util.visitedMethod.size() - Util.visitedNative.size()) + "): " + formattedOutput.getAbsolutePath());
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

    // PrintpathDFS methods
    private static void writeJreUsedSignatures(String filename, Set<MethodSignature> methods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            List<String> lines = methods.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .map(MethodSignature::toString)
                    .collect(Collectors.toList());

            writer.println("JRE native methods actually used by the application:");
            for (int i = 0; i < lines.size(); i++) {
                writer.println((i + 1) + ". " + lines.get(i));
            }

            System.out.println("\nJRE-used native methods written to: " + filename);
            System.out.println("Total: " + lines.size());
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeDepsCalledByTarget_AllTargets(String filename) {
        Set<String> depClassesUsedByTarget = new HashSet<>();

        System.out.println("[DEBUG] Call graph size: " + callGraph.size() + " entries");
        System.out.println("[DEBUG] usedDepClasses size: " + usedDepClasses.size());
        System.out.println("[DEBUG] targetJarClasses count: " + targetJarClasses.size());
        System.out.println("[DEBUG] dependencyClasses count: " + dependencyClasses.size());

        // Option 1: Use call graph edges (most accurate after DFS)
        int targetCallsFound = 0;
        int depCallsFound = 0;
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String caller = entry.getKey();
            // Extract class name from method signature
            // Format: <com.test.target.MainApp: void main(java.lang.String[])>
            int colonIdx = caller.indexOf(':');
            if (colonIdx > 0) {
                String callerClass = caller.substring(1, colonIdx).trim();

                if (targetJarClasses.contains(callerClass)) {
                    targetCallsFound++;
                    // This is a target class, check what it calls
                    for (String callee : entry.getValue()) {
                        int calleeColonIdx = callee.indexOf(':');
                        if (calleeColonIdx > 0) {
                            String calleeClass = callee.substring(1, calleeColonIdx).trim();
                            if (dependencyClasses.contains(calleeClass)) {
                                depClassesUsedByTarget.add(calleeClass);
                                depCallsFound++;
                            }
                        }
                    }
                }
            }
        }

        System.out.println("[DEBUG] Target methods in call graph: " + targetCallsFound);
        System.out.println("[DEBUG] Dep calls from target: " + depCallsFound);

        // Option 2: Also check usedDepClasses from DFS
        depClassesUsedByTarget.addAll(usedDepClasses);
        System.out.println("[DEBUG] Final depClassesUsedByTarget size: " + depClassesUsedByTarget.size());

        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            if (depClassesUsedByTarget.isEmpty()) {
                out.println("No dependency calls detected anywhere in target classes.");
                System.out.println("Deps-called-by-target (ALL) written to: " + new File(filename).getAbsolutePath());
                return;
            }

            Set<String> depJars = depClassesUsedByTarget.stream()
                    .map(cls -> classToJar.getOrDefault(cls, "(unknown-jar)"))
                    .filter(p -> !"(unknown-jar)".equals(p))
                    .collect(Collectors.toCollection(TreeSet::new));

            out.println("Dependency JARs referenced by TARGET code (across all classes/methods):");
            int i = 1;
            for (String jar : depJars) out.println("  " + (i++) + ". " + jar);

            out.println();
            out.println("Dependency classes hit by TARGET code (" + depClassesUsedByTarget.size() + "):");
            depClassesUsedByTarget.stream().sorted().forEach(c -> out.println("  - " + c));

            System.out.println("Deps-called-by-target (ALL) written to: " + new File(filename).getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    /**
     * Scans all classes in the codebase to find native methods (Mode 2)
     * 
     * FUNCTION NAME: scanAllNativeMethods
     * 
     * USAGE:
     *   Called internally when --2 mode is selected for comprehensive scanning
     * 
     * INPUT REQUIRED:
     *   - None (uses global view and class sets)
     * 
     * WHAT IT'S USED FOR:
     *   - Performs comprehensive scan of all classes in target, dependencies, and JRE
     *   - Identifies and categorizes native methods by source (target/deps/JRE)
     *   - Provides detailed statistics about native method distribution
     *   - Detects specific important native methods (Tomcat, JNI, Unsafe, etc.)
     *   - Updates global allUniqueNativeMethods set
     * 
     * PROCESS:
     *   1. Iterate through all classes in the Soot view
     *   2. Categorize classes as target, dependency, or JRE
     *   3. Scan each class for native methods
     *   4. Count and categorize native methods by source
     *   5. Display detailed statistics and important findings
     *   6. Update global native method collections
     */
    private static void scanAllNativeMethods() {
        int targetClassCount = 0;
        int dependencyClassCount = 0;
        int jreClassCount = 0;
        int targetNativeMethodCount = 0;
        int dependencyNativeMethodCount = 0;
        int jreNativeMethodCount = 0;

        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();

            if (targetJarClasses.contains(className)) {
                targetClassCount++;
                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                        allUniqueNativeMethods.add(method.getSignature());
                        targetNativeMethodCount++;
                        System.out.println("Found TARGET native method: " + method.getSignature());
                    }
                }
            } else if (dependencyClasses.contains(className)) {
                dependencyClassCount++;
                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                        allUniqueNativeMethods.add(method.getSignature());
                        dependencyNativeMethodCount++;
                        if (className.contains("tomcat") || className.contains("jni")) {
                            System.out.println("Found Tomcat/JNI native method: " + method.getSignature());
                        }
                    }
                }
            } else {
                jreClassCount++;
                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                        allUniqueNativeMethods.add(method.getSignature());
                        jreNativeMethodCount++;
                        if (className.startsWith("sun.misc.Unsafe") || 
                            className.startsWith("java.lang.Thread") ||
                            className.startsWith("java.lang.Class") ||
                            className.startsWith("java.util.zip.ZipFile") ||
                            className.startsWith("java.lang.ClassLoader")) {
                            System.out.println("Found JRE native method: " + method.getSignature());
                        }
                    }
                }
            }
        }

        System.out.println("Scanned " + (targetClassCount + dependencyClassCount + jreClassCount) + " total classes:");
        System.out.println("  - Target classes: " + targetClassCount);
        System.out.println("  - Dependency classes: " + dependencyClassCount);
        System.out.println("  - JRE classes: " + jreClassCount);
        System.out.println("Found " + allUniqueNativeMethods.size() + " total native methods:");
        System.out.println("  - Target JARs: " + targetNativeMethodCount);
        System.out.println("  - Dependencies: " + dependencyNativeMethodCount);
        System.out.println("  - JRE: " + jreNativeMethodCount);
        
        System.out.println("\nDEBUG: Tomcat class breakdown:");
        long tomcatInTarget = targetJarClasses.stream().filter(cls -> cls.contains("org.apache.tomcat")).count();
        long tomcatInDeps = dependencyClasses.stream().filter(cls -> cls.contains("org.apache.tomcat")).count();
        System.out.println("  - Tomcat classes in target: " + tomcatInTarget);
        System.out.println("  - Tomcat classes in deps: " + tomcatInDeps);
    }

    private static void scanTargetAndDependencyNatives() {
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className) || dependencyClasses.contains(className)) {
                for (JavaSootMethod m : clazz.getMethods()) {
                    if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                        allTargetDepNativeMethods.add(m.getSignature());
                    }
                }
            }
        }
    }

    private static void writeAllTargetDepSignatures(String filename, Set<MethodSignature> methods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            List<MethodSignature> sorted = methods.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .collect(Collectors.toList());

            writer.println("All native methods (target + dependencies) — full signatures:");
            for (int i = 0; i < sorted.size(); i++) {
                writer.println((i + 1) + ". " + sorted.get(i));
            }

            System.out.println("\nTarget+Deps native **signatures** written to: " + filename);
            System.out.println("Total signatures (no overload collapse): " + sorted.size());
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeDepsCalledByTarget(String filename, List<JavaSootMethod> entryMethods, boolean allTargetMode) {
        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            if (entryMethods.isEmpty()) {
                out.println("(No entry point methods found in target JARs.)");
                System.out.println("\nDeps-called-by-target written to: " + filename);
                return;
            }

            if (allTargetMode) {
                Set<String> allUsedDepClasses = new HashSet<>();
                
                for (JavaSootMethod method : entryMethods) {
                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();
                    usedDepClasses.clear();

                    List<MethodSignature> startPath = new ArrayList<>();
                    startPath.add(method.getSignature());
                    dfs(method.getSignature(), startPath);
                    
                    allUsedDepClasses.addAll(usedDepClasses);
                }

                Set<String> usedDepJars = allUsedDepClasses.stream()
                    .map(cls -> classToJar.getOrDefault(cls, "(unknown-jar)"))
                    .filter(p -> !"(unknown-jar)".equals(p))
                    .collect(Collectors.toCollection(TreeSet::new));

                out.println("=== All Target Methods (Mode 3) ===");
                out.println("Total entry points analyzed: " + entryMethods.size());
                if (usedDepJars.isEmpty()) {
                    out.println("No dependency calls detected (only target/JRE classes reached).");
                } else {
                    out.println("Dependency JARs actually called from target:");
                    int idx = 1;
                    for (String jar : usedDepJars) {
                        out.println("  " + (idx++) + ". " + jar);
                    }
                    out.println("\nTotal unique dependency classes used: " + allUsedDepClasses.size());
                }
            } else {
                for (int i = 0; i < entryMethods.size(); i++) {
                    JavaSootMethod main = entryMethods.get(i);

                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();
                    usedDepClasses.clear();

                    List<MethodSignature> startPath = new ArrayList<>();
                    startPath.add(main.getSignature());
                    dfs(main.getSignature(), startPath);

                    Set<String> usedDepJars = usedDepClasses.stream()
                        .map(cls -> classToJar.getOrDefault(cls, "(unknown-jar)"))
                        .filter(p -> !"(unknown-jar)".equals(p))
                        .collect(Collectors.toCollection(TreeSet::new));

                    out.println("=== Main Method " + (i + 1) + ": " + main.getSignature() + " ===");
                    if (usedDepJars.isEmpty()) {
                        out.println("No dependency calls detected (only target/JRE classes reached).");
                    } else {
                        out.println("Dependency JARs actually called from target:");
                        int idx = 1;
                        for (String jar : usedDepJars) {
                            out.println("  " + (idx++) + ". " + jar);
                        }
                    }
                    out.println();
                }
            }
            System.out.println("\nDeps-called-by-target written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeAllTargetDepFlat(String filename, Set<MethodSignature> methods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            Map<String, Long> byName = methods.stream()
                .collect(Collectors.groupingBy(
                    sig -> sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName(),
                    Collectors.counting()
                ));

            List<String> lines = byName.entrySet().stream()
                .map(e -> e.getKey() + (e.getValue() > 1 ? "  (+" + (e.getValue()-1) + " overloads)" : ""))
                .sorted()
                .collect(Collectors.toList());

            for (String line : lines) writer.println(line);

            System.out.println("\nTarget+Deps native methods (flat) written to: " + filename);
            System.out.println("Unique names (overloads collapsed): " + lines.size());
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
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
     * Determines if a method is a valid main method entry point
     * 
     * FUNCTION NAME: isMainMethod
     * 
     * USAGE:
     *   Called internally to identify main methods for analysis entry points
     * 
     * INPUT REQUIRED:
     *   - m: JavaSootMethod to check
     * 
     * WHAT IT'S USED FOR:
     *   - Validates if a method matches Java main method signature
     *   - Ensures proper entry point selection for analysis
     *   - Filters methods to only include valid main methods
     *   - Supports standard Java application entry point detection
     * 
     * VALIDATION CRITERIA:
     *   - Method name must be "main"
     *   - Must be public and static
     *   - Must have exactly one parameter of type String[]
     *   - Must return void
     */
    private static boolean isMainMethod(JavaSootMethod m) {
        return m.getName().equals("main")
                && m.getModifiers().contains(MethodModifier.PUBLIC)
                && m.getModifiers().contains(MethodModifier.STATIC)
                && m.getParameterTypes().size() == 1
                && m.getParameterTypes().get(0).toString().equals("java.lang.String[]")
                && m.getReturnType().toString().equals("void");
    }

    /**
     * Performs depth-first search to trace method calls and find native methods
     * 
     * FUNCTION NAME: dfs
     * 
     * USAGE:
     *   Called recursively to trace method call chains from entry points
     * 
     * INPUT REQUIRED:
     *   - sig: MethodSignature to analyze
     *   - currentPath: List representing current call path from entry point
     * 
     * WHAT IT'S USED FOR:
     *   - Traces method call chains using depth-first search algorithm
     *   - Identifies native methods reachable from entry points
     *   - Builds call paths showing how native methods are reached
     *   - Tracks dependency class usage
     *   - Handles method resolution including inheritance
     *   - Prevents infinite recursion with visited set
     * 
     * PROCESS:
     *   1. Check if method already visited (prevent cycles)
     *   2. Mark method as visited
     *   3. Track dependency class usage
     *   4. Resolve method (including inherited methods)
     *   5. Check if method is native (terminal condition)
     *   6. If not native, analyze method body for calls
     *   7. Recursively call dfs for each method call found
     */
    private static void dfs(MethodSignature sig, List<MethodSignature> currentPath) {
        if (visited.contains(sig)) return;
        visited.add(sig);

        String decl = sig.getDeclClassType().getFullyQualifiedName();

        // OPTIMIZATION: Package filtering for JRE classes
        // Only record JRE natives, don't explore their implementations
        if (decl.startsWith("java.") || decl.startsWith("javax.") ||
            decl.startsWith("jdk.") || decl.startsWith("sun.") ||
            decl.startsWith("com.sun.")) {

            // Check if it's a native method
            Optional<JavaSootMethod> jreOpt = view.getMethod(sig);
            if (jreOpt.isPresent() && jreOpt.get().getModifiers().contains(MethodModifier.NATIVE)) {
                foundNative.add(sig);
                nativePaths.add(new ArrayList<>(currentPath));
                System.out.println("  [NATIVE] Found: " + sig);
            }
            return; // Don't explore JRE method bodies (huge speedup)
        }

        if (dependencyClasses.contains(decl)) {
            usedDepClasses.add(decl);
        }

        // System.out.println("  [DEBUG] Analyzing: " + sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);

        if (!opt.isPresent()) {
            opt = findInheritedMethod(sig);
        }

        if (!opt.isPresent()) {
            // System.out.println("  [WARN] Method not found: " + sig);
            return;
        }

        JavaSootMethod m = opt.get();

        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
            foundNative.add(sig);
            nativePaths.add(new ArrayList<>(currentPath));
            System.out.println("  [NATIVE] Found: " + sig);
            // System.out.println("  [NATIVE] Path: " + buildPathString(currentPath));
            return;
        }

        try {
            if (!m.hasBody()) {
                // System.out.println("  [DEBUG] No body: " + sig);
                return;
            }

            Body body = m.getBody();
            if (body == null) {
                // System.out.println("  [DEBUG] Body is null: " + sig);
                return;
            }

            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        MethodSignature callee = invokeExpr.getMethodSignature();
                        // System.out.println("  [DEBUG] Found call: " + callee);

                        // Record call graph edge: sig -> callee
                        String caller = sig.toString();
                        String calleeStr = callee.toString();
                        callGraph.computeIfAbsent(caller, k -> new HashSet<>()).add(calleeStr);

                        List<MethodSignature> newPath = new ArrayList<>(currentPath);
                        newPath.add(callee);
                        dfs(callee, newPath);
                    });
                }
            }
        } catch (Throwable t) {
            System.err.println("  [WARN] Could not analyze " + sig + ": " + t.getMessage());
        }
    }

    /**
     * Finds inherited methods when direct method resolution fails
     * 
     * FUNCTION NAME: findInheritedMethod
     * 
     * USAGE:
     *   Called internally when direct method lookup fails in dfs
     * 
     * INPUT REQUIRED:
     *   - sig: MethodSignature to search for
     * 
     * WHAT IT'S USED FOR:
     *   - Handles method resolution across inheritance hierarchies
     *   - Searches for methods in superclasses when not found in declared class
     *   - Supports polymorphic method calls and inheritance
     *   - Ensures complete method call tracing
     * 
     * PROCESS:
     *   1. Extract class name and method name from signature
     *   2. Call recursive search through inheritance chain
     *   3. Return first matching method found
     */
    private static Optional<JavaSootMethod> findInheritedMethod(MethodSignature sig) {
        String className = sig.getDeclClassType().getFullyQualifiedName();
        String methodName = sig.getName();

        // System.out.println("  [DEBUG] Looking for inherited method: " + methodName + " from class: " + className);
        return findInheritedMethodRecursive(className, methodName);
    }

    /**
     * Recursively searches inheritance chain for method
     *
     * FUNCTION NAME: findInheritedMethodRecursive
     *
     * USAGE:
     *   Called internally by findInheritedMethod for recursive search
     *
     * INPUT REQUIRED:
     *   - className: Class name to search in
     *   - methodName: Method name to find
     *
     * WHAT IT'S USED FOR:
     *   - Performs recursive search through class hierarchy
     *   - Searches current class for method
     *   - If not found, searches superclass recursively
     *   - Handles single inheritance chains
     *   - Provides detailed debug logging
     *
     * PROCESS:
     *   1. Find class in Soot view
     *   2. Search for method in current class
     *   3. If found, return method
     *   4. If not found and has superclass, search superclass
     *   5. Continue until found or no more superclasses
     */
    private static Optional<JavaSootMethod> findInheritedMethodRecursive(String className, String methodName) {
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            if (clazz.getType().getFullyQualifiedName().equals(className)) {
                // System.out.println("  [DEBUG] Searching in class: " + className);

                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        // System.out.println("  [DEBUG] Found method: " + method.getSignature());
                        return Optional.of(method);
                    }
                }

                if (clazz.hasSuperclass()) {
                    String superClassName = clazz.getSuperclass().get().getFullyQualifiedName();
                    // System.out.println("  [DEBUG] Method not found in " + className + ", checking superclass: " + superClassName);
                    return findInheritedMethodRecursive(superClassName, methodName);
                } else {
                    // System.out.println("  [DEBUG] Class " + className + " has no superclass, method not found");
                }
                break;
            }
        }
        return Optional.empty();
    }

    /**
     * Builds human-readable string representation of method call path
     * 
     * FUNCTION NAME: buildPathString
     * 
     * USAGE:
     *   Called internally to format call paths for output
     * 
     * INPUT REQUIRED:
     *   - path: List of MethodSignature representing call chain
     * 
     * WHAT IT'S USED FOR:
     *   - Converts method call path to readable string format
     *   - Creates arrow-separated chain showing method calls
     *   - Used in output files and console logging
     *   - Provides clear visualization of call chains
     * 
     * PROCESS:
     *   1. Iterate through method signatures in path
     *   2. Join with " -> " separator
     *   3. Return formatted string
     */
    private static String buildPathString(List<MethodSignature> path) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append(path.get(i));
        }
        return sb.toString();
    }

    private static void writeUniqueNativeMethodsToFile(String filename, Set<MethodSignature> nativeMethods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Unique native methods found:");
            int count = 1;
            for (MethodSignature sig : nativeMethods) {
                writer.println(count + ". " + sig);
                count++;
            }
            System.out.println("[INFO] Unique native methods written to " + filename);
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write unique native methods: " + e.getMessage());
        }
    }

    private static void writeCallGraph(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("{");
            writer.println("  \"nodes\": [");

            // Collect all unique nodes (methods)
            Set<String> allNodes = new HashSet<>();
            allNodes.addAll(callGraph.keySet());
            for (Set<String> callees : callGraph.values()) {
                allNodes.addAll(callees);
            }

            List<String> nodeList = new ArrayList<>(allNodes);
            for (int i = 0; i < nodeList.size(); i++) {
                String node = nodeList.get(i);
                String escapedNode = node.replace("\"", "\\\"").replace("\\", "\\\\");
                writer.print("    {\"id\": \"" + escapedNode + "\"}");
                if (i < nodeList.size() - 1) writer.println(",");
                else writer.println();
            }

            writer.println("  ],");
            writer.println("  \"edges\": [");

            // Write edges
            List<String> edges = new ArrayList<>();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"").replace("\\", "\\\\");
                for (String callee : entry.getValue()) {
                    String calleeEscaped = callee.replace("\"", "\\\"").replace("\\", "\\\\");
                    edges.add("{\"from\": \"" + caller + "\", \"to\": \"" + calleeEscaped + "\"}");
                }
            }

            for (int i = 0; i < edges.size(); i++) {
                writer.print("    " + edges.get(i));
                if (i < edges.size() - 1) writer.println(",");
                else writer.println();
            }

            writer.println("  ]");
            writer.println("}");

            System.out.println("\n[INFO] Call graph written to: " + filename);
            System.out.println("  Total nodes (methods): " + allNodes.size());
            System.out.println("  Total edges (calls): " + edges.size());
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write call graph: " + e.getMessage());
        }
    }

    private static void writeNativeMethodsByPackage(String filename, Set<MethodSignature> nativeMethods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Native methods organized by package:");
            writer.println("Total native methods found: " + nativeMethods.size());
            writer.println();

            Map<String, List<MethodSignature>> methodsByPackage = new TreeMap<>();
            for (MethodSignature sig : nativeMethods) {
                String className = sig.getDeclClassType().getFullyQualifiedName();
                String packageName = className.contains(".")
                        ? className.substring(0, className.lastIndexOf('.'))
                        : "(default package)";
                methodsByPackage.computeIfAbsent(packageName, k -> new ArrayList<>()).add(sig);
            }

            for (Map.Entry<String, List<MethodSignature>> entry : methodsByPackage.entrySet()) {
                String packageName = entry.getKey();
                List<MethodSignature> methods = entry.getValue();

                writer.println("=== Package: " + packageName + " ===");
                writer.println("Methods: " + methods.size());
                for (int i = 0; i < methods.size(); i++) {
                    writer.println((i + 1) + ". " + methods.get(i));
                }
                writer.println();
            }

            System.out.println("[INFO] Native methods by package written to " + filename);
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write native methods by package: " + e.getMessage());
        }
    }

    private static void writeMainCalledNativeMethods(String filename, List<JavaSootMethod> entryMethods, boolean allTargetMode) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            if (allTargetMode) {
                writer.println("Native methods called by all target methods (Mode 3):\n");
            } else {
                writer.println("Native methods called by main methods (with call paths):\n");
            }

            if (entryMethods.isEmpty()) {
                writer.println("(No entry point methods found in target JARs.)");
                System.out.println("\nResults written to: " + filename);
                return;
            }

            if (allTargetMode) {
                Set<MethodSignature> allNativesFound = new HashSet<>();
                int pathCount = 0;
                
                for (JavaSootMethod method : entryMethods) {
                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();

                    List<MethodSignature> startPath = new ArrayList<>();
                    startPath.add(method.getSignature());
                    dfs(method.getSignature(), startPath);

                    allNativesFound.addAll(foundNative);
                    pathCount += nativePaths.size();
                }

                writer.println("Total entry points analyzed: " + entryMethods.size());
                writer.println("Total unique native methods found: " + allNativesFound.size());
                writer.println("Total paths found: " + pathCount);
                writer.println("\nUnique native methods:");
                int idx = 1;
                for (MethodSignature sig : allNativesFound) {
                    writer.println((idx++) + ". " + sig);
                }
                writer.println("\n[Note: Individual paths not shown in Mode 3 due to volume]");
            } else {
                for (int i = 0; i < entryMethods.size(); i++) {
                    JavaSootMethod main = entryMethods.get(i);
                    writer.println("=== Main Method " + (i + 1) + ": " + main.getSignature() + " ===");

                    visited.clear();
                    nativePaths.clear();
                    foundNative.clear();

                    List<MethodSignature> startPath = new ArrayList<>();
                    startPath.add(main.getSignature());
                    dfs(main.getSignature(), startPath);

                    if (foundNative.isEmpty()) {
                        writer.println("No native methods found for this main method.");
                    } else {
                        writer.println("Found " + nativePaths.size() + " paths to " + foundNative.size() + " native methods:");
                        for (int j = 0; j < nativePaths.size(); j++) {
                            writer.println("Path " + (j + 1) + ": " + buildPathString(nativePaths.get(j)));
                        }
                    }
                    writer.println();
                }
            }
            System.out.println("\nResults written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
        }
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
