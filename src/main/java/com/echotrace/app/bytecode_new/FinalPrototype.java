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

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.stream.Collectors;
import java.util.Comparator;

/**
 * Final Prototype: Unified Native Method Tracer
 *
 * This tool combines multiple analysis approaches for discovering native methods
 * in Java applications and their dependencies.
 *
 * Modes:
 *   --1 (default): Trace from main methods only; emit paths to reachable native methods.
 *   --2: Scan all classes to list every native method in target+deps, and separately
 *        identify JRE natives reachable from main.
 *   --3: Use ALL methods in target JARs as entry points (not just main) and trace.
 *   --4: Do NOT DFS; scan target+deps for native methods, categorize and write reports.
 *   --5: HybridByteCodeTracer - Uses ASM to trace native methods with bytecode analysis.
 *
 * Inputs:
 *   - target-directory: directory with application JARs
 *   - dependencies-directory: directory with dependency JARs (not used in mode 5)
 *   - mode: --1, --2, --3, --4, or --5
 *
 * Outputs (depending on mode):
 *   Modes 1-4: Various analysis reports (see detailed comments in methods)
 *   Mode 5: elasticsearch_hybrid.txt with traced native methods
 */
public class FinalPrototype {
    // ============================================
    // SootUp-based analysis fields (modes 1-4)
    // ============================================
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

    // ============================================
    // ASM-based analysis fields (mode 5)
    // ============================================
    public static String nativeFile = "/home/rupesh.punna/Prototype/elasticsearch_hybrid.txt";
    public static String pathPrefix = "/home/rupesh.punna/Prototype/JARFILES/";

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java FinalPrototype <target-directory> <dependencies-directory> [--1|--2|--3|--4|--5]");
            System.err.println("  --1: Only include native methods called by main methods (with paths)");
            System.err.println("  --2: Include all native methods present in target+deps JARs + JRE natives from main");
            System.err.println("  --3: Use all target methods as entry points (not just main)");
            System.err.println("  --4: Scan ALL native methods in JAR files (no DFS, no filtering)");
            System.err.println("  --5: HybridByteCodeTracer - ASM-based bytecode analysis");
            return;
        }

        String targetDir = args[0];
        String depsDir = args[1];

        // Parse mode argument
        String mode = "--1"; // default
        if (args.length >= 3) {
            mode = args[2];
        }

        // Mode 5: HybridByteCodeTracer
        if ("--5".equals(mode)) {
            System.out.println("=== Mode 5: HybridByteCodeTracer (ASM-based analysis) ===");
            runHybridByteCodeTracer(targetDir);
            return;
        }

        // Modes 1-4: SootUp-based analysis
        runSootUpAnalysis(targetDir, depsDir, mode);
    }

    // ============================================
    // Mode 5: HybridByteCodeTracer Implementation
    // ============================================
    private static void runHybridByteCodeTracer(String targetDir) {
        pathPrefix = targetDir;
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

        for (String jarPath : jarPathResult) {
            jarPath = pathPrefix + jarPath;
            File file = new File(jarPath);
            if (!file.exists() || !file.isFile()) {
                System.out.println("JAR file not found: " + jarPath);
                continue;
            }
            try {
                classPathResult.addAll(findJarClass.findClass(jarPath));
                nativeMethodResult.addAll(findNativeMethods.findNativeMethods(jarPath));
            } catch (IOException e) {
                System.err.println("Error processing JAR " + jarPath + ": " + e.getMessage());
            }
        }

        System.out.println("DEBUG: classpath: " + classPathResult);
        System.out.println("Total classes: " + classPathResult.size());
        System.out.println("There are " + classPathResult.size() + " classes over all\n");

        System.out.println("Now we start to analyze called native methods!");
        Util.println();
        traceJarFiles(jarPathResult);
        prettyPrint();
        writeToFile();

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("Total execution time: " + totalTimeInSeconds + " seconds");
    }

    private static void traceJarFiles(List<String> jarPaths) {
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

    private static void writeToFile() {
        try {
            String content = "";
            for (String m : Util.visitedNative) {
                content += m + "\n";
            }
            File file = new File(nativeFile);
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content);
            fw.close();
            System.out.println("Native methods written to: " + nativeFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void prettyPrint() {
        Util.println();
        System.out.println("Count of visited methods: " + Util.visitedMethod.size() +
                "\n\nCount of called native methods: " + Util.visitedNative.size() +
                "\n\nWe write all of them into a .txt file for binary analyse");
        Util.println();
    }

    // ============================================
    // Modes 1-4: SootUp-based Analysis
    // ============================================
    private static void runSootUpAnalysis(String targetDir, String depsDir, String mode) {
        boolean onlyMainCalled = false;
        boolean includeAllNative = false;
        boolean allTargetMethods = false;
        boolean scanAllNativesOnly = false;

        switch (mode) {
            case "--1":
                onlyMainCalled = true;
                System.out.println("Mode: Only native methods called by main methods");
                break;
            case "--2":
                includeAllNative = true;
                System.out.println("Mode: All native methods in target+deps JARs + JRE natives from main");
                break;
            case "--3":
                allTargetMethods = true;
                System.out.println("Mode: All methods in target JARs as entry points");
                break;
            case "--4":
                scanAllNativesOnly = true;
                System.out.println("Mode: Scan ALL native methods in JAR files (no DFS)");
                break;
            default:
                System.err.println("Invalid mode. Use --1, --2, --3, --4, or --5");
                return;
        }

        System.out.println("=== Native Method Tracer with Paths ===");
        System.out.println("Analyzing target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);

        // Load JARs from target and dependencies
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        view = new JavaView(inputs);

        System.out.println("Target JARs contain " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // Mode 4: Just scan all natives and exit
        if (scanAllNativesOnly) {
            System.out.println("\n=== Mode 4: Scanning All Native Methods (No DFS) ===");
            scanAllNativesMode4();
            return;
        }

        // Find entry point methods
        List<JavaSootMethod> entryPointMethods = new ArrayList<>();
        int totalTargetMethods = 0;

        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    totalTargetMethods++;

                    if (allTargetMethods) {
                        entryPointMethods.add(method);
                    } else if (isMainMethod(method)) {
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
            writeUniqueNativeMethodsToFile("native_methods.txt", allUniqueNativeMethods);
            writeMainCalledNativeMethods("native_methods_with_paths.txt", entryPointMethods, allTargetMethods);
            writeDepsCalledByTarget("deps_called_by_target.txt", entryPointMethods, allTargetMethods);
            return;
        }

        // DFS from each entry point
        if (onlyMainCalled || allTargetMethods) {
            int processedCount = 0;
            for (JavaSootMethod entryPoint : entryPointMethods) {
                visited.clear();
                nativePaths.clear();
                foundNative.clear();

                processedCount++;
                if (processedCount % 10 == 0 || processedCount == 1) {
                    System.out.println("Processing entry point " + processedCount + "/" + entryPointMethods.size());
                }

                dfs(entryPoint.getSignature(), new ArrayList<>(), 0, 10);
            }

            System.out.println("\nTracing completed!");
            System.out.println("Total unique native methods found: " + allUniqueNativeMethods.size());

            writeUniqueNativeMethodsToFile("native_methods.txt", allUniqueNativeMethods);
            writeMainCalledNativeMethods("native_methods_with_paths.txt", entryPointMethods, allTargetMethods);
            writeDepsCalledByTarget("deps_called_by_target.txt", entryPointMethods, allTargetMethods);
        }

        // Mode 2: Also include all native methods in target+deps
        if (includeAllNative) {
            System.out.println("\n=== Mode 2: Including All Native Methods ===");
            scanAllNativeMethods();
            writeAllTargetDepNativeMethodsToFile("all_target_dep_natives.txt");
            writeAllTargetDepNativeSignatures("all_target_dep_natives_signatures.txt");

            System.out.println("\nTracing JRE native methods called from main methods...");
            Set<MethodSignature> jreNatives = new HashSet<>();
            for (JavaSootMethod entryPoint : entryPointMethods) {
                visited.clear();
                traceJreNatives(entryPoint.getSignature(), jreNatives, 0, 10);
            }
            System.out.println("Total JRE native methods found: " + jreNatives.size());
            writeJreNativeMethodsToFile("jre_used_natives.txt", jreNatives);
            writeJreNativeSignatures("jre_used_natives_signatures.txt", jreNatives);
        }
    }

    // ============================================
    // Helper Methods for Modes 1-4
    // ============================================
    private static List<String> loadJarsFromDirectory(String dirPath, Set<String> classSet,
                                                       Map<String, String> jarMap, String label) {
        List<String> jarPaths = new ArrayList<>();
        File dir = new File(dirPath);

        if (!dir.exists() || !dir.isDirectory()) {
            System.out.println("Directory not found: " + dirPath);
            return jarPaths;
        }

        File[] jarFiles = dir.listFiles((d, name) -> name.endsWith(".jar"));
        if (jarFiles != null) {
            for (File jarFile : jarFiles) {
                String jarPath = jarFile.getAbsolutePath();
                jarPaths.add(jarPath);
                System.out.println("Loading " + label + " JAR: " + jarFile.getName());

                try (JarFile jf = new JarFile(jarPath)) {
                    Enumeration<JarEntry> entries = jf.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        if (entry.getName().endsWith(".class")) {
                            String className = entry.getName()
                                    .replace(".class", "")
                                    .replace("/", ".");
                            classSet.add(className);
                            jarMap.put(className, jarPath);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Error reading JAR " + jarPath + ": " + e.getMessage());
                }
            }
        }

        return jarPaths;
    }

    private static boolean isMainMethod(JavaSootMethod method) {
        if (!method.getName().equals("main")) return false;
        if (!method.getModifiers().contains(MethodModifier.STATIC)) return false;
        if (!method.getModifiers().contains(MethodModifier.PUBLIC)) return false;

        String sig = method.getSignature().toString();
        return sig.contains("java.lang.String[]") && sig.contains("void");
    }

    private static void dfs(MethodSignature sig, List<MethodSignature> path, int depth, int maxDepth) {
        if (depth > maxDepth || visited.contains(sig)) return;
        visited.add(sig);

        path.add(sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) {
            path.remove(path.size() - 1);
            return;
        }

        JavaSootMethod method = opt.get();
        String className = sig.getDeclClassType().getFullyQualifiedName();

        if (dependencyClasses.contains(className)) {
            usedDepClasses.add(className);
        }

        if (method.getModifiers().contains(MethodModifier.NATIVE)) {
            if (!foundNative.contains(sig)) {
                foundNative.add(sig);
                allUniqueNativeMethods.add(sig);
                List<MethodSignature> pathCopy = new ArrayList<>(path);
                nativePaths.add(pathCopy);
            }
            path.remove(path.size() - 1);
            return;
        }

        try {
            if (!method.hasBody()) {
                path.remove(path.size() - 1);
                return;
            }

            Body body = method.getBody();
            if (body == null) {
                path.remove(path.size() - 1);
                return;
            }

            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        dfs(invokeExpr.getMethodSignature(), path, depth + 1, maxDepth);
                    });
                }
            }
        } catch (Throwable t) {
            // Skip methods that cause errors
        }

        path.remove(path.size() - 1);
    }

    private static void scanAllNativeMethods() {
        System.out.println("Scanning all classes for native methods...");

        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className) || dependencyClasses.contains(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                        allTargetDepNativeMethods.add(method.getSignature());
                    }
                }
            }
        }

        System.out.println("Total native methods in target+deps: " + allTargetDepNativeMethods.size());
    }

    private static void scanAllNativesMode4() {
        System.out.println("\n=== Mode 4: SootUp-based Deep Tracing (like Mode 5) ===");

        // Collect all methods from target JARs as entry points
        List<JavaSootMethod> allTargetMethods = new ArrayList<>();
        int totalTargetMethods = 0;

        System.out.println("Collecting all methods from target JARs as entry points...");
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    allTargetMethods.add(method);
                    totalTargetMethods++;
                }
            }
        }

        System.out.println("Total target methods to trace from: " + totalTargetMethods);
        System.out.println("Starting deep tracing to find all reachable native methods...");

        // Use a global visited set to avoid re-tracing methods
        Set<MethodSignature> globalVisited = new HashSet<>();
        Set<MethodSignature> reachableNatives = new HashSet<>();

        int processedCount = 0;
        int lastReportedPercent = 0;

        for (JavaSootMethod entryPoint : allTargetMethods) {
            processedCount++;

            // Report progress every 5%
            int currentPercent = (processedCount * 100) / totalTargetMethods;
            if (currentPercent >= lastReportedPercent + 5 || processedCount == 1) {
                System.out.println("Progress: " + processedCount + "/" + totalTargetMethods +
                                 " (" + currentPercent + "%) - Found " + reachableNatives.size() + " native methods so far");
                lastReportedPercent = currentPercent;
            }

            // DFS from this entry point
            traceNativesMode4(entryPoint.getSignature(), globalVisited, reachableNatives, 0, 15);
        }

        System.out.println("\n=== Mode 4 Tracing Complete ===");
        System.out.println("Total reachable native methods found: " + reachableNatives.size());

        // Categorize the reachable natives
        Map<String, List<MethodSignature>> nativesByCategory = new HashMap<>();
        Map<String, List<MethodSignature>> nativesByPackage = new HashMap<>();
        Map<String, List<MethodSignature>> nativesByJar = new HashMap<>();

        nativesByCategory.put("Target", new ArrayList<>());
        nativesByCategory.put("Dependencies", new ArrayList<>());
        nativesByCategory.put("JRE", new ArrayList<>());

        for (MethodSignature sig : reachableNatives) {
            String className = sig.getDeclClassType().getFullyQualifiedName();

            // Categorize
            if (targetJarClasses.contains(className)) {
                nativesByCategory.get("Target").add(sig);
            } else if (dependencyClasses.contains(className)) {
                nativesByCategory.get("Dependencies").add(sig);
            } else {
                nativesByCategory.get("JRE").add(sig);
            }

            // By package
            String packageName = className.contains(".")
                    ? className.substring(0, className.lastIndexOf("."))
                    : "(default)";
            nativesByPackage.computeIfAbsent(packageName, k -> new ArrayList<>()).add(sig);

            // By JAR
            String jarPath = classToJar.getOrDefault(className, "JRE/Unknown");
            nativesByJar.computeIfAbsent(jarPath, k -> new ArrayList<>()).add(sig);
        }

        System.out.println("\n=== Mode 4 Summary ===");
        System.out.println("Total reachable native methods: " + reachableNatives.size());
        System.out.println("  Target: " + nativesByCategory.get("Target").size());
        System.out.println("  Dependencies: " + nativesByCategory.get("Dependencies").size());
        System.out.println("  JRE: " + nativesByCategory.get("JRE").size());
        System.out.println("  Unique packages: " + nativesByPackage.size());
        System.out.println("  Unique JARs: " + nativesByJar.size());

        // Write reports
        writeMode4ByCategory("mode4_by_category.txt", nativesByCategory);
        writeMode4ByPackage("mode4_by_package.txt", nativesByPackage);
        writeMode4ByJar("mode4_by_jar.txt", nativesByJar);
        writeMode4FlatList("mode4_flat_list.txt", reachableNatives);
        writeAllTargetDepNativeSignatures("mode4_all_signatures.txt", reachableNatives);
        writeMode4SimpleList("mode4_sootup_hybrid.txt", reachableNatives);
    }

    /**
     * Traces method calls to find reachable native methods (Mode 4 tracing)
     * This mimics Mode 5's behavior but uses SootUp instead of ASM
     */
    private static void traceNativesMode4(MethodSignature sig, Set<MethodSignature> globalVisited,
                                          Set<MethodSignature> reachableNatives, int depth, int maxDepth) {
        if (depth > maxDepth || globalVisited.contains(sig)) {
            return;
        }
        globalVisited.add(sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) {
            return;
        }

        JavaSootMethod method = opt.get();

        // If this is a native method, add it to the results
        if (method.getModifiers().contains(MethodModifier.NATIVE)) {
            reachableNatives.add(sig);
            return; // Don't trace further from native methods
        }

        // Try to get method body and trace calls
        try {
            if (!method.hasBody()) {
                return;
            }

            Body body = method.getBody();
            if (body == null) {
                return;
            }

            // Trace all method invocations
            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        traceNativesMode4(invokeExpr.getMethodSignature(), globalVisited,
                                        reachableNatives, depth + 1, maxDepth);
                    });
                }
            }
        } catch (Throwable t) {
            // Skip methods that cause errors
        }
    }

    // ============================================
    // File Writing Methods for Modes 1-4
    // ============================================
    private static void writeUniqueNativeMethodsToFile(String filename, Set<MethodSignature> methods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Unique Native Methods Called:");
            writer.println(repeat("=", 80));
            methods.stream()
                    .map(FinalPrototype::formatSimpleSignature)
                    .sorted()
                    .forEach(writer::println);
            System.out.println("Unique native methods written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    // Returns a concise class.method: format (no return type/params)
    private static String formatSimpleSignature(MethodSignature sig) {
        return sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName() + ":";
    }

    private static void writeMainCalledNativeMethods(String filename, List<JavaSootMethod> entryPoints,
                                                      boolean allTargetMethods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            String mode = allTargetMethods ? "all target methods" : "main methods";
            writer.println("Native Methods Called from " + mode + ":");
            writer.println(repeat("=", 80));
            writer.println("Total unique native methods: " + allUniqueNativeMethods.size());
            writer.println();

            for (MethodSignature nativeSig : allUniqueNativeMethods) {
                writer.println("\nNative Method: " + nativeSig);
                writer.println(repeat("-", 80));
            }

            System.out.println("Native methods with paths written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeDepsCalledByTarget(String filename, List<JavaSootMethod> entryPoints,
                                                 boolean allTargetMethods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            String mode = allTargetMethods ? "all target methods" : "main methods";
            writer.println("Dependency Classes Called from " + mode + ":");
            writer.println(repeat("=", 80));
            writer.println("Total dependency classes used: " + usedDepClasses.size());
            writer.println();

            Map<String, List<String>> jarToClasses = new HashMap<>();
            for (String className : usedDepClasses) {
                String jarPath = classToJar.get(className);
                if (jarPath != null) {
                    String jarName = jarPath.contains("/")
                            ? jarPath.substring(jarPath.lastIndexOf('/') + 1)
                            : jarPath;
                    jarToClasses.computeIfAbsent(jarName, k -> new ArrayList<>()).add(className);
                }
            }

            for (Map.Entry<String, List<String>> entry : jarToClasses.entrySet()) {
                writer.println("\nJAR: " + entry.getKey());
                writer.println("Classes used: " + entry.getValue().size());
                entry.getValue().stream().sorted().forEach(c -> writer.println("  " + c));
            }

            System.out.println("Dependency usage written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeAllTargetDepNativeMethodsToFile(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("All Native Methods in Target+Dependencies:");
            writer.println(repeat("=", 80));
            allTargetDepNativeMethods.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .forEach(writer::println);
            System.out.println("All target+dep natives written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeAllTargetDepNativeSignatures(String filename) {
        writeAllTargetDepNativeSignatures(filename, allTargetDepNativeMethods);
    }

    private static void writeAllTargetDepNativeSignatures(String filename, Set<MethodSignature> methods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Native Method Signatures (Full Details):");
            writer.println(repeat("=", 80));

            for (MethodSignature sig : methods.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .collect(Collectors.toList())) {

                writer.println("\nMethod: " + sig.getName());
                writer.println("Class: " + sig.getDeclClassType().getFullyQualifiedName());
                writer.println("Full Signature: " + sig);
                writer.println(repeat("-", 40));
            }

            System.out.println("Native signatures written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeJreNativeMethodsToFile(String filename, Set<MethodSignature> jreNatives) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("JRE Native Methods Used:");
            writer.println(repeat("=", 80));
            jreNatives.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .forEach(writer::println);
            System.out.println("JRE natives written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeJreNativeSignatures(String filename, Set<MethodSignature> jreNatives) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("JRE Native Method Signatures:");
            writer.println(repeat("=", 80));

            for (MethodSignature sig : jreNatives.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .collect(Collectors.toList())) {

                writer.println("\nMethod: " + sig.getName());
                writer.println("Class: " + sig.getDeclClassType().getFullyQualifiedName());
                writer.println("Full Signature: " + sig);
                writer.println(repeat("-", 40));
            }

            System.out.println("JRE native signatures written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeMode4ByCategory(String filename, Map<String, List<MethodSignature>> byCategory) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Native methods organized by category");
            writer.println(repeat("=", 80));
            writer.println();

            for (Map.Entry<String, List<MethodSignature>> entry : byCategory.entrySet()) {
                String category = entry.getKey();
                List<MethodSignature> methods = entry.getValue();

                writer.println("Category: " + category + " (" + methods.size() + " natives)");
                methods.stream()
                        .sorted(Comparator.comparing(MethodSignature::toString))
                        .forEach(sig -> writer.println("  - " + sig));
                writer.println();
            }

            System.out.println("Natives by category written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeMode4ByPackage(String filename, Map<String, List<MethodSignature>> byPackage) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Native methods organized by package");
            writer.println("Total packages: " + byPackage.size());
            writer.println(repeat("=", 80));
            writer.println();

            for (Map.Entry<String, List<MethodSignature>> entry : byPackage.entrySet()) {
                String packageName = entry.getKey();
                List<MethodSignature> methods = entry.getValue();

                writer.println("Package: " + packageName + " (" + methods.size() + " natives)");
                methods.stream()
                        .sorted(Comparator.comparing(MethodSignature::toString))
                        .forEach(sig -> writer.println("  - " + sig));
                writer.println();
            }

            System.out.println("Natives by package written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeMode4ByJar(String filename, Map<String, List<MethodSignature>> byJar) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Native methods organized by JAR file");
            writer.println("Total JARs with natives: " + byJar.size());
            writer.println(repeat("=", 80));
            writer.println();

            byJar.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        String jarPath = entry.getKey();
                        List<MethodSignature> methods = entry.getValue();

                        String jarName = jarPath.contains("/")
                                ? jarPath.substring(jarPath.lastIndexOf('/') + 1)
                                : jarPath;

                        writer.println("JAR: " + jarName);
                        writer.println("Path: " + jarPath);
                        writer.println("Natives: " + methods.size());
                        methods.stream()
                                .sorted(Comparator.comparing(MethodSignature::toString))
                                .forEach(sig -> writer.println("  - " + sig));
                        writer.println();
                    });

            System.out.println("Natives by JAR written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeMode4FlatList(String filename, Set<MethodSignature> natives) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Flat list of native method names (overloads collapsed)");
            writer.println(repeat("=", 80));

            Map<String, Long> byName = natives.stream()
                    .collect(Collectors.groupingBy(
                            sig -> sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName(),
                            Collectors.counting()
                    ));

            writer.println("Total unique method names: " + byName.size());
            writer.println("Total signatures (with overloads): " + natives.size());
            writer.println();

            byName.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        String name = entry.getKey();
                        long count = entry.getValue();
                        if (count > 1) {
                            writer.println(name + "  (+" + (count - 1) + " overloads)");
                        } else {
                            writer.println(name);
                        }
                    });

            System.out.println("Flat list written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static void writeMode4SimpleList(String filename, Set<MethodSignature> natives) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            // Simple list format like Mode 5, just class.method names
            List<String> nativeNames = natives.stream()
                    .map(sig -> sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName())
                    .sorted()
                    .collect(Collectors.toList());

            for (String name : nativeNames) {
                writer.println(name);
            }

            System.out.println("Simple native method list written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static String repeat(String str, int count) {
        return new String(new char[count]).replace("\0", str);
    }

    private static void traceJreNatives(MethodSignature sig, Set<MethodSignature> jreNatives, int depth, int maxDepth) {
        if (depth > maxDepth || visited.contains(sig)) return;
        visited.add(sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) return;

        JavaSootMethod m = opt.get();

        String className = sig.getDeclClassType().getFullyQualifiedName();
        if (!targetJarClasses.contains(className) && !dependencyClasses.contains(className)) {
            if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                jreNatives.add(sig);
                return;
            }
        }

        try {
            if (!m.hasBody()) return;
            Body body = m.getBody();

            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        traceJreNatives(invokeExpr.getMethodSignature(), jreNatives, depth + 1, maxDepth);
                    });
                }
            }
        } catch (IncompatibleClassChangeError | VerifyError | Exception e) {
            // Skip methods that cause errors
        }
    }

    // ============================================
    // ASM Helper Classes for Mode 5
    // ============================================
    static class Util {
        public static Set<String> visitedMethod = new HashSet<>();
        public static Set<String> visitedNative = new HashSet<>();

        public static void println() {
            System.out.println("--------------------------------");
        }

        public static byte[] getClassBytesFromFile(String classFilePath) throws IOException {
            try (InputStream inputStream = new FileInputStream(classFilePath);
                 ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {

                byte[] data = new byte[1024];
                int nRead;
                while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                return buffer.toByteArray();
            }
        }
    }

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
            if (!this.identifier.equals(name + descriptor)) {
                return null;
            }
            if ((access & 256) > 0) {
                // System.out.println("[ * Find a native method * ] " + className + '.' + name);
                Util.visitedNative.add(className + '.' + name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    static class ClassPrinter extends ClassVisitor {
        private String className;

        public ClassPrinter() {
            super(Opcodes.ASM9);
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
            System.out.println("[ Printer pure visit.. ] " + name + " " + signature);
        }

        public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
            return null;
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' + name);
                Util.visitedNative.add(className + '.' + name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    static class MethodPrinter extends MethodVisitor {
        public MethodPrinter() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String className = owner.replace('/', '.');
            if (Util.visitedMethod.contains(className + name + descriptor)) {
                return;
            }

            Util.visitedMethod.add(className + name + descriptor);
            try {
                ClassReader cr = new ClassReader(className);
                ClassFilter cf = new ClassFilter(name + descriptor);
                cr.accept(cf, 0);
            } catch (IOException e) {
                // Skip classes that can't be loaded
            }

            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }

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
                            .replace("/", ".") + "." + name + "---" + descriptor;
                    nativeMethods.add(jniFunction);
                }
                return null;
            }
        }
    }
}
