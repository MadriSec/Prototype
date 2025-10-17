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
import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.stream.Collectors;
import java.util.Comparator;

/**
 * Native method tracer that discovers native methods and (optionally) full call paths
 * from application entry points.
 *
 * Modes (3rd arg):
 *   --1 (default):
 *       Trace from main methods only; emit paths to reachable native methods.
 *   --2:
 *       Scan all classes to list every native method in target+deps, and separately
 *       identify JRE natives reachable from main.
 *   --3:
 *       Use ALL methods in target JARs as entry points (not just main) and trace.
 *   --4:
 *       Do NOT DFS; scan target+deps for native methods, categorize and write reports.
 *
 * Inputs:
 *   - target-directory: directory with application JARs
 *   - dependencies-directory: directory with dependency JARs
 *
 * Outputs (depending on mode):
 *   - native_methods_with_paths.txt: paths from entry points to natives (modes 1/3)
 *   - unique_native_methods.txt: unique natives found during DFS (modes 1/3)
 *   - deps_called_by_target.txt: dependency usage summary (modes 1/3 and all-target variant)
 *   - all_target_dep_natives*.txt: flat lists and signatures (mode 2/4)
 *   - jre_used_natives*.txt: JRE natives referenced (mode 2/4)
 *   - mode4_*: category/package/jar breakdowns (mode 4)
 */

public class PrintpathDFS {
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

    public static void main(String[] args) {
        // Parse CLI, configure analysis inputs (target + deps + runtime), then run
        // either DFS-based tracing (modes 1/3), combined scanning (mode 2),
        // or pure scanning without DFS (mode 4).
        if (args.length < 2) {
            System.err.println("Usage: java PrintpathDFS <target-directory> <dependencies-directory> [--1|--2|--3|--4]");
            System.err.println("  --1: Only include native methods called by main methods (with paths)");
            System.err.println("  --2: Include all native methods present in target+deps JARs + JRE natives from main");
            System.err.println("  --3: Use all target methods as entry points (not just main)");
            System.err.println("  --4: Scan ALL native methods in JAR files (no DFS, no filtering)");
            return;
        }

        String targetDir = args[0];
        String depsDir = args[1];

        // Parse mode argument
        boolean onlyMainCalled = false;
        boolean includeAllNative = false;
        boolean allTargetMethods = false;
        boolean scanAllNativesOnly = false;

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
                scanAllNativesOnly = true;
                System.out.println("Mode: Scan ALL native methods in JAR files (no DFS)");
            } else {
                System.err.println("Invalid mode. Use --1, --2, --3, or --4");
                return;
            }
        } else {
            onlyMainCalled = true;
            System.out.println("Mode: Only native methods called by main methods (default)");
        }

        System.out.println("=== Native Method Tracer with Paths ===");
        System.out.println("Analyzing target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);

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

        // Mode 4: Just scan all natives and exit
        if (scanAllNativesOnly) {
            System.out.println("\n=== Mode 4: Scanning All Native Methods (No DFS) ===");
            scanAllNativesMode4();
            return;
        }

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
        //    Writes dependency usage summary as well.
        if (onlyMainCalled || allTargetMethods) {
            int processedCount = 0;
            for (JavaSootMethod entryPoint : entryPointMethods) {
                visited.clear();
                nativePaths.clear();
                foundNative.clear();

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
                .filter(PrintpathDFS::isMainMethod)
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
        }
    }

    private static void writeJreUsedSignatures(String filename, Set<MethodSignature> methods) {
        // Write sorted list of JRE native method signatures referenced by the application
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
        // Mode 3: summarize dependency classes/JARs referenced anywhere in target classes
        Set<String> depClassesUsedByTarget = new HashSet<>();

        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (!targetJarClasses.contains(className)) continue;

            for (JavaSootMethod m : clazz.getMethods()) {
                try {
                    if (!m.hasBody()) continue;
                    Body body = m.getBody();
                    if (body == null) continue;

                    for (Object stmtObj : body.getStmts()) {
                        if (stmtObj instanceof InvokableStmt) {
                            ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                                MethodSignature callee = invokeExpr.getMethodSignature();
                                String calleeClass = callee.getDeclClassType().getFullyQualifiedName();
                                if (dependencyClasses.contains(calleeClass)) {
                                    depClassesUsedByTarget.add(calleeClass);
                                }
                            });
                        }
                    }
                } catch (Throwable t) {
                    System.err.println("  [WARN] Could not analyze " + m.getSignature() + ": " + t.getMessage());
                }
            }
        }

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

    private static void scanAllNativeMethods() {
        // Mode 2: scan entire codebase view and count natives by category (target/dep/JRE)
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
        // Helper for mode 2: collect all target+dependency native signatures
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
        // Mode 2: write full signatures for all target+dependency native methods
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
        // For mode 1: per-main dependency usage; for mode 3: aggregate across all target methods
        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            if (entryMethods.isEmpty()) {
                out.println("(No entry point methods found in target JARs.)");
                System.out.println("\nDeps-called-by-target written to: " + filename);
                return;
            }

            if (allTargetMode) {
                // In --3 mode, aggregate all dependencies across all methods
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
                // Mode 1: Per-main method breakdown
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
        // Produce a flat list of native method names (collapse overload counts)
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

    private static List<String> loadJarsFromDirectory(
            String dirPath,
            Set<String> classSet,
            Map<String, String> classToJarMap,
            String type
    ) {
        // Recursively traverse `dirPath`, collect JARs, and index contained classes
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

    private static boolean isMainMethod(JavaSootMethod m) {
        // Recognize canonical public static void main(String[])
        return m.getName().equals("main")
                && m.getModifiers().contains(MethodModifier.PUBLIC)
                && m.getModifiers().contains(MethodModifier.STATIC)
                && m.getParameterTypes().size() == 1
                && m.getParameterTypes().get(0).toString().equals("java.lang.String[]")
                && m.getReturnType().toString().equals("void");
    }

    private static void dfs(MethodSignature sig, List<MethodSignature> currentPath) {
        // Depth-first traversal over the call graph starting at `sig`.
        // - Uses `visited` to prevent cycles/infinite recursion.
        // - Tracks when calls cross into dependency classes (for reporting).
        // - When a native method is reached, the accumulated `currentPath` is
        //   recorded as one full path to a native.
        if (visited.contains(sig)) return;
        visited.add(sig);
        String decl = sig.getDeclClassType().getFullyQualifiedName();
        if (dependencyClasses.contains(decl)) {
            // Mark that current node resides in a dependency class
            usedDepClasses.add(decl);
        }

        System.out.println("  [DEBUG] Analyzing: " + sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);

        if (!opt.isPresent()) {
            opt = findInheritedMethod(sig);
        }

        if (!opt.isPresent()) {
            System.out.println("  [WARN] Method not found: " + sig);
            return;
        }

        JavaSootMethod m = opt.get();

        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
            // Terminal condition: a native method is reached — capture the path
            foundNative.add(sig);
            nativePaths.add(new ArrayList<>(currentPath));
            System.out.println("  [NATIVE] Found: " + sig);
            System.out.println("  [NATIVE] Path: " + buildPathString(currentPath));
            return;
        }

        try {
            if (!m.hasBody()) {
                // No Jimple body available — nothing to traverse from here
                System.out.println("  [DEBUG] No body: " + sig);
                return;
            }

            Body body = m.getBody();
            if (body == null) {
                System.out.println("  [DEBUG] Body is null: " + sig);
                return;
            }

            // Follow invoke sites to traverse into callees
            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        MethodSignature callee = invokeExpr.getMethodSignature();
                        System.out.println("  [DEBUG] Found call: " + callee);
                        List<MethodSignature> newPath = new ArrayList<>(currentPath);
                        newPath.add(callee);
                        dfs(callee, newPath);
                    });
                }
            }
        } catch (Throwable t) {
            // Some methods may fail to resolve bodies due to incomplete deps; continue
            System.err.println("  [WARN] Could not analyze " + sig + ": " + t.getMessage());
        }
    }

    private static Optional<JavaSootMethod> findInheritedMethod(MethodSignature sig) {
        // If a method is not found on its declaring class in the view, walk up the
        // inheritance chain to resolve inherited implementations.
        String className = sig.getDeclClassType().getFullyQualifiedName();
        String methodName = sig.getName();

        System.out.println("  [DEBUG] Looking for inherited method: " + methodName + " from class: " + className);
        return findInheritedMethodRecursive(className, methodName);
    }

    private static Optional<JavaSootMethod> findInheritedMethodRecursive(String className, String methodName) {
        // Recursively search method by name through superclasses present in the view
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            if (clazz.getType().getFullyQualifiedName().equals(className)) {
                System.out.println("  [DEBUG] Searching in class: " + className);

                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        System.out.println("  [DEBUG] Found method: " + method.getSignature());
                        return Optional.of(method);
                    }
                }

                if (clazz.hasSuperclass()) {
                    String superClassName = clazz.getSuperclass().get().getFullyQualifiedName();
                    System.out.println("  [DEBUG] Method not found in " + className + ", checking superclass: " + superClassName);
                    return findInheritedMethodRecursive(superClassName, methodName);
                } else {
                    System.out.println("  [DEBUG] Class " + className + " has no superclass, method not found");
                }
                break;
            }
        }
        return Optional.empty();
    }

    private static String buildPathString(List<MethodSignature> path) {
        // Render a path like A.m -> B.n -> C.o for readability in reports
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append(path.get(i));
        }
        return sb.toString();
    }

    private static void writeUniqueNativeMethodsToFile(String filename, Set<MethodSignature> nativeMethods) {
        // Write unique native signatures found during DFS tracing
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

    private static void writeNativeMethodsByPackage(String filename, Set<MethodSignature> nativeMethods) {
        // Group discovered natives by package for quick inspection
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
                // In mode 3, don't write individual paths (too many), just summary
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
                // Mode 1: Show detailed paths per main method
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

    private static void writeAllNativeMethodsInTarget(String filename, Set<String> targetJarClasses) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            Set<String> nativesFlat = new HashSet<>();
            Set<String> appClasses = new HashSet<>(targetJarClasses);
            appClasses.addAll(dependencyClasses);

            for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
                String className = clazz.getType().getFullyQualifiedName();
                if (!appClasses.contains(className)) continue;

                for (JavaSootMethod m : clazz.getMethods()) {
                    if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                        nativesFlat.add(className + "." + m.getName());
                    }
                }
            }

            List<String> sorted = new ArrayList<>(nativesFlat);
            Collections.sort(sorted);

            for (String line : sorted) {
                writer.println(line);
            }

            System.out.println("\nAll (target+deps) native methods written to: " + filename);
            System.out.println("Total native methods found: " + sorted.size());
        } catch (IOException e) {
            System.err.println("Error writing all native methods: " + e.getMessage());
        }
    }
    /**
 * Mode 4: Scan ALL native methods in target and dependency JARs
 * No DFS, no filtering by usage - just find every native method
 * Similar to ASM-based FindNativeMethods approach
 */
private static void scanAllNativesMode4() {
    System.out.println("Scanning target and dependency JARs for native methods...");
    
    Set<MethodSignature> targetNatives = new HashSet<>();
    Set<MethodSignature> depNatives = new HashSet<>();
    Map<String, List<MethodSignature>> nativesByPackage = new TreeMap<>();
    Map<String, List<MethodSignature>> nativesByJar = new TreeMap<>();
    
    int targetClassesScanned = 0;
    int depClassesScanned = 0;
    
    // CRITICAL FIX: Only scan classes that are in our target or dependency JARs
    for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
        String className = clazz.getType().getFullyQualifiedName();
        
        // SKIP JRE classes entirely - only process our JARs
        boolean isTarget = targetJarClasses.contains(className);
        boolean isDep = dependencyClasses.contains(className);
        
        if (!isTarget && !isDep) {
            continue;  // Skip JRE classes
        }
        
        if (isTarget) targetClassesScanned++;
        if (isDep) depClassesScanned++;
        
        // Check for native methods
        for (JavaSootMethod method : clazz.getMethods()) {
            if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                MethodSignature sig = method.getSignature();
                
                if (isTarget) {
                    targetNatives.add(sig);
                    System.out.println("Found TARGET native: " + sig);
                } else if (isDep) {
                    depNatives.add(sig);
                    System.out.println("Found DEPENDENCY native: " + sig);
                }
                
                // Group by package
                String packageName = className.contains(".")
                    ? className.substring(0, className.lastIndexOf('.'))
                    : "(default package)";
                nativesByPackage.computeIfAbsent(packageName, k -> new ArrayList<>()).add(sig);
                
                // Group by JAR
                String jarPath = classToJar.getOrDefault(className, "(unknown)");
                nativesByJar.computeIfAbsent(jarPath, k -> new ArrayList<>()).add(sig);
            }
        }
    }
    
    // Combine target + dep natives for the total
    Set<MethodSignature> allAppNatives = new HashSet<>();
    allAppNatives.addAll(targetNatives);
    allAppNatives.addAll(depNatives);
    
    // Print summary
    System.out.println("\n=== Mode 4 Summary ===");
    System.out.println("Classes scanned:");
    System.out.println("  - Target classes: " + targetClassesScanned);
    System.out.println("  - Dependency classes: " + depClassesScanned);
    System.out.println("Native methods found:");
    System.out.println("  - In target JARs: " + targetNatives.size());
    System.out.println("  - In dependency JARs: " + depNatives.size());
    System.out.println("  - Total in application: " + allAppNatives.size());
    
    // Write outputs - only application natives, no JRE
    writeMode4AllNatives("all_target_dep_natives.txt", allAppNatives);
    writeMode4ByCategory("mode4_by_category.txt", targetNatives, depNatives);
    writeMode4ByPackage("mode4_by_package.txt", nativesByPackage);
    writeMode4ByJar("mode4_by_jar.txt", nativesByJar);
    writeMode4FlatList("formatted_methods.txt", allAppNatives);
    
    // Optional: Find which JRE natives are referenced by the application
    if (!allAppNatives.isEmpty() || targetClassesScanned > 0 || depClassesScanned > 0) {
        Set<MethodSignature> referencedJreNatives = new HashSet<>();
        findReferencedJreNatives(referencedJreNatives);
        if (!referencedJreNatives.isEmpty()) {
            writeMode4JreNatives("jre_used_natives.txt", referencedJreNatives);
            System.out.println("JRE natives referenced by app: " + referencedJreNatives.size());
        }
    }
    
    System.out.println("\n=== Mode 4 Complete ===");
}

// New 3-category writer
private static void writeMode4ByCategory3(String filename, Set<MethodSignature> targetNatives, 
                                          Set<MethodSignature> depNatives,
                                          Set<MethodSignature> jreNatives) {
    try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
        writer.println("Native methods grouped by category");
        writer.println(repeat("=", 80));
        writer.println();
        
        writer.println("=== TARGET JAR NATIVES (" + targetNatives.size() + ") ===");
        targetNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println("  " + sig));
        
        writer.println();
        writer.println("=== DEPENDENCY JAR NATIVES (" + depNatives.size() + ") ===");
        depNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println("  " + sig));
        
        writer.println();
        writer.println("=== JRE NATIVES REFERENCED (" + jreNatives.size() + ") ===");
        jreNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println("  " + sig));
        
        System.out.println("Natives by category written to: " + filename);
    } catch (IOException e) {
        System.err.println("Error writing " + filename + ": " + e.getMessage());
    }
}

private static void writeMode4JreNatives(String filename, Set<MethodSignature> jreNatives) {
    try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
        writer.println("JRE native methods referenced by target+deps code");
        writer.println("Total: " + jreNatives.size());
        writer.println(repeat("=", 80));
        writer.println();
        
        jreNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println(sig));
        
        System.out.println("JRE natives written to: " + filename);
    } catch (IOException e) {
        System.err.println("Error writing " + filename + ": " + e.getMessage());
    }
}
private static void writeMode4AllNatives(String filename, Set<MethodSignature> natives) {
    try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
        writer.println("All native methods found in target and dependency JARs");
        writer.println("Total: " + natives.size());
        writer.println(repeat("=",80));
        writer.println();
        
        List<MethodSignature> sorted = natives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .collect(Collectors.toList());
        
        for (int i = 0; i < sorted.size(); i++) {
            writer.println((i + 1) + ". " + sorted.get(i));
        }
        
        System.out.println("All natives written to: " + filename);
    } catch (IOException e) {
        System.err.println("Error writing " + filename + ": " + e.getMessage());
    }
}

private static void writeMode4ByCategory(String filename, Set<MethodSignature> targetNatives, 
                                          Set<MethodSignature> depNatives) {
    try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
        writer.println("Native methods grouped by category (Target vs Dependencies)");
        writer.println(repeat("=",80));
        writer.println();
        
        writer.println("=== TARGET JAR NATIVES (" + targetNatives.size() + ") ===");
        targetNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println("  " + sig));
        
        writer.println();
        writer.println("=== DEPENDENCY JAR NATIVES (" + depNatives.size() + ") ===");
        depNatives.stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sig -> writer.println("  " + sig));
        
        System.out.println("Natives by category written to: " + filename);
    } catch (IOException e) {
        System.err.println("Error writing " + filename + ": " + e.getMessage());
    }
}

private static void writeMode4ByPackage(String filename, Map<String, List<MethodSignature>> byPackage) {
    try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
        writer.println("Native methods organized by package");
        writer.println("Total packages: " + byPackage.size());
        writer.println(repeat("=",80));
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
        writer.println(repeat("=",80));
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
        writer.println(repeat("=",80));
        
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
private static String repeat(String str, int count) {
    return new String(new char[count]).replace("\0", str);
}
private static void traceJreNatives(MethodSignature sig, Set<MethodSignature> jreNatives, int depth, int maxDepth) {
    if (depth > maxDepth || visited.contains(sig)) return;
    visited.add(sig);
    
    Optional<JavaSootMethod> opt = view.getMethod(sig);
    if (!opt.isPresent()) return;
    
    JavaSootMethod m = opt.get();
    
    // If it's a JRE native, record it
    String className = sig.getDeclClassType().getFullyQualifiedName();
    if (!targetJarClasses.contains(className) && !dependencyClasses.contains(className)) {
        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
            jreNatives.add(sig);
            return; // Stop at native
        }
    }
    
    // Follow calls - FIXED TRY-CATCH
    try {
        if (!m.hasBody()) return;
        Body body = m.getBody();  // This line throws IncompatibleClassChangeError
        
        for (Object stmtObj : body.getStmts()) {
            if (stmtObj instanceof InvokableStmt) {
                ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                    traceJreNatives(invokeExpr.getMethodSignature(), jreNatives, depth + 1, maxDepth);
                });
            }
        }
    } catch (IncompatibleClassChangeError | VerifyError | Exception e) {
        // Skip methods that cause type resolution errors due to dependency conflicts
        // Silent skip - this is expected for some methods in mode 4
    }
}
private static void findReferencedJreNatives(Set<MethodSignature> jreNatives) {
    System.out.println("Scanning all target+dep methods for direct JRE native calls...");

    for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
        String className = clazz.getType().getFullyQualifiedName();
        if (!targetJarClasses.contains(className) && !dependencyClasses.contains(className)) continue;

        for (JavaSootMethod method : clazz.getMethods()) {
            try {
                if (!method.hasBody()) continue;
                Body body = method.getBody();
                if (body == null) continue;

                for (Object stmtObj : body.getStmts()) {
                    if (stmtObj instanceof InvokableStmt) {
                        ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                            MethodSignature callee = invokeExpr.getMethodSignature();
                            String calleeClass = callee.getDeclClassType().getFullyQualifiedName();

                            // Skip app & deps → focus on JRE classes
                            if (!targetJarClasses.contains(calleeClass)
                                    && !dependencyClasses.contains(calleeClass)
                                    && calleeClass.startsWith("java.")
                                    || calleeClass.startsWith("sun.")
                                    || calleeClass.startsWith("jdk.")) {

                                view.getMethod(callee).ifPresent(m -> {
                                    if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                                        jreNatives.add(callee);
                                    }
                                });
                            }
                        });
                    }
                }
            } catch (Throwable t) {
                System.err.println("[WARN] Skipping method " + method.getSignature() + ": " + t.getMessage());
            }
        }
    }

    System.out.println("Total JRE natives referenced: " + jreNatives.size());
}

}
