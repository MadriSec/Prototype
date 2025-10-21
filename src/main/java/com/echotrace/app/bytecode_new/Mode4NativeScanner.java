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
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.expr.JInterfaceInvokeExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.stream.Collectors;
import java.util.Comparator;

/**
 * Mode 4–only scanner with combined report:
 * - Scans TARGET and DEPENDENCY JARs for methods declared with 'native'
 * - Writes: all natives, by category, by package, by jar, flat list
 * - Finds JRE natives directly referenced by app code
 * - NEW: writes "formatted_methods_plus_jre.txt" combining flat app natives + JRE natives
 *
 * Usage:
 *   java com.echotrace.app.bytecode_new.Mode4NativeScanner <target-dir> <deps-dir>
 */
public class Mode4NativeScanner {

    private static final Map<String, String> classToJar = new HashMap<>();
    private static final Set<String> targetJarClasses = new HashSet<>();
    private static final Set<String> dependencyClasses = new HashSet<>();
    private static JavaView view;

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java com.echotrace.app.bytecode_new.Mode4NativeScanner <target-directory> <dependencies-directory>");
            System.exit(1);
        }

        String targetDir = args[0];
        String depsDir = args[1];

        System.out.println("=== Mode 4: Scan ALL native methods in target and dependency JARs ===");
        System.out.println("Target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);

        // Load JARs and index classes
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        // Build SootUp view with enhanced JRE support
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        
        // Enhanced JRE loading - try modern runtime first, fallback to rt.jar
        try {
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
            System.out.println("Added modern JRE runtime location");
        } catch (Exception e) {
            System.err.println("Modern JRE loading failed, trying rt.jar fallback: " + e.getMessage());
            String javaHome = System.getProperty("java.home");
            File rt = new File(javaHome + File.separator + "lib" + File.separator + "rt.jar");
            if (rt.exists()) {
                inputs.add(new JavaClassPathAnalysisInputLocation(rt.getAbsolutePath()));
                System.out.println("Added rt.jar: " + rt.getAbsolutePath());
            } else {
                System.err.println("rt.jar not found at: " + rt.getAbsolutePath() + " — ensure you run on Java9+ or provide a runtime jar.");
            }
        }
        
        view = new JavaView(inputs);

        System.out.println("Target classes indexed: " + targetJarClasses.size());
        System.out.println("Dependency classes indexed: " + dependencyClasses.size());

        try {
            scanAllNativesMode4();
            System.out.println("\n=== Mode 4 Complete ===");
        } finally {
            // Clean up any remaining threads and resources
            cleanup();
        }
        
        // Force exit to prevent Maven exec plugin thread issues
        System.exit(0);
    }
    
    /**
     * Clean up resources and threads to prevent Maven exec plugin issues
     */
    private static void cleanup() {
        try {
            // Force garbage collection to clean up SootUp resources
            System.gc();
            
            // Give threads time to finish naturally
            Thread.sleep(200);
            
            // Only interrupt threads that are clearly from our application/SootUp
            // Avoid interrupting Maven's internal threads
            ThreadGroup rootGroup = Thread.currentThread().getThreadGroup();
            while (rootGroup.getParent() != null) {
                rootGroup = rootGroup.getParent();
            }
            
            Thread[] threads = new Thread[rootGroup.activeCount()];
            int count = rootGroup.enumerate(threads);
            
            for (int i = 0; i < count; i++) {
                Thread thread = threads[i];
                if (thread != null && thread != Thread.currentThread() && thread.isDaemon()) {
                    // Only interrupt threads that are likely from SootUp or our application
                    // Avoid Maven threads by checking thread name patterns
                    String threadName = thread.getName();
                    if (threadName != null && 
                        (threadName.contains("SootUp") || 
                         threadName.contains("soot") ||
                         threadName.contains("NativeScanner") ||
                         threadName.startsWith("Thread-"))) {
                        thread.interrupt();
                    }
                }
            }
            
        } catch (Exception e) {
            // Ignore cleanup exceptions
        }
    }

    /**
     * Recursively traverse dirPath, collect JARs, and index contained classes.
     * Includes MRJAR normalization: strips META-INF/versions/<N>/ prefix so FQNs match runtime view.
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

                            if (!name.endsWith(".class")) continue;

                            // MRJAR normalization
                            if (name.startsWith("META-INF/versions/")) {
                                name = name.replaceFirst("^META-INF/versions/\\d+/", "");
                                if (!name.endsWith(".class")) continue; // guard after normalization
                            }

                            String className = name.replace('/', '.').substring(0, name.length() - 6);
                            classSet.add(className);
                            String prev = classToJarMap.put(className, f.getAbsolutePath());
                            if (prev != null && !prev.equals(f.getAbsolutePath())) {
                                System.err.println("[WARN] Class " + className + " appears in multiple JARs:\n  - " + prev + "\n  - " + f.getAbsolutePath());
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

    /** Mode 4 scanning and reporting */
    private static void scanAllNativesMode4() {
        System.out.println("Scanning target and dependency JARs for native methods...");

        Set<MethodSignature> targetNatives = new HashSet<>();
        Set<MethodSignature> depNatives = new HashSet<>();
        Map<String, List<MethodSignature>> nativesByPackage = new TreeMap<>();
        Map<String, List<MethodSignature>> nativesByJar = new TreeMap<>();

        int targetClassesScanned = 0;
        int depClassesScanned = 0;

        // Iterate classes visible in the view; keep only those from target/dep (skip JRE)
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();

            boolean isTarget = targetJarClasses.contains(className);
            boolean isDep = dependencyClasses.contains(className);
            if (!isTarget && !isDep) continue;

            if (isTarget) targetClassesScanned++;
            if (isDep) depClassesScanned++;

            for (JavaSootMethod method : clazz.getMethods()) {
                if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                    MethodSignature sig = method.getSignature();

                    if (isTarget) {
                        targetNatives.add(sig);
                        System.out.println("Found TARGET native: " + sig);
                    } else {
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

        // Combine for totals
        Set<MethodSignature> allAppNatives = new HashSet<>();
        allAppNatives.addAll(targetNatives);
        allAppNatives.addAll(depNatives);

        // Summary
        System.out.println("\n=== Mode 4 Summary ===");
        System.out.println("Classes scanned:");
        System.out.println("  - Target classes: " + targetClassesScanned);
        System.out.println("  - Dependency classes: " + depClassesScanned);
        System.out.println("Native methods found:");
        System.out.println("  - In target JARs: " + targetNatives.size());
        System.out.println("  - In dependency JARs: " + depNatives.size());
        System.out.println("  - Total in application: " + allAppNatives.size());

        // Write outputs (app-only)
        writeMode4AllNatives("all_target_dep_natives.txt", allAppNatives);
        writeMode4ByCategory("mode4_by_category.txt", targetNatives, depNatives);
        writeMode4ByPackage("mode4_by_package.txt", nativesByPackage);
        writeMode4ByJar("mode4_by_jar.txt", nativesByJar);
        writeMode4FlatList("formatted_methods.txt", allAppNatives);

        // Enhanced JRE native detection using dynamic discovery only
        Set<MethodSignature> referencedJreNatives = new HashSet<>();
        if (!allAppNatives.isEmpty() || targetClassesScanned > 0 || depClassesScanned > 0) {
            findReferencedJreNatives(referencedJreNatives);
            findJreNativesDynamically(referencedJreNatives);
            findJreNativesDynamicallyEnhanced(referencedJreNatives);
            
            if (!referencedJreNatives.isEmpty()) {
                writeMode4JreNatives("jre_used_natives.txt", referencedJreNatives);
                System.out.println("JRE natives referenced by app: " + referencedJreNatives.size());
            }
        }

        // NEW: Combined report (flat app natives + JRE natives referenced)
        Map<String, Long> appFlat = flattenNativeNames(allAppNatives);
        writeCombinedFlatAndJre("formatted_methods_plus_jre.txt", appFlat, referencedJreNatives);
        
        // NEW: Single flat list with all natives (app + JRE) in simple format
        writeSingleFlatList("flatlist.txt", allAppNatives, referencedJreNatives);
    }

    /** Build "flat" names => overload count map, e.g., com.Foo.bar -> 3 */
    private static Map<String, Long> flattenNativeNames(Set<MethodSignature> natives) {
        return natives.stream().collect(Collectors.groupingBy(
                sig -> sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName(),
                Collectors.counting()
        ));
    }

    /** Combined report writer */
    private static void writeCombinedFlatAndJre(String filename, Map<String, Long> appFlat, Set<MethodSignature> jreNatives) {
        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            out.println("Flat list of application native method names (overloads collapsed)");
            out.println(repeat("=",80));
            out.println("Total unique method names: " + appFlat.size());
            long totalAppSigs = appFlat.values().stream().mapToLong(Long::longValue).sum();
            out.println("Total signatures (with overloads): " + totalAppSigs);
            out.println();

            appFlat.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> {
                        String name = e.getKey();
                        long count = e.getValue();
                        if (count > 1) out.println(name + "  (+" + (count - 1) + " overloads)");
                        else out.println(name);
                    });

            out.println();
            out.println("JRE native methods referenced by target+deps code");
            out.println(repeat("=",80));
            out.println("Total: " + jreNatives.size());
            out.println();

            jreNatives.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .forEach(out::println);

            System.out.println("Combined flat+JRE report written to: " + filename);
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

            Map<String, Long> byName = flattenNativeNames(natives);

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

    private static void writeMode4JreNatives(String filename, Set<MethodSignature> jreNatives) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("JRE native methods referenced by target+deps code");
            writer.println("Total: " + jreNatives.size());
            writer.println(repeat("=", 80));
            writer.println();

            jreNatives.stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .forEach(writer::println);

            System.out.println("JRE natives written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    /** Finds JRE-native methods that app code directly invokes (does NOT include app-declared natives). */
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

                                // Group java/sun/jdk together, but exclude app/dep.
                                if (!targetJarClasses.contains(calleeClass)
                                        && !dependencyClasses.contains(calleeClass)
                                        && (calleeClass.startsWith("java.")
                                            || calleeClass.startsWith("sun.")
                                            || calleeClass.startsWith("jdk."))) {

                                    // Check direct native first
                                    view.getMethod(callee).ifPresent(m -> {
                                        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                                            jreNatives.add(callee);
                                        } else {
                                            // If not native, inspect transitively for wrapper->native patterns
                                            inspectTransitively(callee, jreNatives, 3);
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

        System.out.println("Total JRE natives referenced (direct + transitive): " + jreNatives.size());
    }

    /** 
     * Transitive body inspection: follows call edges into JRE methods to find wrapper->native patterns.
     * This catches cases like Class.forName() -> Class.forName0() (native)
     */
    private static void inspectTransitively(MethodSignature callee, Set<MethodSignature> found, int depth) {
        if (depth <= 0) return;
        
        view.getMethod(callee).ifPresent(m -> {
            // If this method itself is native, add it
            if (m.getModifiers().contains(MethodModifier.NATIVE)) {
                found.add(callee);
                return;
            }
            
            // If no body, can't inspect further
            if (!m.hasBody()) return;
            
            Body body = m.getBody();
            if (body == null) return;
            
            // Look for calls within this JRE method
            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        MethodSignature nested = invokeExpr.getMethodSignature();
                        String nestedClass = nested.getDeclClassType().getFullyQualifiedName();
                        
                        // Only follow JRE calls (java.*, sun.*, jdk.*)
                        if (nestedClass.startsWith("java.") || nestedClass.startsWith("sun.") || nestedClass.startsWith("jdk.")) {
                            inspectTransitively(nested, found, depth - 1);
                        }
                    });
                }
            }
        });
    }

    /**
     * Find JRE natives that are actually used by the application through call graph analysis
     * This method builds a call graph starting from application entry points and finds
     * all reachable JRE native methods
     */
    private static void findJreNativesDynamically(Set<MethodSignature> jreNatives) {
        System.out.println("Building call graph to find JRE natives actually used by application...");
        
        final int[] jreNativesFound = {0};
        
        // Collect all application entry points (main methods and public methods)
        Set<MethodSignature> entryPoints = new HashSet<>();
        
        // Find main methods in application classes - be more selective
        for (String className : targetJarClasses) {
            // Look for classes with this name
            view.getClasses().forEach(clazz -> {
                if (clazz.getType().getFullyQualifiedName().equals(className)) {
                    clazz.getMethods().forEach(method -> {
                        // Only add main methods as entry points to avoid too many entry points
                        if (method.getName().equals("main") && 
                            method.getModifiers().contains(MethodModifier.PUBLIC) &&
                            method.getModifiers().contains(MethodModifier.STATIC)) {
                            entryPoints.add(method.getSignature());
                        }
                        // Limit to a few key public methods to avoid explosion
                        else if (method.getModifiers().contains(MethodModifier.PUBLIC) && 
                                 method.getModifiers().contains(MethodModifier.STATIC) &&
                                 entryPoints.size() < 50) { // Limit to prevent explosion
                            entryPoints.add(method.getSignature());
                        }
                    });
                }
            });
        }
        
        System.out.println("Found " + entryPoints.size() + " application entry points");
        
        // Build call graph from entry points and find reachable JRE natives
        Set<MethodSignature> visited = new HashSet<>();
        Deque<MethodSignature> worklist = new ArrayDeque<>(entryPoints);
        
        while (!worklist.isEmpty()) {
            MethodSignature current = worklist.poll();
            if (visited.contains(current)) continue;
            visited.add(current);
            
            // Get method body and find all calls with error handling
            try {
                view.getMethod(current).ifPresent(method -> {
                    try {
                        if (!method.hasBody()) return;
                        
                        Body body = method.getBody();
                        if (body == null) return;
                        
                        for (Object stmtObj : body.getStmts()) {
                            if (stmtObj instanceof InvokableStmt) {
                                ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                                    MethodSignature callee = invokeExpr.getMethodSignature();
                                    String calleeClass = callee.getDeclClassType().getFullyQualifiedName();
                                    
                                    // If it's a JRE native method, add it
                                    if ((calleeClass.startsWith("java.") || calleeClass.startsWith("sun.") || calleeClass.startsWith("jdk.")) &&
                                        !targetJarClasses.contains(calleeClass) && !dependencyClasses.contains(calleeClass)) {
                                        
                                        view.getMethod(callee).ifPresent(calleeMethod -> {
                                            if (calleeMethod.getModifiers().contains(MethodModifier.NATIVE)) {
                                                if (!jreNatives.contains(callee)) {
                                                    jreNatives.add(callee);
                                                    jreNativesFound[0]++;
                                                    System.out.println("Found JRE native used by app: " + callee);
                                                }
                                            } else {
                                                // Add non-native JRE methods to worklist for further traversal
                                                if (!visited.contains(callee)) {
                                                    worklist.add(callee);
                                                }
                                            }
                                        });
                                    }
                                    // If it's an application method, add it to worklist
                                    else if (targetJarClasses.contains(calleeClass) || dependencyClasses.contains(calleeClass)) {
                                        if (!visited.contains(callee)) {
                                            worklist.add(callee);
                                        }
                                    }
                                });
                            }
                        }
                    } catch (Throwable t) {
                        System.err.println("[WARN] Error processing method " + method.getSignature() + ": " + t.getMessage());
                    }
                });
            } catch (Throwable t) {
                System.err.println("[WARN] Error getting method " + current + ": " + t.getMessage());
            }
        }
        
        System.out.println("Total JRE natives actually used by application: " + jreNativesFound[0]);
    }

    /**
     * Enhanced dynamic discovery of JRE natives based on application usage patterns
     * This method analyzes the application's actual usage patterns to find relevant JRE natives
     */
    private static void findJreNativesDynamicallyEnhanced(Set<MethodSignature> jreNatives) {
        System.out.println("Enhanced dynamic discovery of JRE natives based on application patterns...");
        
        // Track which JRE classes the application actually uses
        Set<String> usedJreClasses = new HashSet<>();
        
        // First pass: find all JRE classes that the application directly references
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className) || dependencyClasses.contains(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    try {
                        if (method.hasBody()) {
                            Body body = method.getBody();
                            if (body != null) {
                                for (Object stmtObj : body.getStmts()) {
                                    if (stmtObj instanceof InvokableStmt) {
                                        ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                                            MethodSignature callee = invokeExpr.getMethodSignature();
                                            String calleeClass = callee.getDeclClassType().getFullyQualifiedName();
                                            
                                            // Track JRE classes used by the application
                                            if ((calleeClass.startsWith("java.") || calleeClass.startsWith("sun.") || calleeClass.startsWith("jdk.")) &&
                                                !targetJarClasses.contains(calleeClass) && !dependencyClasses.contains(calleeClass)) {
                                                usedJreClasses.add(calleeClass);
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    } catch (Throwable t) {
                        System.err.println("[WARN] Skipping method " + method.getSignature() + " in enhanced discovery: " + t.getMessage());
                    }
                }
            }
        }
        
        System.out.println("Found " + usedJreClasses.size() + " JRE classes used by application");
        
        // Second pass: for each used JRE class, find only the native methods that are actually called
        // This is more conservative than adding ALL natives from every used class
        System.out.println("Skipping adding all natives from used classes to avoid false positives");
        
        // Third pass: find JRE natives that might be called transitively through reflection or other mechanisms
        // This is a more conservative approach that looks for patterns in the application code
        findJreNativesFromUsagePatterns(jreNatives, usedJreClasses);
    }
    
    /**
     * Find JRE natives based on usage patterns in the application
     */
    private static void findJreNativesFromUsagePatterns(Set<MethodSignature> jreNatives, Set<String> usedJreClasses) {
        System.out.println("Analyzing usage patterns to find additional JRE natives...");
        
        // This method is now more conservative - it only finds natives that are
        // directly called by the application or transitively called through wrapper methods
        // It does NOT add all natives from every JRE class that the application uses
        
        // The transitive dependency analysis was too aggressive and was adding
        // natives from classes that the application uses but doesn't actually call natives from
        // We'll keep this method simple and let the other methods handle the discovery
        
        System.out.println("Skipping aggressive transitive analysis to avoid false positives");
    }

    /**
     * Write all native methods (app + JRE) to a single flat list file
     */
    private static void writeSingleFlatList(String filename, Set<MethodSignature> appNatives, Set<MethodSignature> jreNatives) {
        try (PrintWriter out = new PrintWriter(new FileWriter(filename))) {
            // Combine all natives
            Set<MethodSignature> allNatives = new HashSet<>();
            allNatives.addAll(appNatives);
            allNatives.addAll(jreNatives);
            
            // Convert to flat names and sort
            Map<String, Long> flatNames = flattenNativeNames(allNatives);
            
            // Write sorted flat list
            flatNames.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        String name = entry.getKey();
                        out.println(name);
                    });
            
            System.out.println("Single flat list written to: " + filename + " (" + flatNames.size() + " unique method names)");
        } catch (IOException e) {
            System.err.println("Error writing " + filename + ": " + e.getMessage());
        }
    }

    private static String repeat(String str, int count) {
        return new String(new char[count]).replace("\0", str);
    }
}
