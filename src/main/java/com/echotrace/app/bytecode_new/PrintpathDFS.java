package com.echotrace.app.bytecode_new;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.jimple.common.expr.*;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;
import sootup.core.model.SourceType;
import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Native method tracer with path from main methods to native methods
 * Shows complete call paths from main to native methods
 * Now supports dependency JARs.
 */
public class PrintpathDFS {
    private static final Set<MethodSignature> visited = new HashSet<>();
    private static final List<List<MethodSignature>> nativePaths = new ArrayList<>();
    private static final Set<MethodSignature> foundNative = new HashSet<>();
    private static JavaView view;
    private static Set<String> targetJarClasses = new HashSet<>();
    private static Set<String> dependencyClasses = new HashSet<>();
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java PrintpathDFS <target.jar> <dependencies-directory>");
            return;
        }
        String jarPath = args[0];
        String depsDir = args[1];

        System.out.println("=== Native Method Tracer with Paths ===");
        System.out.println("Analyzing JAR: " + jarPath);
        System.out.println("Dependencies directory: " + depsDir);

        // 1. Load target JAR classes
        loadTargetJarClasses(jarPath);
        
        // 2. Load dependency JARs
        List<String> depJars = loadDependencyJars(depsDir);
        
        // 3. Initialize SootUp view with target and dependencies
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(jarPath));
        for (String depJar : depJars) {
            inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        }
        inputs.add(new DefaultRuntimeAnalysisInputLocation()); // Include JRE classes
        view = new JavaView(inputs);

        System.out.println("Target JAR contains " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // 4. Find main methods ONLY from the target JAR
        List<JavaSootMethod> mainMethods = new ArrayList<>();
        view.getClasses().forEach(clazz -> {
            String className = clazz.getType().getFullyQualifiedName();
            if (targetJarClasses.contains(className)) {
                clazz.getMethods().forEach(method -> {
                    if (isMainMethod(method)) {
                        mainMethods.add(method);
                        System.out.println("Found main method: " + method.getSignature());
                    }
                });
            }
        });

        if (mainMethods.isEmpty()) {
            System.out.println("No main methods found in the target JAR.");
            return;
        }

        System.out.println("\n=== Starting Analysis ===");
        System.out.println("Total main methods found: " + mainMethods.size());

        // 5. Traverse from each main method
        for (int i = 0; i < mainMethods.size(); i++) {
            JavaSootMethod main = mainMethods.get(i);
            System.out.println("\n=== Processing Main Method " + (i + 1) + " of " + mainMethods.size() + " ===");
            System.out.println("Starting traversal from: " + main.getSignature());
            
            // Clear all tracking collections for this main method
            visited.clear();
            nativePaths.clear();
            foundNative.clear();
            
            List<MethodSignature> startPath = new ArrayList<>();
            startPath.add(main.getSignature());
            dfs(main.getSignature(), startPath);
            
            // Print results for this main method
            System.out.println("\n=== Results for " + main.getSignature() + " ===");
            if (foundNative.isEmpty()) {
                System.out.println("No native methods found for this main method.");
            } else {
                System.out.println("Found " + nativePaths.size() + " paths to " + foundNative.size() + " native methods:");
                for (int j = 0; j < nativePaths.size(); j++) {
                    List<MethodSignature> path = nativePaths.get(j);
                    System.out.println("Path " + (j + 1) + ": " + buildPathString(path));
                }
            }
            
            // Print summary for this main method
            System.out.println("Summary for " + main.getSignature() + ":");
            System.out.println("  - Methods visited: " + visited.size());
            System.out.println("  - Native methods found: " + foundNative.size());
            System.out.println("  - Total paths: " + nativePaths.size());
        }

        // 6. Write results to file
        try (PrintWriter writer = new PrintWriter(new FileWriter("native_methods_with_paths.txt"))) {
            writer.println("Native methods and paths found in: " + jarPath);
            writer.println("Dependencies: " + depsDir);
            writer.println();
            
            for (int i = 0; i < mainMethods.size(); i++) {
                JavaSootMethod main = mainMethods.get(i);
                writer.println("=== Main Method " + (i + 1) + ": " + main.getSignature() + " ===");
                
                // Re-run analysis for this main method to get paths
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
                        List<MethodSignature> path = nativePaths.get(j);
                        writer.println("Path " + (j + 1) + ": " + buildPathString(path));
                    }
                }
                writer.println();
            }
            System.out.println("\nResults written to: native_methods_with_paths.txt");
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
        }
    }

    private static void loadTargetJarClasses(String jarPath) {
        try (ZipFile zipFile = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".class") && !name.contains("$")) {
                    String className = name.replace('/', '.').substring(0, name.length() - 6);
                    targetJarClasses.add(className);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading target JAR: " + e.getMessage());
        }
    }

    private static List<String> loadDependencyJars(String depsDir) {
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
                    System.err.println("Error reading dependency JAR: " + jar.getName());
                }
            }
        }
        return depJars;
    }

    private static boolean isMainMethod(JavaSootMethod m) {
        return m.getName().equals("main")
                && m.getModifiers().contains(MethodModifier.PUBLIC)
                && m.getModifiers().contains(MethodModifier.STATIC)
                && m.getParameterTypes().size() == 1
                && m.getParameterTypes().get(0).toString().equals("java.lang.String[]")
                && m.getReturnType().toString().equals("void");
    }

    private static void dfs(MethodSignature sig, List<MethodSignature> currentPath) {
        if (visited.contains(sig)) return;
        visited.add(sig);
        
        System.out.println("  [DEBUG] Analyzing: " + sig);
        
        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) {
            System.out.println("  [WARN] Method not found: " + sig);
            return;
        }
        
        JavaSootMethod m = opt.get();

        // 1. If native, record the path and stop
        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
            foundNative.add(sig);
            nativePaths.add(new ArrayList<>(currentPath));
            System.out.println("  [NATIVE] Found: " + sig);
            System.out.println("  [NATIVE] Path: " + buildPathString(currentPath));
            return;
        }

        // 2. Try to get body and traverse calls
        try {
            if (!m.hasBody()) {
                System.out.println("  [DEBUG] No body: " + sig);
                return;
            }
            
            Body body = m.getBody();
            if (body == null) {
                System.out.println("  [DEBUG] Body is null: " + sig);
                return;
            }
            
            // Process all invocations
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
            // Skip methods that can't be analyzed
            System.err.println("  [WARN] Could not analyze " + sig + ": " + t.getMessage());
        }
    }

    private static String buildPathString(List<MethodSignature> path) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) {
                sb.append(" -> ");
            }
            sb.append(path.get(i));
        }
        return sb.toString();
    }
}
