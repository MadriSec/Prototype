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
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JInterfaceInvokeExpr;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;
import sootup.java.core.types.JavaClassType;
import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.stream.Collectors;

/**
 * Given a list of method signatures, prints all call paths from each to native methods.
 */
public class PrintNativeFromMethodSignature {
    private static final Set<MethodSignature> visited = new HashSet<>();
    private static final List<List<MethodSignature>> nativePaths = new ArrayList<>();
    private static final Set<MethodSignature> foundNative = new HashSet<>();
    private static JavaView view;
    private static Set<String> targetJarClasses = new HashSet<>();
    private static Set<String> dependencyClasses = new HashSet<>();
    private static final Set<MethodSignature> allUniqueNativeMethods = new HashSet<>();

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java PrintNativeFromMethodSignature <target-directory> <dependencies-directory> <signature-file>");
            return;
        }
        String targetDir = args[0];
        String depsDir = args[1];
        String sigFile = args[2];

        System.out.println("=== Native Method Tracer from Method Signatures ===");
        System.out.println("Target directory: " + targetDir);
        System.out.println("Dependencies directory: " + depsDir);
        System.out.println("Signature file: " + sigFile);

        // 1. Load all target JARs and their classes
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, "target");
        System.out.println("Loaded " + targetJars.size() + " target JARs with " + targetJarClasses.size() + " classes");
        
        // 2. Load dependency JARs and their classes
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, "dependency");
        System.out.println("Loaded " + depJars.size() + " dependency JARs with " + dependencyClasses.size() + " classes");
        
        // 3. Initialize SootUp view
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        view = new JavaView(inputs);
        
        System.out.println("SootUp view initialized with " + view.getClasses().count() + " total classes");

        // 4. Read method signatures from file
        List<MethodSignature> inputSigs = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(sigFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                System.out.println("Parsing signature: " + line);
                MethodSignature sig = parseSignature(line);
                if (sig != null) {
                    inputSigs.add(sig);
                    System.out.println("Successfully parsed: " + sig);
                } else {
                    System.err.println("[WARN] Could not parse signature: " + line);
                }
            }
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to read signature file: " + e.getMessage());
            return;
        }
        if (inputSigs.isEmpty()) {
            System.err.println("No valid method signatures provided.");
            return;
        }

        System.out.println("\n=== Starting Analysis ===");
        System.out.println("Total input signatures: " + inputSigs.size());

        // 5. For each input signature, find all native methods reachable
        for (MethodSignature sig : inputSigs) {
            System.out.println("\n=== Tracing from: " + sig + " ===");
            visited.clear();
            nativePaths.clear();
            foundNative.clear();
            List<MethodSignature> startPath = new ArrayList<>();
            startPath.add(sig);
            dfs(sig, startPath);
            if (foundNative.isEmpty()) {
                System.out.println("No native methods found for this method.");
                System.out.println("Methods visited: " + visited.size());
                System.out.println("This might indicate:");
                System.out.println("  1. The method was not found in the JARs");
                System.out.println("  2. The method has no body (abstract/interface)");
                System.out.println("  3. The method doesn't make any calls");
                System.out.println("  4. There's an issue with the analysis");
            } else {
                System.out.println("Found " + nativePaths.size() + " paths to " + foundNative.size() + " native methods:");
                for (int j = 0; j < nativePaths.size(); j++) {
                    List<MethodSignature> path = nativePaths.get(j);
                    System.out.println("Path " + (j + 1) + ": " + buildPathString(path));
                }
            }
        }
        // New: Print invoke tree for each input signature
        for (MethodSignature sig : inputSigs) {
            System.out.println("\n=== Call Tree for: " + sig + " ===");
            printInvokeTree(sig, new HashSet<>(), 0);
        }

        // Write all call paths from each input method to native methods (including JRE) to file
        try (PrintWriter writer = new PrintWriter(new FileWriter("native_methods_with_paths22.txt"))) {
            for (MethodSignature sig : inputSigs) {
                writer.println("=== Paths from: " + sig + " ===");
                visited.clear();
                nativePaths.clear();
                foundNative.clear();
                List<MethodSignature> startPath = new ArrayList<>();
                startPath.add(sig);
                dfs(sig, startPath);
                if (nativePaths.isEmpty()) {
                    writer.println("No native methods found for this method.");
                } else {
                    for (int j = 0; j < nativePaths.size(); j++) {
                        List<MethodSignature> path = nativePaths.get(j);
                        writer.println("Path " + (j + 1) + ": " + buildPathString(path));
                    }
                }
                writer.println();
            }
            System.out.println("\nResults written to: native_methods_with_paths22.txt");
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
        }
        
        // Write all unique native methods found to a separate file
        writeUniqueNativeMethodsToFile("unique_native_methods22s.txt", allUniqueNativeMethods);
    }

    private static List<String> loadJarsFromDirectory(String dirPath, Set<String> classSet, String type) {
        List<String> jarList = new ArrayList<>();
        File directory = new File(dirPath);
        if (!directory.exists() || !directory.isDirectory()) {
            System.err.println(type + " directory does not exist or is not a directory: " + dirPath);
            return jarList;
        }
        File[] jars = directory.listFiles((d, name) -> name.endsWith(".jar"));
        if (jars != null && jars.length > 0) {
            for (File jar : jars) {
                jarList.add(jar.getAbsolutePath());
                try (ZipFile zipFile = new ZipFile(jar)) {
                    Enumeration<? extends ZipEntry> entries = zipFile.entries();
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();
                        String name = entry.getName();
                        if (name.endsWith(".class") && !name.contains("$")) {
                            String className = name.replace('/', '.').substring(0, name.length() - 6);
                            classSet.add(className);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Error reading " + type + " JAR: " + jar.getName() + " - " + e.getMessage());
                }
            }
        }
        return jarList;
    }

    private static MethodSignature parseSignature(String line) {
        // Format: fully.qualified.ClassName:methodName or fully.qualified.ClassName:methodName(paramType1,paramType2,...)
        try {
            int colon = line.indexOf(":");
            if (colon < 0) return null;
            String className = line.substring(0, colon);
            String rest = line.substring(colon + 1);
            int paren = rest.indexOf('(');
            String methodName = (paren < 0) ? rest : rest.substring(0, paren);
            List<String> paramTypes = new ArrayList<>();
            if (paren >= 0) {
                int close = rest.indexOf(')', paren);
                if (close < 0) return null;
                String params = rest.substring(paren + 1, close).trim();
                if (!params.isEmpty()) {
                    for (String p : params.split(",")) paramTypes.add(p.trim());
                }
            }
            // Try to find the class in the view
            Optional<JavaSootClass> cls = view.getClasses().filter(c -> c.getType().getFullyQualifiedName().equals(className)).findFirst();
            if (!cls.isPresent()) {
                System.err.println("[WARN] Class not found: " + className);
                return null;
            }
            for (JavaSootMethod m : cls.get().getMethods()) {
                if (m.getName().equals(methodName)) {
                    if (paramTypes.isEmpty() || paramTypesMatch(m, paramTypes)) {
                        return m.getSignature();
                    }
                }
            }
            System.err.println("[WARN] Method not found: " + line);
            return null;
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to parse signature: " + line + " - " + e.getMessage());
            return null;
        }
    }

    private static boolean paramTypesMatch(JavaSootMethod m, List<String> paramTypes) {
        if (m.getParameterTypes().size() != paramTypes.size()) return false;
        for (int i = 0; i < paramTypes.size(); i++) {
            if (!m.getParameterTypes().get(i).toString().equals(paramTypes.get(i))) return false;
        }
        return true;
    }

    private static void dfs(MethodSignature sig, List<MethodSignature> currentPath) {
        if (visited.contains(sig)) return;
        visited.add(sig);
        
        // Print every method visited for debugging
        System.out.println("[DFS] Visiting: " + sig);
        
        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) {
            System.out.println("  [DEBUG] Method not found directly, looking for inherited method");
            opt = findInheritedMethod(sig);
        }
        if (!opt.isPresent()) {
            System.out.println("  [WARN] Method not found: " + sig);
            return;
        }
        
        JavaSootMethod m = opt.get();
        System.out.println("  [DEBUG] Found method: " + m.getSignature());
        System.out.println("  [DEBUG] Has body: " + m.hasBody());
        System.out.println("  [DEBUG] Is native: " + m.getModifiers().contains(MethodModifier.NATIVE));
        
        if (m.getModifiers().contains(MethodModifier.NATIVE)) {
            foundNative.add(sig);
            nativePaths.add(new ArrayList<>(currentPath));
            allUniqueNativeMethods.add(sig);
            System.out.println("[DFS] *** FOUND NATIVE METHOD: " + sig + " ***");
            return;
        }
        
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

            int stmtCount = 0;
            for (Object stmtObj : body.getStmts()) {
                stmtCount++;
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        MethodSignature calleeSig = invokeExpr.getMethodSignature();
                        List<MethodSignature> newPath = new ArrayList<>(currentPath);
                        newPath.add(calleeSig);
                        dfs(calleeSig, newPath);
                    });
                }
            }
        } catch (Throwable t) {
            System.err.println("  [WARN] Could not analyze " + sig + ": " + t.getMessage());
            t.printStackTrace();
        }
    }

    private static Optional<JavaSootMethod> findInheritedMethod(MethodSignature sig) {
        String className = sig.getDeclClassType().getFullyQualifiedName();
        String methodName = sig.getName();
        return findInheritedMethodRecursive(className, methodName);
    }
    private static Optional<JavaSootMethod> findInheritedMethodRecursive(String className, String methodName) {
        for (JavaSootClass clazz : view.getClasses().collect(Collectors.toList())) {
            if (clazz.getType().getFullyQualifiedName().equals(className)) {
                for (JavaSootMethod method : clazz.getMethods()) {
                    if (method.getName().equals(methodName)) {
                        return Optional.of(method);
                    }
                }
                if (clazz.hasSuperclass()) {
                    String superClassName = clazz.getSuperclass().get().getFullyQualifiedName();
                    return findInheritedMethodRecursive(superClassName, methodName);
                }
                break;
            }
        }
        return Optional.empty();
    }
    private static boolean isSubclassOf(JavaClassType type, JavaClassType superType) {
        if (type.equals(superType)) return true;
        Optional<JavaSootClass> cls = view.getClass(type);
        if (!cls.isPresent()) return false;
        Optional<JavaClassType> superclass = cls.get().getSuperclass();
        return superclass.isPresent() && isSubclassOf(superclass.get(), superType);
    }
    private static boolean implementsInterface(JavaClassType type, JavaClassType interfaceType) {
        Optional<JavaSootClass> cls = view.getClass(type);
        if (!cls.isPresent()) return false;
        for (sootup.core.types.ClassType iface : cls.get().getInterfaces()) {
            if (iface instanceof JavaClassType && iface.equals(interfaceType)) {
                return true;
            }
        }
        Optional<JavaClassType> superclass = cls.get().getSuperclass();
        if (superclass.isPresent()) {
            return implementsInterface(superclass.get(), interfaceType);
        }
        return false;
    }
    private static String buildPathString(List<MethodSignature> path) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            if (i > 0) sb.append(" -> ");
            sb.append(path.get(i));
        }
        return sb.toString();
    }

    private static void printInvokeTree(MethodSignature sig, Set<MethodSignature> visited, int indent) {
        if (visited.contains(sig)) return;
        visited.add(sig);

        Optional<JavaSootMethod> opt = view.getMethod(sig);
        if (!opt.isPresent()) {
            printIndented(indent, "[WARN] Method not found: " + sig);
            return;
        }
        JavaSootMethod m = opt.get();
        printIndented(indent, sig.toString() + ":");
        if (!m.hasBody()) {
            printIndented(indent + 2, "[No body]");
            return;
        }
        
        try {
            Body body = m.getBody();
            if (body == null) {
                printIndented(indent + 2, "[Body is null]");
                return;
            }
            for (Object stmtObj : body.getStmts()) {
                if (stmtObj instanceof InvokableStmt) {
                    ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                        String invokeType = "Unknown";
                        if (invokeExpr instanceof JVirtualInvokeExpr) invokeType = "invokevirtual";
                        else if (invokeExpr instanceof JStaticInvokeExpr) invokeType = "invokestatic";
                        else if (invokeExpr instanceof JSpecialInvokeExpr) invokeType = "invokespecial";
                        else if (invokeExpr instanceof JInterfaceInvokeExpr) invokeType = "invokeinterface";
                        MethodSignature calleeSig = invokeExpr.getMethodSignature();
                        printIndented(indent + 2, invokeType + " // " + calleeSig);
                        // Recursively print the callee's invokes
                        try {
                            printInvokeTree(calleeSig, visited, indent + 4);
                        } catch (Throwable t) {
                            printIndented(indent + 4, "[ERROR] Could not analyze " + calleeSig + ": " + t.getClass().getSimpleName());
                        }
                    });
                }
            }
        } catch (Throwable t) {
            printIndented(indent + 2, "[ERROR] Could not analyze " + sig + ": " + t.getClass().getSimpleName());
        }
    }

    private static void printIndented(int indent, String msg) {
        for (int i = 0; i < indent; i++) System.out.print(" ");
        System.out.println(msg);
    }

    private static void writeUniqueNativeMethodsToFile(String filename, Set<MethodSignature> uniqueNativeMethods) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("=== Unique Native Methods Found ===");
            writer.println("Total unique native methods: " + uniqueNativeMethods.size());
            for (MethodSignature sig : uniqueNativeMethods) {
                writer.println(sig);
            }
            System.out.println("\nUnique native methods written to: " + filename);
        } catch (IOException e) {
            System.err.println("Error writing unique native methods to file: " + e.getMessage());
        }
    }
} 