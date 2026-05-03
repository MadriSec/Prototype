package com.echotrace.app.bytecode_new;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.views.View;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * JNA Direct Mapping Detector (Target-only analysis)
 *
 * Detects JNA direct-mapped native calls:
 *   class CLibrary {
 *       static { Native.register("c"); }
 *       public static native int strlen(String s);
 *   }
 *   CLibrary.strlen("hello")  ->  lib="c", symbol="strlen"
 *
 * The library name comes from Native.register("c") or
 * Native.register(NativeLibrary.getInstance("c", ...))
 * The symbol name is the native method name itself (JNA convention)
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaDirectMapDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]"
 *
 * Outputs:
 *   - jna_directmap_hits.txt   (native method declarations with lib/symbol/jar)
 *   - skipped_methods.txt      (methods that failed analysis)
 */
public class JnaDirectMapDetector {

    // Enable debug logging for troubleshooting
    private static final boolean DEBUG = false;

    // JNA class names for detection
    private static final String JNA_NATIVE  = "com.sun.jna.Native";
    private static final String JNA_NATIVE_LIBRARY = "com.sun.jna.NativeLibrary";

    // API pattern constants for classification
    private static final String API_REGISTER_STRING              = "Native.register(String)";
    private static final String API_REGISTER_CLASS_STRING        = "Native.register(Class,String)";
    private static final String API_REGISTER_NATIVELIBRARY       = "Native.register(NativeLibrary)";
    private static final String API_REGISTER_CLASS_NATIVELIBRARY = "Native.register(Class,NativeLibrary)";
    private static final String API_UNKNOWN                      = "<?>";

    // Track which classes call Native.register() and with what library name + API pattern
    // Key = fully qualified class name, Value = RegisterInfo(lib, apiPattern)
    private static final Map<String, RegisterInfo> CLASS_TO_REG = new HashMap<>();

    private static final class RegisterInfo {
        final String lib;
        final String apiPattern;
        RegisterInfo(String lib, String apiPattern) {
            this.lib = lib;
            this.apiPattern = apiPattern;
        }
    }

    /**
     * Main entry point for JNA direct mapping detector.
     *
     * Parses command line arguments, sets up the SootUp analysis environment,
     * and runs the two-pass analysis to detect JNA direct-mapped calls.
     *
     * @param args Command line arguments: <target-jars-dir> [outDir]
     * @throws IOException If file operations fail
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnaDirectMapDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir    = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        File hitsFile = new File(out, "jna_directmap_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Collect target jars
        List<String> targetJars = collectJarPaths(targetDir);

        System.out.println("[INFO] target jars: " + targetJars.size());

        // Index target classes for filtering (className -> jarPath)
        Map<String, String> classToJar = collectClassNamesFromJars(targetJars);
        Set<String> targetClassNames = classToJar.keySet();
        System.out.println("[INFO] target classes indexed: " + targetClassNames.size());

        // Build classpath from target jars
        String cp = toClassPath(targetJars);
        System.out.println("[INFO] sootup cp entries: " + targetJars.size());
        System.out.println("[INFO] scanning target classes for JNA direct-mapped calls");
        System.out.println("       target=" + targetDir);
        System.out.println("       out   =" + out.getAbsolutePath());

        // Setup SootUp analysis with target jars and JRE runtime
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(cp));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());

        JavaView view = new JavaView(inputs);

        // Process classes and write results to output files
        try (
                BufferedWriter hitW = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== JNA Direct Mapping Hits ===\n");
            hitW.write("Format: methodSig | lib | symbol | apiPattern | jar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            long classesSeen = 0;
            long targetClassesScanned = 0;
            long clinitScanned = 0;
            long hits = 0;
            long skipped = 0;

            // Collect target classes from the view
            List<SootClass> targetClasses = new ArrayList<>();
            for (Iterator<? extends SootClass> it = view.getClasses().iterator(); it.hasNext();) {
                SootClass sc = it.next();
                classesSeen++;
                String fqcn = sc.getType().getFullyQualifiedName();
                if (targetClassNames.contains(fqcn)) {
                    targetClasses.add(sc);
                }
            }
            targetClassesScanned = targetClasses.size();

            System.out.println("[INFO] collected " + targetClassesScanned + " target classes for analysis");

            // ============================================================
            // PASS 1: Process all <clinit> methods to find Native.register() calls
            // This captures: static { Native.register("c"); }
            //           and: static { Native.register(NativeLibrary.getInstance("c", ...)); }
            // ============================================================
            System.out.println("[PASS 1] Processing <clinit> methods to find Native.register() calls...");

            for (SootClass sc : targetClasses) {
                String className = sc.getType().getFullyQualifiedName();
                for (SootMethod m : sc.getMethods()) {
                    if (!m.getName().equals("<clinit>")) continue;
                    try {
                        if (!m.hasBody()) continue;
                        RegisterInfo regInfo = findRegisterCall(m);
                        if (regInfo != null) {
                            CLASS_TO_REG.put(className, regInfo);
                            if (DEBUG) {
                                System.out.println("[DBG] REGISTER: " + className + " -> lib=" + regInfo.lib + " api=" + regInfo.apiPattern);
                            }
                        }
                        clinitScanned++;
                    } catch (VerifyError e) {
                        skipped++;
                        skipW.write(m.getSignature() + " | VerifyError | " + e.getMessage() + "\n");
                    } catch (Exception e) {
                        skipped++;
                        skipW.write(m.getSignature() + " | " + e.getClass().getSimpleName() + " | " + e.getMessage() + "\n");
                    }
                }
            }
            System.out.println("[PASS 1] Scanned " + clinitScanned + " <clinit> methods");
            System.out.println("[PASS 1] Found " + CLASS_TO_REG.size() + " classes with Native.register()");

            // ============================================================
            // PASS 2: For each class with Native.register(), find all native methods
            // ============================================================
            System.out.println("[PASS 2] Collecting native methods from registered classes...");

            for (SootClass sc : targetClasses) {
                String className = sc.getType().getFullyQualifiedName();
                RegisterInfo regInfo = CLASS_TO_REG.get(className);
                if (regInfo == null) continue; // Class doesn't call Native.register()

                String jarFile = classToJar.get(className);

                // Find all native methods in this class
                for (SootMethod m : sc.getMethods()) {
                    if (!m.isNative()) continue;

                    String methodSig = m.getSignature().toString();
                    String symbol = m.getName(); // Symbol = method name

                    hits++;
                    hitW.write(methodSig + " | " + regInfo.lib + " | " + symbol + " | " + regInfo.apiPattern + " | " + jarFile + "\n");

                    if (DEBUG) {
                        System.out.println("[DBG] HIT: " + methodSig + " | lib=" + regInfo.lib + " | symbol=" + symbol + " | api=" + regInfo.apiPattern);
                    }
                }
            }

            System.out.println("[INFO] total JNA direct-mapped hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Scans a <clinit> method for calls to Native.register(...).
     *
     * Looks for invocations of:
     *   - Native.register(String libName)
     *   - Native.register(Class, String libName)
     *   - Native.register(NativeLibrary)
     *   - Native.register(Class, NativeLibrary)
     *
     * Tracks string literals passed as the library name argument.
     * Also tracks NativeLibrary.getInstance(String, ...) calls to resolve
     * the library name when Native.register(NativeLibrary) is used.
     *
     * @param clinit The <clinit> method to analyze
     * @return RegisterInfo with lib name and API pattern, or null if no register call found
     */
    private static RegisterInfo findRegisterCall(SootMethod clinit) {
        Map<Local, String> localToString = new HashMap<>();
        Map<Local, String> nativeLibraryToLib = new HashMap<>();  // Track NativeLibrary objects

        for (Stmt stmt : clinit.getBody().getStmts()) {
            // Track local = StringConstant
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = as.getRightOp();

                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    String str = ((StringConstant) rhs).getValue();
                    localToString.put((Local) lhs, str);
                }

                // Track local = NativeLibrary.getInstance(String libName, ...)
                if (lhs instanceof Local && rhs instanceof AbstractInvokeExpr) {
                    AbstractInvokeExpr inv = (AbstractInvokeExpr) rhs;
                    MethodSignature sig = inv.getMethodSignature();
                    String declClass = sig.getDeclClassType().getFullyQualifiedName();
                    String methodName = sig.getName();

                    if (declClass.equals(JNA_NATIVE_LIBRARY) && methodName.equals("getInstance")) {
                        List<Immediate> args = inv.getArgs();
                        if (!args.isEmpty()) {
                            Immediate firstArg = args.get(0);
                            String libName = null;

                            if (firstArg instanceof StringConstant) {
                                libName = ((StringConstant) firstArg).getValue();
                            } else if (firstArg instanceof Local) {
                                libName = localToString.get((Local) firstArg);
                            }

                            if (libName != null) {
                                nativeLibraryToLib.put((Local) lhs, libName);
                                if (DEBUG) {
                                    System.out.println("[DBG] NativeLibrary.getInstance: " + lhs + " -> lib=" + libName);
                                }
                            }
                        }
                    }
                }
            }

            // Look for Native.register(...) invocations
            AbstractInvokeExpr inv = getInvoke(stmt);

            if (inv != null) {
                MethodSignature sig = inv.getMethodSignature();
                String declClass = sig.getDeclClassType().getFullyQualifiedName();
                String methodName = sig.getName();

                if (declClass.equals(JNA_NATIVE) && methodName.equals("register")) {
                    List<Immediate> args = inv.getArgs();
                    int argCount = args.size();

                    // Classify by checking parameter types
                    List<?> paramTypes = sig.getSubSignature().getParameterTypes();
                    boolean hasClassParam = !paramTypes.isEmpty()
                            && paramTypes.get(0).toString().equals("java.lang.Class");

                    // Try to resolve String argument (Pattern 1 & 2)
                    for (Immediate arg : args) {
                        if (arg instanceof StringConstant) {
                            String lib = ((StringConstant) arg).getValue();
                            String api = hasClassParam ? API_REGISTER_CLASS_STRING : API_REGISTER_STRING;
                            return new RegisterInfo(lib, api);
                        }
                        if (arg instanceof Local) {
                            String str = localToString.get((Local) arg);
                            if (str != null) {
                                String api = hasClassParam ? API_REGISTER_CLASS_STRING : API_REGISTER_STRING;
                                return new RegisterInfo(str, api);
                            }
                        }
                    }

                    // Try NativeLibrary argument (Pattern 3 & 4)
                    for (Immediate arg : args) {
                        if (arg instanceof Local) {
                            String libName = nativeLibraryToLib.get((Local) arg);
                            if (libName != null) {
                                String api = hasClassParam ? API_REGISTER_CLASS_NATIVELIBRARY : API_REGISTER_NATIVELIBRARY;
                                if (DEBUG) {
                                    System.out.println("[DBG] Resolved " + api + " -> lib=" + libName);
                                }
                                return new RegisterInfo(libName, api);
                            }
                        }
                    }

                    // Couldn't resolve library name
                    return new RegisterInfo("<?>", API_UNKNOWN);
                }
            }
        }

        return null;
    }

    // ------------------- Jar scanning helpers -------------------

    /**
     * Recursively collects all JAR file paths from a directory.
     *
     * Uses a non-recursive stack-based approach to traverse the directory tree
     * and collect all files ending with ".jar".
     *
     * @param dirPath The root directory to scan
     * @return Sorted list of absolute paths to JAR files
     */
    private static List<String> collectJarPaths(String dirPath) {
        List<String> jars = new ArrayList<>();
        File root = new File(dirPath);

        if (!root.exists() || !root.isDirectory()) {
            System.err.println("[ERROR] Invalid directory: " + dirPath);
            return jars;
        }

        Stack<File> stack = new Stack<>();
        stack.push(root);

        while (!stack.isEmpty()) {
            File cur = stack.pop();
            File[] files = cur.listFiles();
            if (files == null) continue;
            for (File f : files) {
                if (f.isDirectory()) stack.push(f);
                else if (f.getName().endsWith(".jar")) jars.add(f.getAbsolutePath());
            }
        }

        Collections.sort(jars);
        return jars;
    }

    /**
     * Extracts all class names from a list of JAR files.
     *
     * Scans each JAR file's entries and collects fully qualified class names
     * by converting .class file paths to dot-separated package names.
     * Excludes module-info.class files. Maps each class to its source JAR.
     *
     * @param jarPaths List of JAR file paths to scan
     * @return Map of fully qualified class names to their source JAR file paths
     */
    private static Map<String, String> collectClassNamesFromJars(List<String> jarPaths) {
        Map<String, String> classToJar = new HashMap<>();
        for (String jar : jarPaths) {
            // Extract just the JAR filename for cleaner output
            String jarName = new File(jar).getName();
            try (ZipFile zf = new ZipFile(jar)) {
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    String name = e.getName();
                    if (name.endsWith(".class") && !name.contains("module-info")) {
                        String cls = name.substring(0, name.length() - 6).replace('/', '.');
                        classToJar.put(cls, jarName);
                    }
                }
            } catch (Exception ex) {
                System.err.println("[WARN] failed reading jar: " + jar + " :: " + ex.getMessage());
            }
        }
        return classToJar;
    }

    /**
     * Converts a list of paths to a classpath string.
     *
     * Joins the paths using the system's path separator (: on Unix, ; on Windows).
     *
     * @param entries List of paths to join
     * @return Classpath string
     */
    private static String toClassPath(List<String> entries) {
        String sep = System.getProperty("path.separator");
        return entries.stream().collect(Collectors.joining(sep));
    }

    /**
     * Extracts the invoke expression from a statement.
     *
     * Handles both JInvokeStmt (standalone calls) and JAssignStmt (calls with return values).
     * Also handles Optional wrapping that may occur in some SootUp versions.
     *
     * @param stmt The statement to extract from
     * @return The invoke expression, or null if not an invoke statement
     */
    private static AbstractInvokeExpr getInvoke(Stmt stmt) {
        if (stmt instanceof JInvokeStmt) {
            Object ie = ((JInvokeStmt) stmt).getInvokeExpr();
            if (ie instanceof AbstractInvokeExpr) return (AbstractInvokeExpr) ie;
            if (ie instanceof Optional) {
                Object val = ((Optional<?>) ie).orElse(null);
                return (val instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) val : null;
            }
        } else if (stmt instanceof JAssignStmt) {
            Value rhs = ((JAssignStmt) stmt).getRightOp();
            if (rhs instanceof AbstractInvokeExpr) {
                return (AbstractInvokeExpr) rhs;
            }
        }
        return null;
    }
}
