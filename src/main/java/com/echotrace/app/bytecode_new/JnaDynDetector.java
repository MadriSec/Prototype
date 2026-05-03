package com.echotrace.app.bytecode_new;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.java.core.views.JavaView;

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

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * JNA Dynamic Use Detector (Target-only analysis)
 *
 * Detects dynamic JNA boundary calls:
 *   com.sun.jna.Function.invoke*
 *
 * Recovers (library, symbol) when constant:
 *   NativeLibrary.getInstance("c") -> getFunction("strlen") -> Function.invoke*()
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaDynDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]"
 *
 * Outputs (in outDir, default=current dir):
 *   - jna_dyn_hits.txt
 *   - skipped_methods.txt
 */
public class JnaDynDetector {

    // Enable debug logging for troubleshooting
    private static final boolean DEBUG = false;

    // JNA class names for detection
    private static final String JNA_NATIVE_LIBRARY = "com.sun.jna.NativeLibrary";
    private static final String JNA_FUNCTION       = "com.sun.jna.Function";

    // JNA library prefix — hits from these classes are JNA framework/platform code, not app FFI
    private static final String JNA_CORE_PREFIX     = "com.sun.jna.";

    // API pattern constants for classification (one per overload)
    private static final String API_NATIVELIB_GETFUNCTION             = "NativeLibrary.getFunction";
    private static final String API_FN_GETFUNCTION_PTR                = "Function.getFunction(Pointer)";
    private static final String API_FN_GETFUNCTION_PTR_INT            = "Function.getFunction(Pointer,int)";
    private static final String API_FN_GETFUNCTION_STR_STR            = "Function.getFunction(String,String)";
    private static final String API_FN_GETFUNCTION_STR_STR_INT        = "Function.getFunction(String,String,int)";
    private static final String API_FN_GETFUNCTION_STR_STR_INT_STR    = "Function.getFunction(String,String,int,String)";
    private static final String API_UNKNOWN                           = "<?>";

    // Progress logging intervals
    private static final long HEARTBEAT_MS = 5000;
    private static final int  METHOD_TICK  = 50_000;

    // Global field taint tracking (key = fieldRef.toString() -> library/function info)
    // This persists across methods so that <clinit> assignments are visible to other methods
    private static final Map<String, String> FIELD_TO_LIB = new HashMap<>();
    private static final Map<String, FuncInfo> FIELD_TO_FUNC = new HashMap<>();

    /**
     * Main entry point for JNA dynamic detector.
     *
     * Parses command line arguments, sets up the SootUp analysis environment,
     * and runs the two-pass analysis to detect JNA dynamic calls.
     *
     * @param args Command line arguments: <target-jars-dir> [outDir]
     * @throws IOException If file operations fail
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 1) { 
            System.err.println("Usage: JnaDynDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir    = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        File hitsFile = new File(out, "jna_dyn_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Collect target jars
        List<String> targetJars = collectJarPaths(targetDir);

        System.out.println("[INFO] target jars: " + targetJars.size());

        // Index target classes for filtering
        Set<String> targetClassNames = collectClassNamesFromJars(targetJars);
        System.out.println("[INFO] target classes indexed: " + targetClassNames.size());

        // Build classpath from target jars
        String cp = toClassPath(targetJars);
        System.out.println("[INFO] sootup cp entries: " + targetJars.size());
        System.out.println("[INFO] scanning target classes");
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
            hitW.write("=== JNA Dynamic Hits (Function.invoke*) ===\n");
            hitW.write("Format: callerSig | lib | symbol | apiPattern | sinkSig | stmt\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions during body building) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();
            final long[] lastBeat = { System.currentTimeMillis() };

            long classesSeen = 0;
            long targetClassesScanned = 0;
            long methodsSeen = 0;
            long methodsScanned = 0;

            long hits = 0;
            long jnaInternalFiltered = 0;
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
            // PASS 1: Process all <clinit> methods first to populate field maps
            // This ensures static field taints are available when analyzing other methods
            // ============================================================
            System.out.println("[PASS 1] Processing <clinit> methods to populate field taints...");
            int clinitCount = 0;
            for (SootClass sc : targetClasses) {
                for (SootMethod m : sc.getMethods()) {
                    if (!m.getName().equals("<clinit>")) continue;
                    try {
                        if (!m.hasBody()) continue;
                        analyzeMethod(m);
                        clinitCount++;
                    } catch (VerifyError ignored) {
                    } catch (Exception ignored) {
                    }
                }
            }
            System.out.println("[PASS 1] Processed " + clinitCount + " <clinit> methods");
            System.out.println("[PASS 1] Field taints: FIELD_TO_LIB=" + FIELD_TO_LIB.size() + ", FIELD_TO_FUNC=" + FIELD_TO_FUNC.size());

            // ============================================================
            // PASS 2: Process all methods and collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for JNA hits...");
            for (SootClass sc : targetClasses) {
                // Skip hits from all JNA library classes (com.sun.jna.* including platform).
                // We still analyze them for field-taint side effects, just don't report hits.
                String fqcn = sc.getType().getFullyQualifiedName();
                boolean isJnaInternal = fqcn.startsWith(JNA_CORE_PREFIX);

                for (SootMethod m : sc.getMethods()) {
                    methodsSeen++;

                    long now = System.currentTimeMillis();
                    if (methodsSeen % METHOD_TICK == 0) {
                        long elapsed = (now - start) / 1000;
                        System.out.println("[PROGRESS] elapsed=" + elapsed + "s"
                                + " classesSeen=" + classesSeen
                                + " targetClasses=" + targetClassesScanned
                                + " methodsSeen=" + methodsSeen
                                + " methodsScanned=" + methodsScanned
                                + " hits=" + hits
                                + " skipped=" + skipped);
                    }
                    if (now - lastBeat[0] >= HEARTBEAT_MS) {
                        long elapsed = (now - start) / 1000;
                        System.out.println("[HEARTBEAT] elapsed=" + elapsed + "s"
                                + " targetClasses=" + targetClassesScanned
                                + " methodsSeen=" + methodsSeen
                                + " methodsScanned=" + methodsScanned
                                + " hits=" + hits
                                + " skipped=" + skipped);
                        lastBeat[0] = now;
                    }

                    try {
                        if (!m.hasBody()) continue;
                        methodsScanned++;

                        // Analyze and stream hits
                        List<Hit> found = analyzeMethod(m);
                        if (!found.isEmpty()) {
                            if (isJnaInternal) {
                                // JNA framework internals (e.g. Function.invokeDouble -> Function.invoke)
                                // These are internal delegation, not app FFI crossings.
                                jnaInternalFiltered += found.size();
                            } else {
                                for (Hit h : found) {
                                    hits++;
                                    hitW.write(h.callerSig);
                                    hitW.write(" | ");
                                    hitW.write(h.lib);
                                    hitW.write(" | ");
                                    hitW.write(h.symbol);
                                    hitW.write(" | ");
                                    hitW.write(h.apiPattern);
                                    hitW.write(" | ");
                                    hitW.write(h.sinkSig);
                                    hitW.write(" | ");
                                    hitW.write(h.stmt);
                                    hitW.write("\n");
                                }
                                hitW.flush();
                            }
                        }

                    } catch (VerifyError ve) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), ve);

                    } catch (RuntimeException re) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), re);

                    } catch (Exception e) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }
            }

            hitW.flush();
            skipW.flush();

            System.out.println("[INFO] total dynamic-JNA hits: " + hits);
            System.out.println("[INFO] JNA-internal filtered:  " + jnaInternalFiltered);
            System.out.println("[INFO] skipped methods (errors/verify): " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Writes a skipped method entry to the skip log file.
     *
     * Formats the exception information and writes it in a consistent format
     * for later analysis of methods that couldn't be processed.
     *
     * @param w         The BufferedWriter for the skip log file
     * @param methodSig The signature of the method that was skipped
     * @param t         The throwable that caused the skip
     * @throws IOException If writing fails
     */
    private static void writeSkip(BufferedWriter w, String methodSig, Throwable t) throws IOException {
        String msg = (t.getMessage() == null) ? "" : t.getMessage().replace('\n', ' ').replace('\r', ' ');
        w.write(methodSig);
        w.write(" | ");
        w.write(t.getClass().getName());
        w.write(" | ");
        w.write(msg);
        w.write("\n");

        if (DEBUG) {
            System.err.println("[SKIPPED] " + methodSig + " :: " + t.getClass().getSimpleName() + " " + msg);
        }
    }

    /**
     * Analyzes a single method for JNA dynamic calls.
     *
     * Performs intra-procedural taint tracking to resolve library and symbol names
     * for JNA Function.invoke* calls. Tracks:
     * - NativeLibrary.getInstance("lib") calls to map locals/fields to library names
     * - NativeLibrary.getFunction("sym") calls to map locals/fields to function info
     * - Local-to-local and local-to-field propagation
     * - Field loads (getstatic/getfield) to recover taint info from static fields
     *
     * @param m The SootMethod to analyze
     * @return List of JNA dynamic call hits found in the method
     */
    private static List<Hit> analyzeMethod(SootMethod m) {
        // Local variable taint maps
        Map<Local, String> nlToLib = new HashMap<>();
        Map<Local, FuncInfo> fnToInfo = new HashMap<>();
        Map<Local, String> localToString = new HashMap<>();
        List<Hit> hits = new ArrayList<>();

        for (Stmt stmt : m.getBody().getStmts()) {

            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs0 = as.getRightOp();
                Value rhs = unwrapCasts(rhs0);

                // ---- CASE 1: local = something ----
                if (lhs instanceof Local) {
                    Local l = (Local) lhs;

                    // local = StringConstant (track for resolving args later)
                    if (rhs instanceof StringConstant) {
                        localToString.put(l, ((StringConstant) rhs).getValue());
                    }

                    // local = invoke
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().toString();
                        String name = sig.getName();

                        // nl = NativeLibrary.getInstance("c")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && name.equals("getInstance")) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) nlToLib.put(l, lib);
                        }

                        // fn = nl.getFunction("strlen")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && name.equals("getFunction")) {
                            String lib = resolveLibFromInvokeBase(inv, nlToLib);
                            String sym = resolveStringArg(inv, localToString, 0);
                            fnToInfo.put(l, new FuncInfo(lib, sym, API_NATIVELIB_GETFUNCTION));
                        }

                        // fn = Function.getFunction(...) -- 5 static overloads
                        if (JNA_FUNCTION.equals(decl) && name.equals("getFunction")) {
                            FuncInfo fi = classifyFunctionGetFunction(inv, localToString);
                            fnToInfo.put(l, fi);
                        }
                    }

                    // local = local propagation
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (nlToLib.containsKey(r)) nlToLib.put(l, nlToLib.get(r));
                        if (fnToInfo.containsKey(r)) fnToInfo.put(l, fnToInfo.get(r));
                        if (localToString.containsKey(r)) localToString.put(l, localToString.get(r));
                    }

                    // local = getstatic/getfield (load from field)
                    if (isFieldRef(rhs)) {
                        String fkey = fieldKey(rhs);
                        if (FIELD_TO_LIB.containsKey(fkey)) nlToLib.put(l, FIELD_TO_LIB.get(fkey));
                        if (FIELD_TO_FUNC.containsKey(fkey)) fnToInfo.put(l, FIELD_TO_FUNC.get(fkey));
                    }
                }

                // ---- CASE 2: field = something (putstatic/putfield) ----
                if (isFieldRef(lhs)) {
                    String fkey = fieldKey(lhs);

                    // field = invoke
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().toString();
                        String name = sig.getName();

                        // FIELD = NativeLibrary.getInstance("c")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && name.equals("getInstance")) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                FIELD_TO_LIB.put(fkey, lib);
                                if (DEBUG) System.out.println("[DBG] FIELD_TO_LIB: " + fkey + " -> " + lib);
                            }
                        }

                        // FIELD = nl.getFunction("sym")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && name.equals("getFunction")) {
                            String lib = resolveLibFromInvokeBase(inv, nlToLib);
                            String sym = resolveStringArg(inv, localToString, 0);
                            FIELD_TO_FUNC.put(fkey, new FuncInfo(lib, sym, API_NATIVELIB_GETFUNCTION));
                            if (DEBUG) System.out.println("[DBG] FIELD_TO_FUNC: " + fkey + " -> (" + lib + ", " + sym + ")");
                        }

                        // FIELD = Function.getFunction(...) -- 5 static overloads
                        if (JNA_FUNCTION.equals(decl) && name.equals("getFunction")) {
                            FuncInfo fi = classifyFunctionGetFunction(inv, localToString);
                            FIELD_TO_FUNC.put(fkey, fi);
                            if (DEBUG) System.out.println("[DBG] FIELD_TO_FUNC (static factory): " + fkey
                                    + " -> (" + fi.lib + ", " + fi.sym + ", " + fi.apiPattern + ")");
                        }
                    }

                    // field = local
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (nlToLib.containsKey(r)) FIELD_TO_LIB.put(fkey, nlToLib.get(r));
                        if (fnToInfo.containsKey(r)) FIELD_TO_FUNC.put(fkey, fnToInfo.get(r));
                    }
                }
            }

            // ---- Handle sink: Function.invoke* ----
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature sinkSig = inv.getMethodSignature();
            String decl = sinkSig.getDeclClassType().toString();
            String name = sinkSig.getName();

            // sink: com.sun.jna.Function.invoke*
            if (JNA_FUNCTION.equals(decl) && name.startsWith("invoke")) {
                FuncInfo fi = resolveFuncInfoFromInvoke(inv, fnToInfo);

                String lib = (fi != null && fi.lib != null) ? fi.lib : "<?>";
                String sym = (fi != null && fi.sym != null) ? fi.sym : "<?>";
                String api = (fi != null && fi.apiPattern != null) ? fi.apiPattern : API_UNKNOWN;

                hits.add(new Hit(
                        m.getSignature().toString(),
                        lib,
                        sym,
                        api,
                        sinkSig.toString(),
                        stmt.toString()
                ));
            }
        }

        return hits;
    }

    /**
     * Resolves the library name from an invoke expression's base object.
     *
     * First checks if the base local is in the local taint map, then falls back
     * to checking field references in the invoke's uses against the global field map.
     *
     * @param inv     The invoke expression to resolve
     * @param nlToLib Map of local variables to library names
     * @return The library name if found, null otherwise
     */
    private static String resolveLibFromInvokeBase(AbstractInvokeExpr inv, Map<Local, String> nlToLib) {
        // Try local first
        Local base = getInvokeBaseLocal(inv);
        if (base != null && nlToLib.containsKey(base)) {
            return nlToLib.get(base);
        }

        // Try field refs in uses
        Optional<String> fromField = inv.getUses()
                .filter(JnaDynDetector::isFieldRef)
                .map(JnaDynDetector::fieldKey)
                .map(FIELD_TO_LIB::get)
                .filter(Objects::nonNull)
                .findFirst();

        return fromField.orElse(null);
    }

    /**
     * Resolves the function info (library + symbol) from an invoke expression.
     *
     * First checks if the base local is in the local taint map, then falls back
     * to checking field references in the invoke's uses against the global field map.
     *
     * @param inv      The invoke expression to resolve
     * @param fnToInfo Map of local variables to FuncInfo objects
     * @return The FuncInfo if found, null otherwise
     */
    private static FuncInfo resolveFuncInfoFromInvoke(AbstractInvokeExpr inv, Map<Local, FuncInfo> fnToInfo) {
        // Try local first
        Local base = getInvokeBaseLocal(inv);
        if (base != null && fnToInfo.containsKey(base)) {
            return fnToInfo.get(base);
        }

        // Try field refs in uses
        Optional<FuncInfo> fromField = inv.getUses()
                .filter(JnaDynDetector::isFieldRef)
                .map(JnaDynDetector::fieldKey)
                .map(FIELD_TO_FUNC::get)
                .filter(Objects::nonNull)
                .findFirst();

        return fromField.orElse(null);
    }

    // ----------------- Jimple helpers -----------------

    /**
     * Casts a Value to AbstractInvokeExpr if it is one.
     *
     * @param v The Value to check
     * @return The AbstractInvokeExpr or null if not an invoke
     */
    private static AbstractInvokeExpr asInvoke(Value v) {
        return (v instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) v : null;
    }

    /**
     * Extracts the invoke expression from a statement.
     *
     * Handles both JInvokeStmt (standalone calls) and JAssignStmt (calls with return values).
     * Also handles Optional wrapping that may occur in some SootUp versions.
     *
     * @param stmt The statement to extract from
     * @return The AbstractInvokeExpr or null if not present
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
            return asInvoke(((JAssignStmt) stmt).getRightOp());
        }
        return null;
    }

    /**
     * Resolves a string argument from an invoke expression at the given index.
     *
     * Checks if the argument is a StringConstant first, then falls back to
     * looking up the local in the localToString taint map.
     *
     * @param inv           The invoke expression
     * @param localToString Map of locals to their string constant values
     * @param argIndex      The argument index to resolve
     * @return The string value if resolvable, null otherwise
     */
    private static String resolveStringArg(AbstractInvokeExpr inv,
                                            Map<Local, String> localToString,
                                            int argIndex) {
        List<Immediate> args = inv.getArgs();
        if (args.size() <= argIndex) return null;

        Immediate arg = args.get(argIndex);
        if (arg instanceof StringConstant) {
            return ((StringConstant) arg).getValue();
        }
        if (arg instanceof Local) {
            return localToString.get((Local) arg);
        }
        return null;
    }

    /**
     * Classifies a Function.getFunction(...) static invoke and extracts args.
     *
     * 5 overloads, each mapped to its own API pattern:
     *   1. getFunction(Pointer p)                                        -> NOT resolvable
     *   2. getFunction(Pointer p, int callFlags)                         -> NOT resolvable
     *   3. getFunction(String libraryName, String functionName)          -> resolvable
     *   4. getFunction(String libraryName, String functionName, int)     -> resolvable
     *   5. getFunction(String libraryName, String functionName, int, String) -> resolvable
     *
     * @param inv           The invoke expression for Function.getFunction(...)
     * @param localToString Map of locals to their string constant values
     * @return FuncInfo with lib, sym, and apiPattern filled in
     */
    private static FuncInfo classifyFunctionGetFunction(AbstractInvokeExpr inv,
                                                         Map<Local, String> localToString) {
        MethodSignature sig = inv.getMethodSignature();

        // Distinguish by first parameter type and param count
        List<?> paramTypes = sig.getSubSignature().getParameterTypes();
        int paramCount = paramTypes.size();

        if (paramCount == 0) {
            return new FuncInfo("<?>", "<?>", API_UNKNOWN);
        }

        String firstParamType = paramTypes.get(0).toString();

        // String-based overloads: resolvable
        if ("java.lang.String".equals(firstParamType)) {
            String lib = resolveStringArg(inv, localToString, 0);
            String sym = resolveStringArg(inv, localToString, 1);

            String api;
            switch (paramCount) {
                case 2: api = API_FN_GETFUNCTION_STR_STR;         break;
                case 3: api = API_FN_GETFUNCTION_STR_STR_INT;     break;
                case 4: api = API_FN_GETFUNCTION_STR_STR_INT_STR; break;
                default: api = API_UNKNOWN;                        break;
            }
            return new FuncInfo(lib, sym, api);
        }

        // Pointer-based overloads: NOT resolvable
        if (firstParamType.contains("Pointer")) {
            String api = (paramCount == 1) ? API_FN_GETFUNCTION_PTR : API_FN_GETFUNCTION_PTR_INT;
            return new FuncInfo("<?>", "<?>", api);
        }

        // Fallback: unknown overload
        return new FuncInfo("<?>", "<?>", API_UNKNOWN);
    }

    /**
     * Extracts the base local (receiver) from an instance invoke expression.
     *
     * Uses reflection to handle different SootUp API versions that may have
     * different methods for accessing the base object. Falls back to searching
     * the uses stream if direct methods don't work.
     *
     * @param inv The invoke expression
     * @return The base Local or null if not found or static invoke
     */
    private static Local getInvokeBaseLocal(AbstractInvokeExpr inv) {
        Value base = tryInvokeValue(inv, "getBase");
        if (base instanceof Local) return (Local) base;

        Object baseBox = tryInvokeObj(inv, "getBaseBox");
        if (baseBox != null) {
            Object v = tryInvokeObj(baseBox, "getValue");
            if (v instanceof Local) return (Local) v;
            if (v instanceof Value && v instanceof Local) return (Local) v;
        }

        return inv.getUses().filter(u -> u instanceof Local).map(u -> (Local) u).findFirst().orElse(null);
    }

    /**
     * Attempts to invoke a method that returns a Value via reflection.
     *
     * Used for API compatibility across SootUp versions.
     *
     * @param target The object to invoke the method on
     * @param method The method name to invoke
     * @return The Value result or null if invocation fails
     */
    private static Value tryInvokeValue(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            Object r = m.invoke(target);
            return (r instanceof Value) ? (Value) r : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Attempts to invoke a method that returns an Object via reflection.
     *
     * Used for API compatibility across SootUp versions.
     *
     * @param target The object to invoke the method on
     * @param method The method name to invoke
     * @return The Object result or null if invocation fails
     */
    private static Object tryInvokeObj(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            return m.invoke(target);
        } catch (Exception ignored) {
            return null;
        }
    }

    // ----------------- Field reference helpers -----------------

    /**
     * Checks if a Value is a field reference (static or instance).
     *
     * Works across SootUp API versions by checking the class name
     * rather than using instanceof with specific types.
     *
     * @param v The Value to check
     * @return true if it's a field reference, false otherwise
     */
    private static boolean isFieldRef(Value v) {
        if (v == null) return false;
        return v.getClass().getName().contains("FieldRef");
    }

    /**
     * Gets a stable string key for a field reference.
     *
     * Used as a map key to track field taints across methods.
     * The string representation includes class and field name.
     *
     * @param fieldRef The field reference Value
     * @return A string key for the field
     */
    private static String fieldKey(Value fieldRef) {
        return fieldRef.toString();
    }

    /**
     * Unwraps cast expressions to get the underlying value.
     *
     * Common in <clinit> methods where values are cast before being stored
     * to static fields (e.g., checkcast then putstatic). Iterates up to 8 times
     * to handle nested casts.
     *
     * @param v The Value that may be wrapped in casts
     * @return The unwrapped Value
     */
    private static Value unwrapCasts(Value v) {
        Value cur = v;
        for (int i = 0; i < 8 && cur != null; i++) {
            String cn = cur.getClass().getName().toLowerCase(Locale.ROOT);
            if (!cn.contains("cast")) break;

            Value inner = tryInvokeValue(cur, "getOp");
            if (inner == null) inner = tryInvokeValue(cur, "getOperand");
            if (inner == null) inner = tryInvokeValue(cur, "getValue");

            if (inner == null) break;
            cur = inner;
        }
        return cur;
    }

    /**
     * Holds function information: library name and symbol name.
     *
     * Used to track the library and symbol associated with a JNA Function object.
     */
    private static final class FuncInfo {
        final String lib;
        final String sym;
        final String apiPattern;

        FuncInfo(String lib, String sym, String apiPattern) {
            this.lib = lib;
            this.sym = sym;
            this.apiPattern = apiPattern;
        }
    }

    /**
     * Represents a detected JNA dynamic call hit.
     *
     * Contains all information about a detected Function.invoke* call including
     * the caller method, resolved library/symbol names, and the statement.
     */
    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String apiPattern;
        final String sinkSig;
        final String stmt;

        Hit(String callerSig, String lib, String symbol, String apiPattern, String sinkSig, String stmt) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.apiPattern = apiPattern;
            this.sinkSig = sinkSig;
            this.stmt = stmt;
        }
    }

    // ----------------- Jar scanning helpers -----------------

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
            System.err.println("[WARN] not a directory: " + dirPath);
            return jars;
        }

        Deque<File> stack = new ArrayDeque<>();
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
     * Excludes module-info.class files.
     *
     * @param jarPaths List of JAR file paths to scan
     * @return Set of fully qualified class names
     */
    private static Set<String> collectClassNamesFromJars(List<String> jarPaths) {
        Set<String> classes = new HashSet<>();
        for (String jar : jarPaths) {
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(jar)) {
                java.util.Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    java.util.zip.ZipEntry e = en.nextElement();
                    String name = e.getName();
                    if (name.endsWith(".class") && !name.contains("module-info")) {
                        String cls = name.substring(0, name.length() - 6).replace('/', '.');
                        classes.add(cls);
                    }
                }
            } catch (Exception ex) {
                System.err.println("[WARN] failed reading jar for class index: " + jar + " :: " + ex.getMessage());
            }
        }
        return classes;
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
}
