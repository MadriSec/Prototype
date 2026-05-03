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
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * JNA Interface Mapping Detector (Target-only analysis)
 *
 * Detects JNA interface-based native calls:
 *   interface CLib extends Library { int strlen(String s); }
 *   CLib.INSTANCE.strlen("hello")  ->  lib="c", symbol="strlen"
 *
 * The library name comes from Native.load("c", CLib.class)
 * The symbol name is the method name itself (JNA convention)
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaIfaceDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]"
 *
 * Outputs:
 *   - jna_iface_hits.txt   (interface method calls with lib/symbol/jar)
 *   - skipped_methods.txt  (methods that failed analysis)
 */
public class JnaIfaceDetector {

    // Enable debug logging for troubleshooting
    private static final boolean DEBUG = false;

    // JNA class names for detection
    private static final String JNA_NATIVE  = "com.sun.jna.Native";
    private static final String JNA_LIBRARY = "com.sun.jna.Library";

    // Methods that load native libraries
    private static final Set<String> LOAD_METHODS = new HashSet<>(Arrays.asList("load", "loadLibrary"));
    // Methods that wrap library instances
    private static final Set<String> WRAPPER_METHODS = new HashSet<>(Collections.singletonList("synchronizedLibrary"));

    // API pattern constants for classification
    private static final String API_NATIVE_LOAD_STR_CLASS           = "Native.load(String,Class)";
    private static final String API_NATIVE_LOAD_CLASS               = "Native.load(Class)";
    private static final String API_NATIVE_LOAD_CLASS_MAP           = "Native.load(Class,Map)";
    private static final String API_NATIVE_LOAD_NULL                = "Native.load(null,Class)";
    private static final String API_NATIVE_LOADLIBRARY_STR_CLASS    = "Native.loadLibrary(String,Class)";
    private static final String API_NATIVE_LOADLIBRARY_CLASS        = "Native.loadLibrary(Class)";
    private static final String API_NATIVE_SYNCHRONIZED_LIBRARY     = "Native.synchronizedLibrary(Library)";
    private static final String API_UNKNOWN                         = "<?>";

    // Progress logging intervals
    private static final long HEARTBEAT_MS = 5000;
    private static final int  METHOD_TICK  = 50_000;

    // Global field taint tracking (persists across methods for <clinit> -> usage pattern)
    private static final Map<String, LoadInfo> FIELD_TAINT = new HashMap<>();

    // Track string values assigned to static fields (for conditional assignments like Platform.isWindows() ? "msvcrt" : "c")
    private static final Map<String, Set<String>> FIELD_STRING_VALUES = new HashMap<>();

    // Track accessor method return values (e.g., access$000 -> returns LIBRARY_NAME field)
    private static final Map<String, String> ACCESSOR_TO_FIELD = new HashMap<>();

    /**
     * Main entry point for JNA interface detector.
     *
     * Parses command line arguments, sets up the SootUp analysis environment,
     * and runs the three-pass analysis to detect JNA interface-based calls.
     *
     * @param args Command line arguments: <target-jars-dir> [outDir]
     * @throws IOException If file operations fail
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnaIfaceDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir    = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        File hitsFile = new File(out, "jna_iface_hits.txt");
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
        System.out.println("[INFO] scanning target classes for JNA interface calls");
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
            hitW.write("=== JNA Interface Mapping Hits ===\n");
            hitW.write("Format: callerSig | lib | symbol | apiPattern | interface | calleeSig | callerJar | calleeJar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();
            final long[] lastBeat = { System.currentTimeMillis() };

            long classesSeen = 0;
            long targetClassesScanned = 0;
            long methodsSeen = 0;
            long methodsScanned = 0;
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
            // PRE-SCAN: Quick brute-force check for ANY Native.load/loadLibrary calls
            // This runs BEFORE taint analysis to confirm whether calls exist at all
            // ============================================================
            System.out.println("[PRE-SCAN] Searching for Native.load / Native.loadLibrary calls...");
            int preHitCount = 0;
            for (SootClass sc : targetClasses) {
                for (SootMethod sm : sc.getMethods()) {
                    try {
                        if (!sm.hasBody()) continue;
                        for (Stmt s : sm.getBody().getStmts()) {
                            AbstractInvokeExpr inv = getInvoke(s);
                            if (inv == null) continue;
                            MethodSignature calleeSig = inv.getMethodSignature();
                            String declClass = calleeSig.getDeclClassType().getFullyQualifiedName();
                            String mName = calleeSig.getName();
                            if (JNA_NATIVE.equals(declClass) && LOAD_METHODS.contains(mName)) {
                                preHitCount++;
                                // Print the raw call with args
                                StringBuilder argStr = new StringBuilder();
                                for (Immediate arg : inv.getArgs()) {
                                    if (argStr.length() > 0) argStr.append(", ");
                                    argStr.append(arg.getClass().getSimpleName()).append("=").append(arg);
                                }
                                System.out.println("[PRE-SCAN]   " + sm.getSignature()
                                    + " -> " + declClass + "." + mName + "(" + argStr + ")");
                            }
                        }
                    } catch (Exception ignored) {
                    } catch (VerifyError ignored) {
                    }
                }
            }
            System.out.println("[PRE-SCAN] Found " + preHitCount + " raw Native.load/loadLibrary call(s)");
            System.out.println("");

            // ============================================================
            // PASS 0: Track all accessor methods (access$NNN) that return field values
            // These are synthetic methods generated by javac for inner class access
            // ============================================================
            System.out.println("[PASS 0] Tracking accessor methods...");
            int accessorCount = 0;
            for (SootClass sc : targetClasses) {
                for (SootMethod m : sc.getMethods()) {
                    String methodName = m.getName();
                    if (!methodName.startsWith("access$")) continue;
                    try {
                        if (!m.hasBody()) continue;
                        trackAccessorMethod(m);
                        accessorCount++;
                    } catch (VerifyError ignored) {
                    } catch (Exception ignored) {
                    }
                }
            }
            System.out.println("[PASS 0] Tracked " + accessorCount + " accessor methods -> " + ACCESSOR_TO_FIELD.size() + " field mappings");

            // ============================================================
            // PASS 1: Process all <clinit> methods first to populate field taints
            // This captures: CLib INSTANCE = Native.load("c", CLib.class)
            // Also captures: LIBRARY_NAME = Platform.isWindows() ? "msvcrt" : "c"
            //
            // IMPORTANT: Sort classes so outer classes are processed before inner classes.
            // Inner classes (with $) depend on outer class fields via access$NNN methods.
            // E.g., PosixJNAAffinity must be processed before PosixJNAAffinity$CLibrary
            // ============================================================
            System.out.println("[PASS 1] Processing <clinit> methods to populate field taints...");

            // Sort: outer classes first (classes without $), then inner classes (with $)
            targetClasses.sort((a, b) -> {
                String nameA = a.getType().getFullyQualifiedName();
                String nameB = b.getType().getFullyQualifiedName();
                boolean aIsInner = nameA.contains("$");
                boolean bIsInner = nameB.contains("$");
                if (aIsInner != bIsInner) {
                    return aIsInner ? 1 : -1;  // outer classes first
                }
                return nameA.compareTo(nameB);  // alphabetical within same category
            });

            // Run PASS 1 twice to handle transitive dependencies
            // (e.g., inner class A depends on outer class, inner class B depends on inner class A)
            int clinitCount = 0;
            for (int pass1Iter = 0; pass1Iter < 2; pass1Iter++) {
                int prevFieldTaints = FIELD_TAINT.size();
                int prevFieldStrings = FIELD_STRING_VALUES.size();

                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        if (!m.getName().equals("<clinit>")) continue;
                        try {
                            if (!m.hasBody()) continue;
                            analyzeMethod(view, m, null, null, null);
                            if (pass1Iter == 0) clinitCount++;
                        } catch (VerifyError ignored) {
                        } catch (Exception ignored) {
                        }
                    }
                }

                int newTaints = FIELD_TAINT.size() - prevFieldTaints;
                int newStrings = FIELD_STRING_VALUES.size() - prevFieldStrings;
                System.out.println("[PASS 1." + pass1Iter + "] Field taints: " + FIELD_TAINT.size() + " (+" + newTaints + ")");
                System.out.println("[PASS 1." + pass1Iter + "] Field strings: " + FIELD_STRING_VALUES.size() + " (+" + newStrings + ")");

                // Early exit if no new taints discovered
                if (newTaints == 0 && newStrings == 0 && pass1Iter > 0) break;
            }
            System.out.println("[PASS 1] Processed " + clinitCount + " <clinit> methods");

            // ============================================================
            // PASS 2: Process all methods and collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for JNA interface calls...");
            for (SootClass sc : targetClasses) {
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

                        // Get the JAR file for this class
                        String callerClass = sc.getType().getFullyQualifiedName();
                        String jarFile = classToJar.getOrDefault(callerClass, "<unknown>");

                        List<Hit> found = analyzeMethod(view, m, hitW, jarFile, classToJar);
                        if (found != null && !found.isEmpty()) {
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
                                hitW.write(h.iface);
                                hitW.write(" | ");
                                hitW.write(h.calleeSig);
                                hitW.write(" | ");
                                hitW.write(h.callerJar);
                                hitW.write(" | ");
                                hitW.write(h.calleeJar);
                                hitW.write("\n");
                            }
                            hitW.flush();
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

            System.out.println("[INFO] total JNA interface hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
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
        w.write(methodSig + " | " + t.getClass().getName() + " | " + msg + "\n");
    }

    /**
     * Analyzes a single method for JNA interface-based calls.
     *
     * Performs intra-procedural taint tracking to resolve library names for
     * calls to interfaces that extend com.sun.jna.Library. Tracks:
     * - Native.load("lib", Interface.class) calls to map locals/fields to LoadInfo
     * - Native.synchronizedLibrary() wrapper calls
     * - String constants for conditional library name assignments
     * - Local-to-local and local-to-field propagation
     * - Accessor method (access$NNN) return values
     *
     * @param view       The SootUp JavaView for type resolution
     * @param m          The SootMethod to analyze
     * @param hitW       BufferedWriter for hits (null during pass 1)
     * @param callerJar  The JAR file containing the caller method (null during pass 1)
     * @param classToJar Map of class names to JAR files for callee lookup (null during pass 1)
     * @return List of JNA interface call hits found, or null if in pass 1
     */
    private static List<Hit> analyzeMethod(View view, SootMethod m, BufferedWriter hitW, String callerJar, Map<String, String> classToJar) {
        Map<Local, LoadInfo> localTaint = new HashMap<>();
        Map<Local, Set<String>> localStringValues = new HashMap<>();
        List<Hit> hits = (hitW != null) ? new ArrayList<>() : null;

        // Track if this is an accessor method (access$NNN) and what field it returns
        String methodName = m.getName();
        if (methodName.startsWith("access$") && m.getReturnType().toString().equals("java.lang.String")) {
            trackAccessorMethod(m);
        }

        for (Stmt stmt : m.getBody().getStmts()) {

            // --- Handle assignments (taint tracking) ---
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                // local = StringConstant (track for conditional branch handling)
                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    String strVal = ((StringConstant) rhs).getValue();
                    localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).add(strVal);
                    if (DEBUG) {
                        System.out.println("[DBG] STRING local: " + lhs + " = \"" + strVal + "\"");
                    }
                }

                // local = local (propagate string values and LoadInfo)
                if (lhs instanceof Local && rhs instanceof Local) {
                    LoadInfo li = localTaint.get((Local) rhs);
                    if (li != null) localTaint.put((Local) lhs, li);

                    Set<String> strs = localStringValues.get((Local) rhs);
                    if (strs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(strs);
                    }
                }

                // local = fieldref (getstatic/getfield)
                if (lhs instanceof Local && isFieldRef(rhs)) {
                    LoadInfo li = FIELD_TAINT.get(fieldKey(rhs));
                    if (li != null) localTaint.put((Local) lhs, li);

                    // Also check string values stored in fields (for conditional assignments)
                    Set<String> fieldStrs = FIELD_STRING_VALUES.get(fieldKey(rhs));
                    if (fieldStrs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(fieldStrs);
                    }
                }

                // local = invoke (Native.load / wrapper / accessor method)
                if (lhs instanceof Local) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        LoadInfo li = parseIfLoadOrWrapper(inv, localTaint, localStringValues);
                        if (li != null) {
                            localTaint.put((Local) lhs, li);
                            if (DEBUG) {
                                System.out.println("[DBG] TAINT local: " + lhs + " -> " + li.libName);
                            }
                        }

                        // Check if this is an accessor method returning a string field
                        String accessorField = checkAccessorMethod(inv);
                        if (accessorField != null) {
                            Set<String> fieldStrs = FIELD_STRING_VALUES.get(accessorField);
                            if (fieldStrs != null) {
                                localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(fieldStrs);
                                if (DEBUG) {
                                    System.out.println("[DBG] ACCESSOR: " + inv.getMethodSignature().getName() + " returns " + accessorField + " -> " + fieldStrs);
                                }
                            }
                        }
                    }
                }

                // fieldref = local (putstatic/putfield) - track both LoadInfo and string values
                if (isFieldRef(lhs) && rhs instanceof Local) {
                    LoadInfo li = localTaint.get((Local) rhs);
                    if (li != null) {
                        FIELD_TAINT.put(fieldKey(lhs), li);
                        if (DEBUG) {
                            System.out.println("[DBG] TAINT field: " + fieldKey(lhs) + " -> " + li.libName);
                        }
                    }

                    // Track string values for conditional assignments
                    Set<String> strs = localStringValues.get((Local) rhs);
                    if (strs != null && !strs.isEmpty()) {
                        FIELD_STRING_VALUES.computeIfAbsent(fieldKey(lhs), k -> new HashSet<>()).addAll(strs);
                        if (DEBUG) {
                            System.out.println("[DBG] STRING field: " + fieldKey(lhs) + " <- " + strs);
                        }
                    }
                }

                // fieldref = StringConstant (direct assignment)
                if (isFieldRef(lhs) && rhs instanceof StringConstant) {
                    String strVal = ((StringConstant) rhs).getValue();
                    FIELD_STRING_VALUES.computeIfAbsent(fieldKey(lhs), k -> new HashSet<>()).add(strVal);
                    if (DEBUG) {
                        System.out.println("[DBG] STRING field direct: " + fieldKey(lhs) + " = \"" + strVal + "\"");
                    }
                }

                // fieldref = invoke (direct: INSTANCE = Native.load(...))
                if (isFieldRef(lhs)) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        LoadInfo li = parseIfLoadOrWrapper(inv, localTaint, localStringValues);
                        if (li != null) {
                            FIELD_TAINT.put(fieldKey(lhs), li);
                            if (DEBUG) {
                                System.out.println("[DBG] TAINT field from load: " + fieldKey(lhs) + " -> " + li.libName);
                            }
                        }
                    }
                }
            }

            // Skip hit collection in pass 1
            if (hits == null) continue;

            // --- Handle invoke: detect calls to JNA Library interfaces ---
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature callee = inv.getMethodSignature();
            ClassType declType = callee.getDeclClassType();

            // Skip if not an interface extending JNA Library
            if (!extendsJnaLibrary(view, declType)) continue;

            // Find taint from receiver (local or field)
            LoadInfo li = findTaintFromUses(inv, localTaint);
            if (li == null) continue;

            String lib = (li.libName != null) ? li.libName : "<?>";
            String api = (li.apiPattern != null) ? li.apiPattern : API_UNKNOWN;
            String symbol = callee.getName();

            // Look up the JAR file for the callee interface
            String calleeClass = declType.toString();
            String calleeJar = (classToJar != null) ? classToJar.getOrDefault(calleeClass, "<unknown>") : "<unknown>";

            hits.add(new Hit(
                    m.getSignature().toString(),
                    lib,
                    symbol,
                    api,
                    declType.toString(),
                    callee.toString(),
                    callerJar != null ? callerJar : "<unknown>",
                    calleeJar
            ));
        }

        return hits;
    }

    /**
     * Tracks accessor methods (access$NNN) that return static fields.
     *
     * These are synthetic methods generated by javac for inner class access
     * to outer class private fields. We track them to resolve field values
     * when the accessor is called instead of direct field access.
     *
     * @param m The accessor method to track
     */
    private static void trackAccessorMethod(SootMethod m) {
        String methodKey = m.getDeclaringClassType().toString() + "." + m.getName();
        if (DEBUG) {
            System.out.println("[DBG] ACCESSOR CHECK: " + methodKey + " (return type: " + m.getReturnType() + ")");
        }
        if (!m.hasBody()) return;

        // Track local -> field assignments in the method
        // Accessor methods typically look like:
        //   $stack0 = <Class: Type FIELD>
        //   return $stack0
        Map<String, String> localToField = new HashMap<>();
        String returnedLocal = null;

        for (Stmt stmt : m.getBody().getStmts()) {
            String stmtStr = stmt.toString();

            // Look for: $local = <FieldRef>
            if (stmt instanceof JAssignStmt) {
                JAssignStmt assign = (JAssignStmt) stmt;
                Value lhs = assign.getLeftOp();
                Value rhs = assign.getRightOp();
                if (lhs instanceof Local && isFieldRef(rhs)) {
                    String fk = fieldKey(rhs);
                    localToField.put(lhs.toString(), fk);
                    if (DEBUG) {
                        System.out.println("[DBG]   local " + lhs + " <- field " + fk);
                    }
                }
            }

            // Look for: return $local or return <FieldRef>
            if (stmtStr.startsWith("return ")) {
                // Direct field return: return <FieldRef>
                if (stmtStr.contains("<")) {
                    int start = stmtStr.indexOf("<");
                    int end = stmtStr.lastIndexOf(">");
                    if (start >= 0 && end > start) {
                        String fieldRef = stmtStr.substring(start, end + 1);
                        ACCESSOR_TO_FIELD.put(methodKey, fieldRef);
                        if (DEBUG) {
                            System.out.println("[DBG] ACCESSOR TRACKED (direct): " + methodKey + " -> " + fieldRef);
                        }
                        return;
                    }
                }
                // Local return: return $local
                String retVar = stmtStr.substring(7).trim();
                if (!retVar.isEmpty() && !retVar.equals("null")) {
                    returnedLocal = retVar;
                }
            }
        }

        // If we found a return of a local that was assigned from a field
        if (returnedLocal != null && localToField.containsKey(returnedLocal)) {
            String fieldRef = localToField.get(returnedLocal);
            ACCESSOR_TO_FIELD.put(methodKey, fieldRef);
            if (DEBUG) {
                System.out.println("[DBG] ACCESSOR TRACKED (via local): " + methodKey + " -> " + fieldRef);
            }
        }
    }

    /**
     * Checks if an invoke is to an accessor method and returns the field it accesses.
     *
     * @param inv The invoke expression to check
     * @return The field key if this is a tracked accessor, null otherwise
     */
    private static String checkAccessorMethod(AbstractInvokeExpr inv) {
        MethodSignature sig = inv.getMethodSignature();
        String methodKey = sig.getDeclClassType().toString() + "." + sig.getName();
        return ACCESSOR_TO_FIELD.get(methodKey);
    }

    // ------------------- Taint recovery from invoke uses -------------------

    /**
     * Finds LoadInfo taint from an invoke expression's uses (receiver/arguments).
     *
     * First checks local variables, then falls back to field references.
     *
     * @param inv        The invoke expression
     * @param localTaint Map of local variables to LoadInfo
     * @return The LoadInfo if found, null otherwise
     */
    private static LoadInfo findTaintFromUses(AbstractInvokeExpr inv, Map<Local, LoadInfo> localTaint) {
        // Try locals first
        Optional<LoadInfo> fromLocal = inv.getUses()
                .filter(v -> v instanceof Local)
                .map(v -> localTaint.get((Local) v))
                .filter(Objects::nonNull)
                .findFirst();

        if (fromLocal.isPresent()) return fromLocal.get();

        // Then try field refs
        Optional<LoadInfo> fromField = inv.getUses()
                .filter(JnaIfaceDetector::isFieldRef)
                .map(JnaIfaceDetector::fieldKey)
                .map(FIELD_TAINT::get)
                .filter(Objects::nonNull)
                .findFirst();

        return fromField.orElse(null);
    }

    // ------------------- Invoke extraction helpers -------------------

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
            Value rhs = ((JAssignStmt) stmt).getRightOp();
            rhs = unwrapCasts(rhs);
            return asInvoke(rhs);
        }
        return null;
    }

    // ------------------- Native.load parsing -------------------

    /**
     * Parses an invoke expression to check if it's a Native.load() or wrapper call.
     *
     * Handles:
     * - Native.load("libname", Interface.class) - extracts library name
     * - Native.load(Interface.class) - no library name (uses current process)
     * - Native.load(Interface.class, Map) - no library name (uses current process)
     * - Native.loadLibrary("libname", Interface.class) - extracts library name
     * - Native.synchronizedLibrary(lib) - propagates taint from argument
     *
     * Also resolves library names from local variables that hold string constants
     * (for conditional assignments like Platform.isWindows() ? "msvcrt" : "c").
     *
     * @param inv               The invoke expression to parse
     * @param localTaint        Map of local variables to LoadInfo
     * @param localStringValues Map of local variables to possible string values
     * @return LoadInfo if this is a load/wrapper call, null otherwise
     */
    private static LoadInfo parseIfLoadOrWrapper(AbstractInvokeExpr inv, Map<Local, LoadInfo> localTaint,
                                                  Map<Local, Set<String>> localStringValues) {
        MethodSignature sig = inv.getMethodSignature();
        String decl = sig.getDeclClassType().toString();
        String name = sig.getName();

        // Native.load("libname", Interface.class) or Native.loadLibrary(...)
        if (JNA_NATIVE.equals(decl) && LOAD_METHODS.contains(name)) {
            boolean isLoadLibrary = "loadLibrary".equals(name);
            String lib = null;
            String api = API_UNKNOWN;
            List<Immediate> args = inv.getArgs();

            // Handle Native.load(Class) or Native.load(Class, Map) - no library name
            // First arg is a Class, not a String -> defaults to current process
            if (args.size() >= 1) {
                Immediate arg0 = args.get(0);
                String arg0Type = arg0.getType().toString();
                if (arg0Type.equals("java.lang.Class") || arg0Type.startsWith("java.lang.Class<")) {
                    lib = "<null:default-c-lib>";
                    if (isLoadLibrary) {
                        api = API_NATIVE_LOADLIBRARY_CLASS;
                    } else {
                        api = (args.size() >= 2) ? API_NATIVE_LOAD_CLASS_MAP : API_NATIVE_LOAD_CLASS;
                    }
                    if (DEBUG) {
                        System.out.println("[DBG] " + api + " -> default C library");
                    }
                    return new LoadInfo(lib, api);
                }
            }

            if (!args.isEmpty()) {
                Immediate arg0 = args.get(0);
                if (arg0 instanceof StringConstant) {
                    lib = ((StringConstant) arg0).getValue();
                    api = isLoadLibrary ? API_NATIVE_LOADLIBRARY_STR_CLASS : API_NATIVE_LOAD_STR_CLASS;
                } else if (isNullConstant(arg0)) {
                    lib = "<null:default-c-lib>";
                    api = API_NATIVE_LOAD_NULL;
                    if (DEBUG) {
                        System.out.println("[DBG] Native.load with null -> default C library");
                    }
                } else if (arg0 instanceof Local) {
                    Set<String> possibleLibs = localStringValues.get((Local) arg0);
                    if (possibleLibs != null && !possibleLibs.isEmpty()) {
                        lib = String.join("|", possibleLibs);
                    }
                    api = isLoadLibrary ? API_NATIVE_LOADLIBRARY_STR_CLASS : API_NATIVE_LOAD_STR_CLASS;
                    if (DEBUG) {
                        System.out.println("[DBG] " + api + " with local -> resolved to: " + lib);
                    }
                }
            }
            return new LoadInfo(lib, api);
        }

        // Native.synchronizedLibrary(lib) - propagate taint (preserves inner apiPattern)
        if (JNA_NATIVE.equals(decl) && WRAPPER_METHODS.contains(name)) {
            List<Immediate> args = inv.getArgs();
            if (args.size() == 1 && args.get(0) instanceof Local) {
                return localTaint.get((Local) args.get(0));
            }
        }

        return null;
    }

    // ------------------- Type/hierarchy check -------------------

    /**
     * Checks if a class type is an interface that extends com.sun.jna.Library.
     *
     * Performs a BFS traversal of the interface hierarchy to find if JNA Library
     * is a superinterface. If the class is not found in the view (e.g., JNA not
     * on analysis classpath), returns true to allow detection.
     *
     * @param view      The SootUp view for class resolution
     * @param ifaceType The class type to check
     * @return true if this extends JNA Library, false otherwise
     */
    private static boolean extendsJnaLibrary(View view, ClassType ifaceType) {
        Optional<? extends SootClass> scOpt = view.getClass(ifaceType);
        if (!scOpt.isPresent()) {
            // If class not found, allow (JNA might not be on analysis classpath)
            return true;
        }

        SootClass sc = scOpt.get();
        if (!sc.isInterface()) return false;

        Deque<ClassType> q = new ArrayDeque<>();
        Set<ClassType> seen = new HashSet<>();
        q.add(ifaceType);

        while (!q.isEmpty()) {
            ClassType cur = q.removeFirst();
            if (!seen.add(cur)) continue;

            Optional<? extends SootClass> curOpt = view.getClass(cur);
            if (!curOpt.isPresent()) continue;

            SootClass curSc = curOpt.get();

            if (JNA_LIBRARY.equals(curSc.getType().toString())) return true;

            for (ClassType itf : curSc.getInterfaces()) {
                if (JNA_LIBRARY.equals(itf.toString())) return true;
                q.addLast(itf);
            }
        }
        return false;
    }

    // ------------------- FieldRef + Cast unwrapping -------------------

    /**
     * Checks if a Value is a NullConstant (aconst_null in bytecode).
     *
     * Used to detect Native.load(null, ...) which means "use default C library".
     *
     * @param v The Value to check
     * @return true if it's a null constant, false otherwise
     */
    private static boolean isNullConstant(Value v) {
        if (v == null) return false;
        // Check class name since NullConstant may be in different packages across SootUp versions
        String className = v.getClass().getName().toLowerCase(Locale.ROOT);
        return className.contains("nullconstant") || "null".equals(v.toString());
    }

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
     * to static fields. Iterates up to 8 times to handle nested casts.
     *
     * @param v The Value that may be wrapped in casts
     * @return The unwrapped Value
     */
    private static Value unwrapCasts(Value v) {
        Value cur = v;
        for (int i = 0; i < 8 && cur != null; i++) {
            String cn = cur.getClass().getName().toLowerCase(Locale.ROOT);
            if (!cn.contains("cast")) break;

            Value inner = tryCallValueGetter(cur, "getOp");
            if (inner == null) inner = tryCallValueGetter(cur, "getOperand");
            if (inner == null) inner = tryCallValueGetter(cur, "getValue");

            if (inner == null) break;
            cur = inner;
        }
        return cur;
    }

    /**
     * Attempts to invoke a getter method that returns a Value via reflection.
     *
     * Used for API compatibility across SootUp versions.
     *
     * @param obj        The object to invoke the method on
     * @param methodName The method name to invoke
     * @return The Value result or null if invocation fails
     */
    private static Value tryCallValueGetter(Object obj, String methodName) {
        try {
            Method m = obj.getClass().getMethod(methodName);
            Object r = m.invoke(obj);
            if (r instanceof Value) return (Value) r;
        } catch (Exception ignored) {}
        return null;
    }

    // ------------------- Data classes -------------------

    /**
     * Holds library load information.
     *
     * Used to track the library name associated with a Native.load() call.
     */
    private static final class LoadInfo {
        final String libName;
        final String apiPattern;

        LoadInfo(String libName, String apiPattern) {
            this.libName = libName;
            this.apiPattern = apiPattern;
        }
    }

    /**
     * Represents a detected JNA interface call hit.
     *
     * Contains all information about a detected call to an interface method
     * that extends com.sun.jna.Library, including both caller and callee JAR files.
     */
    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String apiPattern;
        final String iface;
        final String calleeSig;
        final String callerJar;
        final String calleeJar;

        Hit(String callerSig, String lib, String symbol, String apiPattern, String iface, String calleeSig, String callerJar, String calleeJar) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.apiPattern = apiPattern;
            this.iface = iface;
            this.calleeSig = calleeSig;
            this.callerJar = callerJar;
            this.calleeJar = calleeJar;
        }
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
}
