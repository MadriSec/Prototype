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
 * FFI (Foreign Function &amp; Memory API) Detector
 *
 * Detects native calls made via Java's Foreign Function &amp; Memory API (Panama):
 *   - Finalized API: java.lang.foreign (Java 22+)
 *   - Incubator API: jdk.incubator.foreign (Java 17-21)
 *
 * Recovers (library, symbol) via taint tracking:
 *   SymbolLookup.libraryLookup("ssl", arena) -&gt; lookup.find("SSL_read") -&gt; Linker.downcallHandle(addr, desc) -&gt; handle.invokeExact(...)
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.FfiDetector \
 *     -Dexec.args="&lt;target-jars-dir&gt; [outDir]"
 *
 * Outputs (in outDir, default=current dir):
 *   - ffi_hits.txt
 *   - skipped_methods.txt
 */
public class FfiDetector {

    private static final boolean DEBUG = false;

    // ---- Finalized API (Java 22+) ----
    private static final String FFI_SYMBOL_LOOKUP = "java.lang.foreign.SymbolLookup";
    private static final String FFI_LINKER        = "java.lang.foreign.Linker";
    private static final String FFI_METHOD_HANDLE = "java.lang.invoke.MethodHandle";

    // ---- Incubator API (Java 17-21) ----
    private static final String INC_SYMBOL_LOOKUP   = "jdk.incubator.foreign.SymbolLookup";
    private static final String INC_LIBRARY_LOOKUP   = "jdk.incubator.foreign.LibraryLookup";
    private static final String INC_CLINKER          = "jdk.incubator.foreign.CLinker";

    // Sets for matching either API version
    private static final Set<String> SYMBOL_LOOKUP_CLASSES = new HashSet<>(Arrays.asList(
            FFI_SYMBOL_LOOKUP, INC_SYMBOL_LOOKUP, INC_LIBRARY_LOOKUP));
    private static final Set<String> LINKER_CLASSES = new HashSet<>(Arrays.asList(
            FFI_LINKER, INC_CLINKER));

    // Progress logging
    private static final long HEARTBEAT_MS = 5000;
    private static final int  METHOD_TICK  = 50_000;
    private static final String DEBUG_LOG_PATH = "/home/rupesh.punna/Prototype/.cursor/debug-3e1f76.log";

    private static final String DEBUG_SESSION_ID = "3e1f76";

    // ---- Global taint maps (populated in PASS 1, used in PASS 2) ----

    // SymbolLookup field -> library name
    private static final Map<String, String> FIELD_TO_LOOKUP_LIB = new HashMap<>();
    // MemorySegment field -> symbol name
    private static final Map<String, String> FIELD_TO_SYMBOL = new HashMap<>();
    // MethodHandle field -> lib+symbol
    private static final Map<String, FuncInfo> FIELD_TO_HANDLE = new HashMap<>();
    // Declaring class FQCN -> library name(s)
    private static final Map<String, String> CLASS_TO_LIBS = new HashMap<>();
    // Field -> set of possible string values (for conditional assignments)
    private static final Map<String, Set<String>> FIELD_STRING_VALUES = new HashMap<>();
    // Local string tracking for <clinit> field assignment resolution
    private static final Map<String, String> FIELD_TO_STRING = new HashMap<>();
    // symbol name -> library basename (e.g. "SSL_read" -> "libssl.so.3"), built from nm -D on LIBS dir
    private static final Map<String, String> LIB_SYMBOL_INDEX = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: FfiDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir    = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        File hitsFile    = new File(out, "ffi_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Build library symbol index from LIBS_* sibling directory
        File libsDir = deriveLibsDir(targetDir);
        if (libsDir != null) {
            buildLibSymbolIndex(libsDir);
        } else {
            System.out.println("[INFO] no LIBS directory found, callback symbol resolution disabled");
        }

        // Collect target jars
        List<String> targetJars = collectJarPaths(targetDir);
        System.out.println("[INFO] target jars: " + targetJars.size());

        // Index target classes
        Set<String> targetClassNames = collectClassNamesFromJars(targetJars);
        System.out.println("[INFO] target classes indexed: " + targetClassNames.size());

        // Build classpath
        String cp = toClassPath(targetJars);
        System.out.println("[INFO] scanning target classes");
        System.out.println("       target=" + targetDir);
        System.out.println("       out   =" + out.getAbsolutePath());

        // Setup SootUp
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(cp));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());

        JavaView view = new JavaView(inputs);

        try (
                BufferedWriter hitW  = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== FFI (Foreign Function & Memory API) Hits ===\n");
            hitW.write("Format: callerSig | lib | symbol | mechanism | jar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions during body building) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();
            final long[] lastBeat = { System.currentTimeMillis() };

            long classesSeen = 0;
            long methodsSeen = 0;
            long methodsScanned = 0;
            long hits = 0;
            long skipped = 0;

            // Collect target classes
            List<SootClass> targetClasses = new ArrayList<>();
            for (Iterator<? extends SootClass> it = view.getClasses().iterator(); it.hasNext();) {
                SootClass sc = it.next();
                classesSeen++;
                String fqcn = sc.getType().getFullyQualifiedName();
                if (targetClassNames.contains(fqcn)) {
                    targetClasses.add(sc);
                }
            }

            System.out.println("[INFO] collected " + targetClasses.size() + " target classes for analysis");

            // Sort: outer classes first (no $), then inner classes
            // This ensures outer class <clinit> (which loads the library) is processed
            // before inner class <clinit> (which looks up the symbol)
            targetClasses.sort((a, b) -> {
                String an = a.getType().getFullyQualifiedName();
                String bn = b.getType().getFullyQualifiedName();
                boolean aInner = an.contains("$");
                boolean bInner = bn.contains("$");
                if (aInner != bInner) return aInner ? 1 : -1;
                return an.compareTo(bn);
            });

            // ============================================================
            // PASS 1: Process <clinit> methods (2 iterations for transitive deps)
            // ============================================================
            for (int iter = 0; iter < 2; iter++) {
                System.out.println("[PASS 1] Iteration " + (iter + 1) + " - processing <clinit> methods...");
                int clinitCount = 0;
                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        if (!m.getName().equals("<clinit>")) continue;
                        try {
                            if (!m.hasBody()) continue;
                            analyzeMethod(m, null); // null jar = we don't record hits in pass 1
                            clinitCount++;
                        } catch (LinkageError ignored) {
                        } catch (Exception ignored) {
                        }
                    }
                }
                System.out.println("[PASS 1] Iteration " + (iter + 1) + " processed " + clinitCount + " <clinit> methods");
            }
            System.out.println("[PASS 1] Field taints: LOOKUP_LIB=" + FIELD_TO_LOOKUP_LIB.size()
                    + ", SYMBOL=" + FIELD_TO_SYMBOL.size()
                    + ", HANDLE=" + FIELD_TO_HANDLE.size()
                    + ", CLASS_TO_LIBS=" + CLASS_TO_LIBS.size());

            // ============================================================
            // PASS 2: Process all methods, collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for FFI hits...");

            // Build class-to-jar map for output
            Map<String, String> classToJar = buildClassToJarMap(targetJars);
            // Track classes that already produced hits (avoid double-counting in fallback)
            Set<String> classesWithHits = new HashSet<>();
            // Track symbols already emitted (avoid duplication in PASS 3 method-name scan)
            Set<String> hitSymbols = new HashSet<>();

            for (SootClass sc : targetClasses) {
                String fqcn = sc.getType().getFullyQualifiedName();
                String jar = classToJar.getOrDefault(fqcn, "?");

                for (SootMethod m : sc.getMethods()) {
                    methodsSeen++;

                    long now = System.currentTimeMillis();
                    if (methodsSeen % METHOD_TICK == 0) {
                        long elapsed = (now - start) / 1000;
                        System.out.println("[PROGRESS] elapsed=" + elapsed + "s"
                                + " methods=" + methodsSeen
                                + " scanned=" + methodsScanned
                                + " hits=" + hits
                                + " skipped=" + skipped);
                    }
                    if (now - lastBeat[0] >= HEARTBEAT_MS) {
                        long elapsed = (now - start) / 1000;
                        System.out.println("[HEARTBEAT] elapsed=" + elapsed + "s"
                                + " methods=" + methodsSeen
                                + " scanned=" + methodsScanned
                                + " hits=" + hits);
                        lastBeat[0] = now;
                    }

                    try {
                        if (!m.hasBody()) continue;
                        methodsScanned++;

                        List<Hit> found = analyzeMethod(m, jar);
                        for (Hit h : found) {
                            hits++;
                            classesWithHits.add(fqcn);
                            hitSymbols.add(h.symbol);
                            hitW.write(h.callerSig);
                            hitW.write(" | ");
                            hitW.write(h.lib);
                            hitW.write(" | ");
                            hitW.write(h.symbol);
                            hitW.write(" | ");
                            hitW.write(h.mechanism);
                            hitW.write(" | ");
                            hitW.write(h.jar);
                            hitW.write("\n");
                        }
                        if (!found.isEmpty()) hitW.flush();

                    } catch (LinkageError le) {
                        // Covers VerifyError, IncompatibleClassChangeError, etc.
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), le);
                    } catch (Exception e) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }

                // Library-index fallback: for classes whose <clinit> fails with
                // VerifyError (e.g. MemorySegment is final in Java 22+, SootUp
                // can't load it), try to infer the symbol from the class name
                // and verify it against the container's library symbols.
                // Covers both jextract inner classes (openssl_h$SSL_read) and
                // callback wrappers (SSL_CTX_set_verify$callback).
                // Skip non-symbol classes: $Function, $Holder, $NHolder.
                if (!fqcn.endsWith("$Function")
                        && !classesWithHits.contains(fqcn)) {
                    FuncInfo cbInfo = !LIB_SYMBOL_INDEX.isEmpty()
                            ? resolveCallbackFromLibs(fqcn) : null;
                    if (cbInfo != null) {
                        // #region agent log
                        debugLog("ffi-fallback-hit", "H1", "library-index fallback emitted hit", Map.of(
                                "class", fqcn,
                                "resolvedLib", cbInfo.lib,
                                "resolvedSym", cbInfo.sym,
                                "jar", String.valueOf(jar)
                        ));
                        // #endregion
                        hits++;
                        classesWithHits.add(fqcn);
                        hitSymbols.add(cbInfo.sym);
                        String sig = "<" + fqcn + ": " + cbInfo.sym + ">";
                        hitW.write(sig + " | " + cbInfo.lib + " | " + cbInfo.sym
                                + " | downcallHandle | " + jar + "\n");
                        hitW.flush();
                    } else if (cbInfo == null
                            && hasInvokeMethod(sc)
                            && resolveLibForCallbackClass(fqcn) != null) {
                        // Callback typedef class (e.g. pem_password_cb) whose symbol
                        // isn't an exported library function — emit with <?> markers.
                        // The resolveLibForCallbackClass check ensures we only do this
                        // for classes in known FFM packages (not random invoke methods).
                        hits++;
                        classesWithHits.add(fqcn);
                        String cbSig = findInvokeMethodSig(sc);
                        hitW.write(cbSig + " | <?> | <?>"
                                + " | downcallHandle | " + jar + "\n");
                        hitW.flush();
                    }
                }
            }

            // ============================================================
            // PASS 3: Method-name fallback for jextract parent classes
            // whose method bodies fail with VerifyError.
            // Covers openssl_h_Compatibility, openssl_h_Macros, etc.
            // These classes use $<digit>Holder lazy-init inner classes;
            // the parent's method names correspond to C function/macro names.
            // ============================================================
            System.out.println("[PASS 3] Scanning jextract parent classes with Holder inner classes...");

            // Identify jextract parent classes by detecting $<digit>Holder inner classes.
            // Then filter: only keep classes where PASS 2 didn't already cover most
            // methods (avoids duplicating openssl_h which is handled by inner-class fallback).
            Set<String> holderParents = new HashSet<>();
            for (SootClass sc : targetClasses) {
                String fqcn = sc.getType().getFullyQualifiedName();
                int dollar = fqcn.lastIndexOf('$');
                if (dollar > 0) {
                    String inner = fqcn.substring(dollar + 1);
                    if (inner.matches("\\d+Holder")) {
                        holderParents.add(fqcn.substring(0, dollar));
                    }
                }
            }
            // Coverage filter: skip parents where >50% of C-identifier methods
            // are already in hitSymbols (well-covered by PASS 2 inner-class fallback).
            Set<String> jextractParents = new HashSet<>();
            for (SootClass sc : targetClasses) {
                String fqcn = sc.getType().getFullyQualifiedName();
                if (!holderParents.contains(fqcn)) continue;
                int total = 0, covered = 0;
                for (SootMethod m : sc.getMethods()) {
                    String mn = m.getName();
                    if (mn.startsWith("<") || mn.startsWith("$")) continue;
                    if (!mn.matches("[A-Za-z_][A-Za-z0-9_]*")) continue;
                    total++;
                    if (hitSymbols.contains(mn)) covered++;
                }
                if (total > 0 && covered < total / 2) {
                    jextractParents.add(fqcn);
                }
            }

            if (!jextractParents.isEmpty()) {
                System.out.println("[PASS 3] Found " + jextractParents.size()
                        + " jextract parent classes: " + jextractParents);
                int pass3Hits = 0;

                for (SootClass sc : targetClasses) {
                    String fqcn = sc.getType().getFullyQualifiedName();
                    if (!jextractParents.contains(fqcn)) continue;

                    // Check if ANY methods in this class are exported library symbols.
                    // If so, only emit index-verified methods (avoids false positives
                    // from Java helpers like isLibreSSLPre35 or constant getters).
                    // If none are in the index (pure macro wrapper class), allow
                    // package-based fallback for all methods.
                    boolean hasIndexedSymbols = false;
                    for (SootMethod check : sc.getMethods()) {
                        String cn = check.getName();
                        if (!cn.startsWith("<") && !cn.startsWith("$")
                                && LIB_SYMBOL_INDEX.containsKey(cn)) {
                            hasIndexedSymbols = true;
                            break;
                        }
                    }

                    String jar = classToJar.getOrDefault(fqcn, "?");

                    for (SootMethod m : sc.getMethods()) {
                        String methodName = m.getName();
                        // Skip constructors, static initializers, internal methods
                        if (methodName.startsWith("<") || methodName.startsWith("$")) continue;
                        // Must be a valid C identifier
                        if (!methodName.matches("[A-Za-z_][A-Za-z0-9_]*")) continue;
                        // Skip symbols already found via taint analysis or inner-class fallback
                        if (hitSymbols.contains(methodName)) continue;

                        // Resolve library from symbol index first
                        String lib = resolveLibFromSymbolIndex(methodName);
                        // Only fall back to package-based resolution if the class has
                        // NO methods in the symbol index (pure macro wrapper class).
                        // This prevents false positives from Java utility methods in
                        // classes that mix real C wrappers with helpers.
                        if (lib == null && !hasIndexedSymbols) {
                            lib = resolveLibForCallbackClass(fqcn);
                        }
                        if (lib == null) continue;

                        hitSymbols.add(methodName);
                        hits++;
                        pass3Hits++;
                        classesWithHits.add(fqcn);
                        String msig = m.getSignature().toString();
                        hitW.write(msig + " | " + lib + " | " + methodName
                                + " | downcallHandle | " + jar + "\n");
                    }
                }
                hitW.flush();
                System.out.println("[PASS 3] Added " + pass3Hits + " hits from method-name scan");
            } else {
                System.out.println("[PASS 3] No jextract parent classes found, skipping");
            }

            hitW.flush();
            skipW.flush();

            System.out.println("[INFO] total FFI hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Analyzes a single method for FFI calls.
     *
     * Tracks:
     * - SymbolLookup.libraryLookup / loaderLookup / defaultLookup -> library taint
     * - System.loadLibrary -> library taint
     * - SymbolLookup.find / findOrThrow -> symbol taint
     * - Linker.downcallHandle -> combines lib + symbol into FuncInfo
     * - MethodHandle.invokeExact / invoke -> SINK (hit)
     *
     * @param m   The SootMethod to analyze
     * @param jar The jar file name (null during PASS 1)
     * @return List of FFI hits found
     */
    private static List<Hit> analyzeMethod(SootMethod m, String jar) {
        // Local taint maps
        Map<Local, String> localToLookupLib = new HashMap<>();   // SymbolLookup -> lib
        Map<Local, String> localToSymbol    = new HashMap<>();   // MemorySegment -> symbol
        Map<Local, FuncInfo> localToHandle  = new HashMap<>();   // MethodHandle -> lib+sym
        Map<Local, String> localToString    = new HashMap<>();   // String locals

        List<Hit> hits = new ArrayList<>();

        String callerClass = m.getDeclaringClassType().getFullyQualifiedName();
        String callerSig = m.getSignature().toString();
        boolean ffiCallbackProbe =
                callerClass.startsWith("org.apache.tomcat.util.openssl.")
                        && callerSig.contains(":")
                        && callerSig.contains(" invoke(")
                        && (callerClass.contains("$cb")
                        || callerClass.contains("$callback")
                        || callerClass.endsWith(".pem_password_cb")
                        || callerClass.endsWith(".SSL_CTX_set_tmp_dh_callback$dh"));

        // Track traceDowncall symbol as fallback (populated during method scan)
        String traceDowncallSymbol = null;

        for (Stmt stmt : m.getBody().getStmts()) {

            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs0 = as.getRightOp();
                Value rhs = unwrapCasts(rhs0);

                // ---- CASE 1: local = something ----
                if (lhs instanceof Local) {
                    Local l = (Local) lhs;

                    // local = string constant
                    if (rhs instanceof StringConstant) {
                        localToString.put(l, ((StringConstant) rhs).getValue());
                    }

                    // local = invoke
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().toString();
                        String name = sig.getName();

                        // --- Library loading ---

                        // SymbolLookup.libraryLookup(String name, Arena arena)
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("libraryLookup")) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                localToLookupLib.put(l, lib);
                                if (DEBUG) System.out.println("[DBG] libraryLookup: " + lib);
                            }
                        }

                        // LibraryLookup.ofPath(Path) / ofDefault() (incubator)
                        if (INC_LIBRARY_LOOKUP.equals(decl)) {
                            if (name.equals("ofDefault")) {
                                localToLookupLib.put(l, "<default-c-lib>");
                            } else if (name.equals("ofPath")) {
                                String path = resolveStringArg(inv, localToString, 0);
                                localToLookupLib.put(l, path != null ? path : "<?>");
                            }
                        }

                        // Linker.nativeLinker().defaultLookup() / CLinker.getInstance().lookup()
                        if (LINKER_CLASSES.contains(decl) && name.equals("defaultLookup")) {
                            localToLookupLib.put(l, "<default-c-lib>");
                        }
                        // CLinker.getInstance() (incubator)
                        if (INC_CLINKER.equals(decl) && name.equals("getInstance")) {
                            localToLookupLib.put(l, "<default-c-lib>");
                        }

                        // SymbolLookup.loaderLookup()
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("loaderLookup")) {
                            localToLookupLib.put(l, "<loader>");
                        }

                        // lookup.or(otherLookup) — merge library info
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("or")) {
                            Local base = getInvokeBaseLocal(inv);
                            String basLib = resolveLocalLookupLib(base, localToLookupLib);
                            // Inherit base lib (the primary is the one with actual lib name)
                            if (basLib != null && !basLib.startsWith("<")) {
                                localToLookupLib.put(l, basLib);
                            } else {
                                // Check the arg
                                List<Immediate> orArgs = inv.getArgs();
                                if (!orArgs.isEmpty() && orArgs.get(0) instanceof Local) {
                                    String argLib = resolveLocalLookupLib((Local) orArgs.get(0), localToLookupLib);
                                    if (argLib != null && !argLib.startsWith("<")) {
                                        localToLookupLib.put(l, argLib);
                                    } else if (basLib != null) {
                                        localToLookupLib.put(l, basLib);
                                    }
                                } else if (basLib != null) {
                                    localToLookupLib.put(l, basLib);
                                }
                            }
                        }

                        // System.mapLibraryName(String name) — pass through input
                        if ("java.lang.System".equals(decl) && name.equals("mapLibraryName")) {
                            String innerName = resolveStringArg(inv, localToString, 0);
                            if (innerName != null) {
                                localToString.put(l, innerName);
                            }
                        }

                        // System.loadLibrary(String name)
                        if ("java.lang.System".equals(decl) && name.equals("loadLibrary")) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                // Record the lib for this class (loadLibrary is class-level)
                                mergeClassLib(callerClass, lib);
                                if (DEBUG) System.out.println("[DBG] System.loadLibrary: " + lib);
                            }
                        }

                        // System.getProperty(key, default) — track the default
                        if ("java.lang.System".equals(decl) && name.equals("getProperty")) {
                            List<Immediate> gpArgs = inv.getArgs();
                            // 2-arg version: getProperty(key, default)
                            if (gpArgs.size() >= 2 && gpArgs.get(1) instanceof StringConstant) {
                                localToString.put(l, ((StringConstant) gpArgs.get(1)).getValue());
                            } else if (gpArgs.size() >= 2 && gpArgs.get(1) instanceof Local) {
                                String def = localToString.get((Local) gpArgs.get(1));
                                if (def != null) localToString.put(l, def);
                            }
                            // 1-arg version: can't resolve statically
                        }

                        // --- Symbol lookup ---

                        // SymbolLookup.find(String name) -> Optional<MemorySegment>
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("find")) {
                            String sym = resolveStringArg(inv, localToString, 0);
                            if (sym != null) {
                                localToSymbol.put(l, sym);
                                if (DEBUG) System.out.println("[DBG] find: " + sym);
                            }
                        }

                        // findOrThrow(String name) — jextract helper
                        // Match any method named findOrThrow that takes a String and returns MemorySegment
                        if (name.equals("findOrThrow")) {
                            String sym = resolveStringArg(inv, localToString, 0);
                            if (sym != null) {
                                localToSymbol.put(l, sym);
                                // Propagate lib from the declaring class of findOrThrow
                                // (e.g., openssl_h loaded "ssl" → inner class inherits it)
                                String libFromClass = CLASS_TO_LIBS.get(decl);
                                if (libFromClass != null) {
                                    mergeClassLib(callerClass, libFromClass);
                                }
                                if (DEBUG) System.out.println("[DBG] findOrThrow: " + sym + " (decl=" + decl + ", lib=" + libFromClass + ")");
                            }
                        }

                        // LibraryLookup.lookup(String name) (incubator)
                        if (INC_LIBRARY_LOOKUP.equals(decl) && name.equals("lookup")) {
                            String sym = resolveStringArg(inv, localToString, 0);
                            if (sym != null) {
                                localToSymbol.put(l, sym);
                            }
                        }

                        // --- Downcall handle creation ---

                        // Linker.downcallHandle(MemorySegment, FunctionDescriptor, Option...)
                        if (LINKER_CLASSES.contains(decl) && name.equals("downcallHandle")) {
                            String sym = null;
                            String lib = null;

                            // First arg is MemorySegment (the function address)
                            List<Immediate> dhArgs = inv.getArgs();
                            if (!dhArgs.isEmpty() && dhArgs.get(0) instanceof Local) {
                                Local addrLocal = (Local) dhArgs.get(0);
                                sym = localToSymbol.get(addrLocal);
                            }
                            boolean descriptorOnlyDowncall = dhArgs.isEmpty() || !(dhArgs.get(0) instanceof Local);
                            if (descriptorOnlyDowncall) {
                                FuncInfo cbInfo = resolveCallbackFromLibs(callerClass);
                                if (cbInfo != null) {
                                    sym = cbInfo.sym;
                                    if (lib == null) lib = cbInfo.lib;
                                }
                            }
                            // Field-based address is already handled: when a local
                            // is loaded via getstatic, the taint-loading block
                            // (isFieldRef check below) propagates FIELD_TO_SYMBOL
                            // into localToSymbol before we reach here.

                            // Resolve library: try local lookup taint, then CLASS_TO_LIBS
                            lib = resolveLibForDowncall(inv, localToLookupLib, callerClass);
                            // LIB_SYMBOL_INDEX fallback: when CLASS_TO_LIBS is empty
                            // (e.g. openssl_h <clinit> failed with VerifyError), look up
                            // the symbol directly in the container's library exports.
                            if (lib == null && sym != null) {
                                lib = resolveLibFromSymbolIndex(sym);
                            }
                            if (lib == null && descriptorOnlyDowncall) {
                                lib = resolveLibForCallbackClass(callerClass);
                            }
                            if (ffiCallbackProbe) {
                                // #region agent log
                                debugLog("ffi-probe-pre-funcinfo", "H1", "before storing downcallHandle FuncInfo", Map.of(
                                        "callerSig", callerSig,
                                        "downcallArgs", dhArgs.size(),
                                        "arg0IsLocal", !dhArgs.isEmpty() && (dhArgs.get(0) instanceof Local),
                                        "descriptorOnlyDowncall", descriptorOnlyDowncall,
                                        "resolvedLib", String.valueOf(lib),
                                        "resolvedSym", String.valueOf(sym)
                                ));
                                // #endregion
                            }

                            localToHandle.put(l, new FuncInfo(lib, sym));
                            if (DEBUG) System.out.println("[DBG] downcallHandle: lib=" + lib + ", sym=" + sym);
                        }

                        // CLinker.downcallHandle(MethodHandle/Addressable, MethodType, FunctionDescriptor) (incubator)
                        if (INC_CLINKER.equals(decl) && name.equals("downcallHandle")) {
                            String sym = null;
                            String lib = null;

                            List<Immediate> dhArgs = inv.getArgs();
                            if (!dhArgs.isEmpty() && dhArgs.get(0) instanceof Local) {
                                sym = localToSymbol.get((Local) dhArgs.get(0));
                            }
                            lib = resolveLibForDowncall(inv, localToLookupLib, callerClass);

                            localToHandle.put(l, new FuncInfo(lib, sym));
                        }

                        // --- traceDowncall detection (jextract bonus) ---
                        if (name.equals("traceDowncall")) {
                            String sym = resolveStringArg(inv, localToString, 0);
                            if (sym != null) {
                                traceDowncallSymbol = sym;
                            }
                        }

                        // --- Optional.orElseThrow / get (unwrap Optional<MemorySegment>) ---
                        if ("java.util.Optional".equals(decl) &&
                                (name.equals("orElseThrow") || name.equals("get"))) {
                            Local base = getInvokeBaseLocal(inv);
                            if (base != null && localToSymbol.containsKey(base)) {
                                localToSymbol.put(l, localToSymbol.get(base));
                            }
                        }

                        // --- Linker.nativeLinker() ---
                        if (LINKER_CLASSES.contains(decl) && name.equals("nativeLinker")) {
                            // No taint needed — just a Linker instance
                        }

                        // ---- SINK: local = MethodHandle.invokeExact / invoke ----
                        // Non-void FFM calls compile to JAssignStmt ($r = invokeExact(...)),
                        // not JInvokeStmt. This block catches those; the standalone section
                        // below handles void calls (JInvokeStmt).
                        if (FFI_METHOD_HANDLE.equals(decl) &&
                                (name.equals("invokeExact") || name.equals("invoke"))) {
                            Local base = getInvokeBaseLocal(inv);
                            FuncInfo fi = null;
                            if (base != null) {
                                fi = localToHandle.get(base);
                            }
                            if (fi == null) {
                                fi = inv.getUses()
                                        .filter(FfiDetector::isFieldRef)
                                        .map(FfiDetector::fieldKey)
                                        .map(FIELD_TO_HANDLE::get)
                                        .filter(Objects::nonNull)
                                        .findFirst()
                                        .orElse(null);
                            }
                            if (fi != null && jar != null) {
                                String sLib = (fi.lib != null) ? fi.lib : "<?>";
                                String sSym = (fi.sym != null) ? fi.sym : "<?>";
                                if ("<?>".equals(sSym) && traceDowncallSymbol != null) {
                                    sSym = traceDowncallSymbol;
                                }
                                if (ffiCallbackProbe) {
                                    // #region agent log
                                    debugLog("ffi-probe-hit-assign", "H3", "recording callback invoke hit", Map.of(
                                            "callerSig", callerSig,
                                            "lib", sLib,
                                            "sym", sSym,
                                            "mechanism", "downcallHandle"
                                    ));
                                    // #endregion
                                }
                                hits.add(new Hit(m.getSignature().toString(), sLib, sSym, "downcallHandle", jar));
                                traceDowncallSymbol = null;
                            }
                        }
                    }

                    // local = local propagation
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (localToLookupLib.containsKey(r)) localToLookupLib.put(l, localToLookupLib.get(r));
                        if (localToSymbol.containsKey(r))    localToSymbol.put(l, localToSymbol.get(r));
                        if (localToHandle.containsKey(r))    localToHandle.put(l, localToHandle.get(r));
                        if (localToString.containsKey(r))    localToString.put(l, localToString.get(r));
                    }

                    // local = getstatic/getfield (load taint from global maps)
                    if (isFieldRef(rhs)) {
                        String fkey = fieldKey(rhs);
                        if (FIELD_TO_LOOKUP_LIB.containsKey(fkey)) localToLookupLib.put(l, FIELD_TO_LOOKUP_LIB.get(fkey));
                        if (FIELD_TO_SYMBOL.containsKey(fkey))     localToSymbol.put(l, FIELD_TO_SYMBOL.get(fkey));
                        if (FIELD_TO_HANDLE.containsKey(fkey))     localToHandle.put(l, FIELD_TO_HANDLE.get(fkey));
                        if (FIELD_TO_STRING.containsKey(fkey))     localToString.put(l, FIELD_TO_STRING.get(fkey));
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

                        // FIELD = SymbolLookup.libraryLookup(...)
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("libraryLookup")) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                FIELD_TO_LOOKUP_LIB.put(fkey, lib);
                                mergeClassLib(callerClass, lib);
                            }
                        }

                        // FIELD = loaderLookup()
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("loaderLookup")) {
                            FIELD_TO_LOOKUP_LIB.put(fkey, "<loader>");
                        }

                        // FIELD = defaultLookup()
                        if (LINKER_CLASSES.contains(decl) && name.equals("defaultLookup")) {
                            FIELD_TO_LOOKUP_LIB.put(fkey, "<default-c-lib>");
                        }

                        // FIELD = lookup.or(other) — merge and store
                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("or")) {
                            Local base = getInvokeBaseLocal(inv);
                            String basLib = resolveLocalLookupLib(base, localToLookupLib);
                            if (basLib != null && !basLib.startsWith("<")) {
                                FIELD_TO_LOOKUP_LIB.put(fkey, basLib);
                                mergeClassLib(callerClass, basLib);
                            } else {
                                // Check arg
                                List<Immediate> orArgs = inv.getArgs();
                                if (!orArgs.isEmpty() && orArgs.get(0) instanceof Local) {
                                    String argLib = resolveLocalLookupLib((Local) orArgs.get(0), localToLookupLib);
                                    if (argLib != null && !argLib.startsWith("<")) {
                                        FIELD_TO_LOOKUP_LIB.put(fkey, argLib);
                                        mergeClassLib(callerClass, argLib);
                                    } else if (basLib != null) {
                                        FIELD_TO_LOOKUP_LIB.put(fkey, basLib);
                                    }
                                } else if (basLib != null) {
                                    FIELD_TO_LOOKUP_LIB.put(fkey, basLib);
                                }
                            }
                        }

                        // FIELD = find("sym") / findOrThrow("sym")
                        if ((SYMBOL_LOOKUP_CLASSES.contains(decl) && name.equals("find"))
                                || name.equals("findOrThrow")) {
                            String sym = resolveStringArg(inv, localToString, 0);
                            if (sym != null) {
                                FIELD_TO_SYMBOL.put(fkey, sym);
                                // For findOrThrow, also resolve lib from declaring class
                                if (name.equals("findOrThrow")) {
                                    String libFromClass = CLASS_TO_LIBS.get(decl);
                                    if (libFromClass != null) {
                                        mergeClassLib(callerClass, libFromClass);
                                    }
                                }
                            }
                        }

                        // FIELD = Linker.downcallHandle(addr, desc)
                        if ((LINKER_CLASSES.contains(decl) || INC_CLINKER.equals(decl))
                                && name.equals("downcallHandle")) {
                            String sym = null;
                            String lib = null;

                            List<Immediate> dhArgs = inv.getArgs();
                            if (!dhArgs.isEmpty() && dhArgs.get(0) instanceof Local) {
                                sym = localToSymbol.get((Local) dhArgs.get(0));
                            }
                            boolean descriptorOnlyDowncall = dhArgs.isEmpty() || !(dhArgs.get(0) instanceof Local);
                            if (descriptorOnlyDowncall) {
                                FuncInfo cbInfo = resolveCallbackFromLibs(callerClass);
                                if (cbInfo != null) {
                                    sym = cbInfo.sym;
                                    lib = cbInfo.lib;
                                }
                            }
                            if (lib == null) {
                                lib = resolveLibForDowncall(inv, localToLookupLib, callerClass);
                            }
                            // LIB_SYMBOL_INDEX fallback (same as local variant above)
                            if (lib == null && sym != null) {
                                lib = resolveLibFromSymbolIndex(sym);
                            }
                            if (lib == null && descriptorOnlyDowncall) {
                                lib = resolveLibForCallbackClass(callerClass);
                            }

                            FIELD_TO_HANDLE.put(fkey, new FuncInfo(lib, sym));
                            if (DEBUG) System.out.println("[DBG] FIELD downcallHandle: " + fkey + " -> (" + lib + ", " + sym + ")");
                        }

                        // FIELD = System.getProperty(key, default)
                        if ("java.lang.System".equals(decl) && name.equals("getProperty")) {
                            List<Immediate> gpArgs = inv.getArgs();
                            if (gpArgs.size() >= 2 && gpArgs.get(1) instanceof StringConstant) {
                                String def = ((StringConstant) gpArgs.get(1)).getValue();
                                FIELD_TO_STRING.put(fkey, def);
                                FIELD_STRING_VALUES.computeIfAbsent(fkey, k -> new LinkedHashSet<>()).add(def);
                            } else if (gpArgs.size() >= 2 && gpArgs.get(1) instanceof Local) {
                                String def = localToString.get((Local) gpArgs.get(1));
                                if (def != null) {
                                    FIELD_TO_STRING.put(fkey, def);
                                    FIELD_STRING_VALUES.computeIfAbsent(fkey, k -> new LinkedHashSet<>()).add(def);
                                }
                            }
                        }
                    }

                    // field = local
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (localToLookupLib.containsKey(r)) {
                            FIELD_TO_LOOKUP_LIB.put(fkey, localToLookupLib.get(r));
                            String lib = localToLookupLib.get(r);
                            if (lib != null && !lib.startsWith("<")) mergeClassLib(callerClass, lib);
                        }
                        if (localToSymbol.containsKey(r))    FIELD_TO_SYMBOL.put(fkey, localToSymbol.get(r));
                        if (localToHandle.containsKey(r))    FIELD_TO_HANDLE.put(fkey, localToHandle.get(r));
                        if (localToString.containsKey(r)) {
                            FIELD_TO_STRING.put(fkey, localToString.get(r));
                        }
                    }

                    // field = string constant
                    if (rhs instanceof StringConstant) {
                        String sv = ((StringConstant) rhs).getValue();
                        FIELD_TO_STRING.put(fkey, sv);
                        FIELD_STRING_VALUES.computeIfAbsent(fkey, k -> new LinkedHashSet<>()).add(sv);
                    }
                }
            }

            // ---- Handle standalone invokes (not in assignments) ----
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature sinkSig = inv.getMethodSignature();
            String decl = sinkSig.getDeclClassType().toString();
            String name = sinkSig.getName();

            // System.loadLibrary(name) — standalone call
            if ("java.lang.System".equals(decl) && name.equals("loadLibrary")) {
                String lib = resolveStringArg(inv, localToString, 0);
                if (lib != null) {
                    mergeClassLib(callerClass, lib);
                }
            }

            // traceDowncall("SSL_read", ...) — standalone call
            if (name.equals("traceDowncall")) {
                String sym = resolveStringArg(inv, localToString, 0);
                if (sym != null) {
                    traceDowncallSymbol = sym;
                }
            }

            // ---- SINK: MethodHandle.invokeExact / invoke (void-returning only) ----
            // Non-void invokeExact is handled in CASE 1 above (JAssignStmt).
            // This block handles void invokeExact (JInvokeStmt).
            if (FFI_METHOD_HANDLE.equals(decl) &&
                    (name.equals("invokeExact") || name.equals("invoke")) &&
                    !(stmt instanceof JAssignStmt)) {

                // Only flag if the MethodHandle is tainted from downcallHandle
                Local base = getInvokeBaseLocal(inv);
                FuncInfo fi = null;

                if (base != null) {
                    fi = localToHandle.get(base);
                }

                // Also check field refs
                if (fi == null) {
                    fi = inv.getUses()
                            .filter(FfiDetector::isFieldRef)
                            .map(FfiDetector::fieldKey)
                            .map(FIELD_TO_HANDLE::get)
                            .filter(Objects::nonNull)
                            .findFirst()
                            .orElse(null);
                }

                // Skip non-FFI MethodHandle.invokeExact calls
                if (fi == null) continue;

                String lib = (fi.lib != null) ? fi.lib : "<?>";
                String sym = (fi.sym != null) ? fi.sym : "<?>";

                // Fallback: use traceDowncall symbol if symbol is unknown
                if ("<?>".equals(sym) && traceDowncallSymbol != null) {
                    sym = traceDowncallSymbol;
                }

                // Only record hits in PASS 2 (jar != null)
                if (jar != null) {
                    if (ffiCallbackProbe) {
                        // #region agent log
                        debugLog("ffi-probe-hit-void", "H3", "recording callback invoke hit (void path)", Map.of(
                                "callerSig", callerSig,
                                "lib", lib,
                                "sym", sym,
                                "mechanism", "downcallHandle"
                        ));
                        // #endregion
                    }
                    hits.add(new Hit(
                            m.getSignature().toString(),
                            lib,
                            sym,
                            "downcallHandle",
                            jar
                    ));
                }

                // Reset traceDowncall for next hit in same method
                traceDowncallSymbol = null;
            }
        }

        return hits;
    }

    // ---- Resolution helpers ----

    /**
     * Resolves a string argument from an invoke expression.
     * Checks if the arg at the given index is a StringConstant or a tainted Local.
     */
    private static String resolveStringArg(AbstractInvokeExpr inv, Map<Local, String> localToString, int argIndex) {
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
     * Resolves the lookup library from a local, with fallback to field map.
     */
    private static String resolveLocalLookupLib(Local l, Map<Local, String> localToLookupLib) {
        if (l == null) return null;
        return localToLookupLib.get(l);
    }

    /**
     * Resolves the library name for a downcallHandle invocation.
     * Tries: invoke base local -> CLASS_TO_LIBS for caller class -> CLASS_TO_LIBS for outer class
     */
    private static String resolveLibForDowncall(AbstractInvokeExpr inv,
                                                 Map<Local, String> localToLookupLib,
                                                 String callerClass) {
        // Not applicable for downcallHandle (Linker doesn't carry lib info)
        // Library comes from the SymbolLookup that produced the address

        // Try CLASS_TO_LIBS for the caller class
        String lib = CLASS_TO_LIBS.get(callerClass);
        if (lib != null) return lib;

        // Try outer class (strip $ suffix)
        if (callerClass.contains("$")) {
            String outer = callerClass.substring(0, callerClass.indexOf('$'));
            lib = CLASS_TO_LIBS.get(outer);
            if (lib != null) return lib;
        }

        return null;
    }

    /**
     * Looks up a symbol in LIB_SYMBOL_INDEX and normalises the library basename.
     * e.g. "ERR_clear_error" → libcrypto.so.3 → "crypto"
     */
    private static String resolveLibFromSymbolIndex(String sym) {
        String libFile = LIB_SYMBOL_INDEX.get(sym);
        if (libFile == null) return null;
        String lib = libFile;
        if (lib.startsWith("lib")) lib = lib.substring(3);
        int dotSo = lib.indexOf(".so");
        if (dotSo > 0) lib = lib.substring(0, dotSo);
        return lib;
    }

    /**
     * Infers the native symbol name for a jextract-generated callback wrapper class.
     *
     * For inner classes like SSL_CTX_set_verify$callback, the outer class name
     * (SSL_CTX_set_verify) is the C function that accepts the callback.
     * For top-level classes like pem_password_cb, the class name itself is the
     * C typedef name (not an exported symbol, but still useful for identification).
     */
    /** Generic inner-class names that are NOT C symbols. */
    private static final Set<String> GENERIC_INNER_NAMES = Set.of(
            "callback", "cb", "dh", "Function", "Holder");

    /**
     * Infers the native symbol name from a jextract-generated class name.
     *
     * Two patterns:
     *   openssl_h$SSL_read           → inner part "SSL_read" is the C symbol
     *   SSL_CTX_set_verify$callback  → outer part "SSL_CTX_set_verify" is the C symbol
     *   pem_password_cb              → top-level class name is the C typedef
     */
    private static String inferCallbackSymbol(String callerClass) {
        if (callerClass == null) return null;
        // Get simple class name (strip package)
        int lastDot = callerClass.lastIndexOf('.');
        String simple = (lastDot >= 0) ? callerClass.substring(lastDot + 1) : callerClass;
        int dollar = simple.indexOf('$');
        if (dollar > 0) {
            String outer = simple.substring(0, dollar);
            String inner = simple.substring(dollar + 1);
            // If inner is a generic name (callback, cb, dh, Function, Holder, NHolder),
            // the outer class is the C function that registers this callback.
            // Otherwise the inner part IS the C symbol (e.g. openssl_h$SSL_read → SSL_read).
            if (GENERIC_INNER_NAMES.contains(inner) || inner.matches("\\d+Holder")) {
                return outer;
            }
            return inner;
        }
        // Top-level class (e.g. pem_password_cb) — the class name is the typedef
        return simple;
    }

    private static String resolveLibForCallbackClass(String callerClass) {
        // Tomcat jextract callback wrappers are generated under this package and route to OpenSSL.
        if (callerClass != null && callerClass.startsWith("org.apache.tomcat.util.openssl.")) {
            String lib = CLASS_TO_LIBS.get("org.apache.tomcat.util.openssl.openssl_h");
            if (lib != null) return lib;
            return "ssl";
        }
        return null;
    }

    /**
     * Merges a library name into the CLASS_TO_LIBS map.
     * If the class already has a library, joins with | for multiple possible values.
     */
    private static void mergeClassLib(String className, String lib) {
        String existing = CLASS_TO_LIBS.get(className);
        if (existing == null) {
            CLASS_TO_LIBS.put(className, lib);
        } else if (!existing.equals(lib) && !existing.contains(lib)) {
            CLASS_TO_LIBS.put(className, existing + "|" + lib);
        }
    }

    /**
     * Checks whether a class has an "invoke" method — the callback trampoline pattern
     * used by jextract for callback typedefs (e.g. pem_password_cb).
     */
    private static boolean hasInvokeMethod(SootClass sc) {
        for (SootMethod m : sc.getMethods()) {
            if ("invoke".equals(m.getName())) return true;
        }
        return false;
    }

    /**
     * Returns the full method signature of the "invoke" method in a callback class.
     */
    private static String findInvokeMethodSig(SootClass sc) {
        for (SootMethod m : sc.getMethods()) {
            if ("invoke".equals(m.getName())) return m.getSignature().toString();
        }
        return "<" + sc.getType().getFullyQualifiedName() + ": invoke>";
    }

    // ---- Library symbol index (built from nm -D on LIBS dir) ----

    /**
     * Derives the LIBS directory from the JARFILES directory by convention.
     * JARFILES_&lt;app&gt; -> LIBS_&lt;app&gt; in the same parent directory.
     */
    private static File deriveLibsDir(String jarFilesDir) {
        File jarDir = new File(jarFilesDir);
        String name = jarDir.getName();  // e.g. JARFILES_tomcat_11.0.18-jdk25-temurin-noble
        if (name.startsWith("JARFILES_")) {
            String suffix = name.substring("JARFILES_".length());
            File libsDir = new File(jarDir.getParentFile(), "LIBS_" + suffix);
            if (libsDir.isDirectory()) return libsDir;
        }
        // Fallback: look for any LIBS_* sibling
        File parent = jarDir.getParentFile();
        if (parent != null) {
            File[] siblings = parent.listFiles((d, n) -> n.startsWith("LIBS_") && new File(d, n).isDirectory());
            if (siblings != null && siblings.length == 1) return siblings[0];
        }
        return null;
    }

    /**
     * Builds a symbol -> library-basename index by running nm -D on each .so file.
     * Strips versioned suffixes (e.g. SSL_read@@OPENSSL_3.0.0 -> SSL_read).
     */
    private static void buildLibSymbolIndex(File libsDir) {
        if (libsDir == null || !libsDir.isDirectory()) return;

        File[] soFiles = libsDir.listFiles((d, n) -> n.contains(".so"));
        if (soFiles == null) return;

        int totalSyms = 0;
        for (File so : soFiles) {
            // Skip debug symbol files
            if (so.getName().endsWith(".debug")) continue;

            try {
                ProcessBuilder pb = new ProcessBuilder("nm", "-D", "--defined-only", so.getAbsolutePath());
                pb.redirectErrorStream(true);
                Process proc = pb.start();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        // Format: "addr T symbolname" or "addr T symbolname@@VERSION"
                        String[] parts = line.trim().split("\\s+", 3);
                        if (parts.length < 3) continue;
                        String type = parts[1];
                        // Only exported text/data symbols (T, t, W, w, D, B, etc.)
                        if ("U".equals(type) || "u".equals(type)) continue;
                        String sym = parts[2];
                        // Strip version suffix: SSL_read@@OPENSSL_3.0.0 -> SSL_read
                        int at = sym.indexOf('@');
                        if (at > 0) sym = sym.substring(0, at);
                        // First library wins (prefer libssl over libcrypto for shared symbols)
                        if (!LIB_SYMBOL_INDEX.containsKey(sym)) {
                            LIB_SYMBOL_INDEX.put(sym, so.getName());
                            totalSyms++;
                        }
                    }
                }
                proc.waitFor();
            } catch (Exception e) {
                System.err.println("[WARN] nm failed for " + so.getName() + ": " + e.getMessage());
            }
        }
        System.out.println("[INFO] LIB_SYMBOL_INDEX: " + totalSyms + " symbols from " + soFiles.length + " libraries in " + libsDir.getName());
    }

    /**
     * For a callback wrapper class, extracts the candidate C symbol from the class name,
     * then verifies it exists in the container's libraries via LIB_SYMBOL_INDEX.
     * Returns a FuncInfo(lib, sym) if found, or null if not resolvable.
     */
    private static FuncInfo resolveCallbackFromLibs(String callerClass) {
        if (callerClass == null || LIB_SYMBOL_INDEX.isEmpty()) return null;
        String candidate = inferCallbackSymbol(callerClass);
        if (candidate == null) return null;
        String libFile = LIB_SYMBOL_INDEX.get(candidate);
        // #region agent log
        debugLog("ffi-fallback-resolve", "H2", "resolveCallbackFromLibs candidate lookup", Map.of(
                "class", callerClass,
                "candidate", candidate,
                "libFile", String.valueOf(libFile),
                "indexSize", LIB_SYMBOL_INDEX.size()
        ));
        // #endregion
        if (libFile != null) {
            // Strip "lib" prefix and ".so*" suffix: libssl.so.3 -> ssl
            String lib = libFile;
            if (lib.startsWith("lib")) lib = lib.substring(3);
            int dotSo = lib.indexOf(".so");
            if (dotSo > 0) lib = lib.substring(0, dotSo);
            return new FuncInfo(lib, candidate);
        }
        return null;
    }

    // ---- Data classes ----

    private static final class FuncInfo {
        final String lib;
        final String sym;

        FuncInfo(String lib, String sym) {
            this.lib = lib;
            this.sym = sym;
        }
    }

    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String mechanism;
        final String jar;

        Hit(String callerSig, String lib, String symbol, String mechanism, String jar) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.mechanism = mechanism;
            this.jar = jar;
        }
    }

    // ---- Jimple helpers ----

    private static AbstractInvokeExpr asInvoke(Value v) {
        return (v instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) v : null;
    }

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

    private static String firstStringConst(AbstractInvokeExpr inv) {
        List<Immediate> args = inv.getArgs();
        if (!args.isEmpty() && args.get(0) instanceof StringConstant) {
            return ((StringConstant) args.get(0)).getValue();
        }
        return null;
    }

    private static Local getInvokeBaseLocal(AbstractInvokeExpr inv) {
        Value base = tryInvokeValue(inv, "getBase");
        if (base instanceof Local) return (Local) base;

        Object baseBox = tryInvokeObj(inv, "getBaseBox");
        if (baseBox != null) {
            Object v = tryInvokeObj(baseBox, "getValue");
            if (v instanceof Local) return (Local) v;
        }

        return inv.getUses().filter(u -> u instanceof Local).map(u -> (Local) u).findFirst().orElse(null);
    }

    private static Value tryInvokeValue(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            Object r = m.invoke(target);
            return (r instanceof Value) ? (Value) r : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Object tryInvokeObj(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            return m.invoke(target);
        } catch (Exception ignored) {
            return null;
        }
    }

    // ---- Field reference helpers ----

    private static boolean isFieldRef(Value v) {
        if (v == null) return false;
        return v.getClass().getName().contains("FieldRef");
    }

    private static String fieldKey(Value fieldRef) {
        return fieldRef.toString();
    }

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

    // ---- Jar scanning helpers ----

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
                System.err.println("[WARN] failed reading jar: " + jar + " :: " + ex.getMessage());
            }
        }
        return classes;
    }

    /**
     * Builds a map from fully qualified class name to the JAR file basename.
     */
    private static Map<String, String> buildClassToJarMap(List<String> jarPaths) {
        Map<String, String> map = new HashMap<>();
        for (String jar : jarPaths) {
            String jarName = new File(jar).getName();
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(jar)) {
                java.util.Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    java.util.zip.ZipEntry e = en.nextElement();
                    String name = e.getName();
                    if (name.endsWith(".class") && !name.contains("module-info")) {
                        String cls = name.substring(0, name.length() - 6).replace('/', '.');
                        map.put(cls, jarName);
                    }
                }
            } catch (Exception ex) {
                // skip
            }
        }
        return map;
    }

    private static String toClassPath(List<String> entries) {
        String sep = System.getProperty("path.separator");
        return entries.stream().collect(Collectors.joining(sep));
    }

    private static void debugLog(String runId, String hypothesisId, String message, Map<String, Object> data) {
        try (FileWriter fw = new FileWriter(DEBUG_LOG_PATH, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"sessionId\":\"").append(DEBUG_SESSION_ID).append("\"");
            sb.append(",\"runId\":\"").append(escapeJson(runId)).append("\"");
            sb.append(",\"hypothesisId\":\"").append(escapeJson(hypothesisId)).append("\"");
            sb.append(",\"location\":\"").append("FfiDetector.java").append("\"");
            sb.append(",\"message\":\"").append(escapeJson(message)).append("\"");
            sb.append(",\"data\":").append(toJsonMap(data));
            sb.append(",\"timestamp\":").append(System.currentTimeMillis()).append("}");
            bw.write(sb.toString());
            bw.newLine();
        } catch (Exception ignored) {
        }
    }

    private static String toJsonMap(Map<String, Object> data) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : data.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(e.getKey())).append("\":");
            Object v = e.getValue();
            if (v == null) {
                sb.append("null");
            } else if (v instanceof Number || v instanceof Boolean) {
                sb.append(v.toString());
            } else {
                sb.append("\"").append(escapeJson(String.valueOf(v))).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
