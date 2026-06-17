package com.echotrace.app.bytecode_new;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.echotrace.app.bytecode_new.DetectorSupport.deriveDefaultOutDir;

/**
 * Unified native-binding detector.
 *
 * PARSE ONCE, DETECT MANY: builds a single {@link AnalysisContext} (one jar
 * scan, one SootUp view, one body warm-up) and runs the JNA dynamic, JNA
 * interface, JNA direct-map, and Java FFM/Panama detectors over it — in
 * parallel by default (disable with -Ddetector.parallel=false). Previously
 * each detector re-parsed every jar; now parsing cost is paid exactly once.
 *
 * jnr-ffi (JnrFfiDetector) and JNI (PrototypeFinal) still run via their own
 * main() and re-parse independently — port them to accept AnalysisContext
 * the same way (a `run(ctx, outDir)` method) to fold them into the shared
 * parse as well.
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
 *     -Dexec.args="<target-jars-dir> [outDir] [runtime-jars-dir]"
 *
 * Outputs (in outDir):
 *   - jna_hits.txt, skipped_methods.txt
 *   - jna_dyn_hits.txt, jna_iface_hits.txt, jna_directmap_hits.txt
 *   - ffi_hits.txt, jnr_ffi_hits.txt, ffi_all_hits.txt, ffi_all_skipped_methods.txt
 *   - analyzed_jars.txt
 */
public final class JNADetector {

    private static final String DYN = "dyn";
    private static final String IFACE = "iface";
    private static final String DIRECTMAP = "directmap";
    private static final String FFI = "ffi";
    private static final String JNR_FFI = "jnr-ffi";

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JNADetector <target-jars-dir> [outDir] [runtime-jars-dir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : deriveDefaultOutDir(targetDir);

        String runtimeDir = (args.length >= 3) ? args[2] : detectRuntimeDir(targetDir);
        if (runtimeDir == null || runtimeDir.isEmpty()) {
            throw new IllegalArgumentException(
                    "PrototypeFinal requires a runtime JAR directory. Pass: JNADetector <target-jars-dir> [outDir] <runtime-jars-dir>");
        }

        Path outPath = Paths.get(outDir);
        Files.createDirectories(outPath);

        Path workRoot = outPath.resolve("jna_detector_work_" + LocalDateTime.now().format(TS_FMT));
        Path dynOut = Files.createDirectories(workRoot.resolve(DYN));
        Path ifaceOut = Files.createDirectories(workRoot.resolve(IFACE));
        Path directOut = Files.createDirectories(workRoot.resolve(DIRECTMAP));
        Path ffiOut = Files.createDirectories(workRoot.resolve(FFI));
        Path jnrOut = Files.createDirectories(workRoot.resolve(JNR_FFI));

        System.out.println("[JNADetector] target=" + targetDir);
        System.out.println("[JNADetector] out   =" + outPath.toAbsolutePath());
        System.out.println("[JNADetector] runtime=" + Paths.get(runtimeDir).toAbsolutePath());
        System.out.println("[JNADetector] work  =" + workRoot.toAbsolutePath());

        writeAnalyzedJarsManifest(targetDir, runtimeDir, outPath.resolve("analyzed_jars.txt"));
        copyIfExists(outPath.resolve("analyzed_jars.txt"), workRoot.resolve("analyzed_jars.txt"));

        // ============================================================
        // Phase 1: parse ONCE (jar index + SootUp view + body warm-up)
        // ============================================================
        System.out.println("[JNADetector] phase=shared-context (single jar parse)");
        AnalysisContext ctx = AnalysisContext.build(targetDir, runtimeDir);

        // ============================================================
        // Phase 2: run detectors over the shared context, in parallel.
        // Each writes to its own work subdir; instance state is per-detector;
        // the context is immutable and bodies are pre-cached, so concurrent
        // runs only read. Console lines may interleave across phases.
        // ============================================================
        List<DetectorPhase> phases = new ArrayList<>();
        phases.add(new DetectorPhase(DYN, () -> new JnaDynDetector().run(ctx, dynOut.toFile())));
        phases.add(new DetectorPhase(IFACE, () -> new JnaIfaceDetector().run(ctx, ifaceOut.toFile())));
        phases.add(new DetectorPhase(DIRECTMAP, () -> new JnaDirectMapDetector().run(ctx, directOut.toFile())));
        phases.add(new DetectorPhase(FFI, () -> new FfiDetector().run(ctx, ffiOut.toFile())));
        runPhases(phases);

        // Not yet ported to AnalysisContext: parses jars on its own.
        System.out.println("[JNADetector] phase=" + JNR_FFI);
        JnrFfiDetector.main(new String[]{targetDir, jnrOut.toString()});

        // ============================================================
        // Phase 3: merge + copy outputs (unchanged file layout)
        // ============================================================
        Path dynHits = dynOut.resolve("jna_dyn_hits.txt");
        Path ifaceHits = ifaceOut.resolve("jna_iface_hits.txt");
        Path directHits = directOut.resolve("jna_directmap_hits.txt");
        Path ffiHits = ffiOut.resolve("ffi_hits.txt");
        Path jnrHits = jnrOut.resolve("jnr_ffi_hits.txt");

        Map<String, Path> allHits = new LinkedHashMap<>();
        allHits.put(DYN, dynHits);
        allHits.put(IFACE, ifaceHits);
        allHits.put(DIRECTMAP, directHits);
        allHits.put(FFI, ffiHits);
        allHits.put(JNR_FFI, jnrHits);

        Map<String, Path> allSkipped = new LinkedHashMap<>();
        allSkipped.put(DYN, dynOut.resolve("skipped_methods.txt"));
        allSkipped.put(IFACE, ifaceOut.resolve("skipped_methods.txt"));
        allSkipped.put(DIRECTMAP, directOut.resolve("skipped_methods.txt"));
        allSkipped.put(FFI, ffiOut.resolve("skipped_methods.txt"));
        allSkipped.put(JNR_FFI, jnrOut.resolve("skipped_methods.txt"));

        Map<String, Path> ffiFamilyHits = new LinkedHashMap<>();
        ffiFamilyHits.put(FFI, ffiHits);
        ffiFamilyHits.put(JNR_FFI, jnrHits);

        Map<String, Path> ffiFamilySkipped = new LinkedHashMap<>();
        ffiFamilySkipped.put(FFI, allSkipped.get(FFI));
        ffiFamilySkipped.put(JNR_FFI, allSkipped.get(JNR_FFI));

        mergePrefixed(outPath.resolve("jna_hits.txt"), "Combined Native Binding Hits", allHits);
        mergePrefixed(outPath.resolve("skipped_methods.txt"), "Combined Skipped Methods", allSkipped);
        mergePrefixed(outPath.resolve("ffi_all_hits.txt"), "Combined FFI Native Binding Hits", ffiFamilyHits);
        mergePrefixed(outPath.resolve("ffi_all_skipped_methods.txt"), "Combined FFI Skipped Methods", ffiFamilySkipped);

        // Keep detector-native output files in the requested outDir as well.
        copyIfExists(dynHits, outPath.resolve("jna_dyn_hits.txt"));
        copyIfExists(ifaceHits, outPath.resolve("jna_iface_hits.txt"));
        copyIfExists(directHits, outPath.resolve("jna_directmap_hits.txt"));
        copyIfExists(ffiHits, outPath.resolve("ffi_hits.txt"));
        copyIfExists(jnrHits, outPath.resolve("jnr_ffi_hits.txt"));

        // ============================================================
        // Phase 4: JNI detection (PrototypeFinal) — still its own parse.
        // ============================================================
        runPrototypeFinal(targetDir, runtimeDir, outPath);

        System.out.println("[JNADetector] done");
    }

    // ------------------- Detector execution -------------------

    /** A named detector run that can throw. */
    private static final class DetectorPhase {
        final String name;
        final ThrowingRunnable body;

        DetectorPhase(String name, ThrowingRunnable body) {
            this.name = name;
            this.body = body;
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * Runs detector phases in parallel (default) or sequentially with
     * -Ddetector.parallel=false. Any phase failure aborts the run.
     */
    private static void runPhases(List<DetectorPhase> phases) throws Exception {
        boolean parallel = !"false".equals(System.getProperty("detector.parallel"));

        if (!parallel) {
            for (DetectorPhase p : phases) {
                System.out.println("[JNADetector] phase=" + p.name);
                p.body.run();
            }
            return;
        }

        ExecutorService pool = Executors.newFixedThreadPool(phases.size());
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (DetectorPhase p : phases) {
                futures.add(pool.submit((Callable<Void>) () -> {
                    System.out.println("[JNADetector] phase=" + p.name + " (parallel)");
                    p.body.run();
                    System.out.println("[JNADetector] phase=" + p.name + " done");
                    return null;
                }));
            }
            for (int i = 0; i < futures.size(); i++) {
                try {
                    futures.get(i).get();
                } catch (ExecutionException e) {
                    throw new RuntimeException("detector phase '" + phases.get(i).name + "' failed", e.getCause());
                }
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static void runPrototypeFinal(String targetDir, String runtimeDir, Path outDir) throws Exception {
        Files.createDirectories(outDir);
        System.out.println("[JNADetector] phase=prototype-final");
        System.out.println("[JNADetector] prototype-final out=" + outDir.toAbsolutePath());

        String previousOutDir = System.getProperty("prototype.output.dir");
        System.setProperty("prototype.output.dir", outDir.toString());
        try {
            PrototypeFinal.main(new String[]{targetDir, "--1", "--runtime", runtimeDir});
        } finally {
            if (previousOutDir == null) {
                System.clearProperty("prototype.output.dir");
            } else {
                System.setProperty("prototype.output.dir", previousOutDir);
            }
        }
    }

    // ------------------- Runtime dir detection -------------------

    private static String detectRuntimeDir(String targetDir) {
        String envRuntime = System.getenv("PROTOTYPE_RUNTIME_DIR");
        if (envRuntime != null && !envRuntime.isEmpty()) {
            return envRuntime;
        }

        File target = new File(targetDir).getAbsoluteFile();
        String name = target.getName();
        if (!name.startsWith("JARFILES_")) {
            return null;
        }
        File parent = target.getParentFile();
        if (parent == null) {
            return null;
        }

        String suffix = name.substring("JARFILES_".length());
        for (String prefix : new String[]{"RUNTIME_", "JDK_RUNTIME_"}) {
            File candidate = new File(parent, prefix + suffix);
            if (candidate.isDirectory()) {
                return candidate.getAbsolutePath();
            }
        }
        return null;
    }

    // ------------------- Manifest -------------------

    private static void writeAnalyzedJarsManifest(String targetDir, String runtimeDir, Path outFile) throws IOException {
        List<String> targetJars = listArchiveFiles(Paths.get(targetDir));
        List<String> runtimeJars = listArchiveFiles(Paths.get(runtimeDir));

        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== JNADetector Analyzed Archives ===\n");
            w.write("targetDir=" + Paths.get(targetDir).toAbsolutePath() + "\n");
            w.write("runtimeDir=" + Paths.get(runtimeDir).toAbsolutePath() + "\n");
            w.write("targetArchives=" + targetJars.size() + "\n");
            w.write("runtimeArchives=" + runtimeJars.size() + "\n\n");

            w.write("[target]\n");
            for (String jar : targetJars) {
                w.write(jar + "\n");
            }
            w.write("\n[runtime]\n");
            for (String jar : runtimeJars) {
                w.write(jar + "\n");
            }
        }

        System.out.println("[JNADetector] wrote " + outFile.toAbsolutePath()
                + " (target=" + targetJars.size() + ", runtime=" + runtimeJars.size() + ")");
    }

    private static List<String> listArchiveFiles(Path dir) throws IOException {
        List<String> archives = new ArrayList<>();
        if (dir == null || !Files.isDirectory(dir)) {
            return archives;
        }
        try (java.util.stream.Stream<Path> stream = Files.walk(dir)) {
            stream.filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.endsWith(".jar") || name.endsWith(".jmod");
                    })
                    .forEach(p -> archives.add(p.toAbsolutePath().toString()));
        }
        Collections.sort(archives);
        return archives;
    }

    // ------------------- Merging (one helper for hits AND skips) -------------------

    /**
     * Merges per-detector files into one, prefixing each payload line with the
     * detector name. Headers ("===", "Format:") and blank lines are dropped.
     */
    private static void mergePrefixed(Path outFile, String title, Map<String, Path> sources) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== " + title + " ===\n");
            w.write("Format: detector | payload\n\n");
            for (Map.Entry<String, Path> e : sources.entrySet()) {
                appendPrefixed(w, e.getKey(), e.getValue());
            }
        }
        System.out.println("[JNADetector] wrote " + outFile.toAbsolutePath());
    }

    private static void appendPrefixed(BufferedWriter w, String detector, Path file) throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("===") || trimmed.startsWith("Format:")) {
                    continue;
                }
                w.write(detector + " | " + line + "\n");
            }
        }
    }

    private static void copyIfExists(Path src, Path dst) throws IOException {
        if (Files.exists(src)) {
            Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
