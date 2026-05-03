package com.echotrace.app.bytecode_new;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Unified JNA detector that runs dynamic, interface, and direct-map detectors,
 * then merges their outputs into a single keep-all report.
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
 *     -Dexec.args="<target-jars-dir> [outDir]"
 *
 * Outputs (in outDir):
 *   - jna_hits.txt
 *   - skipped_methods.txt
 *   - jna_dyn_hits.txt
 *   - jna_iface_hits.txt
 *   - jna_directmap_hits.txt
 */
public class JNADetector {

    private static final String DYN = "dyn";
    private static final String IFACE = "iface";
    private static final String DIRECTMAP = "directmap";

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JNADetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : ".";

        Path outPath = Paths.get(outDir);
        Files.createDirectories(outPath);

        String runStamp = LocalDateTime.now().format(TS_FMT);
        Path workRoot = outPath.resolve("jna_detector_work_" + runStamp);
        Files.createDirectories(workRoot);

        Path dynOutDir = workRoot.resolve("dyn");
        Path ifaceOutDir = workRoot.resolve("iface");
        Path directOutDir = workRoot.resolve("directmap");
        Files.createDirectories(dynOutDir);
        Files.createDirectories(ifaceOutDir);
        Files.createDirectories(directOutDir);

        System.out.println("[JNADetector] target=" + targetDir);
        System.out.println("[JNADetector] out   =" + outPath.toAbsolutePath());
        System.out.println("[JNADetector] work  =" + workRoot.toAbsolutePath());

        runDynamic(targetDir, dynOutDir.toString());
        runInterface(targetDir, ifaceOutDir.toString());
        runDirectMap(targetDir, directOutDir.toString());

        Path dynHits = dynOutDir.resolve("jna_dyn_hits.txt");
        Path ifaceHits = ifaceOutDir.resolve("jna_iface_hits.txt");
        Path directHits = directOutDir.resolve("jna_directmap_hits.txt");

        Path dynSkipped = dynOutDir.resolve("skipped_methods.txt");
        Path ifaceSkipped = ifaceOutDir.resolve("skipped_methods.txt");
        Path directSkipped = directOutDir.resolve("skipped_methods.txt");

        Path combinedHits = outPath.resolve("jna_hits.txt");
        Path combinedSkipped = outPath.resolve("skipped_methods.txt");

        mergeHits(combinedHits, dynHits, ifaceHits, directHits);
        mergeSkipped(combinedSkipped, dynSkipped, ifaceSkipped, directSkipped);

        // Keep detector-native output files in the requested outDir as well.
        copyIfExists(dynHits, outPath.resolve("jna_dyn_hits.txt"));
        copyIfExists(ifaceHits, outPath.resolve("jna_iface_hits.txt"));
        copyIfExists(directHits, outPath.resolve("jna_directmap_hits.txt"));

        System.out.println("[JNADetector] wrote " + combinedHits.toAbsolutePath());
        System.out.println("[JNADetector] wrote " + combinedSkipped.toAbsolutePath());
        System.out.println("[JNADetector] done");
    }

    private static void runDynamic(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + DYN);
        JnaDynDetector.main(new String[]{targetDir, outDir});
    }

    private static void runInterface(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + IFACE);
        JnaIfaceDetector.main(new String[]{targetDir, outDir});
    }

    private static void runDirectMap(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + DIRECTMAP);
        JnaDirectMapDetector.main(new String[]{targetDir, outDir});
    }

    private static void mergeHits(Path outFile, Path dynFile, Path ifaceFile, Path directFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined JNA Hits ===\n");
            w.write("Format: detector | payload\n\n");

            appendHitsFile(w, DYN, dynFile);
            appendHitsFile(w, IFACE, ifaceFile);
            appendHitsFile(w, DIRECTMAP, directFile);
        }
    }

    private static void appendHitsFile(BufferedWriter w, String detector, Path file) throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (trimmed.startsWith("===") || trimmed.startsWith("Format:")) {
                    continue;
                }
                w.write(detector);
                w.write(" | ");
                w.write(line);
                w.write('\n');
            }
        }
    }

    private static void mergeSkipped(Path outFile, Path dynFile, Path ifaceFile, Path directFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined Skipped Methods ===\n");
            w.write("Format: detector | payload\n\n");

            appendSkippedFile(w, DYN, dynFile);
            appendSkippedFile(w, IFACE, ifaceFile);
            appendSkippedFile(w, DIRECTMAP, directFile);
        }
    }

    private static void appendSkippedFile(BufferedWriter w, String detector, Path file) throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (trimmed.startsWith("===") || trimmed.startsWith("Format:")) {
                    continue;
                }
                w.write(detector);
                w.write(" | ");
                w.write(line);
                w.write('\n');
            }
        }
    }

    private static void copyIfExists(Path src, Path dst) throws IOException {
        if (!Files.exists(src)) {
            return;
        }
        Files.copy(src, dst, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
}
