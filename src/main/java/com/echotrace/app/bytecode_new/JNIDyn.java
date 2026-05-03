package com.echotrace.app.bytecode_new;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * JNI Dynamic Binding Analyzer
 *
 * Scans a directory of .so files (produced by sysdig_complete.sh into
 * LIBS_<image>/) to detect JNI dynamic binding via RegisterNatives().
 *
 * USAGE:
 *   java JNIDyn <libs-dir> <natives-file> [--verbose]
 *
 * INPUT:
 *   libs-dir      : LIBS_<image>/ directory from sysdig_complete.sh
 *   natives-file  : native_methods.txt or sootup_visitor_natives.txt
 *                   produced by PrototypeFinal (one "ClassName.method"
 *                   per line, or the full SootUp report format)
 *   --verbose     : print per-symbol detail to stdout
 *
 * OUTPUT:
 *   jni_dynamic_report.txt in the current working directory
 *
 * WHAT IT DETECTS:
 *   Static binding  — Java_ClassName_methodName convention, resolved
 *                     automatically by the JVM linker, no runtime call
 *                     needed. PrototypeFinal already covers this.
 *   Dynamic binding — Library calls RegisterNatives() (usually from
 *                     JNI_OnLoad) to map Java native declarations to
 *                     arbitrary C function names at runtime.
 *                     This tool detects which libraries do this and
 *                     which exported C symbols are candidates.
 *
 * SIGNAL LEVELS:
 *   HIGH   — RegisterNatives string found AND JNI_OnLoad exported symbol
 *             present in ELF dynamic symbol table. Library almost
 *             certainly uses dynamic binding.
 *   MEDIUM — RegisterNatives string found, JNI_OnLoad not in symbol
 *             table (may be present but not exported, or string is an
 *             import reference rather than a call site).
 *   LOW    — JNI_OnLoad in symbol table but RegisterNatives string
 *             absent. Library has a JNI entry point but may use static
 *             binding only.
 */
public class JNIDyn {

    // ----------------------------------------------------------------
    // ELF constants needed for symbol table parsing
    // ----------------------------------------------------------------

    private static final int ELF_MAGIC       = 0x7f454c46; // \x7fELF
    private static final int ET_DYN          = 3;           // shared object
    private static final int SHT_DYNSYM      = 11;          // dynamic symbol section
    private static final int SHT_STRTAB      = 3;           // string table section
    private static final int STB_GLOBAL      = 1;           // global binding
    private static final int STB_WEAK        = 2;           // weak binding
    private static final int EI_CLASS        = 4;           // offset of EI_CLASS in e_ident
    private static final int ELFCLASS32      = 1;
    private static final int ELFCLASS64      = 2;

    // ----------------------------------------------------------------
    // Data classes
    // ----------------------------------------------------------------

    /**
     * Per-.so scan result.
     */
    static class SoScanResult {
        final String soPath;
        final String soName;

        // String-scan results
        boolean hasRegisterNatives = false;
        long    rnOffset           = -1;   // byte offset of first occurrence
        boolean hasJniOnLoadString = false; // raw string present anywhere

        // ELF symbol table results
        boolean jniOnLoadExported  = false; // JNI_OnLoad is in .dynsym
        List<String> exportedSymbols = new ArrayList<>(); // all exported symbol names
        List<String> jniStyleSymbols = new ArrayList<>(); // Java_* exports (static binding)
        boolean elfParsed          = false; // false if ELF parse failed

        // Derived signal
        enum Signal { HIGH, MEDIUM, LOW, NONE }
// Replace the current signal() method in SoScanResult
        Signal signal() {
            if (jniOnLoadExported)    return Signal.HIGH;    // JNI_OnLoad = dynamic binding
            if (hasRegisterNatives)   return Signal.MEDIUM;  // unusual string match
            if (!jniStyleSymbols.isEmpty()) return Signal.LOW; // static binding only
            return Signal.NONE;
        }
        SoScanResult(String soPath) {
            this.soPath = soPath;
            this.soName = new File(soPath).getName();
        }
    }

    // ----------------------------------------------------------------
    // Main entry point
    // ----------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: java JNIDyn <libs-dir> <natives-file> [--verbose]");
            System.err.println("  libs-dir     : LIBS_<image>/ from sysdig_complete.sh");
            System.err.println("  natives-file : native_methods.txt from PrototypeFinal");
            System.err.println("  --verbose    : print per-symbol detail");
            return;
        }

        String libsDir     = args[0];
        String nativesFile = args[1];
        boolean verbose    = args.length >= 3 && "--verbose".equals(args[2]);

        System.out.println("=== JNIDyn: JNI Dynamic Binding Analyzer ===");
        System.out.println("Libs dir    : " + libsDir);
        System.out.println("Natives file: " + nativesFile);

        long startTime = System.currentTimeMillis();

        // Load declared native methods from PrototypeFinal output
        Set<String> declaredNatives = loadDeclaredNatives(nativesFile);
        System.out.println("Loaded " + declaredNatives.size() + " declared native methods");

        // Scan all .so files
        List<SoScanResult> results = scanLibsDirectory(libsDir, verbose);

        // Write report
        String outputFile = "jni_dynamic_report.txt";
        writeReport(outputFile, results, declaredNatives);

        long elapsed = System.currentTimeMillis() - startTime;
        System.out.printf("%nDone in %.2fs%n", elapsed / 1000.0);
        System.out.println("Report: " + new File(outputFile).getAbsolutePath());
    }

    // ----------------------------------------------------------------
    // Load declared natives from PrototypeFinal output
    // ----------------------------------------------------------------

    /**
     * Parses native_methods.txt or sootup_visitor_natives.txt.
     *
     * Both files contain lines like:
     *   java.lang.System.currentTimeMillis
     *   sun.nio.ch.FileDispatcherImpl.read0
     *
     * The SootUp report has header lines starting with '=' or 'Total'
     * which are skipped automatically.
     *
     * Returns a Set of "ClassName.methodName" strings.
     */
    private static Set<String> loadDeclaredNatives(String filePath) throws IOException {
        Set<String> result = new LinkedHashSet<>();
        File f = new File(filePath);
        if (!f.exists()) {
            System.err.println("WARNING: natives file not found: " + filePath);
            return result;
        }
        for (String line : Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("=") || line.startsWith("Total")
                    || line.startsWith("Native") || line.startsWith("#")) {
                continue;
            }
            // Strip the "---descriptor" suffix produced by FindNativeMethods in Mode 1
            // e.g. "java.lang.System.currentTimeMillis---()J" -> "java.lang.System.currentTimeMillis"
            int dashIdx = line.indexOf("---");
            if (dashIdx != -1) {
                line = line.substring(0, dashIdx);
            }
            result.add(line);
        }
        return result;
    }

    // ----------------------------------------------------------------
    // Directory walker
    // ----------------------------------------------------------------

    /**
     * Recursively finds all .so files under libsDir and scans each one.
     * Matches both plain "libfoo.so" and versioned "libfoo.so.1.2.3".
     */
    private static List<SoScanResult> scanLibsDirectory(String libsDir, boolean verbose) {
        List<SoScanResult> results = new ArrayList<>();
        File root = new File(libsDir);
        if (!root.exists() || !root.isDirectory()) {
            System.err.println("ERROR: libs directory not found: " + libsDir);
            return results;
        }

        Deque<File> stack = new ArrayDeque<>();
        stack.push(root);
        int total = 0;

        while (!stack.isEmpty()) {
            File dir = stack.pop();
            File[] files = dir.listFiles();
            if (files == null) continue;
            for (File f : files) {
                if (f.isDirectory()) {
                    stack.push(f);
                } else if (isSoFile(f.getName())) {
                    total++;
                    SoScanResult r = scanSoFile(f, verbose);
                    if (r.signal() != SoScanResult.Signal.NONE) {
                        results.add(r);
                    }
                }
            }
        }

        System.out.println("Scanned " + total + " .so files, "
            + results.size() + " with JNI dynamic binding signals.");

        // Sort: HIGH first, then MEDIUM, then LOW
        results.sort(Comparator.comparingInt(r -> -r.signal().ordinal()));
        // ordinal: HIGH=0, MEDIUM=1, LOW=2 — negate to get descending
        // Fix: HIGH has lowest ordinal, so ascending ordinal = HIGH first
        results.sort(Comparator.comparingInt(r -> r.signal().ordinal()));

        return results;
    }

    private static boolean isSoFile(String name) {
        return name.endsWith(".so") || name.contains(".so.");
    }

    // ----------------------------------------------------------------
    // Per-file scan: string scan + ELF symbol table
    // ----------------------------------------------------------------

    private static SoScanResult scanSoFile(File f, boolean verbose) {
        SoScanResult result = new SoScanResult(f.getAbsolutePath());

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(f.toPath());
        } catch (IOException e) {
            System.err.println("  [skip] cannot read: " + f.getName() + " — " + e.getMessage());
            return result;
        }

        // ---- 1. Raw string scan (fast, always runs) ----
        // ISO_8859_1: 1-to-1 byte↔char, so indexOf on ASCII strings is exact
        String raw = new String(bytes, StandardCharsets.ISO_8859_1);

        int rnIdx = raw.indexOf("RegisterNatives");
        if (rnIdx != -1) {
            result.hasRegisterNatives = true;
            result.rnOffset = rnIdx;
        }
        result.hasJniOnLoadString = raw.contains("JNI_OnLoad");

        // ---- 2. ELF dynamic symbol table parse ----
        if (bytes.length >= 16 && isElfMagic(bytes)) {
            try {
                parseElfDynsym(bytes, result);
                result.elfParsed = true;
            } catch (Exception e) {
                // Non-fatal — string scan results are still valid
                if (verbose) {
                    System.err.println("  [warn] ELF parse error in " + f.getName()
                        + ": " + e.getMessage());
                }
            }
        }

        if (verbose && result.signal() != SoScanResult.Signal.NONE) {
            System.out.println("  [" + result.signal() + "] " + f.getName()
                + "  RN=" + result.hasRegisterNatives
                + "  JNI_OnLoad_exported=" + result.jniOnLoadExported
                + "  exports=" + result.exportedSymbols.size());
        }

        return result;
    }

    private static boolean isElfMagic(byte[] bytes) {
        return bytes[0] == 0x7f && bytes[1] == 'E'
            && bytes[2] == 'L' && bytes[3] == 'F';
    }

    // ----------------------------------------------------------------
    // ELF dynamic symbol table parser (32-bit and 64-bit)
    //
    // We only need the .dynsym section (type SHT_DYNSYM) and its
    // associated string table (.dynstr).
    //
    // ELF64 layout used below; ELF32 uses different field sizes/offsets
    // but the same logical structure.
    // ----------------------------------------------------------------

    private static void parseElfDynsym(byte[] bytes, SoScanResult result) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        // Determine endianness from EI_DATA (byte 5 in e_ident)
        // 1 = little-endian (ELFDATA2LSB), 2 = big-endian (ELFDATA2MSB)
        byte eiData = bytes[5];
        buf.order(eiData == 2 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        // EI_CLASS: 1 = 32-bit, 2 = 64-bit
        byte eiClass = bytes[EI_CLASS];

        if (eiClass == ELFCLASS64) {
            parseElf64(buf, result);
        } else if (eiClass == ELFCLASS32) {
            parseElf32(buf, result);
        }
        // else: unknown class, skip silently
    }

    // ---- ELF64 ----
    private static void parseElf64(ByteBuffer buf, SoScanResult result) throws Exception {
        // ELF64 header offsets (all little-endian fields):
        //   e_shoff   @ 0x28 (8 bytes) — offset to section header table
        //   e_shentsize @ 0x3A (2 bytes) — size of one section header entry
        //   e_shnum   @ 0x3C (2 bytes) — number of section headers
        //   e_shstrndx @ 0x3E (2 bytes) — index of section name string table

        long  shoff     = buf.getLong(0x28);
        short shentsize = buf.getShort(0x3A);
        short shnum     = buf.getShort(0x3C);
        short shstrndx  = buf.getShort(0x3E);

        if (shoff == 0 || shnum == 0) return; // stripped, no section headers

        // Read section name string table first (for finding ".dynsym"/".dynstr")
        byte[] shstrtab = readSection64(buf, shoff, shentsize, shstrndx);

        // Find .dynsym and .dynstr section indices
        int dynsymIdx = -1, dynstrIdx = -1;
        for (int i = 0; i < (shnum & 0xffff); i++) {
            long shEntryOffset = shoff + (long) i * (shentsize & 0xffff);
            int  sh_name = buf.getInt((int) shEntryOffset);     // offset into shstrtab
            int  sh_type = buf.getInt((int) shEntryOffset + 4);

            String sname = readCString(shstrtab, sh_name);
            if (sh_type == SHT_DYNSYM && ".dynsym".equals(sname)) dynsymIdx = i;
            if (sh_type == SHT_STRTAB && ".dynstr".equals(sname)) dynstrIdx = i;
        }

        if (dynsymIdx == -1 || dynstrIdx == -1) return; // section not found

        byte[] dynsymData = readSection64(buf, shoff, shentsize, dynsymIdx);
        byte[] dynstrData = readSection64(buf, shoff, shentsize, dynstrIdx);

        // ELF64 symbol entry: 24 bytes
        //   st_name  @ 0  (4 bytes) — index into .dynstr
        //   st_info  @ 4  (1 byte)  — type and binding
        //   st_other @ 5  (1 byte)
        //   st_shndx @ 6  (2 bytes)
        //   st_value @ 8  (8 bytes)
        //   st_size  @ 16 (8 bytes)
        int symSize = 24;
        int count   = dynsymData.length / symSize;
        ByteBuffer symBuf = ByteBuffer.wrap(dynsymData).order(buf.order());

        for (int i = 0; i < count; i++) {
            int offset  = i * symSize;
            int stName  = symBuf.getInt(offset);
            byte stInfo = symBuf.get(offset + 4);
            int binding = (stInfo >> 4) & 0xf;

            // Only global and weak symbols are externally visible
            if (binding != STB_GLOBAL && binding != STB_WEAK) continue;

            String symName = readCString(dynstrData, stName);
            if (symName.isEmpty()) continue;

            result.exportedSymbols.add(symName);

            if ("JNI_OnLoad".equals(symName)) {
                result.jniOnLoadExported = true;
            }
            if (symName.startsWith("Java_")) {
                result.jniStyleSymbols.add(symName);
            }
        }
    }

    // ---- ELF32 ----
    private static void parseElf32(ByteBuffer buf, SoScanResult result) throws Exception {
        // ELF32 header offsets:
        //   e_shoff     @ 0x20 (4 bytes)
        //   e_shentsize @ 0x2E (2 bytes)
        //   e_shnum     @ 0x30 (2 bytes)
        //   e_shstrndx  @ 0x32 (2 bytes)

        int   shoff     = buf.getInt(0x20);
        short shentsize = buf.getShort(0x2E);
        short shnum     = buf.getShort(0x30);
        short shstrndx  = buf.getShort(0x32);

        if (shoff == 0 || shnum == 0) return;

        byte[] shstrtab = readSection32(buf, shoff, shentsize, shstrndx);

        int dynsymIdx = -1, dynstrIdx = -1;
        for (int i = 0; i < (shnum & 0xffff); i++) {
            int  shEntryOffset = shoff + i * (shentsize & 0xffff);
            int  sh_name = buf.getInt(shEntryOffset);
            int  sh_type = buf.getInt(shEntryOffset + 4);

            String sname = readCString(shstrtab, sh_name);
            if (sh_type == SHT_DYNSYM && ".dynsym".equals(sname)) dynsymIdx = i;
            if (sh_type == SHT_STRTAB && ".dynstr".equals(sname)) dynstrIdx = i;
        }

        if (dynsymIdx == -1 || dynstrIdx == -1) return;

        byte[] dynsymData = readSection32(buf, shoff, shentsize, dynsymIdx);
        byte[] dynstrData = readSection32(buf, shoff, shentsize, dynstrIdx);

        // ELF32 symbol entry: 16 bytes
        //   st_name  @ 0  (4 bytes)
        //   st_value @ 4  (4 bytes)
        //   st_size  @ 8  (4 bytes)
        //   st_info  @ 12 (1 byte)
        //   st_other @ 13 (1 byte)
        //   st_shndx @ 14 (2 bytes)
        int symSize = 16;
        int count   = dynsymData.length / symSize;
        ByteBuffer symBuf = ByteBuffer.wrap(dynsymData).order(buf.order());

        for (int i = 0; i < count; i++) {
            int offset  = i * symSize;
            int stName  = symBuf.getInt(offset);
            byte stInfo = symBuf.get(offset + 12);
            int binding = (stInfo >> 4) & 0xf;

            if (binding != STB_GLOBAL && binding != STB_WEAK) continue;

            String symName = readCString(dynstrData, stName);
            if (symName.isEmpty()) continue;

            result.exportedSymbols.add(symName);

            if ("JNI_OnLoad".equals(symName)) {
                result.jniOnLoadExported = true;
            }
            if (symName.startsWith("Java_")) {
                result.jniStyleSymbols.add(symName);
            }
        }
    }

    // ---- ELF section data helpers ----

    private static byte[] readSection64(ByteBuffer buf, long shoff, short shentsize, int idx)
            throws Exception {
        long entryOff = shoff + (long) idx * (shentsize & 0xffff);
        // sh_offset @ +24 (8 bytes), sh_size @ +32 (8 bytes) in ELF64 section header
        long sectionOff  = buf.getLong((int) entryOff + 24);
        long sectionSize = buf.getLong((int) entryOff + 32);
        if (sectionOff < 0 || sectionSize <= 0 || sectionOff + sectionSize > buf.capacity()) {
            return new byte[0];
        }
        byte[] data = new byte[(int) sectionSize];
        buf.position((int) sectionOff);
        buf.get(data);
        return data;
    }

    private static byte[] readSection32(ByteBuffer buf, int shoff, short shentsize, int idx)
            throws Exception {
        int entryOff = shoff + idx * (shentsize & 0xffff);
        // sh_offset @ +16 (4 bytes), sh_size @ +20 (4 bytes) in ELF32 section header
        int sectionOff  = buf.getInt(entryOff + 16);
        int sectionSize = buf.getInt(entryOff + 20);
        if (sectionOff < 0 || sectionSize <= 0 || sectionOff + sectionSize > buf.capacity()) {
            return new byte[0];
        }
        byte[] data = new byte[sectionSize];
        buf.position(sectionOff);
        buf.get(data);
        return data;
    }

    /**
     * Reads a null-terminated C string from a byte array at a given offset.
     * Returns empty string if offset is out of bounds.
     */
    private static String readCString(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) return "";
        int end = offset;
        while (end < data.length && data[end] != 0) end++;
        return new String(data, offset, end - offset, StandardCharsets.US_ASCII);
    }

    // ----------------------------------------------------------------
    // Report writer
    // ----------------------------------------------------------------

    private static void writeReport(
            String filename,
            List<SoScanResult> results,
            Set<String> declaredNatives) throws IOException {

        StringBuilder sb = new StringBuilder();

        sb.append("=== JNIDyn: JNI Dynamic Binding Report ===\n\n");
        sb.append("Libraries with dynamic binding signals: ").append(results.size()).append("\n\n");

        // -- Summary table --
        sb.append("Signal  Library\n");
        sb.append("------  -------\n");
        for (SoScanResult r : results) {
            sb.append(String.format("%-7s %s%n", "[" + r.signal() + "]", r.soName));
        }
        sb.append("\n");

        // -- Per-library detail --
        sb.append("=== Per-Library Detail ===\n\n");
        for (SoScanResult r : results) {
            sb.append("Library : ").append(r.soName).append("\n");
            sb.append("Path    : ").append(r.soPath).append("\n");
            sb.append("Signal  : ").append(r.signal()).append("\n");
            sb.append("  RegisterNatives string : ").append(r.hasRegisterNatives)
              .append(r.hasRegisterNatives ? "  @offset=" + r.rnOffset : "").append("\n");
            sb.append("  JNI_OnLoad exported    : ").append(r.jniOnLoadExported).append("\n");
            sb.append("  JNI_OnLoad string      : ").append(r.hasJniOnLoadString).append("\n");
            sb.append("  ELF parsed             : ").append(r.elfParsed).append("\n");
            sb.append("  Exported symbols total : ").append(r.exportedSymbols.size()).append("\n");

            if (!r.jniStyleSymbols.isEmpty()) {
                sb.append("  Java_* exports (static binding also present):\n");
                for (String sym : r.jniStyleSymbols) {
                    sb.append("    ").append(sym).append("\n");
                }
            }

            // Cross-reference: which declared native methods could be backed
            // by this library?
            //
            // Heuristic: extract the simple class name from the library name
            // e.g. "libzip.so" -> look for natives in classes containing "zip"
            // e.g. "libnet.so" -> look for natives in classes containing "net"
            //
            // This is intentionally loose — the goal is to surface candidates,
            // not to make definitive claims. Follow up with runtime analysis
            // (Frida / RegisterNatives hook) for confirmation.
            String libBase = r.soName
                .replaceAll("^lib", "")
                .replaceAll("\\.so.*$", "")
                .toLowerCase();

            List<String> candidates = new ArrayList<>();
            for (String native_ : declaredNatives) {
                if (native_.toLowerCase().contains(libBase)) {
                    candidates.add(native_);
                }
            }

            if (!candidates.isEmpty()) {
                sb.append("  Possible Java-side native declarations (name-heuristic):\n");
                for (String c : candidates) {
                    sb.append("    ").append(c).append("\n");
                }
            } else {
                sb.append("  Possible Java-side native declarations: (no name match — check manually)\n");
            }

            sb.append("\n");
        }

        // -- All declared natives reminder --
        sb.append("=== All Declared Native Methods from PrototypeFinal ===\n");
        sb.append("(").append(declaredNatives.size()).append(" total)\n\n");
        List<String> sorted = new ArrayList<>(declaredNatives);
        Collections.sort(sorted);
        for (String n : sorted) {
            sb.append("  ").append(n).append("\n");
        }

        sb.append("\n=== Notes ===\n");
        sb.append("HIGH   = JNI_OnLoad exported → uses RegisterNatives() via vtable.\n");
        sb.append("         C functions have arbitrary names, not Java_* convention.\n");
        sb.append("         Use nm -D <lib> to see exported symbols.\n");
        sb.append("MEDIUM = RegisterNatives string found but no JNI_OnLoad. Unusual.\n");
        sb.append("LOW    = Static binding only (Java_* exports, no JNI_OnLoad).\n");
        sb.append("         Likely static binding only, or RegisterNatives was inlined.\n");

        try (FileWriter fw = new FileWriter(filename)) {
            fw.write(sb.toString());
        }

        // Console summary
        long high   = results.stream().filter(r -> r.signal() == SoScanResult.Signal.HIGH).count();
        long medium = results.stream().filter(r -> r.signal() == SoScanResult.Signal.MEDIUM).count();
        long low    = results.stream().filter(r -> r.signal() == SoScanResult.Signal.LOW).count();
        System.out.println("  HIGH   (RegisterNatives + JNI_OnLoad exported): " + high);
        System.out.println("  MEDIUM (RegisterNatives string only)           : " + medium);
        System.out.println("  LOW    (JNI_OnLoad exported, no RN string)     : " + low);
    }
}