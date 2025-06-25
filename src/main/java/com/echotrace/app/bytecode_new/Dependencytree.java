package com.echotrace.app.bytecode_new;

import java.io.File;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * /// dependencytree
 *
 * This utility analyzes a directory containing JAR files and generates a comprehensive
 * dependency tree showing all classes contained within each JAR. It scans through
 * all JAR files in the specified directory, extracts class information, and presents
 * a hierarchical view of the dependency structure. This is particularly useful for
 * understanding the composition of dependency JARs used in Java static analysis
 * tools and for debugging class loading issues.
 *
 * /// Function Arguments
 * - args[0]: The path to the directory containing dependency JAR files.
 *   This should be a valid directory path where JAR files are stored.
 *   The tool will scan all files with `.jar` extension in this directory.
 *
 * /// Returns
 * - Prints a formatted dependency tree to stdout showing:
 *   - JAR file names
 *   - All classes contained within each JAR (excluding inner classes)
 *   - Total class count per JAR
 *   - Debug information about directory structure and file discovery
 *
 * /// Errors
 * - IllegalArgumentException: If no arguments are provided or the directory path is missing.
 * - FileNotFoundException: If the specified dependency directory does not exist.
 * - IOException: If the specified path is not a directory or if JAR files
 *   cannot be read due to permission issues or corruption.
 * - ZipException: If any JAR file is corrupted or cannot be opened as a ZIP archive.
 *
 * /// Behavior
 * 1. Validates input arguments and directory existence
 * 2. Lists all files in the directory for debugging purposes
 * 3. Filters for files with `.jar` extension
 * 4. Opens each JAR file as a ZIP archive
 * 5. Extracts class names from the archive entries
 * 6. Filters out inner classes (containing '$' in the name)
 * 7. Converts class file paths to fully qualified class names
 * 8. Outputs a formatted tree structure with class counts
 *
 * /// Debug Information
 * - Directory existence and type validation
 * - List of all files found in the directory
 * - Number of JAR files discovered
 * - Error messages for unreadable JAR files
 *
 * /// Example Output
 * Dependency Tree
 * ===============
 * JAR: example.jar
 * Classes:
 *   com.example.MainClass
 *   com.example.UtilityClass
 *   Total classes: 2
 */
public class Dependencytree {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java com.echotrace.app.bytecode_new.Dependencytree <deps-dir>");
            return;
        }
        String depsDir = args[0];
        File depDir = new File(depsDir);
        
        System.out.println("[DEBUG] Checking directory: " + depDir.getAbsolutePath());
        System.out.println("[DEBUG] Directory exists: " + depDir.exists());
        System.out.println("[DEBUG] Is directory: " + depDir.isDirectory());
        
        if (!depDir.exists()) {
            System.err.println("[ERROR] Dependency directory does not exist: " + depsDir);
            return;
        }
        
        if (!depDir.isDirectory()) {
            System.err.println("[ERROR] Dependency path is not a directory: " + depsDir);
            return;
        }
        
        // List all files in directory for debugging
        File[] allFiles = depDir.listFiles();
        if (allFiles != null) {
            System.out.println("[DEBUG] All files in directory:");
            for (File file : allFiles) {
                System.out.println("[DEBUG]   " + file.getName() + " (isFile: " + file.isFile() + ")");
            }
        }
        
        System.out.println("\nDependency Tree\n===============");
        File[] jars = depDir.listFiles((d, name) -> name.endsWith(".jar"));
        
        if (jars == null || jars.length == 0) {
            System.err.println("[ERROR] No JAR files found in directory: " + depDir.getAbsolutePath());
            return;
        }
        
        System.out.println("[DEBUG] Found " + jars.length + " JAR files");
        
        for (File jar : jars) {
            System.out.println();
            System.out.println("JAR: " + jar.getName());
            System.out.println("Classes:");
            try (ZipFile zipFile = new ZipFile(jar)) {
                Enumeration<? extends ZipEntry> entries = zipFile.entries();
                int classCount = 0;
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (name.endsWith(".class") && !name.contains("$")) {
                        String className = name.replace('/', '.').substring(0, name.length() - 6);
                        System.out.println("  " + className);
                        classCount++;
                    }
                }
                System.out.println("  Total classes: " + classCount);
            } catch (Exception e) {
                System.err.println("[ERROR] Could not read JAR: " + jar.getName() + " - " + e.getMessage());
            }
        }
    }
} 
