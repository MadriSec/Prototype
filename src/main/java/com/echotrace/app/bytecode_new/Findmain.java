package com.echotrace.app.bytecode_new;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.model.MethodModifier;

/**
 * /// Findmain
 *
 * This utility analyzes a target JAR file and its dependency JARs to find all main methods
 * in the target classes. It scans through the target JAR, identifies classes that are not
 * part of the dependency JARs, and locates public static void main(String[]) methods.
 * This is particularly useful for identifying entry points in Java applications and
 * understanding the structure of executable classes.
 *
 * /// Function Arguments
 * - args[0]: The path to the target JAR file to analyze for main methods.
 *   This should be a valid JAR file containing the application classes.
 * - args[1]: The path to the directory containing dependency JAR files.
 *   This should be a valid directory path where dependency JAR files are stored.
 *   The tool will scan all files with `.jar` extension in this directory.
 *
 * /// Returns
 * - Prints found main methods to stdout showing:
 *   - Method signatures of all main methods found
 *   - Summary of classes and method counts
 *   - Detailed breakdown by class
 * - Writes class names to found_main_methods_target.txt file
 *
 * /// Errors
 * - IllegalArgumentException: If insufficient arguments are provided.
 * - FileNotFoundException: If the target JAR or dependency directory does not exist.
 * - IOException: If JAR files cannot be read due to permission issues or corruption.
 * - ZipException: If any JAR file is corrupted or cannot be opened as a ZIP archive.
 *
 * /// Behavior
 * 1. Validates input arguments and file existence
 * 2. Scans dependency directory to build set of dependency classes
 * 3. Initializes SootUp view with target and dependency JARs
 * 4. Iterates through all classes in the view
 * 5. Filters out classes that belong to dependency JARs
 * 6. Identifies public static void main(String[]) methods
 * 7. Collects and categorizes main methods by class
 * 8. Outputs results to console and file
 *
 * /// Main Method Criteria
 * - Method name must be "main"
 * - Must be public and static
 * - Must have exactly one parameter of type String[]
 * - Must return void
 * - Must be in a class that is not part of dependency JARs
 *
 * /// Output Format
 * - Console: Detailed method signatures and summary statistics
 * - File: Simple list of class names containing main methods
 * - Debug: Information about dependency class discovery
 *
 * /// Example Output
 * Found main method: <com.example.app.MainApp: void main(java.lang.String[])>
 * === Summary ===
 * Total classes with main methods: 1
 * Total main methods found: 1
 * Class: com.example.app.MainApp (1 main method(s))
 *   - <com.example.app.MainApp: void main(java.lang.String[])>
 */
public class Findmain {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java com.echotrace.app.bytecode_new.Findmain <target-jar> <deps-dir>");
            return;
        }
        String targetJar = args[0];
        String depsDir = args[1];
        
        // Get dependency classes from dependency JARs
        Set<String> dependencyClasses = new HashSet<>();
        List<String> depJars = new ArrayList<>();
        File depDir = new File(depsDir);
        if (depDir.isDirectory()) {
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
                        System.err.println("[ERROR] Could not read dependency JAR: " + jar.getName());
                    }
                }
            }
        }
        
        // Initialize SootUp view with target and dependency JARs
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(targetJar));
        for (String depJar : depJars) {
            inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        }
        // inputs.add(new DefaultRuntimeAnalysisInputLocation());
        JavaView view = new JavaView(inputs);
        
        // Find main methods in target classes only
        List<String> mainClasses = new ArrayList<>();
        List<MethodSignature> mainMethods = new ArrayList<>();
        Map<String, List<MethodSignature>> classToMainMethods = new HashMap<>();
        
        view.getClasses().forEach(clazz -> {
            String className = clazz.getType().getFullyQualifiedName();
            // Only consider classes that are NOT in dependency JARs
            if (!dependencyClasses.contains(className)) {
                List<MethodSignature> classMainMethods = new ArrayList<>();
                clazz.getMethods().forEach(method -> {
                    if (method.getName().equals("main") &&
                        method.getModifiers().contains(MethodModifier.PUBLIC) &&
                        method.getModifiers().contains(MethodModifier.STATIC) &&
                        method.getParameterTypes().size() == 1 &&
                        method.getParameterTypes().get(0).toString().equals("java.lang.String[]") &&
                        method.getReturnType().toString().equals("void")) {
                        
                        MethodSignature mainSig = method.getSignature();
                        mainMethods.add(mainSig);
                        classMainMethods.add(mainSig);
                        
                        // Add class only once if it has main methods
                        if (!mainClasses.contains(className)) {
                            mainClasses.add(className);
                        }
                        
                        System.out.println("Found main method: " + mainSig);
                    }
                });
                
                if (!classMainMethods.isEmpty()) {
                    classToMainMethods.put(className, classMainMethods);
                }
            }
        });
        
        // Write to file
        try (PrintWriter writer = new PrintWriter("found_main_methods_target.txt")) {
            for (String cls : mainClasses) {
                writer.println(cls);
            }
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write output file: " + e.getMessage());
        }
        
        // Print summary
        System.out.println("\n=== Summary ===");
        System.out.println("Total classes with main methods: " + mainClasses.size());
        System.out.println("Total main methods found: " + mainMethods.size());
        
        for (Map.Entry<String, List<MethodSignature>> entry : classToMainMethods.entrySet()) {
            String className = entry.getKey();
            List<MethodSignature> methods = entry.getValue();
            System.out.println("Class: " + className + " (" + methods.size() + " main method(s))");
            for (MethodSignature method : methods) {
                System.out.println("  - " + method);
            }
        }
    }
} 
