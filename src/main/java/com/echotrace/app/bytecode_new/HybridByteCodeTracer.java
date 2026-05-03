package com.echotrace.app.bytecode_new;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class HybridByteCodeTracer {
    public static String nativeFile = "/home/rupesh.punna/Prototype/elasticsearch_hybrid.txt";
    public static String pathPrefix = "/home/rupesh.punna/Prototype/JARFILES/";

    public static void main(String[] args) throws IOException {
        // Check if folder path is provided as argument
        if (args.length > 0) {
            pathPrefix = args[0];
            if (!pathPrefix.endsWith("/")) {
                pathPrefix += "/";
            }
        }

        long startTime = System.currentTimeMillis();
        List<String> jarPathResult = new ArrayList<>();
        Set<String> nativeMethodResult = new HashSet<>();
        GetJarPaths getJarPaths = new GetJarPaths();

        List<String> classPathResult = new ArrayList<>();
        FindJarClass findJarClass = new FindJarClass();

        FindNativeMethods findNativeMethods = new FindNativeMethods();
        try {
            jarPathResult = getJarPaths.getJarPaths();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        for(String jarPath : jarPathResult){
            jarPath = pathPrefix + jarPath;
            File file = new File(jarPath);
            if (!file.exists() || !file.isFile()){
                System.out.println("Opps!");
                continue;
            }
            classPathResult.addAll(findJarClass.findClass(jarPath));
            nativeMethodResult.addAll(findNativeMethods.findNativeMethods(jarPath));
        }
       System.out.println("DEBUG: classpath: "+classPathResult);
       System.out.println(classPathResult.size());
        System.out.println("There are " + classPathResult.size() + " classes over all\n");
        
        System.out.println("Now we start to analyze called native methods!");
        Util.println();
        HybridByteCodeTracer bct = new HybridByteCodeTracer();
        bct.traceJarFiles(jarPathResult);
        bct.prettyPrint();
        bct.writeToFile();
        
        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("程序运行时间：" + totalTimeInSeconds + "秒");

    }

    public void trace(String className) throws IOException {
        ClassReader cr = new ClassReader(className);
        ClassPrinter cp = new ClassPrinter();
        cr.accept(cp, 0);
    }

    public void trace(List<String> classes) throws IOException {
        for (String className : classes) {
            trace(className);
        }
    }

    public void traceJarFiles(List<String> jarPaths) throws IOException {
        for (String jarPath : jarPaths) {
            String fullJarPath = pathPrefix + jarPath;
            File file = new File(fullJarPath);
            if (!file.exists() || !file.isFile()) {
                System.out.println("JAR file not found: " + fullJarPath);
                continue;
            }

            try (JarFile jarFile = new JarFile(fullJarPath)) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.getName().endsWith(".class")) {
                        try (InputStream inputStream = jarFile.getInputStream(entry)) {
                            ClassReader cr = new ClassReader(inputStream);
                            ClassPrinter cp = new ClassPrinter();
                            cr.accept(cp, 0);
                        } catch (Exception e) {
                            System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing JAR " + fullJarPath + ": " + e.getMessage());
            }
        }
    }

    public void writeToFile() {
        try {
            String content = "";
            for (String m : Util.visitedNative) {
                content += m + "\n";
            }
            File file =new File(nativeFile);
            if(!file.exists()){
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content);
            fw.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public void prettyPrint() {
        Util.println();
        System.out.println("Count of visited methods: " + Util.visitedMethod.size() +
                "\n\nCount of called native methods: " + Util.visitedNative.size() +
                "\n\nWe write all of them into a .txt file for binary analyse");
        Util.println();
    }

    // Nested class: Util
    static class Util {
        public static Set<String> visitedMethod = new HashSet<>();
        public static Set<String> visitedNative = new HashSet<>();

        public static void println() {
            System.out.println("--------------------------------");
        }

        public static byte[] getClassBytesFromFile(String classFilePath) throws IOException {
            try (InputStream inputStream = new FileInputStream(classFilePath);
                 ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {

                byte[] data = new byte[1024];
                int nRead;
                while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                return buffer.toByteArray();
            }
        }
    }

    // Nested class: ClassFilter
    static class ClassFilter extends ClassVisitor {
        private String identifier;
        private String className;

        public ClassFilter(String identifier) {
            super(Opcodes.ASM9);
            this.identifier = identifier;
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (!this.identifier.equals(name+descriptor)) {
                return null;
            }
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    // Nested class: ClassPrinter
    static class ClassPrinter extends ClassVisitor {
        private String className;

        public ClassPrinter() {
            super(Opcodes.ASM9);
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
            System.out.println("[ Printer pure visit.. ] " + name + " " + signature);
        }

        public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
            return null;
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    // Nested class: MethodPrinter
    static class MethodPrinter extends MethodVisitor {
        public MethodPrinter() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String className = owner.replace('/', '.');
            if (Util.visitedMethod.contains(className+name+descriptor)) {
                return;
            }

            Util.visitedMethod.add(className+name+descriptor);
            try {
                ClassReader cr = new ClassReader(className);
                ClassFilter cf = new ClassFilter(name+descriptor);
                cr.accept(cf, 0);
            } catch (IOException e) {
                // System.out.println("oops exception.. " + className + " " + name + " " + descriptor);
            }

            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }

    // Nested class: FindJarClass
    static class FindJarClass {
        public List<String> findClass(String jarFileName) throws IOException {
            List<String> classPaths = new ArrayList<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    classPaths.add(entry.getName().replace(".class", "")
                            .replace("/", "."));
                }
            }

            jarFile.close();
            return classPaths;
        }
    }

    // Nested class: GetJarPaths
    static class GetJarPaths {
        public List<String> getJarPaths() throws IOException {
            ArrayList<String> result = new ArrayList<>();

            String jarDir = pathPrefix;
            File jarFolder = new File(jarDir);

            if (!jarFolder.exists() || !jarFolder.isDirectory()) {
                System.out.println("JAR directory not found: " + jarDir);
                return result;
            }

            File[] jarFiles = jarFolder.listFiles((dir, name) -> name.endsWith(".jar"));
            if (jarFiles != null) {
                for (File jarFile : jarFiles) {
                    result.add(jarFile.getName());
                    System.out.println("Found JAR: " + jarFile.getName());
                }
            }

            return result;
        }
    }

    // Nested class: FindNativeMethods
    static class FindNativeMethods {
        public Set<String> findNativeMethods(String jarFileName) throws IOException {
            Set<String> nativeMethods = new HashSet<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        ClassReader classReader = new ClassReader(inputStream);
                        classReader.accept(new NativeMethodVisitor(entry.getName(), nativeMethods), 0);
                    } catch (Exception e) {
                        System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                    }
                }
            }

            jarFile.close();
            return nativeMethods;
        }

        // Nested inner class: NativeMethodVisitor
        private static class NativeMethodVisitor extends ClassVisitor {
            private final String className;
            private final Set<String> nativeMethods;

            public NativeMethodVisitor(String className, Set<String> nativeMethods) {
                super(Opcodes.ASM9);
                this.className = className;
                this.nativeMethods = nativeMethods;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0) {
                    String jniFunction = className.replace(".class", "")
                            .replace("/", ".")+ "." + name + "---" + descriptor;
                    nativeMethods.add(jniFunction);
                }
                return null;
            }
        }
    }

}
