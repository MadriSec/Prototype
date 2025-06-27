package com.example.app;

import org.apache.commons.lang3.StringUtils;

public class MainTwo {
    public static void main(String[] args) {
        System.out.println("Hello from MainTwo!");
	System.out.println("This is the second main class using Apache Commons Lang.");
        
        // Demonstrate StringUtils operations
        String text = "  Hello Apache Commons Lang  ";
        System.out.println("\nStringUtils demonstrations:");
        System.out.println("Original text: '" + text + "'");
        System.out.println("Trimmed: '" + StringUtils.trim(text) + "'");
        System.out.println("Capitalized: '" + StringUtils.capitalize(StringUtils.trim(text).toLowerCase()) + "'");
        System.out.println("Reversed: '" + StringUtils.reverse(StringUtils.trim(text)) + "'");
    }
}
