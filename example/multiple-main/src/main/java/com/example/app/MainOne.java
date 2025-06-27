package com.example.app;

import com.example.util.HelperClass;

public class MainOne {
    public static void main(String[] args) {
        System.out.println("Hello from MainOne!");
        System.out.println("This is the first main class in the project.");

	System.out.println( new HelperClass().helperMessage());
    }
}
