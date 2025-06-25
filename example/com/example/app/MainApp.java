package com.example.app;

import com.example.library.LibraryClass;

public class MainApp {
    public static void main(String[] args) {
        LibraryClass lib = new LibraryClass();
        System.out.println(lib.getMessage());
        System.out.println("Hello from MainApp!");
    }
}