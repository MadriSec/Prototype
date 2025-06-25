package com.example.library;

import com.example.util.HelperClass;

public class LibraryClass {
    public String getMessage() {
        return "Hello from Library! " + new HelperClass().helperMessage();
    }
}