package com.example.util;

public class HelperClass {

    /** Returns a friendly message containing sqrt(25). */
    public String helperMessage() {
        double value = 25.0;
        double root  = Math.sqrt(value);   // native call
        return "sqrt(" + value + ") = " + root;
    }
}