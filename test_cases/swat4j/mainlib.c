// mainlib.c
// This is the main library that triggers the bug
// It calls do_work() which doesn't exist, triggering suffix matching

#include <stdio.h>

// Forward declaration - this function does NOT exist anywhere!
// This will create a PLT stub and trigger suffix matching
extern void do_work(void);
// Function that actually exists inside middlelib.c
extern void does_syscall(void);

// Entry point function that will be analyzed by SWAT4J
void lib_init(void) {
    //"lib_init: Calling do_work() which doesn't exist...\n";

    // This call will:
    // 1. Create do_work@plt
    // 2. Normalized to "dowork"
    // 3. Not found in func_map (doesn't exist!)
    // 4. Suffix matching: finds "anotherdowork"
    // 5. FALSE ALIAS: links to another_do_work in middlelib.so
    do_work();
    does_syscall();
}
