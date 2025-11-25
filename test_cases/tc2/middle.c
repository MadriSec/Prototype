// middle.c
// Middle library with another_call() that calls do_work() (which doesn't exist)
// and three functions that will be FALSE ALIASES

// External functions from final.so
extern void syscall_mkdir(void);
extern void syscall_getgid(void);
extern void syscall_fchown(void);

// Forward declaration - this function does NOT exist!
extern void do_work(void);

// Function called by mainlib.so
// This will call do_work() which doesn't exist, triggering suffix matching
void another_call(void) {
    // This call will:
    // 1. Create do_work@plt
    // 2. Normalize to "dowork"
    // 3. Not found in func_map (doesn't exist!)
    // 4. Suffix matching will find:
    //    - "doesdowork" (does_do_work)
    //    - "willdowork" (will_do_work)
    //    - "candowork" (can_do_work)
    // 5. FALSE ALIASES: all three will be linked!
    do_work();
}

// This function will be matched as an alias for "do_work"
// Suffix matching: "does_do_work" ends with "do_work"
void does_do_work(void) {
    syscall_mkdir();
}

// This function will also be matched as an alias for "do_work"
// Suffix matching: "will_do_work" ends with "do_work"
void will_do_work(void) {
    syscall_getgid();
}

// This function will also be matched as an alias for "do_work"
// Suffix matching: "can_do_work" ends with "do_work"
void can_do_work(void) {
    syscall_fchown();
}
