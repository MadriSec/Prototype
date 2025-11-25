// mainlib.c
// Test case 2: Multiple suffix matching bugs
// This library calls another_call() which exists in middle.so
// middle.so's another_call() will call do_work() which doesn't exist

// Forward declaration - exists in middle.so
extern void another_call(void);

// Entry point function that will be analyzed by SWAT4J
void lib_init(void) {
    another_call();
}
