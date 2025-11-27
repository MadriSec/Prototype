#include <stdio.h>
#include <stdlib.h>

// External functions from the library
extern void call_string_func(int index, const char* str);
extern size_t call_size_func(int index, const char* str);

int main() {
        printf("Main program starting\n");

        // Test func_array1 functions
        call_string_func(0, "Hello from puts!");

        // Test func_array2 functions
        size_t len = call_size_func(0, "Test string");
        printf("String length: %zu\n", len);

        // Test syscall functions in array2
        size_t pid = call_size_func(1, NULL);  // getpid
        printf("PID: %zu\n", pid);

        size_t uid = call_size_func(2, NULL);  // getuid
        printf("UID: %zu\n", uid);

        return 0;
}
