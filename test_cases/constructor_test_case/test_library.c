#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Define function pointer types
typedef void (*libc_func1_t)(const char*);
typedef size_t (*libc_func2_t)(const char*);

// Arrays of function pointers
static libc_func1_t func_array1[] = {
        (libc_func1_t)puts,
        (libc_func1_t)perror,
        NULL
};

// Updated func_array2 to include functions with syscalls
static libc_func2_t func_array2[] = {
        strlen,
        (libc_func2_t)getpid,   // syscall function
        (libc_func2_t)getuid,   // syscall function
        NULL
};

// Constructor - runs automatically when library is loaded
// Modified to use write syscall instead of printf
__attribute__((constructor))
static void lib_init(void) {
        const char* msg = "Library initialized\n";
        write(STDOUT_FILENO, msg, strlen(msg));  // Direct syscall
}

// First exported function - uses func_array1
void call_string_func(int index, const char* str) {
        if (index >= 0 && func_array1[index] != NULL) {
                func_array1[index](str);
        }
}

// Second exported function - uses func_array2
size_t call_size_func(int index, const char* str) {
        if (index >= 0 && func_array2[index] != NULL) {
                return func_array2[index](str);
        }
        return 0;
}
