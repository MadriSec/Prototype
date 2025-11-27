#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

// Define function pointer types
typedef void (*libc_func1_t)(const char*);
typedef size_t (*libc_func2_t)(const char*);

// Arrays of function pointers
static libc_func1_t func_array1[] = {
        (libc_func1_t)puts,
        (libc_func1_t)perror,
        NULL
};

static size_t syscall_getpid(const char* unused) {
        (void)unused;
        return (size_t)syscall(SYS_getpid);
}

static size_t syscall_getuid(const char* unused) {
        (void)unused;
        return (size_t)syscall(SYS_getuid);
}

static libc_func2_t func_array2[] = {
        strlen,
        syscall_getpid,
        syscall_getuid,
        NULL
};

// Constructor - runs automatically when library is loaded
__attribute__((constructor))
static void lib_init(void) {
        pid_t pid = (pid_t)syscall(SYS_getpid);
        char msg[128];
        int len = snprintf(msg, sizeof(msg),
                        "Library initialized via syscall, pid=%d\n", pid);
        if (len > 0) {
                syscall(SYS_write, STDOUT_FILENO, msg, (size_t)len);
        }
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
