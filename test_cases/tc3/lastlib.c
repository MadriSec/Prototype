// lastlib.c - Contains the actual mkdir syscall
#include <sys/stat.h>
#include <sys/types.h>

// Function that actually performs the mkdir syscall
int mkdir_syscall(const char* path) {
    return mkdir(path, 0755);
}
