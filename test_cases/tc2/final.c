// final.c
// Final library that contains the actual syscall implementations

// Function that makes a mkdir syscall (syscall 83)
void syscall_mkdir(void) {
    long ret;
    __asm__ volatile (
        "mov $83, %%eax\n\t"   // SYS_mkdir = 83
        "syscall\n\t"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
}

// Function that makes a getgid syscall (syscall 104)
void syscall_getgid(void) {
    long ret;
    __asm__ volatile (
        "mov $104, %%eax\n\t"   // SYS_getgid = 104
        "syscall\n\t"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
}

// Function that makes a fchown syscall (syscall 93)
void syscall_fchown(void) {
    long ret;
    __asm__ volatile (
        "mov $93, %%eax\n\t"   // SYS_fchown = 93
        "syscall\n\t"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
}
