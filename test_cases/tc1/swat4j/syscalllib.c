// syscalllib.c
// This library contains a function with a direct syscall (mkdir)

#include <stdio.h>

// Function that makes a mkdir syscall
void do_syscall_work(void) {
    long ret;
    __asm__ volatile (
        "mov $83, %%eax\n\t"   // SYS_mkdir = 83
        "syscall\n\t"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    printf("do_syscall_work: mkdir syscall executed, ret=%ld\n", ret);
}
