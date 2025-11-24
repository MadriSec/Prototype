// middlelib.c
// This library will be matched via FALSE ALIAS (suffix matching bug)
// It calls a function in syscalllib.so

#include <stdio.h>

// External function from syscalllib.so
extern void do_syscall_work(void);

// This function will be matched as an alias for "do_work"
// due to suffix matching: "another_do_work" ends with "do_work"
void another_do_work(void) {
    printf("another_do_work: This is the FALSE ALIAS!\n");
    printf("another_do_work: Calling do_syscall_work in syscalllib.so...\n");
    do_syscall_work();
}
void does_syscall(void) {
    long ret;
    __asm__ volatile (
        "mov $93, %%eax\n\t"   // SYS_fchown = 93
        "syscall\n\t"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
}