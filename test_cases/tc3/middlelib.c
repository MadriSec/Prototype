// middlelib.c - Contains work functions that call lastlib

// External function from lastlib
extern int mkdir_syscall(const char* path);
extern void do_work(void);
// Function that will call mkdir_syscall (viable path)
void will_do_work(const char* dirname) {
    mkdir_syscall(dirname);
}

// Empty function (no syscall path)
void can_do_work(const char* dirname) {
}

// Empty function (no syscall path)
void wont_do_work(const char* dirname) {
}


// Function called from mainlib
void another_call() {
    do_work();
}
