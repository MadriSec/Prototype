

// External function from middlelib
extern void another_call();

// Library initialization function - entry point
void libinit() {
    another_call();
}

// JNI_OnLoad - called when library is loaded

