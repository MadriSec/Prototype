#include <stdio.h>
#include <stdlib.h>

void call_string_func(int index, const char* str);
size_t call_size_func(int index, const char* str);

int main(void) {
    call_string_func(0, "hello world");
    call_string_func(1, "oops");

    size_t len = call_size_func(0, "abcdef");
    printf("strlen result: %zu\n", len);

    size_t num = call_size_func(1, "12345");
    printf("atoi result: %zu\n", num);
    return 0;
}
