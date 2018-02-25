#include <stdio.h>
#include <stdarg.h>
#include "log.h"
#define DBGLOG 0
void dbglog(const char *format, ...) {
#if DBGLOG
	va_list arglist;
    va_start(arglist, format);
    vprintf(format, arglist);
    va_end(arglist);
#endif
}
void show_buf(void *addr, int len) {
    int num = 0;
	printf("show buf: addr=%p  length=%d\n", addr, len);
    for(num = 0; num < len; num++) {
        printf("%02x ", ((unsigned char *)addr)[num]);
    }   
    printf("\n");
}
void play_buf(void *addr, int len) {
    int num = 0;
    for(num = 0; num < len; num++) {
        printf("%c", ((unsigned char *)addr)[num]);
    }
    printf("\n");
}
