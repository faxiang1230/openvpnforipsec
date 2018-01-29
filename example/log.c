#include <stdio.h>
#include <stdarg.h>
#include "log.h"
#define DBGLOG 1
void dbglog(const char *format, ...) {
#if DBGLOG
	va_list arglist;
    va_start(arglist, format);
    vprintf(format, arglist);
    va_end(arglist);
#endif
}
