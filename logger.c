#pragma once

// #define LOG_LEVEL LOG_ERROR
#ifdef LOG_LEVEL

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>

#include "main.h"


typedef enum {
    LOG_NONE = 0,
    LOG_ERROR,
    LOG_INFO,
    LOG_DEBUG_MEM,
    LOG_DEBUG_PACK,
    LOG_DEBUG_IDX,
    LOG_DEBUG,
} LogLevel;


static void logger(LogLevel lv, const char *fmt, ...)
{
    if (lv > LOG_LEVEL) return;
    printf("%c", 27);
    switch (lv) {
        case LOG_ERROR:      printf("[31m[ERROR]: ");  break;
        case LOG_INFO:       printf("[32m[INFO]: ");   break;
        case LOG_DEBUG_PACK: printf("[33m[PACK]: ");   break;
        case LOG_DEBUG_MEM:  printf("[34m[MEMORY]: "); break;
        case LOG_DEBUG_IDX:  printf("[35m[INDEX]: ");  break;
        case LOG_DEBUG:      printf("[36m[DEBUG]: ");  break;
        default: assert(0 && "Unreachable");
    }
    va_list ap;
    va_start(ap, fmt);
    vprintf_s(fmt, ap);
    va_end(ap);

    printf("%c[0m\n", 27);
}

static void logger_iter_ign(LogLevel lv, Ignore *ign, const char *mask) {
    for (int i = 0; i < ign->qtt; i++) {
        logger(LOG_DEBUG, mask, ign->specs[i]);
    }
}
#else
#define logger(...)
#define logger_iter_ign(...)
#endif  // LOG_LEVEL