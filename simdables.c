#pragma once

#include <stdio.h>
#include <stdbool.h>

#include "arena.h"


static char *strtolower(const char *_str)
{
    // On small tests it seems git only lowercases ascii chars
    // so we must not use `tolower()`... or we should if set
    // the "correct" locale.
    // Tested git behavior with é, â, ã...

    if (_str == NULL) return NULL;

    char *str, *p;
    str = arena_strdup(&g_arena, _str);
    p = str;

    while (*p) {
        if (*p & 0b1000000 && *p < 123)  // 'z'
            *p |= 0b0100000;
        p++;
    }

    return str;
}


/*
 * Convert crlf to lf.
*/
static int convert_newlines(unsigned char *data, size_t size, bool next_call)
{
    //  RNabcdRNabRNcd
    //            ^  ^
    //  NabcdNabNcd
    unsigned char *ptr = data - (int)next_call;
    int i = 0, j = 0;
    for (; i < size - j; ++i) {
        if (ptr[i + j] == '\r' && ptr[i + j + 1] == '\n')
            j++;
        ptr[i] = ptr[i + j];
    }
    ptr[i] = '\0';
    return j;
}
