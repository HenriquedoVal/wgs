#pragma once

#include <stdint.h>

#include <Windows.h>

#include "arena.c"


static char *GetLastErrorAsString(unsigned long id) {
    if (0 == id)
        return NULL;

    LPSTR win32_buffer = NULL;

    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        id,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&win32_buffer,
        0,
        NULL
    );
    assert(size);

    char *our_buffer = arena_alloc(size + 1);
    memcpy(our_buffer, win32_buffer, size);
    our_buffer[size] = '\0';
    LocalFree(win32_buffer);
    return our_buffer;
}


#define log_crash_win32_error(id)                                                             \
    logger(LOG_ERROR, "%s:%i: Win error: %s", __FILE__, __LINE__, GetLastErrorAsString(id));  \
    assert(0 && "Check error log")


static bool path_exists(char *p)
{
    return (GetFileAttributes(p) != INVALID_FILE_ATTRIBUTES);
}


static bool make_path_parent(char *path)
{
    size_t len = strlen(path);
    char *found;
    int j = 2;

    if (path[len - 1] != '\\') j--;

    for (int i = 0; i < j; i++) {
        found = strrchr(path, '\\');
        if (found == NULL) return false;
        *found = '\0';
    }

    return true;
}


static void mtimes_to_filetime(uint64_t mtime, uint64_t mtime_nano, LPFILETIME pft)
{
    ULARGE_INTEGER time_value;
    uint64_t nmtime = mtime * 10000000LL;
    uint64_t nmtime_nano = mtime_nano / 100;
    time_value.QuadPart = nmtime + nmtime_nano + 116444736000000000LL;
    pft->dwLowDateTime = time_value.LowPart;
    pft->dwHighDateTime = time_value.HighPart;
}


static uint64_t get_be_from_buffer(const unsigned char *buffer, int length)
{
    uint64_t res = 0;
    int mul = 0;
    for (int i = length - 1; i >= 0; i--) {
        res += buffer[i] << (8 * mul);
        mul++;
    }
    return res;
}
