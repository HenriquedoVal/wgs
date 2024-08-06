#pragma once

#pragma comment(lib, "libcrypto_static.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "zlib.lib")

#include <stdbool.h>

#include <Windows.h>


/*
 * Mem config
*/
#define PREALLOC_SPECS 10
#define CHUNK 16384
#define CAPACITY 4096
#define ZLIB_CAPACITY CAPACITY
#define EF_CAPACITY CAPACITY

// TODO: "too much" for stack
#define INDEX_BUF_LEN 0xfff


typedef struct STRUCT_IGNORE {
    size_t qtt;
    size_t capacity;
    char **specs;
    struct STRUCT_IGNORE *important;
} Ignore;

typedef struct {
    bool git_found;
    char *branch;
    char *status;
} GitStatus;

typedef struct {
    unsigned char *data;
    size_t capacity;
    size_t current_file_size;
    bool converted;
} EntireFile;

typedef struct {
    char *name;
    char *path;
    char *rel_path;
    DWORD attributes;
    LARGE_INTEGER size;
    FILETIME mtime;
    int extra;
} DirEntry;

typedef struct {
    DirEntry **entries;
    size_t capacity;
    size_t qtt;
} Dir;

typedef struct {
    char *path;
    LARGE_INTEGER file_size;
    HANDLE hFile;
    HANDLE hMap;
    LPVOID hView;
} FileMap;

static EntireFile g_entire_file;

extern int fnmatch(char *spec, char *path);
GitStatus gitstatus(const char *path);
void setup_memory(void);
void reset_memory(void);
void free_memory(void);

#define ARENA_PAGE_MUL 64  // 256kb if pf = 4kb
#define ARENA_IMPLEMENTATION
#include "arena.h"

static Arena g_arena = {0};
