#pragma once

#include <assert.h>
#include <stdint.h>

#include <Windows.h>

#include "main.h"

#include "arena.c"
#include "logger.c"
#include "util.c"


size_t g_async_ef_alloc = 0;

typedef struct {
    HANDLE hFile;
    OVERLAPPED *items;
    size_t o_count;
} Overl;


void async_wait(Overl *overl)
{
    // Use Events here?
    for (int i = 0; i < overl->o_count; ++i) {
        while (!HasOverlappedIoCompleted(&overl->items[i])) {
            Sleep(1);
        }
    }
    CloseHandle(overl->hFile);
}


void read_async(EntireFile *ef, DirEntry *file, Overl *overl)
{
    overl->hFile = CreateFile(
        file->file_path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (INVALID_HANDLE_VALUE == overl->hFile) {
        logger(LOG_ERROR, "Could not open file %s", file->file_path);
        assert(0 && "Check log_error");
    }

    size_t total_bytes = file->file_size.QuadPart;
    overl->o_count = total_bytes / USHRT_MAX + (total_bytes % USHRT_MAX > 0);
    overl->items = arena_alloc(overl->o_count * sizeof(OVERLAPPED));

    if (total_bytes > ef->capacity) {
        HANDLE heap = GetProcessHeap();
        assert(heap != NULL);
        bool res = HeapFree(heap, 0, ef->data);
        assert(res);
        ef->data = HeapAlloc(heap, 0, total_bytes);
        assert(ef->data != NULL);
        ef->capacity = total_bytes;
        logger(LOG_DEBUG_MEM, "async ef: \"Realloc\" %zu bytes", total_bytes);
    }

    ef->current_file_size = total_bytes;

    uint64_t readden = 0;
    uint64_t it_to_read = total_bytes;
    int it = 0;
    while (readden < total_bytes) {
        unsigned short to_read;
        if (it_to_read > USHRT_MAX)
            to_read = USHRT_MAX;
        else
            to_read = (unsigned short)it_to_read;

        OVERLAPPED *o = &overl->items[it];
        *(uint64_t *)&o->Offset = readden;
        ReadFile(overl->hFile, ef->data + readden, to_read, NULL, o);
        unsigned long id = GetLastError();

        if (id != ERROR_IO_PENDING) {
            log_crash_win32_error(id);
        }

        readden += to_read;
        it_to_read -= to_read;
        it++;
    }
}
