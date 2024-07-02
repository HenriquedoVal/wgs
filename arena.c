#pragma once

#include <assert.h>

#include <Windows.h>

#include "main.h"

#include "logger.c"


typedef struct BUFFER {
    char *data;
    size_t capacity;
    size_t offset;
    struct BUFFER *next;
} Buffer;


typedef struct {
    Buffer first;
    Buffer *current;
    size_t allocated;
} Arena;


static Arena g_general_arena;


static void *arena_alloc(size_t size)
{
    Arena *arena = &g_general_arena;
    Buffer *buffer = arena->current;

    size += 8 - (size & 7);
    assert(size % 8 == 0);

    size_t req_size = buffer->offset + size;

    if (req_size > buffer->capacity) {
        HANDLE heap = GetProcessHeap();
        assert(heap != NULL);

        logger(LOG_DEBUG_MEM, "Wasted %zu bytes",
               buffer->capacity - buffer->offset);

        size_t max_size = size > CAPACITY ? size : CAPACITY;

        if (buffer->next == NULL) {
            buffer->next = HeapAlloc(heap, 0, sizeof(Buffer));
            assert(buffer->next != NULL);
            arena->allocated += sizeof(Buffer);
            buffer = buffer->next;

            buffer->data = HeapAlloc(heap, 0, max_size);
            assert(buffer->data != NULL);
            buffer->offset = 0;
            buffer->next = NULL;
            buffer->capacity = max_size;

            arena->allocated += max_size;
            arena->current = buffer;
            logger(LOG_DEBUG_MEM, "New buffer allocated: %zu bytes", max_size);
        } else {
            buffer = buffer->next;
            arena->current = buffer;
            buffer->offset = 0;
            logger(LOG_DEBUG_MEM, "Buffer switch");

            if (buffer->capacity < max_size) {
                HeapFree(heap, 0, buffer->data);
                arena->allocated -= buffer->capacity;
                buffer->data = HeapAlloc(heap, 0, max_size);
                assert(buffer->data != NULL);
                arena->allocated += max_size;
                buffer->capacity = max_size;
                logger(LOG_DEBUG_MEM,
                       "Buffer size wasn't enough, \"reallocated\" %zu bytes",
                       max_size);
            }
        }
    }

    void *ptr = &buffer->data[buffer->offset];
    memset(ptr, 0, size);
    buffer->offset += size;
    return ptr;
}


/*
 * Must be in the reverse order of `arena_alloc`
 */
static void arena_str_unalloc(char *str)
{
    Buffer *buffer = g_general_arena.current;
    buffer->offset -= strlen(str) + 1;
}

static void *arena_realloc(void *ptr, size_t new_size, size_t prev_size)
{
    void *nptr = arena_alloc(new_size);
    memcpy_s(nptr, new_size, ptr, prev_size);
    return nptr;
}


static char *arena_strdup(const char *_str)
{
    size_t size = strlen(_str) + 1;
    char *p = arena_alloc(size);
    strcpy_s(p, size, _str);
    return p;
}
