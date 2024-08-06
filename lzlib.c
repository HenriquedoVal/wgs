#pragma once

#include <Windows.h>

#include <zlib/zlib.h>

#include "main.h"

#include "util.c"
#include "logger.c"


typedef struct {
    char *data;
    char *end_ptr;
    size_t capacity;
} ZlibBuffer;


static ZlibBuffer g_zlib_buffer;


static int zlib_inflate_source(HANDLE source, char **dest, size_t *dest_size)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    *dest_size = 0;
    size_t needed;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) return ret;

    do {
        if (!ReadFile(source, in, CHUNK, (LPDWORD)&strm.avail_in, NULL)) {
            log_crash_win32_error(GetLastError());
        }
        if (strm.avail_in == 0) break;
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);
            switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                return ret;
            }

            have = CHUNK - strm.avail_out;
            needed = *dest_size + have;
            if (needed > g_zlib_buffer.capacity) {
                HANDLE heap = GetProcessHeap();
                assert(heap != NULL);

                logger(LOG_DEBUG_MEM, "lzlib:");
                logger(LOG_DEBUG_MEM, "\t%p realloc prev", g_zlib_buffer.data);

                void *nptr = HeapReAlloc(heap, 0, g_zlib_buffer.data, needed);
                assert(nptr != NULL);
                g_zlib_buffer.data = nptr;
                g_zlib_buffer.capacity = needed;
                g_zlib_buffer.end_ptr = g_zlib_buffer.data + *dest_size;

                logger(LOG_DEBUG_MEM, "\t%p realloc post", g_zlib_buffer.data);
            }

            errno_t err = memcpy_s(
                g_zlib_buffer.end_ptr, g_zlib_buffer.capacity, out, have
            );
            assert(err == 0);

            g_zlib_buffer.end_ptr += have;
            *dest_size += have;

        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    *dest = g_zlib_buffer.data;
    g_zlib_buffer.end_ptr = g_zlib_buffer.data;
    return ret;
}


static void zlib_error(int ret)
{
    // I think this is the return when we pass more input than needed.
    // On tests it seems needed and safe to silently ignore this error.
    if (ret == Z_STREAM_END)
        return;

    switch (ret) {
    case Z_ERRNO:
        logger(LOG_ERROR, "Z_ERRNO: error on pipe. "
            "Should never happen on our program");
        break;
    case Z_STREAM_ERROR:
        logger(LOG_ERROR, "Z_STREAM_ERROR: Invalid compression level");
        break;
    case Z_DATA_ERROR:
        logger(LOG_ERROR, "Z_DATA_ERROR: Invalid or "
            "incomplete deflate data");
        break;
    case Z_MEM_ERROR:
        logger(LOG_ERROR, "Z_MEM_ERROR: Out of memory");
        break;
    case Z_VERSION_ERROR:
        logger(LOG_ERROR, "Z_VERSION_ERROR: Zlib version mismatch");
        break;
    case Z_NEED_DICT:
        logger(LOG_ERROR, "Z_NEED_DICT: I don't know");
        break;
    default:
        logger(LOG_ERROR, "Zlib unknown error");
    }
    assert(0 && "Check error log");
}


static char *zlib_inflate(size_t obj_size,
                             unsigned char *buf,
                             FileMap *fm,
                             size_t *dest_size)
{
    if (obj_size > g_zlib_buffer.capacity) {
        HANDLE heap = GetProcessHeap();
        assert(heap != NULL);

        logger(LOG_DEBUG_MEM, "lzlib:");
        logger(LOG_DEBUG_MEM, "\t%p freed", g_zlib_buffer.data);

        int ret = HeapFree(heap, 0, g_zlib_buffer.data);
        assert(ret);
        g_zlib_buffer.data = HeapAlloc(heap, 0, obj_size + 1);
        assert(g_zlib_buffer.data != NULL);

        logger(LOG_DEBUG_MEM, "\t%p alloc", g_zlib_buffer.data);

        g_zlib_buffer.capacity = obj_size + 1;
    }

    z_stream strm = {0};
    int ret = inflateInit(&strm);
    assert(ret == Z_OK);

    unsigned it_in;
    long long input_done = 0;

    // We already know the needed capacity and reallocd
    unsigned capacity = g_zlib_buffer.capacity > UINT32_MAX
        ? UINT32_MAX
        : (unsigned)g_zlib_buffer.capacity;

    do {
        it_in = fm->file_size.QuadPart - input_done > UINT32_MAX
            ? UINT32_MAX
            : (unsigned)(fm->file_size.QuadPart - input_done);

        strm.avail_in = it_in;
        strm.next_in = buf + input_done;
        strm.avail_out = capacity;
        strm.next_out = (Bytef *)(g_zlib_buffer.data + strm.total_out);

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_END)
            break;
        zlib_error(ret);

        input_done += it_in;

    } while (input_done < fm->file_size.QuadPart);

    ret = inflateEnd(&strm);
    assert(ret == Z_OK);

    assert(strm.total_out == obj_size);
    g_zlib_buffer.data[obj_size] = '\0';

    *dest_size = strm.total_out;
    return g_zlib_buffer.data;
}
