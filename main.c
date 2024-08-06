#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#define NOGDI
#include <Windows.h>
#include <strsafe.h>

#include <zlib/zlib.h>
#include <openssl/evp.h>

// #define LOG_LEVEL LOG_ERROR

#include "main.h"

#include "logger.c"
#include "lzlib.c"
#include "simdables.c"
#include "util.c"

/*
 * Magic
*/
#define SHA1LEN  20
#define PACK_HEADER 12  // 8 actually
#define FANOUT_1 (255 * 4)
#define FANOUT_2_ITEM_SIZE 20
#define FANOUT_3_ITEM_SIZE 4
#define FANOUT_4_ITEM_SIZE 4


typedef struct {
    char *type;
    char *content;
    size_t content_len;
} GitObject;

typedef struct TE {
    char *type;
    char *name;
    unsigned char *hash;
    struct TE *next;
    bool on_fs_or_ign;
} TreeEntry;

typedef struct {
    char *type;
    TreeEntry *first_entry;
} Tree;

typedef struct {
    char *rel_path;
    FILETIME *mtime;
    bool on_fs;
} IndexEntry;

typedef struct {
    uint64_t qtt;
    IndexEntry *items;
} Index;

typedef struct {
    bool any_staged;
    bool any_file;
    int staged;
    int untracked;
} UntrackedDirResult;

typedef struct {
    int untracked;
    int staged;
    int modified;
    int deleted;
} FinalResult;

typedef enum {
    CO_NONE = 0,
    CO_LOOSE,
    CO_PACK
} ContentOrigin;

static ContentOrigin get_content_by_hash(const char *hash, GitObject *go);
static char *get_hash_string(BYTE rgbHash[20]);

static struct {
    size_t qtt;
    size_t qtt_cap;
    FileMap **items;
    Arena arena;
} g_file_maps = {0};

static char *g_git_root;
static inline void set_git_root(char *path) { g_git_root = path; }
static char *g_root_dir;
static inline void set_root_dir(char *path) { g_root_dir = path; }

#define alloc(size) arena_alloc(&g_arena, size)


static void setup_memory(void)
{
    HANDLE heap = GetProcessHeap();
    assert(heap != NULL);

    g_zlib_buffer.data = HeapAlloc(heap, 0, ZLIB_CAPACITY);
    assert(g_zlib_buffer.data != NULL);
    g_zlib_buffer.capacity = ZLIB_CAPACITY;
    g_zlib_buffer.end_ptr = g_zlib_buffer.data;

    logger(LOG_DEBUG_MEM, "lzlib:");
    logger(LOG_DEBUG_MEM, "\t%p alloc", g_zlib_buffer.data);

    g_entire_file.data = HeapAlloc(heap, 0, EF_CAPACITY);
    assert(g_entire_file.data != NULL);
    g_entire_file.capacity = EF_CAPACITY;

    logger(LOG_DEBUG_MEM, "g_entire_file:");
    logger(LOG_DEBUG_MEM, "\t%p alloc", g_entire_file.data);
}


static void reset_memory(void)
{
    g_zlib_buffer.end_ptr = g_zlib_buffer.data;

    for (size_t i = 0; i < g_file_maps.qtt; i++) {
        FileMap *fm = g_file_maps.items[i];
        int res;
        res = UnmapViewOfFile(fm->hView);
        assert(res);
        res = CloseHandle(fm->hFile);
        assert(res);
        res = CloseHandle(fm->hMap);
        assert(res);
    }

    arena_reset(&g_arena);
    arena_reset(&g_file_maps.arena);
    g_file_maps.qtt = 0;
    g_file_maps.items = NULL;
}


static void free_memory(void) {
    HANDLE heap = GetProcessHeap();
    assert(heap != NULL);

    logger(LOG_DEBUG_MEM, "lzlib:");
    logger(LOG_DEBUG_MEM, "\t%p free", g_zlib_buffer.data);
    logger(LOG_DEBUG_MEM, "g_entire_file:");
    logger(LOG_DEBUG_MEM, "\t%p free", g_entire_file.data);

    int ret = HeapFree(heap, 0, g_zlib_buffer.data);
    assert(ret);
    ret = HeapFree(heap, 0, g_entire_file.data);
    assert(ret);

    arena_free(&g_file_maps.arena);
    arena_free(&g_arena);
}


static void hash_buffer(unsigned char *buffer,
                        size_t buf_size,
                        unsigned char result[20])
{
    unsigned char tmp[26];  // UINT64_MAX has 20 digits + "blob " + 0
    int preamble = sprintf_s((char *)tmp, 26, "blob %zu", buf_size) + 1;
    unsigned out = 0;

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, tmp, preamble);
    EVP_DigestUpdate(ctx, buffer, buf_size);
    EVP_DigestFinal_ex(ctx, result, &out);
    EVP_MD_CTX_free(ctx);
    assert(out == SHA1LEN);
}


static unsigned char *_main_read(DWORD len, unsigned char buf[45],  HANDLE hFile)
{
    DWORD cbRead = 0;
    assert(len < INDEX_BUF_LEN);
    bool res = ReadFile(hFile, buf, len, &cbRead, NULL);
    assert(res);
    assert(len == cbRead);
    buf[cbRead] = '\0';
    return buf;
}


static uint64_t _read_be(DWORD len, unsigned char buf[45], HANDLE hFile)
{
    DWORD cbRead = 0;

    assert(len < INDEX_BUF_LEN);
    bool res = ReadFile(hFile, buf, len, &cbRead, NULL);
    assert(res);
    assert(len == cbRead);
    return get_be_from_buffer(buf, len);
}


#define main_read(x) _main_read(x, buf, hFile)
#define read_be(x) _read_be(x, buf, hFile)


static void *get_git_index(void)
{
    unsigned char buf[INDEX_BUF_LEN];

    size_t size = strlen(g_git_root) + 7;
    char *index_path = alloc(size);
    sprintf_s(index_path, size, "%s\\%s", g_git_root, "index");

    if (!path_exists(index_path))
        return NULL;

    Index *idx = alloc(sizeof(Index));

    HANDLE hFile = CreateFile(index_path,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);

    if (INVALID_HANDLE_VALUE == hFile) {
        log_crash_win32_error(GetLastError());
    }

    main_read(4);
    // unsigned char *constant = main_read(4);

    uint64_t version = read_be(4);
    assert(version > 1 && version < 4);
    uint64_t entries = read_be(4);
    if (0 == entries) {
        CloseHandle(hFile);
        return NULL;
    }

    idx->items = alloc(entries * sizeof(IndexEntry));
    idx->qtt = entries;

    for (int i = 0; i < entries; i++) {
        main_read(8);
        // unsigned ctime      = read_be(4);
        // unsigned ctime_nano = read_be(4);

        uint64_t mtime      = read_be(4);
        uint64_t mtime_nano = read_be(4);
        FILETIME *ft = alloc(sizeof(FILETIME));
        mtimes_to_filetime(mtime, mtime_nano, ft);

        // Lazy solution for the tranformation of mtimes to FILETIME:
        // loose last 5 bits of precision for both on `Low`
        // resulting in 31 * 100 nsecs imprecision.
        // The quantity of bits of loss is somewhat random
        ft->dwLowDateTime &= 0xffffffe0;

        main_read(44);
        uint64_t flags = read_be(2);
        unsigned namelen = flags & 0xfff;
        unsigned extended = flags & 16384;
        size_t entrylen = 62;

        if (extended) {
            main_read(2);
            entrylen += 2;
        }

        unsigned char *name;
        if (namelen < 0xfff) {
            name = main_read(namelen);
            entrylen += namelen;
        } else {
            // On Windows this size of path is not enabled by default
            // and I won't enable to test this.
            
            size_t counter = 0;
            while (main_read(1))
                counter++;

            assert(counter < INTMAX_MAX);

            name = alloc(counter);
            entrylen += counter;

            LARGE_INTEGER li;
            li.QuadPart = -(long long)counter;
            SetFilePointerEx(hFile, li, NULL, FILE_CURRENT);

            size_t readden = 0;
            while (readden < counter) {
                unsigned long it_readden;
                unsigned it_read = counter - readden > UINT32_MAX
                                 ? UINT32_MAX
                                 : (unsigned)(counter - readden);
                bool success = ReadFile(hFile, name, it_read, &it_readden, NULL);
                assert(success);
                readden += it_readden;
            }
        }

        IndexEntry *ent = &idx->items[i];
        ent->rel_path = arena_strdup(&g_arena, (char *)name);
        ent->mtime = ft;

        unsigned first = 8 - (entrylen % 8);
        unsigned padlen = first ? first : 8;
        main_read(padlen);

        logger(LOG_DEBUG_IDX,
               "%s: mtime: %zu; mtime_nano: %zu\nft->High: %lu; ft->Low: %lu",
               ent->rel_path,
               mtime,
               mtime_nano,
               ent->mtime->dwHighDateTime,
               ent->mtime->dwLowDateTime);
    }

    CloseHandle(hFile);
    return idx;
}


static void make_git_object(GitObject *dest, char *buffer, size_t count)
{
    dest->type = arena_strdup(&g_arena, buffer);
    dest->content_len = count;
    dest->content = alloc(count);
    errno_t err = memcpy_s(dest->content, count, buffer, count);
    assert(err == 0);
}


static IndexEntry *get_index_entry(Index *idx, const char *rel_path)
{
    size_t upper_bound = idx->qtt;
    size_t lower_bound = 0;
    size_t mid;

    do {
        mid = (upper_bound - lower_bound) / 2;
        IndexEntry *ie = &idx->items[lower_bound + mid];
        int res = strcmp(ie->rel_path, rel_path);

        if (res == 0)
            return ie;

        if (res < 0)
            lower_bound += mid;
        else
            upper_bound -= mid;

    } while (mid);

    return NULL;
}


static FileMap *read_file_map(const char *path) {
    if (g_file_maps.items == NULL) {
        g_file_maps.items = arena_alloc(
            &g_file_maps.arena, PREALLOC_SPECS * sizeof(FileMap *)
        );
        g_file_maps.qtt_cap = PREALLOC_SPECS;

        for (int i = 0; i < g_file_maps.qtt_cap; i++) {
            g_file_maps.items[i] = arena_alloc(
                &g_file_maps.arena, sizeof(FileMap)
            );
        }
    }

    FileMap *fm;
    for (int i = 0; i < g_file_maps.qtt; i++) {
        fm = g_file_maps.items[i];
        if (strcmp(fm->path, path) == 0) {
            return fm;
        }
    }

    if (g_file_maps.qtt == g_file_maps.qtt_cap) {
        size_t size = g_file_maps.qtt * sizeof(FileMap *);
        g_file_maps.items = arena_realloc(
            &g_file_maps.arena, g_file_maps.items, size, size * 2
        );

        g_file_maps.qtt_cap *= 2;
        for (int i = 0; i < g_file_maps.qtt_cap; i++) {
            g_file_maps.items[i] = arena_alloc(
                &g_file_maps.arena, sizeof(FileMap)
            );
        }
    }

    fm = g_file_maps.items[g_file_maps.qtt];
    fm->path = arena_strdup(&g_file_maps.arena, path);

    fm->hFile = CreateFile(
        path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (INVALID_HANDLE_VALUE == fm->hFile)
        log_crash_win32_error(GetLastError());

    if (!GetFileSizeEx(fm->hFile, &fm->file_size))
        log_crash_win32_error(GetLastError());

    fm->hMap = CreateFileMapping(
        fm->hFile, NULL, PAGE_READONLY, 0, 0, NULL
    );
    if (NULL == fm->hMap)
        log_crash_win32_error(GetLastError());

    fm->hView = MapViewOfFileEx(
        fm->hMap, FILE_MAP_READ, 0, 0, 0, NULL
    );
    if (NULL == fm->hView)
        log_crash_win32_error(GetLastError());

    g_file_maps.qtt++;

    return fm;
}


static char* build_delta_obj(unsigned char *buf,
                             size_t obj_size,
                             FileMap *fm,
                             char *base_obj,
                             size_t base_obj_size,
                             size_t *dest_size)
{
    // Populate g_zlib_buffer with tranformation data
    char *trans = zlib_inflate(obj_size, buf, fm, dest_size);
    size_t trans_size = *dest_size;
    size_t trans_readden = 0;

    int vlis[2];
    for (int i = 0; i < 2; i++) {
        int val = 0, bshift = 0;
        for (;;) {
            val |= (*trans & 0x7f) << bshift;
            if ((*trans++ & 0x80) == 0) {
                trans_readden++;
                break;
            }
            trans_readden++;
            bshift += 7;
        }
        vlis[i] = val;
    }

    size_t again_base_obj_size = vlis[0];
    size_t undelta_size = vlis[1];
    assert(base_obj_size == again_base_obj_size);

    // Build actual file
    char *undelta = alloc(undelta_size + 1);
    char *und_ptr = undelta;
    while (trans_readden < trans_size) {
        int nbytes;
        char c = *trans++;
        trans_readden++;

        if (c == 0)
            continue;

        else if (c & 0x80) {  // Copy data from base_obj
            char tmp[6];
            for (int j = 0; j < 6; j++) {
                int bmask = 1 << j;

                if (c & bmask) {
                    tmp[j] = *trans++;
                    trans_readden++;

                } else
                    tmp[j] = 0;
            }

            unsigned start = *(unsigned *)tmp;
            nbytes = *(unsigned short *)(tmp + 4);
            if (!nbytes)
                nbytes = 0x10000;

            memcpy(und_ptr, base_obj + start, nbytes);

        } else {  // Append bytes
            nbytes = c & 0x7f;
            memcpy(und_ptr, trans, nbytes);
            trans += nbytes;
            trans_readden += nbytes;
        }

        und_ptr += nbytes;
    }

    assert(trans_readden == trans_size);

    *dest_size = undelta_size;
    undelta[undelta_size] = '\0';

    return undelta;
}


static char *get_content_by_offset(const char *path,
                                   size_t offset,
                                   size_t *dest_size)
{
    FileMap *fm = read_file_map(path);
    unsigned char *buf = fm->hView;
    buf += offset;

    // https://git-scm.com/docs/pack-format
    int type = (*buf & 0x70) >> 4;
    assert(!(type <= 0 || type == 5 || type > 7) && "Invalid type");

    int obj_size = *buf & 0x0f;
    int bit_shift = 4;
    int msb = *buf++ & 0x80;

    while (msb) {
        obj_size |= (*buf & 0x7f) << bit_shift;
        bit_shift += 7;
        msb = *buf++ & 0x80;
    }
    logger(LOG_DEBUG_PACK, "Type: %i; Obj size: %i", type, obj_size);

    char *dest = NULL;
    *dest_size = 0;

    if (type < 6)
        dest = zlib_inflate(obj_size, buf, fm, dest_size);

    else if (type == 6) {
        // read variable length value big endian
        size_t rel_offset = 0;
        for (;;) {
            rel_offset = (rel_offset << 7) | (*buf & 0x7f);
            if ((*buf++ & 0x80) == 0)
                break;
            rel_offset++;
        }

        size_t base_obj_offset = offset - rel_offset;
        size_t base_obj_size;
        char *nested = get_content_by_offset(
            path, base_obj_offset, &base_obj_size
        );

        char *base_obj;
        if (nested == g_zlib_buffer.data) {
            base_obj = alloc(base_obj_size);
            errno_t err = memcpy_s(
                base_obj, base_obj_size, nested, base_obj_size
            );
            assert(err == 0);
        } else
            base_obj = nested;

        dest = build_delta_obj(
            buf, obj_size, fm, base_obj, base_obj_size, dest_size
        );

    } else {
        char *base_obj;
        GitObject base_git_obj;
        ContentOrigin co = get_content_by_hash(
            get_hash_string(buf), &base_git_obj
        );
        buf += 20;
        assert(co != CO_NONE);

        size_t base_obj_size = base_git_obj.content_len;
        if (base_git_obj.content == g_zlib_buffer.data) {
            base_obj = alloc(base_obj_size);
            errno_t err = memcpy_s(
                base_obj, base_obj_size, base_git_obj.content, base_obj_size
            );
            assert(err == 0);
        } else
            base_obj = base_git_obj.content;

        dest = build_delta_obj(
            buf, obj_size, fm, base_obj, base_obj_size, dest_size
        );
    }

    return dest;
}


static char *get_dot_git(const char *path)
{
    bool continue_search;
    char *w_path = arena_strdup(&g_arena, path);
    size_t size = strlen(w_path) + 5 + 1;  // "\\.git" + '\0'
    char *dot_git = alloc(size);

    strcpy_s(dot_git, size, w_path);

    do {
        sprintf_s(dot_git, size, "%s\\.git", w_path);
        if (path_exists(dot_git))
            return dot_git;

        continue_search = make_path_parent(w_path);
    } while (continue_search);

    return NULL;
}


static char *read_file_alloc(const char* path)
{
    HANDLE hFile;
    LARGE_INTEGER lpFileSize;
    DWORD cbRead = 0;

    hFile = CreateFile(path,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);

    if (INVALID_HANDLE_VALUE == hFile)
        goto fail1;
    if (!GetFileSizeEx(hFile, &lpFileSize))
        goto fail2;

    char *buffer = alloc(lpFileSize.QuadPart + 1);
    int64_t readden = 0;
    unsigned long it_read;

    while (lpFileSize.QuadPart > readden) {
        if (lpFileSize.QuadPart - readden > USHRT_MAX)
            it_read = USHRT_MAX;
        else
            it_read = (unsigned long)lpFileSize.QuadPart;

        if (!ReadFile(hFile, buffer + readden, it_read, &cbRead, NULL))
            goto fail2;

        assert(cbRead == it_read);
        readden += it_read;
    };

    CloseHandle(hFile);
    return buffer;

fail2:
    CloseHandle(hFile);
fail1:
    log_crash_win32_error(GetLastError());
    return NULL;
}


static char *get_branch_on_head(bool *detached)
{
    size_t len = strlen(g_git_root) + 6;
    char *path = alloc(len);
    
    sprintf_s(path, len, "%s\\HEAD", g_git_root);
    if (!path_exists(path))
        return NULL;

    char *buffer = read_file_alloc(path);
    char *branch = strrchr(buffer, '/');
    if (branch == NULL) {
        *detached = true;

        char *det_head = alloc(20);
        buffer[7] = '\0';
        sprintf_s(det_head, 20, "detached at %s", buffer);

        return det_head;
    }
    *detached = false;

    branch++;
    branch[strcspn(branch, "\r\n")] = '\0';

    return branch;
}


static char *get_last_commit_loose(const char *branch)
{
    size_t len = strlen(g_git_root) + strlen(branch) + 13; // "/refs/heads/"
    char *path = alloc(len);
    sprintf_s(path, len, "%s\\refs\\heads\\%s", g_git_root, branch);

    if (!path_exists(path))
        return NULL;

    char *buffer = read_file_alloc(path);
    buffer[strcspn(buffer, "\r\n")] = '\0';

    return buffer;
}


static char *get_last_commit_packed(const char *branch)
{
    size_t len = strlen(g_git_root) + 11;  // "/info/refs"
    char *path = alloc(len);
    sprintf_s(path, len, "%s\\info\\refs", g_git_root);

    if (!path_exists(path))
        return NULL;

    size_t size = strlen(branch) + 12;  // refs/heads/
    char *test = alloc(size);
    sprintf_s(test, size, "refs/heads/%s", branch);

    // TODO: Can't read this shit
    char *buffer = read_file_alloc(path);
    char *res = buffer;
    size_t readden = strlen(buffer);
    bool second = false;
    char *ref = NULL;
    for (size_t i = 0; i < readden; ++i) {
        if (buffer[i] == '\t') {
            buffer[i] = '\0';
            second = true;
        }
        if (second) {
            ref = &buffer[i + 1];
            second = false;
        }
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            if (strcmp(test, ref) == 0)
                return res;
            res = &buffer[i + 1];
        }
    }
    return NULL;
}


static char *get_last_commit(const char *branch)
{
    char *res =  get_last_commit_loose(branch);
    if (NULL != res)
        return res;

    return get_last_commit_packed(branch);
}


static bool get_content_by_hash_loose(const char *hash, GitObject *dest)
{
    // \objects\83\f7993f33e9a7dd73139212f309cfed1d722129
    size_t len = strlen(g_git_root) + 51; 
    char *path = alloc(len);
    sprintf_s(path, len, "%s\\objects\\%.2s\\%s", g_git_root, hash, hash + 2);

    logger(LOG_DEBUG, "Searching for %s", path);
    if (!path_exists(path))
        return false;

    HANDLE hFile = INVALID_HANDLE_VALUE;
    hFile = CreateFile(path,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);

    if (INVALID_HANDLE_VALUE == hFile)
        log_crash_win32_error(GetLastError());

    char *buffer;
    size_t count;
    zlib_error(zlib_inflate_source(hFile, &buffer, &count));
    make_git_object(dest, buffer, count);

    CloseHandle(hFile);
    return true;
}


static char *get_tree_hash(const char *commit_content, ContentOrigin co)
{
    char *res = alloc(41);

    if (co == CO_LOOSE)
        // jump first null byte
        commit_content = &commit_content[strlen(commit_content)];

    char *hash_init = strchr(commit_content + 1, ' ') + 1;
    strncpy_s(res, 41, hash_init, 40);
    res[40] = '\0';

    return res;
}


static void make_tree_object(GitObject *git, Tree *tree, bool from_pack)
{
    size_t size;
    size_t copied = 0;

    if (!from_pack) {
        tree->type = arena_strdup(&g_arena, git->content);

        size = strlen(tree->type) + 1;
        copied += size;
        if (copied == git->content_len) return;
        git->content += copied;
    }

    tree->first_entry = alloc(sizeof(TreeEntry));
    TreeEntry *te = tree->first_entry;
    te->next = NULL;
    bool first = true;
    while (copied < git->content_len) {

        if (!first) {
            te->next = alloc(sizeof(TreeEntry));
            te = te->next;
            te->next = NULL;
        }

        char *type_name = arena_strdup(&g_arena, git->content);
        size = strlen(type_name) + 1;
        copied += size;
        git->content += size;

        te->type = type_name;
        char *space = strchr(type_name, ' ');
        *space = '\0';
        te->name = space + 1;

        size = 20;
        te->hash = alloc(size);
        errno_t err = memcpy_s(te->hash, size, git->content, size);
        assert(err == 0);
        copied += size;
        git->content += size;

        first = false;
    }

    if (copied != git->content_len) {
        logger(
            LOG_ERROR,
            "`make_tree_object`: "
            "copied %zu; content_len: %zu; from_pack: %s",
            copied, git->content_len, from_pack ? "True" : "False"
        );
        assert(0 && "Check error log");
    }
}


static TreeEntry *get_tree_entry(Tree *tree, const char *file_name)
{
    TreeEntry *te = tree->first_entry;
    while (te != NULL) {
        if (strcmp(te->name, file_name) == 0)
            return te;

        te = te->next;
    }

    return NULL;
}


static void read_file(const char *path, size_t size)
{
    if (g_entire_file.capacity < size) {
        HANDLE heap = GetProcessHeap();
        assert(heap != NULL);

        logger(LOG_DEBUG_MEM, "entire_file:");
        logger(LOG_DEBUG_MEM, "\t%p free", g_entire_file.data);

        bool res = HeapFree(heap, 0, g_entire_file.data);
        assert(res);

        // we check if the next char is '\n' on `convert_newlines`
        g_entire_file.data = HeapAlloc(heap, 0, size + 1);
        assert(g_entire_file.data != NULL);
        g_entire_file.capacity = size + 1;

        logger(LOG_DEBUG_MEM, "\t%p alloc", g_entire_file.data);
    }

    g_entire_file.current_file_size = size;
    g_entire_file.converted = false;

    HANDLE hFile = CreateFile(path,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_SEQUENTIAL_SCAN,
                              NULL);

    if (INVALID_HANDLE_VALUE == hFile)
        log_crash_win32_error(GetLastError());

    DWORD cbRead = 0;
#if 0
    size_t readden = 0;
    unsigned long it_read;

    while (readden < size) {
        if (size - readden > USHRT_MAX)
            it_read = USHRT_MAX;
        else
            it_read = (unsigned long)size;

        if (!ReadFile(hFile, g_entire_file.data + readden, it_read, &cbRead, NULL))
            log_crash_win32_error(GetLastError());

        assert(cbRead == it_read);
        readden += it_read;
    };

#else
    // TODO: iterate through USHRT_MAX
    assert(size < 0x7fffffff);
    bool res = ReadFile(hFile, g_entire_file.data, (DWORD)size, &cbRead, NULL);
    if (!res)
        return;
    assert(cbRead == size);
    g_entire_file.data[size] = '\0';
#endif

    CloseHandle(hFile);
}


static char *get_hash_string(BYTE rgbHash[20])
{
    CHAR rgbDigits[] = "0123456789abcdef";
    char *res = alloc(41);
    char buf[3] = {0};
    for (DWORD i = 0; i < SHA1LEN; i++) {
        sprintf_s(buf, 3, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        strcat_s(res, 41, buf);
    }

    return res;
}


static BYTE *get_hash_bytes(const char *str)
{
    BYTE *hash = alloc(20);
    int k = 0;
    for (int i = 0; i < 20; i++) {

        char values[] = {str[k], str[k + 1]};
        for (int j = 0; j < 2; j++) {

            char val = values[j];
            if      (val >= 97 && val <= 102) val -= 87; // a-f
            else if (val <= 57 && val >= 48)  val -= 48; // 0-9
            else    assert(0 && "Not a valid hash");

            if (j)
                hash[i] += val;
            else
                hash[i] += val * 16;
        }
        k += 2;
    }

    return hash;
}


static void get_file_hash(DirEntry *file,
                          unsigned char result[20],
                          bool use_cr,
                          bool second_call)
{
    if (!second_call || g_entire_file.converted)
        read_file(file->path, file->size.QuadPart);

    if (!use_cr) {
        int stripped = convert_newlines(g_entire_file.data, g_entire_file.current_file_size, false);
        g_entire_file.current_file_size -= stripped;
        g_entire_file.converted = true;
    }

    hash_buffer(g_entire_file.data, g_entire_file.current_file_size, result);
}


static char *get_rel_path(const char *full_path, size_t fpath_size)
{
    if (strcmp(full_path, g_root_dir) == 0)
        return "";

    int equal = 0;
    char *p = g_root_dir;
    while (*p++ == *full_path++)
        equal++;

    char *res = alloc(fpath_size - equal);
    strcpy_s(res, fpath_size - equal, full_path);

    char *backslash = strchr(res, '\\');
    while (backslash != NULL) {
        *backslash = '/';
        backslash = strchr(res, '\\');
    }

    return res;
}


static bool check_ignore(DirEntry *file, Ignore *ign)
{
    char *rel_path = strtolower(file->rel_path);
    char *file_name = strtolower(file->name);
    char *spec = NULL;

    for (int i = 0; i < ign->qtt; i++) {
        spec = ign->specs[i];

        char *last_char = spec + strlen(spec) - 1;
        bool must_be_dir = *last_char == '/';

        if (must_be_dir) {
            if ((file->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                continue;
            *last_char = '\0';
        }

        bool must_be_rooted = spec[0] == '/';

        if (must_be_rooted) {
            if (fnmatch(++spec, rel_path))
                goto found;

        } else {
            if (strchr(spec, '/') != NULL) {
                size_t size = strlen(spec) + 3;
                char *new_spec = alloc(size);
                sprintf_s(new_spec, size, "**%s", spec);

                if (fnmatch(new_spec, rel_path))
                    goto found;

            } else if (fnmatch(spec, file_name))
                goto found;
        }
    
    }

    return false;

found:
    Ignore *imp = ign->important;
    if (imp == NULL)
        return true;

    for (int i = 0; i < imp->qtt; i++) {
        spec = imp->specs[i];
        if (fnmatch(spec, file_name))
            // printf("Important not ignored: %s\n", rel_path);
            return false;
    }

    return true;
}


static Dir *get_dir(const char *path, bool allow_dot_git)
{
    WIN32_FIND_DATA ffd;

    unsigned id = 0;
    char dir_path[MAX_PATH] = {0};
    size_t path_size = strlen(path);

    Dir *dir = alloc(sizeof(Dir));
    dir->entries = alloc(sizeof(char *) * PREALLOC_SPECS);
    dir->capacity = PREALLOC_SPECS;

    if (path_size > (MAX_PATH - 3)) {
        logger(LOG_ERROR, "Directory path is too long.");
        assert(0 && "Check error log");
    }

    strcpy_s(dir_path, MAX_PATH, path);
    strcat_s(dir_path, MAX_PATH, "\\*");

    HANDLE hFind = FindFirstFileEx(
        dir_path,
        FindExInfoBasic,
        &ffd,
        FindExSearchNameMatch,
        NULL,
        FIND_FIRST_EX_LARGE_FETCH
    );

    if (INVALID_HANDLE_VALUE == hFind)
        log_crash_win32_error(GetLastError());

    do {
        if (!strcmp(ffd.cFileName, ".") || !strcmp(ffd.cFileName, ".."))
            continue;
        if (!allow_dot_git && !strcmp(ffd.cFileName, ".git"))
            continue;

        DirEntry *file = alloc(sizeof(DirEntry));
        file->name = arena_strdup(&g_arena, ffd.cFileName);
        file->attributes = ffd.dwFileAttributes;
        file->size.LowPart = ffd.nFileSizeLow;
        file->size.HighPart = ffd.nFileSizeHigh;
        file->mtime = ffd.ftLastWriteTime;
        file->mtime.dwLowDateTime &= 0xffffffe0;

        size_t size = path_size + strlen(file->name) + 2;
        file->path = alloc(size);
        sprintf_s(file->path, size, "%s\\%s", path, file->name);
        file->rel_path = get_rel_path(file->path, size);

        if (dir->qtt >= dir->capacity) {
            size_t prev_size = dir->capacity * sizeof(char *);
            dir->capacity += PREALLOC_SPECS;
            size_t new_size = dir->capacity * sizeof(char *);
            dir->entries = arena_realloc(&g_arena, dir->entries, new_size, prev_size);
        }
        dir->entries[dir->qtt] = file;
        dir->qtt++;
    } while (FindNextFile(hFind, &ffd) != 0);

    id = GetLastError();
    if (id != ERROR_NO_MORE_FILES)
        log_crash_win32_error(id);

    if (!FindClose(hFind))
        log_crash_win32_error(id);

    return dir;
}


Ignore *get_gitignore(const char *path)
{
    size_t size = strlen(path) + 12;
    char *gitignore_path = alloc(size);
    sprintf_s(gitignore_path, size, "%s\\%s", path, ".gitignore");

    if (!path_exists(gitignore_path))
        return NULL;

    size = strlen(path);
    char *rel_path = get_rel_path(path, size);
    size = strlen(rel_path);

    Ignore *ign = alloc(sizeof(Ignore));
    ign->capacity = PREALLOC_SPECS;
    ign->qtt = 0;
    ign->specs = alloc(ign->capacity * sizeof(char *));

    HANDLE hFile = CreateFile(gitignore_path,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_SEQUENTIAL_SCAN,
                              NULL);
    if (INVALID_HANDLE_VALUE == hFile)
        log_crash_win32_error(GetLastError());

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li))
        log_crash_win32_error(GetLastError());

    read_file(gitignore_path, (size_t)li.QuadPart);
    char *content = (char *)g_entire_file.data;

    char *next_tok, *tok;
    tok = strtok_s(content, "\r\n", &next_tok);

    while (tok != NULL) {

        char first_char = tok[strspn(tok, " ")];

        if (first_char == '\\')
            tok++;
        else if (first_char == '#') {
            tok = strtok_s(NULL, "\r\n", &next_tok);
            continue;

        } else if (first_char == '!') {
            Ignore *important = ign->important;;
            if (important == NULL) {
                ign->important = alloc(sizeof(Ignore));
                important = ign->important;

                important->capacity = PREALLOC_SPECS;
                important->qtt      = 0;
                important->specs    = alloc(ign->capacity * sizeof(char *));
            }

            if (important->qtt == important->capacity) {
                size_t prev_size = important->capacity * sizeof(char *);
                important->capacity += PREALLOC_SPECS;
                size_t new_size = important->capacity * sizeof(char *);
                important->specs = arena_realloc(&g_arena, important->specs, new_size, prev_size);
            }

            important->specs[important->qtt] = strtolower(tok + 1);
            important->qtt++;
            tok = strtok_s(NULL, "\r\n", &next_tok);
            continue;
        }

        if (ign->qtt >= ign->capacity) {
            size_t prev_size = ign->capacity * sizeof(char *);
            ign->capacity += PREALLOC_SPECS;
            size_t new_size = ign->capacity * sizeof(char *);
            ign->specs = arena_realloc(&g_arena, ign->specs, new_size, prev_size);
        }

        if (strlen(tok)) {
            ign->specs[ign->qtt] = strtolower(tok);
            ign->qtt++;
        }
        tok = strtok_s(NULL, "\r\n", &next_tok);
    }

    CloseHandle(hFile);
    return ign;
}


static Ignore *get_gitignore_copy(Ignore *ign)
{
    if (ign == NULL)
        return NULL;

    Ignore *new = alloc(sizeof(Ignore));
    new->qtt = ign->qtt;
    new->capacity = ign->capacity;
    new->specs = alloc(new->capacity * sizeof(char *));

    for (int i = 0; i < new->qtt; i++)
        new->specs[i] = ign->specs[i];

    return new;
}


static void merge_gitignore(Ignore **dest, Ignore **nign)
{
    if (*nign == NULL)
        return;
    if (*dest == NULL) {
        *dest = *nign;
        return;
    }

    Ignore *ia, *ib;
    ia = *dest;
    ib = *nign;

    size_t nsize = ia->qtt + ib->qtt;
    if (ia->capacity < nsize) {
        size_t prev_size = ia->capacity * sizeof(char *);
        ia->capacity = nsize;
        size_t new_size = ia->capacity * sizeof(char *);
        ia->specs = arena_realloc(&g_arena, ia->specs, new_size, prev_size);
    }

    for (int i = 0; i < ib->qtt; i++) {
        ia->specs[ia->qtt] = ib->specs[i];
        ia->qtt++;
    }
}


// they are mutually exclusive but i want to be specific
typedef enum {
    FE_IN_INDEX = 0,
    FE_IGNORED = 1,
    FE_REITERATE = 4
} FileExtra;


static void handle_untracked_dir(const char *path,
                                 Index *idx,
                                 Ignore *ign,
                                 UntrackedDirResult *udr)
{
    bool any_staged = false;
    bool any_staged_below = false;
    bool any_file = false;
    int staged = 0;
    int untracked = 0;

    logger(LOG_DEBUG, "Dealing with untracked dir %s", path);

    Dir *dir = get_dir(path, true);
    DirEntry *file;
    int i;

    for (i = 0; i < dir->qtt; ++i) {
        file = dir->entries[i];
        if (file->attributes & FILE_ATTRIBUTE_DIRECTORY
            && strcmp(file->name, ".git") == 0) {
            return;
        }
    }

    Ignore *nign = get_gitignore(path);
    logger_iter_ign(nign, path);
    merge_gitignore(&ign, &nign);

    for (i = 0; i < dir->qtt; ++i) {
        file = dir->entries[i]; 
        assert(file->extra == 0);

        if (ign != NULL && check_ignore(file, ign)) {
            file->extra = FE_IGNORED;
            continue;
        }

        if (file->attributes & FILE_ATTRIBUTE_DIRECTORY) {
            Ignore *ign_copy = get_gitignore_copy(ign);
            UntrackedDirResult nudr = {0};
            handle_untracked_dir(file->path, idx, ign_copy, &nudr);

            any_staged_below = nudr.any_staged;
            any_file += nudr.any_file;
            staged += nudr.staged;
            untracked += nudr.untracked;

            if (nudr.any_file)
                file->extra = FE_REITERATE;

            logger(LOG_DEBUG, 
                   "Untracked dir [%s] result is {untracked: %i, staged: %i}",
                   file->rel_path, nudr.untracked, nudr.staged);

            continue;
        }

        any_file = true;

        IndexEntry *ie = idx != NULL
                       ? get_index_entry(idx, file->rel_path)
                       : NULL;

        if (ie != NULL) {
            logger(LOG_INFO, "`untracked dir` Staged %s", file->rel_path);
            staged++;
            any_staged = true;
            file->extra = FE_IN_INDEX;
            ie->on_fs = true;
        }
    }

    if (any_staged_below) {
        for (i = 0; i < dir->qtt; ++i) {
            file = dir->entries[i]; 

            switch (file->extra) {
                case FE_REITERATE: {
                    logger(LOG_INFO,
                           "`untracked dir` untracked %s",
                           file->rel_path);
                    untracked++;  // and fallback
                }
                case FE_IGNORED:
                case FE_IN_INDEX: continue;
            }

            // Only marked dirs are stated as ignored
            if (file->attributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            logger(LOG_INFO,
                   "`untracked dir` untracked %s",
                   file->rel_path);

            untracked++;
        }

        // The files in this level were classified, don't mark whole dir
        if (!any_staged)
            any_file = false;
    }

    udr->any_staged = any_staged || any_staged_below;
    udr->staged += staged;
    udr->any_file = any_file;
    udr->untracked += untracked;
}


static bool search_idx(unsigned char *data, BYTE *hash, size_t *offset, int idx)
{
    // TODO: name all these magics
    uint64_t version = get_be_from_buffer(data + 4, 4);
    assert(version == 2);

    uint64_t files_before = idx > 0
                          ? get_be_from_buffer(data + 8 + (idx - 1) * 4, 4)
                          : 0;
    uint64_t total_files = get_be_from_buffer(data + 8 + 255 * 4, 4);

    if (total_files == files_before)
        return false;

    uint64_t upper_bound = get_be_from_buffer(data + 8 + idx * 4, 4);

    for (;;) {
        uint64_t mid = (upper_bound - files_before) / 2;
        uint64_t test = PACK_HEADER + FANOUT_1
                      + FANOUT_2_ITEM_SIZE * (files_before + mid);


        int res = memcmp(data + test, hash, SHA1LEN);
        if (res == 0) {
            *offset = get_be_from_buffer(
                data + PACK_HEADER + FANOUT_1
                + FANOUT_2_ITEM_SIZE * total_files
                + FANOUT_3_ITEM_SIZE * total_files
                + FANOUT_4_ITEM_SIZE * (files_before + mid),
                4
            );
            logger(LOG_DEBUG_PACK, "Found. Offset: %i", *offset);
            return true;
        }

        if (!mid)
            break;

        if (res > 0)
            upper_bound -= mid;
        else
            files_before += mid;
    }

    return false;
}


static bool get_content_by_hash_packed(const char *hash, GitObject *go)
{
    LARGE_INTEGER filesize;
    WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    // objects\pack\pack-db0b11a014f69b7e29c639e2c879346b28dce960.pack
    size_t size = strlen(g_git_root) + 65;
    char *path = alloc(size);
    sprintf_s(path, size, "%s\\%s", g_git_root, "objects\\pack\\*.idx");

    hFind = FindFirstFileEx(
        path,
        FindExInfoBasic,
        &ffd,
        FindExSearchNameMatch,
        NULL,
        FIND_FIRST_EX_LARGE_FETCH
    );

    if (INVALID_HANDLE_VALUE == hFind)
        log_crash_win32_error(GetLastError());

    logger(LOG_DEBUG_PACK, "Search for hash: %s", hash);
    char buf[3] = {0};
    snprintf(buf, 3, "%s", hash);
    int idx = strtol(buf, NULL, 16);

    do {
        sprintf_s(path, size, "%s\\objects\\pack\\%s", g_git_root, ffd.cFileName);
        filesize.HighPart = ffd.nFileSizeHigh;
        filesize.LowPart = ffd.nFileSizeLow;

        FileMap *fm = read_file_map(path);
        unsigned char *data = fm->hView;

        size_t offset;
        if (!search_idx(data, get_hash_bytes(hash), &offset, idx))
            continue;

        sprintf_s(path + size - 5, size, "%s", "pack");
        size_t dest_size;
        char *content = get_content_by_offset(path, offset, &dest_size);
        make_git_object(go, content, dest_size);
        goto success;

    } while (FindNextFile(hFind, &ffd) != 0);

    unsigned long id = GetLastError();
    if (id != ERROR_NO_MORE_FILES)
        log_crash_win32_error(id);

    FindClose(hFind);
    return false;

success:
    FindClose(hFind);
    return true;
}


static ContentOrigin get_content_by_hash(const char *hash, GitObject *go)
{
    if (get_content_by_hash_loose(hash, go))
        return CO_LOOSE;
    if (get_content_by_hash_packed(hash, go))
        return CO_PACK;

    return CO_NONE;
}


static void scandir(const char *path,
                    Index *idx,
                    Tree *tree,
                    Ignore *ign,
                    FinalResult *res)
{
    logger(LOG_DEBUG, "Scandir: %s", path);

    BYTE rgbHash[SHA1LEN];
    TreeEntry *te;
    IndexEntry *ie;
    DirEntry *file;
    static bool use_cr = false;

    Ignore *nign = get_gitignore(path);
    logger_iter_ign(nign, path);
    merge_gitignore(&ign, &nign);

    Dir *dir = get_dir(path, false);
    ArenaMark m = arena_mark(&g_arena);

    for (int i = 0; i < dir->qtt; ++i) {
        file = dir->entries[i];

        if (file->attributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        arena_mark_reset(&g_arena, m);

        te = tree != NULL ? get_tree_entry(tree, file->name) : NULL;
        if (ign != NULL && check_ignore(file, ign)) {
            if (te != NULL)
                te->on_fs_or_ign = true;
            continue;
        }

        if (idx == NULL) {
            logger(LOG_INFO, "Untracked: Idx is NULL: %s", file->rel_path);
            res->untracked++;
            continue;
        }

        ie = idx != NULL ? get_index_entry(idx, file->rel_path) : NULL;
        if (ie == NULL) {
            logger(LOG_INFO, "Untracked: Not in index: %s", file->rel_path);
            res->untracked++;
            continue;
        }
        ie->on_fs = true;

        if (te == NULL) {
            logger(LOG_INFO, "`scandir` Staged %s", file->rel_path);
            res->staged++;
            continue;
        }
        te->on_fs_or_ign = true;

        if (memcmp(&file->mtime, ie->mtime, sizeof(FILETIME)) == 0)
            continue;

        get_file_hash(file, rgbHash, use_cr, false);
        if (memcmp(te->hash, rgbHash, SHA1LEN) == 0) {
            logger(LOG_INFO, "Hashes are equal for [%s]", file->rel_path);
            continue;
        }

        get_file_hash(file, rgbHash, !use_cr, true);
        if (memcmp(te->hash, rgbHash, SHA1LEN) == 0) {
            logger(LOG_INFO, "Hashes are equal for [%s]", file->rel_path);
            use_cr = !use_cr;
            continue;
        }

        logger(LOG_INFO, "Modified %s", file->rel_path);
        res->modified++;
    }

    for (int i = 0; i < dir->qtt; ++i) {
        file = dir->entries[i];

        if ((file->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            continue;

        arena_mark_reset(&g_arena, m);

        te = tree != NULL ? get_tree_entry(tree, file->name) : NULL;
        if (ign != NULL && check_ignore(file, ign)) {
            if (te != NULL)
                te->on_fs_or_ign = true;
            continue;
        }

        Ignore *ign_copy = get_gitignore_copy(ign);

        if (te == NULL) {
            UntrackedDirResult udr = {0};
            handle_untracked_dir(file->path, idx, ign_copy, &udr);
            udr.untracked += !!udr.any_file;

            res->untracked += udr.untracked;
            res->staged += udr.staged;
            
            logger(LOG_DEBUG, 
                   "Untracked dir result [%s] is {untracked: %i, staged: %i}",
                   file->rel_path, udr.untracked, udr.staged);

        } else {
            te->on_fs_or_ign = true;
            if (strcmp(te->type, "40000") != 0) {
                if (strcmp(te->type, "160000") == 0)
                    continue;  // submodule
                logger(LOG_ERROR,
                       "Entry %s has unexpected type %s with hash %s",
                       te->name, te->type, get_hash_string(te->hash));
                assert(0 && "Check error log");
            }

            GitObject obj;
            ContentOrigin found = get_content_by_hash(
                get_hash_string(te->hash), &obj
            );
            if (found == CO_NONE) {
                logger(LOG_ERROR, "Could not find entry %s with hash: %s",
                       te->name, get_hash_string(te->hash));
                assert(0 && "Check error log");
            }

            Tree nested;
            make_tree_object(&obj, &nested, found == CO_PACK);
            scandir(file->path, idx, &nested, ign_copy, res);
        }
    }

    if (tree != NULL) {
        te = tree->first_entry;
        while (te != NULL) {
            if (!te->on_fs_or_ign)
                res->deleted++;

            te = te->next;
        }
    }

    arena_mark_reset(&g_arena, m);
}


static char *get_final_result(FinalResult *fr)
{
    // "?...... +...... m...... x......"
    int total_len = 32;
    char *res = alloc(total_len);

    int buf_len = 8;
    char buf[9] = {0}; // " +......"  // buf[buf_len + 1]

    char mask[] = "X%i";
    char marks[] = {'?', '+', 'm', 'x'};

    for (int i = 0; i < 4; i++) {
        int val = ((int *)&fr->untracked)[i];
        if (val) {
            assert(val >= 0 && val < 1000000);

            if (strlen(res))
                strcat_s(res, total_len, " ");

            mask[0] = marks[i];
            sprintf_s(buf, buf_len, mask, val);
            strcat_s(res, total_len, buf);
        }
    }

    return res;
}


static Tree *get_first_tree(GitObject *git, char *branch)
{
    char *last_cmmt = get_last_commit(branch);
    if (last_cmmt == NULL)
        return NULL;

    ContentOrigin co = get_content_by_hash(last_cmmt, git);
    if (co == CO_NONE)
        return NULL;

    char *tree_hash = get_tree_hash(git->content, co);

    co = get_content_by_hash(tree_hash, git);
    if (co == CO_NONE)
        return NULL;

    Tree *tree = alloc(sizeof(Tree));
    make_tree_object(git, tree, co == CO_PACK);

    return tree;
}


static GitStatus gitstatus(const char *path)
{
    GitStatus gs = {0};

    char *dot_git = get_dot_git(path);
    if (dot_git == NULL)
        return gs;

    gs.git_found = true;

    set_git_root(dot_git);
    char *root_dir = arena_strdup(&g_arena, dot_git);
    bool res = make_path_parent(root_dir);
    assert(res);
    set_root_dir(root_dir);

    logger(LOG_DEBUG, "Set g_dot_git: %s", g_git_root);
    logger(LOG_DEBUG, "Set g_root_dir: %s", g_root_dir);

    bool detached;
    gs.branch = get_branch_on_head(&detached);
    if (detached) {
        gs.status = "";
        return gs;
    }

    logger(LOG_DEBUG, "Branch found: %s", gs.branch);

    GitObject git;
    Tree *tree = get_first_tree(&git, gs.branch);
    logger(LOG_DEBUG, "Inital tree not null? %s", NULL == tree ? "False" : "True");
    Index *idx = get_git_index();

    FinalResult fr = {0};
    scandir(root_dir, idx, tree, NULL, &fr);

#if 0
    if (idx != NULL)
        for (int i = 0; i < idx->qtt; i++) {
            IndexEntry *ie = &idx->items[i];
            if (!ie->on_fs) {
                printf("rel_path: %s; on_fs: %i\n", ie->rel_path, ie->on_fs);
                fr.deleted++;
            }
        }
#endif

    gs.status = get_final_result(&fr);

    return gs;
}

// #define PYTHON_BINDING
// #define TEST_REPOS
// #define MAIN

#ifdef PYTHON_BINDING
#    ifdef LOG_LEVEL
#        pragma message("Warning: Logging is enabled for a python binding")
#    endif
#    include "python_binding.c"
#else
#    ifdef TEST_REPOS
#        include "test_repos.c"
#    else
#        include "cli.c"
#    endif
#endif
