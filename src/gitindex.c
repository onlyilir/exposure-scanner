#include "gitindex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsutil.h"

#define INDEX_MAX_BYTES (64L * 1024 * 1024)

#ifdef _WIN32
#include <strings.h>
#define PATH_EQ(a, b) (strcasecmp((a), (b)) == 0)
#else
#define PATH_EQ(a, b) (strcmp((a), (b)) == 0)
#endif

static unsigned long be32(const unsigned char *p)
{
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

static int read_all(const char *path, unsigned char **buf, size_t *len)
{
    long long size;
    FILE *f;
    unsigned char *b;
    size_t got;

    if (!fs_is_file(path, &size) || size < 12 || size > INDEX_MAX_BYTES)
        return -1;
    f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    b = malloc((size_t)size);
    if (b == NULL) {
        fclose(f);
        return -1;
    }
    got = fread(b, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(b);
        return -1;
    }
    *buf = b;
    *len = got;
    return 0;
}

int gitidx_tracked(const char *file)
{
    char abs[1024];
    char idx[1100];
    size_t end, i, off, count, n;
    unsigned char *buf = NULL;
    size_t len = 0;
    unsigned long ver;
    const char *rel;
    int result = 0;

    if (fs_abs_path(file, abs, sizeof abs) != 0)
        return -2;
    for (i = 0; abs[i] != '\0'; i++)
        if (abs[i] == '\\')
            abs[i] = '/';

    end = strlen(abs);
    for (;;) {
        while (end > 0 && abs[end - 1] != '/')
            end--;
        if (end == 0)
            return -2;
        end--; /* abs[end] is a '/': the directory is abs[0..end) */
        if (snprintf(idx, sizeof idx, "%.*s/.git/index", (int)end, abs) >= (int)sizeof idx)
            return -2;
        if (fs_is_file(idx, NULL))
            break;
        if (end == 0)
            return -2;
    }
    rel = abs + end + 1;

    if (read_all(idx, &buf, &len) != 0)
        return -1;
    ver = be32(buf + 4);
    if (memcmp(buf, "DIRC", 4) != 0 || ver < 2 || ver > 3) {
        free(buf);
        return -1;
    }
    count = (size_t)be32(buf + 8);
    off = 12;
    for (n = 0; n < count; n++) {
        size_t p, plen, total;
        unsigned flags;

        if (off + 62 > len) {
            result = -1;
            break;
        }
        flags = ((unsigned)buf[off + 60] << 8) | buf[off + 61];
        p = off + 62;
        if (ver == 3 && (flags & 0x4000))
            p += 2;
        if (p >= len) {
            result = -1;
            break;
        }
        plen = strnlen((const char *)buf + p, len - p);
        if (p + plen >= len) {
            result = -1;
            break;
        }
        if (PATH_EQ((const char *)buf + p, rel)) {
            result = 1;
            break;
        }
        total = (p - off + plen + 8) & ~(size_t)7;
        off += total;
    }
    free(buf);
    return result;
}
