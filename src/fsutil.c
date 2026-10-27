#include "fsutil.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int fs_join(char *dst, size_t n, const char *a, const char *b)
{
    size_t la = strlen(a);
    int sep = la > 0 && a[la - 1] != '/' && a[la - 1] != '\\';
    int w = snprintf(dst, n, "%s%s%s", a, sep ? "/" : "", b);

    return (w < 0 || (size_t)w >= n) ? -1 : 0;
}

int fs_is_dir(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int fs_is_file(const char *path, long long *size)
{
    struct stat st;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (size != NULL)
        *size = (long long)st.st_size;
    return 1;
}

int fs_abs_path(const char *in, char *out, size_t n)
{
#ifdef _WIN32
    return _fullpath(out, in, n) != NULL ? 0 : -1;
#else
    char tmp[PATH_MAX];
    int w;

    if (realpath(in, tmp) == NULL)
        return -1;
    w = snprintf(out, n, "%s", tmp);
    return (w < 0 || (size_t)w >= n) ? -1 : 0;
#endif
}

const char *fs_basename(const char *path)
{
    const char *b = path;
    const char *p;

    for (p = path; *p != '\0'; p++)
        if (*p == '/' || *p == '\\')
            b = p + 1;
    return b;
}

int fs_has_suffix_ci(const char *s, const char *suffix)
{
    size_t ls = strlen(s);
    size_t lx = strlen(suffix);
    size_t i;

    if (lx > ls)
        return 0;
    for (i = 0; i < lx; i++)
        if (tolower((unsigned char)s[ls - lx + i]) != tolower((unsigned char)suffix[i]))
            return 0;
    return 1;
}
