#include "version.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

static int has_prefix_ci(const char *s, const char *prefix)
{
    while (*prefix) {
        if (tolower((unsigned char)*s) != *prefix)
            return 0;
        s++;
        prefix++;
    }
    return 1;
}

int ver_parse(const char *s, ver_t *out)
{
    const char *t;

    memset(out, 0, sizeof *out);
    if (s == NULL)
        return -1;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == 'v' || *s == 'V')
        s++;
    if (!isdigit((unsigned char)*s))
        return -1;

    for (;;) {
        unsigned long v = 0;

        if (out->count >= VER_MAX_PARTS)
            return -1;
        while (isdigit((unsigned char)*s)) {
            unsigned long d = (unsigned long)(*s - '0');
            if (v > (ULONG_MAX - d) / 10)
                return -1;
            v = v * 10 + d;
            s++;
        }
        out->part[out->count++] = v;
        if (*s == '.' && isdigit((unsigned char)s[1])) {
            s++;
            continue;
        }
        break;
    }

    t = s;
    if (*t == '-' || *t == '~' || *t == '_' || *t == '.')
        t++;
    if (has_prefix_ci(t, "alpha") || has_prefix_ci(t, "beta") ||
        has_prefix_ci(t, "rc") || has_prefix_ci(t, "dev") ||
        has_prefix_ci(t, "pre"))
        out->pre = 1;
    else if ((tolower((unsigned char)t[0]) == 'a' || tolower((unsigned char)t[0]) == 'b') &&
             isdigit((unsigned char)t[1]))
        out->pre = 1;
    return 0;
}

int ver_cmp(const ver_t *a, const ver_t *b)
{
    int i;
    int n = a->count > b->count ? a->count : b->count;

    for (i = 0; i < n; i++) {
        unsigned long x = i < a->count ? a->part[i] : 0;
        unsigned long y = i < b->count ? b->part[i] : 0;
        if (x != y)
            return x < y ? -1 : 1;
    }
    if (a->pre != b->pre)
        return a->pre ? -1 : 1;
    return 0;
}
