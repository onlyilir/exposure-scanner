#ifndef VERSION_H
#define VERSION_H

#define VER_MAX_PARTS 8

typedef struct {
    unsigned long part[VER_MAX_PARTS];
    int count; /* number of numeric components parsed */
    int pre;   /* 1 if a pre-release tag (alpha/beta/rc/dev/pre) follows */
} ver_t;

/* Parse a dotted numeric version ("1.2.3", "v8.2.35", "1.0rc1").
   Trailing text that is not a pre-release tag (e.g. a distro revision such as
   "-1ubuntu2") is ignored. Returns 0 on success, -1 if there is no leading number,
   too many components, or a component overflows. */
int ver_parse(const char *s, ver_t *out);

/* Numeric, component-wise compare; missing components count as 0 and a
   pre-release sorts below the same release. Returns <0, 0 or >0. */
int ver_cmp(const ver_t *a, const ver_t *b);

#endif
