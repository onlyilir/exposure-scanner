#ifndef VERSION_H
#define VERSION_H

#define VER_MAX_PARTS 8

typedef struct {
    unsigned long part[VER_MAX_PARTS];
    int count; /* number of numeric components parsed */
    int pre;   /* 1 if a pre-release tag (alpha/beta/rc/dev/pre/canary) follows */
    unsigned long post; /* Magento-style patch release: "2.4.7-p3" -> 3, else 0 */
} ver_t;

/* Parse a dotted numeric version ("1.2.3", "v8.2.35", "1.0rc1").
   Trailing text that is not a pre-release tag (e.g. a distro revision such as
   "-1ubuntu2") is ignored. Returns 0 on success, -1 if there is no leading number,
   too many components, or a component overflows. */
int ver_parse(const char *s, ver_t *out);

/* Numeric, component-wise compare; missing components count as 0 and a
   pre-release sorts below the same release, a "-pN" patch release above it. Returns <0, 0 or >0. */
int ver_cmp(const ver_t *a, const ver_t *b);

#endif
