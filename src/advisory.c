#include "advisory.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 1024

static int set_err(char *err, size_t errlen, const char *msg)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "%s", msg);
    return -1;
}

/* Copy src (trimmed) into dst; -1 if it would not fit. */
static int copy_trim(char *dst, size_t dstlen, const char *src)
{
    size_t len;

    while (isspace((unsigned char)*src))
        src++;
    len = strlen(src);
    while (len > 0 && isspace((unsigned char)src[len - 1]))
        len--;
    if (len >= dstlen)
        return -1;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return 0;
}

static int parse_constraint(const char *tok, adv_constraint *c)
{
    const char *v;

    if (tok[0] == '>' && tok[1] == '=') { c->op = OP_GE; v = tok + 2; }
    else if (tok[0] == '<' && tok[1] == '=') { c->op = OP_LE; v = tok + 2; }
    else if (tok[0] == '=' && tok[1] == '=') { c->op = OP_EQ; v = tok + 2; }
    else if (tok[0] == '>') { c->op = OP_GT; v = tok + 1; }
    else if (tok[0] == '<') { c->op = OP_LT; v = tok + 1; }
    else if (tok[0] == '=') { c->op = OP_EQ; v = tok + 1; }
    else return -1;
    return ver_parse(v, &c->ver);
}

static int parse_alt(const char *text, adv_alt *alt)
{
    char buf[128];
    char *tok;

    memset(alt, 0, sizeof *alt);
    if (copy_trim(buf, sizeof buf, text) != 0 || buf[0] == '\0')
        return -1;
    for (tok = buf; *tok != '\0';) {
        char *end;

        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok == '\0')
            break;
        end = tok;
        while (*end != '\0' && *end != ' ' && *end != '\t')
            end++;
        if (*end != '\0')
            *end++ = '\0';
        if (alt->n >= ADV_MAX_CONSTRAINTS)
            return -1;
        if (parse_constraint(tok, &alt->c[alt->n]) != 0)
            return -1;
        alt->n++;
        tok = end;
    }
    return alt->n > 0 ? 0 : -1;
}

static int parse_range(const char *text, adv_entry *e)
{
    char buf[sizeof e->range_text];
    char *p;

    e->any = 0;
    e->n_alts = 0;
    if (strcmp(text, "*") == 0) {
        e->any = 1;
        return 0;
    }
    if (strcmp(text, "-") == 0)
        return 0;
    if (copy_trim(buf, sizeof buf, text) != 0)
        return -1;
    p = buf;
    for (;;) {
        char *semi = strchr(p, ';');

        if (semi != NULL)
            *semi = '\0';
        if (e->n_alts >= ADV_MAX_ALTS)
            return -1;
        if (parse_alt(p, &e->alt[e->n_alts]) != 0)
            return -1;
        e->n_alts++;
        if (semi == NULL)
            break;
        p = semi + 1;
    }
    return 0;
}

int adv_parse_line(const char *line, int lineno, adv_entry *out, char *err, size_t errlen)
{
    char buf[LINE_MAX_LEN];
    char *field[5];
    char *p;
    int nf = 0;

    while (isspace((unsigned char)*line))
        line++;
    if (*line == '\0' || *line == '#')
        return 1;
    if (strlen(line) >= sizeof buf)
        return set_err(err, errlen, "line too long");
    memcpy(buf, line, strlen(line) + 1);

    p = buf;
    field[nf++] = p;
    while ((p = strchr(p, '|')) != NULL) {
        *p++ = '\0';
        if (nf >= 5)
            return set_err(err, errlen, "too many fields (need exactly 5)");
        field[nf++] = p;
    }
    if (nf != 5)
        return set_err(err, errlen, "wrong field count (need exactly 5)");

    memset(out, 0, sizeof *out);
    out->line = lineno;
    if (copy_trim(out->module, sizeof out->module, field[0]) != 0 || out->module[0] == '\0')
        return set_err(err, errlen, "bad module");
    if (copy_trim(out->product, sizeof out->product, field[1]) != 0 || out->product[0] == '\0')
        return set_err(err, errlen, "bad product");
    if (copy_trim(out->range_text, sizeof out->range_text, field[2]) != 0 ||
        out->range_text[0] == '\0')
        return set_err(err, errlen, "bad range");
    if (copy_trim(out->fixed, sizeof out->fixed, field[3]) != 0)
        return set_err(err, errlen, "fixed-in too long");
    if (copy_trim(out->url, sizeof out->url, field[4]) != 0)
        return set_err(err, errlen, "url too long");
    if (parse_range(out->range_text, out) != 0)
        return set_err(err, errlen, "unparsable range");
    return 0;
}

static int list_push(adv_list *l, const adv_entry *e)
{
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 16;
        adv_entry *ne = realloc(l->e, ncap * sizeof *ne);

        if (ne == NULL)
            return -1;
        l->e = ne;
        l->cap = ncap;
    }
    l->e[l->n++] = *e;
    return 0;
}

int adv_load(const char *path, adv_list *list, int *nerrors)
{
    FILE *f;
    char line[LINE_MAX_LEN];
    int lineno = 0;
    int skipping = 0; /* inside an over-long line */

    if (nerrors != NULL)
        *nerrors = 0;
    f = fopen(path, "r");
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f) != NULL) {
        size_t len = strlen(line);
        int complete = len > 0 && line[len - 1] == '\n';
        adv_entry e;
        char err[64];
        int rc;

        if (skipping) {
            skipping = !complete;
            continue;
        }
        lineno++;
        if (!complete && !feof(f)) {
            fprintf(stderr, "%s:%d: line too long, skipped\n", path, lineno);
            if (nerrors != NULL)
                (*nerrors)++;
            skipping = 1;
            continue;
        }
        rc = adv_parse_line(line, lineno, &e, err, sizeof err);
        if (rc == 1)
            continue;
        if (rc != 0) {
            fprintf(stderr, "%s:%d: %s\n", path, lineno, err);
            if (nerrors != NULL)
                (*nerrors)++;
            continue;
        }
        if (list_push(list, &e) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

void adv_free(adv_list *list)
{
    free(list->e);
    list->e = NULL;
    list->n = 0;
    list->cap = 0;
}

static int constraint_holds(const adv_constraint *c, const ver_t *v)
{
    int r = ver_cmp(v, &c->ver);

    switch (c->op) {
    case OP_LT: return r < 0;
    case OP_LE: return r <= 0;
    case OP_GT: return r > 0;
    case OP_GE: return r >= 0;
    case OP_EQ: return r == 0;
    }
    return 0;
}

int adv_match(const adv_entry *e, const char *version)
{
    ver_t v;
    int a, i;

    if (ver_parse(version, &v) != 0)
        return -1;
    if (e->any)
        return 1;
    for (a = 0; a < e->n_alts; a++) {
        int ok = 1;

        for (i = 0; i < e->alt[a].n; i++) {
            if (!constraint_holds(&e->alt[a].c[i], &v)) {
                ok = 0;
                break;
            }
        }
        if (ok)
            return 1;
    }
    return 0;
}
