#ifndef ADVISORY_H
#define ADVISORY_H

#include <stddef.h>

#include "version.h"

#define ADV_MAX_ALTS 8
#define ADV_MAX_CONSTRAINTS 4

typedef enum { OP_LT, OP_LE, OP_GT, OP_GE, OP_EQ } adv_op;

typedef struct {
    adv_op op;
    ver_t ver;
} adv_constraint;

typedef struct {
    int n;
    adv_constraint c[ADV_MAX_CONSTRAINTS]; /* all must hold */
} adv_alt;

typedef struct {
    char module[16];
    char product[32];
    char range_text[256];
    char fixed[192];
    char url[256];
    int any;    /* range was '*' */
    int n_alts; /* 0 with any==0 means not a version rule ('-') */
    adv_alt alt[ADV_MAX_ALTS]; /* affected if any alternative holds */
    int line;
} adv_entry;

typedef struct {
    adv_entry *e;
    size_t n;
    size_t cap;
} adv_list;

/* Parse one data line. Returns 0 ok, 1 blank/comment (nothing produced), -1 malformed
   (message written to err, if non-NULL). */
int adv_parse_line(const char *line, int lineno, adv_entry *out, char *err, size_t errlen);

/* Load a file. Malformed lines are reported on stderr, counted in *nerrors (may be NULL)
   and skipped. Returns 0, or -1 if the file cannot be read / out of memory. */
int adv_load(const char *path, adv_list *list, int *nerrors);

void adv_free(adv_list *list);

/* 1 = version is in the affected range, 0 = not, -1 = version string unparsable.
   Non-version rules ('-') never match. */
int adv_match(const adv_entry *e, const char *version);

#endif
