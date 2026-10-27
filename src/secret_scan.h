#ifndef SECRET_SCAN_H
#define SECRET_SCAN_H

#include <stddef.h>
#include <stdio.h>

#define SECRET_MAX_HITS 10000

typedef struct {
    char path[512];
    int line;
    char rule[24];
    char masked[24]; /* "****" or "****abcd" (last 4 of values >= 12 chars); never the secret */
    int tracked;     /* gitidx_tracked() result */
} secret_hit;

typedef struct {
    secret_hit *h;
    size_t n;
    size_t cap;
    unsigned long files_scanned;
    unsigned long files_skipped;
    int truncated; /* hit limit reached */
} secret_report;

typedef struct {
    const char *rule;
    char masked[24];
} line_hit;

/* Match one line against all rules. Fills up to max hits, returns the count. */
int secret_scan_line(const char *line, line_hit *out, int max);

/* Walk root (skips node_modules, .git except .git/config, __pycache__, venvs, binaries,
   files over 1 MiB). 0 ok, -1 if root is not a directory or on out-of-memory. */
int secret_scan_dir(const char *root, secret_report *r);

void secret_report_print(const secret_report *r, FILE *out);
void secret_report_free(secret_report *r);

#endif
