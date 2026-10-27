#ifndef PYSUPPLY_H
#define PYSUPPLY_H

#include <stddef.h>
#include <stdio.h>

#include "advisory.h"

typedef struct {
    int severity;     /* 2 = installed/confirmed match, 1 = pinned in a file or heuristic */
    char kind[20];    /* installed-package, locked-package, pth-suspicious, ioc-file */
    char path[512];
    int line;         /* 0 when not applicable */
    char name[64];
    char version[40];
    char detail[200];
} py_finding;

typedef struct {
    py_finding *f;
    size_t n;
    size_t cap;
    unsigned long packages_seen;   /* installed dist-info/egg-info entries */
    unsigned long pinned_seen;     /* name==version pins read from requirements/lock files */
    unsigned long pth_import_seen; /* benign-looking .pth import lines (not listed) */
} py_report;

/* Walk root for site-packages contents and requirements/poetry.lock/uv.lock files and check
   them against the "py"/"pyioc" rules in adv. 0 ok, -1 root not a directory / out of memory. */
int py_scan(const char *root, const adv_list *adv, py_report *r);

void py_report_print(const py_report *r, FILE *out);
void py_report_free(py_report *r);

/* Exposed for tests. */
void py_normalize_name(const char *in, char *out, size_t n); /* lowercase, [_.-]+ -> '-' */
/* "name==1.2.3" (extras and markers allowed). 1 parsed, 0 not a pin. */
int py_parse_requirement_line(const char *line, char *name, size_t nn, char *ver, size_t vn);
/* .pth line: 0 plain path/comment, 1 'import' line, 2 'import' line with exec/network markers. */
int py_pth_line_class(const char *line);

#endif
