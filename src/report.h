#ifndef REPORT_H
#define REPORT_H

#include <stddef.h>
#include <stdio.h>

#include "http_probe.h"
#include "pysupply.h"
#include "secret_scan.h"
#include "tls_audit.h"

#define SCANNER_VERSION "0.7.0"

/* Results of one CLI run. A module that did not run has run_* == 0 (or n == 0 for the
   network lists). *_error marks a module that ran but could not finish (e.g. out of memory). */
typedef struct {
    const char *root; /* directory given to secrets/py, NULL if neither ran */
    int run_secrets, secrets_error;
    secret_report secrets;
    int run_py, py_error;
    py_report py;
    probe_result *http; /* nhttp entries, owned by the report */
    size_t nhttp;
    tls_result *tls; /* ntls entries, owned by the report */
    size_t ntls;
} scan_report;

/* Per-module exit codes (0 clean, 1 findings, 2 error/no result); -1 when the module did
   not run. http/tls: 1 if any target has a finding, 2 only if every target failed. */
int report_rc_secrets(const scan_report *r);
int report_rc_py(const scan_report *r);
int report_rc_http(const scan_report *r);
int report_rc_tls(const scan_report *r);
/* Whole run: 1 if any module has findings, else 2 if any module failed, else 0. */
int report_exit_code(const scan_report *r);

/* Certificate flags that count as a finding (blocklisted, advisory issuer, expired). */
int report_tls_cert_flagged(const tls_cert_info *c);
unsigned long report_count_findings(const scan_report *r);

/* Human-readable output: each module's own printer under a header, then a summary. */
void report_print_text(const scan_report *r, FILE *out);

/* One JSON object for the whole run (UTF-8; invalid bytes become U+FFFD). Secret values
   are never included: only the masked form the scanner already keeps. */
void report_print_json(const scan_report *r, const char *command, FILE *out);

/* JSON string literal with quotes. Exposed for tests. */
void report_json_string(FILE *out, const char *s);

/* Website settings across all http results at exactly this level (WEB_TIP and up). */
unsigned long report_count_settings(const scan_report *r, int level);

/* Length of the valid UTF-8 sequence at s (1-4), 0 if invalid. Never reads past a NUL. */
int report_utf8_len(const unsigned char *s);

/* Client-facing HTML report (report_html.c). */
typedef struct {
    const char *client; /* shown as the title; may be NULL */
    const char *by;     /* "Prepared by ..."; may be NULL */
    const char *date;   /* e.g. "23 October 2026" */
} report_meta;

/* Self-contained page (no external files), prints to PDF from a browser. Returns the number of
   operator warnings shown at the top ("not ready to send": local HTTPS inspection, targets
   that failed, unfinished scans); 0 means the report is ready to hand over. */
int report_write_html(const scan_report *r, const report_meta *m, FILE *out);

/* The same verdict the HTML report shows, for the JSON "summary" (the desktop app reads it). */
#define SUMMARY_MAX_ITEMS 40
typedef struct {
    int level; /* WEB_TIP .. WEB_IMPORTANT */
    char site[128];
    char title[200];
    char fix[360];
    char detail[300]; /* where / technical detail, e.g. "src/a.c, line 3, value ****abcd" */
} summary_item;

typedef struct {
    unsigned long count[WEB_IMPORTANT + 1]; /* items per level; [WEB_OK] = passed */
    int warnings;                           /* > 0 means "not ready to send" */
    int intercepted, failed_targets, unfinished;
    summary_item items[SUMMARY_MAX_ITEMS];  /* issues, worst first */
    int nitems;
} report_summary;

void report_summarize(const scan_report *r, report_summary *s);

void report_free(scan_report *r);

#endif
