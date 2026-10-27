#ifndef WEBCHECK_H
#define WEBCHECK_H

#include <stddef.h>

/* Website security settings read from the response headers of one ordinary request.
   Pure functions: no network. */

#define WEB_MAX_CHECKS 12

/* levels, mildest first */
enum { WEB_OK = 0, WEB_NOTE, WEB_TIP, WEB_RECOMMENDED, WEB_IMPORTANT };

typedef struct {
    char id[20];      /* "hsts", "frame", ... (see web_check_info) */
    int level;
    char detail[200]; /* technical detail, e.g. the header value seen; never cookie values */
} web_check;

typedef struct {
    const char *id;
    const char *title_ok;  /* when the level is WEB_OK or WEB_NOTE */
    const char *title_bad; /* otherwise */
    const char *why;       /* plain language */
    const char *fix;       /* plain language, what to ask the host or developer for */
} web_info;

/* headers = the raw header block after the status line (stops at the first empty line).
   is_https = the request went over TLS. Returns the number of checks written (<= max). */
int web_check_headers(const char *headers, int is_https, int status, web_check *out, int max);

/* 1 if browsers force https for every name under host's top-level domain (whole-TLD HSTS
   preload). Then the https_redirect and hsts checks of that host cannot fail in practice;
   web_apply_preload() turns those results into passes with an explaining detail. */
int web_tld_preloaded(const char *host);
void web_apply_preload(const char *host, web_check *checks, int n);

/* Hosting platform recognised from one response (headers after the status line) and the host
   name, as an id such as "github-pages"; NULL when unknown. */
const char *web_detect_platform(const char *headers, const char *host);
const char *web_platform_name(const char *platform); /* "GitHub Pages"; the id if unknown */

/* Advice for check `id` that the owner can follow on `platform` (written to out). 1 written,
   0 when the general advice applies (unknown platform, or nothing platform-specific). */
int web_platform_fix(const char *platform, const char *id, char *out, size_t n);

/* Value of the first header called name (case-insensitive). 1 found, 0 not. */
int web_header_value(const char *headers, const char *name, char *out, size_t outlen);

const web_info *web_check_info(const char *id); /* NULL for an unknown id */
const char *web_level_name(int level);          /* "ok", "note", "tip", "recommended", "important" */

#endif
