#ifndef HTTP_PROBE_H
#define HTTP_PROBE_H

#include <stddef.h>
#include <stdio.h>

#include "advisory.h"
#include "webcheck.h"

#define PROBE_MAX_TARGETS 64
#define PROBE_MAX_THREADS 16
#define PROBE_MAX_TOKENS 8
#define PROBE_MAX_HITS 8

typedef struct {
    char host[128];
    unsigned short port;
    int tls;
} probe_target;

typedef struct {
    char product[32]; /* lowercase, e.g. "nginx" */
    char version[40];
    char source[16];  /* "Server" or "X-Powered-By" */
} banner_tok;

typedef struct {
    char product[32];
    char version[40];
    char source[16];
    char fixed[192];
    char url[256];
} probe_hit;

typedef struct {
    probe_target t;
    int connected;
    int status; /* HTTP status code, 0 if none */
    char error[96];
    char server[128];
    char powered_by[128];
    char location[256]; /* Location header of a redirect, if any */
    char via[160];      /* "http://host:port" when this probe followed that target's redirect */
    char platform[24];  /* hosting platform id (web_detect_platform), "" if not recognised */
    probe_hit hit[PROBE_MAX_HITS];
    int nhit;
    web_check web[WEB_MAX_CHECKS]; /* security settings read from the response headers */
    int nweb;
} probe_result;

typedef struct {
    int timeout_ms; /* per connect/read, default 5000 */
    int rate_ms;    /* minimum gap between request starts across all threads, default 200 */
    int threads;    /* default 8, max PROBE_MAX_THREADS */
} probe_opts;

/* "host", "host:port", "http://host[:port][/path]", "https://...", "[v6]:port".
   0 ok, -1 invalid. */
int probe_parse_target(const char *arg, probe_target *t);

/* Extract "name/version" tokens from the Server and X-Powered-By headers of a raw header
   block. Returns the count (<= max). */
int http_parse_banners(const char *headers, banner_tok *out, int max);

/* One request. Always fills res; returns 0 when a response was parsed. */
int probe_one(const probe_target *t, const probe_opts *o, const adv_list *adv, probe_result *res);

/* Probe n targets with a bounded thread pool and a shared rate limit. res must hold n
   entries. Returns 0, or -1 for invalid arguments (n > PROBE_MAX_TARGETS). */
int probe_run(const probe_target *t, size_t n, const probe_opts *o, const adv_list *adv,
              probe_result *res);

/* If r is a redirect to https:// on the same host or its www./bare twin, store that target in
   *out and return 1 (so the caller can check the page visitors actually land on). Redirects to
   other hosts are never followed: they may not be covered by the owner's permission. */
int probe_redirect_target(const probe_result *r, probe_target *out);

void probe_print(const probe_result *r, FILE *out);

#endif
