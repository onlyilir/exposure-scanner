/* Exposure scanner CLI: secrets, py, http, tls, site and all, with text, --json or an --html
   client report. Defensive and read-only: it never exploits, brute-forces or modifies anything.
   Network modules only send ordinary requests (a HEAD request / a TLS handshake) and must only
   be pointed at hosts you own or are explicitly authorized to test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "advisory.h"
#include "fsutil.h"
#include "http_probe.h"
#include "net_compat.h"
#include "pysupply.h"
#include "report.h"
#include "secret_scan.h"
#include "tls_audit.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define DEFAULT_ADV "advisories.txt"
#define DEFAULT_BLOCKLIST "spki_blocklist.txt"

/* data/<name> under the current folder (the project), else next to scanner.exe (an installed
   copy runs from any folder). Returns buf. */
static const char *data_file(const char *name, char *buf, size_t n)
{
    snprintf(buf, n, "data/%s", name);
#ifdef _WIN32
    if (!fs_is_file(buf, NULL)) {
        char exe[MAX_PATH];
        DWORD len = GetModuleFileNameA(NULL, exe, sizeof exe);
        char *slash;

        if (len > 0 && len < sizeof exe && (slash = strrchr(exe, '\\')) != NULL) {
            *slash = '\0';
            snprintf(buf, n, "%s\\data\\%s", exe, name);
        }
    }
#endif
    return buf;
}
#define MAX_TLS_TARGETS 16

/* option groups a command accepts */
#define O_JSON 1u
#define O_ADV 2u
#define O_NET 4u     /* --rate --threads */
#define O_TIMEOUT 8u
#define O_TLS 16u    /* --spki-blocklist --ca-file */
#define O_OWN 32u
#define O_TARGETS 64u /* --http --tls --site (all) */
#define O_HTML 128u   /* --html --client --by */

enum { CMD_SECRETS, CMD_PY, CMD_HTTP, CMD_TLS, CMD_SITE, CMD_ALL };

static const struct {
    const char *name;
    int cmd;
    unsigned opts;
} commands[] = {
    {"secrets", CMD_SECRETS, O_JSON | O_HTML},
    {"py", CMD_PY, O_JSON | O_HTML | O_ADV},
    {"http", CMD_HTTP, O_JSON | O_HTML | O_ADV | O_NET | O_TIMEOUT | O_OWN},
    {"tls", CMD_TLS, O_JSON | O_HTML | O_ADV | O_TIMEOUT | O_TLS | O_OWN},
    {"site", CMD_SITE, O_JSON | O_HTML | O_ADV | O_NET | O_TIMEOUT | O_TLS | O_OWN},
    {"all", CMD_ALL, O_JSON | O_HTML | O_ADV | O_NET | O_TIMEOUT | O_TLS | O_OWN | O_TARGETS},
};

typedef struct {
    int cmd;
    unsigned opts;
    const char *dir, *adv_path, *bl_path, *ca;
    const char *html_path, *client, *by;
    probe_target http[PROBE_MAX_TARGETS];
    size_t nhttp;
    probe_target tls[MAX_TLS_TARGETS];
    size_t ntls;
    probe_opts po;
    int owned, json;
} cli_args;

static void usage(void)
{
    fprintf(stderr,
            "Usage:\n"
            "  scanner site <domain>... --i-own-this [--html report.html --client \"Name\"\n"
            "                --by \"Your name\"]\n"
            "  scanner secrets <dir>\n"
            "  scanner py <dir> [--advisories <file>]\n"
            "  scanner http <target>... --i-own-this [--rate ms] [--threads n] [--timeout ms]\n"
            "  scanner tls <host[:port]> --i-own-this [--spki-blocklist <file>]\n"
            "                [--ca-file <file>] [--timeout ms]\n"
            "  scanner all [<dir>] [--site <domain>]... [--http <target>]...\n"
            "                [--tls <host[:port]>]... [--i-own-this] [any option above]\n"
            "Every command also takes --json, and --html <file> [--client ..] [--by ..].\n"
            "\n"
            "`site` checks one website: http:// and https:// (HTTPS redirect, security headers,\n"
            "software versions) plus its certificate. A redirect to the same site (www. or not)\n"
            "is followed once; redirects to other hosts are never followed.\n"
            "\n"
            "Read-only and defensive. Network commands send ordinary requests only; use them\n"
            "ONLY on hosts you own or are authorized to test. Every network check (`site`,\n"
            "`http`, `tls`, `all` with targets) needs --i-own-this to confirm that. Targets:\n"
            "host, host:port,\n"
            "http://host, https://host (tls: a bare host means port 443).\n"
            "Banner versions are weak evidence (hidden/faked headers, distro back-ports).\n"
            "Secret values are never printed. Exit: 0 clean, 1 findings, 2 error.\n");
}

static int parse_int_opt(const char *s, int lo, int hi, int *out)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (s[0] == '\0' || *end != '\0' || v < lo || v > hi)
        return -1;
    *out = (int)v;
    return 0;
}

static int same_target(const probe_target *a, const probe_target *b)
{
    return a->port == b->port && a->tls == b->tls && strcasecmp(a->host, b->host) == 0;
}

static int add_http_t(cli_args *c, const probe_target *t)
{
    size_t i;

    for (i = 0; i < c->nhttp; i++)
        if (same_target(&c->http[i], t))
            return 0; /* already listed */
    if (c->nhttp >= PROBE_MAX_TARGETS) {
        fprintf(stderr, "error: at most %d http targets per run\n", PROBE_MAX_TARGETS);
        return -1;
    }
    c->http[c->nhttp++] = *t;
    return 0;
}

static int add_http(cli_args *c, const char *arg)
{
    probe_target t;

    if (probe_parse_target(arg, &t) != 0) {
        fprintf(stderr, "error: invalid target '%s'\n", arg);
        return -1;
    }
    return add_http_t(c, &t);
}

static int add_tls(cli_args *c, const char *arg)
{
    char spec[200];
    probe_target t;
    size_t i;

    /* default to https so that a bare host means port 443 */
    if (strstr(arg, "://") == NULL)
        snprintf(spec, sizeof spec, "https://%s", arg);
    else
        snprintf(spec, sizeof spec, "%s", arg);
    if (probe_parse_target(spec, &t) != 0) {
        fprintf(stderr, "error: invalid target '%s'\n", arg);
        return -1;
    }
    for (i = 0; i < c->ntls; i++)
        if (same_target(&c->tls[i], &t))
            return 0;
    if (c->ntls >= MAX_TLS_TARGETS) {
        fprintf(stderr, "error: at most %d tls targets per run\n", MAX_TLS_TARGETS);
        return -1;
    }
    c->tls[c->ntls++] = t;
    return 0;
}

/* "host:port", with brackets for IPv6, as add_tls expects */
static void host_port(char *out, size_t n, const probe_target *t)
{
    if (strchr(t->host, ':') != NULL)
        snprintf(out, n, "[%s]:%u", t->host, (unsigned)t->port);
    else
        snprintf(out, n, "%s:%u", t->host, (unsigned)t->port);
}

/* A website: http://host and https://host[:port] plus the certificate of host[:port]. */
static int add_site(cli_args *c, const char *arg)
{
    char spec[200], tspec[160];
    probe_target t;

    if (strstr(arg, "://") == NULL)
        snprintf(spec, sizeof spec, "https://%s", arg);
    else
        snprintf(spec, sizeof spec, "%s", arg);
    if (probe_parse_target(spec, &t) != 0) {
        fprintf(stderr, "error: invalid site '%s'\n", arg);
        return -1;
    }
    if (!t.tls) { /* http://host given: still check its https side on 443 */
        t.tls = 1;
        t.port = 443;
    }
    host_port(tspec, sizeof tspec, &t);
    if (add_http_t(c, &t) != 0 || add_tls(c, tspec) != 0)
        return -1;
    t.tls = 0;
    t.port = 80;
    return add_http_t(c, &t);
}

/* Value-taking option: returns its value and advances *a, or NULL if the command does not
   accept it or the value is missing. */
static const char *opt_val(const cli_args *c, int argc, char **argv, int *a, const char *name,
                           unsigned group)
{
    if (strcmp(argv[*a], name) != 0 || !(c->opts & group) || *a + 1 >= argc)
        return NULL;
    return argv[++*a];
}

/* 0 ok, -1 error (message printed). */
static int parse_args(int argc, char **argv, cli_args *c)
{
    const char *v;
    int a;

    for (a = 2; a < argc; a++) {
        const char *s = argv[a];

        if (strcmp(s, "--json") == 0 && (c->opts & O_JSON)) {
            c->json = 1;
        } else if (strcmp(s, "--i-own-this") == 0 && (c->opts & O_OWN)) {
            c->owned = 1;
        } else if ((v = opt_val(c, argc, argv, &a, "--advisories", O_ADV)) != NULL) {
            c->adv_path = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--rate", O_NET)) != NULL) {
            if (parse_int_opt(v, 0, 60000, &c->po.rate_ms) != 0) {
                fprintf(stderr, "error: bad --rate\n");
                return -1;
            }
        } else if ((v = opt_val(c, argc, argv, &a, "--threads", O_NET)) != NULL) {
            if (parse_int_opt(v, 1, PROBE_MAX_THREADS, &c->po.threads) != 0) {
                fprintf(stderr, "error: bad --threads (1-%d)\n", PROBE_MAX_THREADS);
                return -1;
            }
        } else if ((v = opt_val(c, argc, argv, &a, "--timeout", O_TIMEOUT)) != NULL) {
            if (parse_int_opt(v, 100, 60000, &c->po.timeout_ms) != 0) {
                fprintf(stderr, "error: bad --timeout\n");
                return -1;
            }
        } else if ((v = opt_val(c, argc, argv, &a, "--spki-blocklist", O_TLS)) != NULL) {
            c->bl_path = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--ca-file", O_TLS)) != NULL) {
            c->ca = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--html", O_HTML)) != NULL) {
            c->html_path = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--client", O_HTML)) != NULL) {
            c->client = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--by", O_HTML)) != NULL) {
            c->by = v;
        } else if ((v = opt_val(c, argc, argv, &a, "--http", O_TARGETS)) != NULL) {
            if (add_http(c, v) != 0)
                return -1;
        } else if ((v = opt_val(c, argc, argv, &a, "--tls", O_TARGETS)) != NULL) {
            if (add_tls(c, v) != 0)
                return -1;
        } else if ((v = opt_val(c, argc, argv, &a, "--site", O_TARGETS)) != NULL) {
            if (add_site(c, v) != 0)
                return -1;
        } else if (s[0] == '-') {
            fprintf(stderr, "error: unknown option, or missing value, for '%s %s'\n", argv[1],
                    s);
            return -1;
        } else if (c->cmd == CMD_HTTP) {
            if (add_http(c, s) != 0)
                return -1;
        } else if (c->cmd == CMD_SITE) {
            if (add_site(c, s) != 0)
                return -1;
        } else if (c->cmd == CMD_TLS) {
            if (c->ntls > 0) {
                fprintf(stderr, "error: tls takes one target (use `all --tls` for more)\n");
                return -1;
            }
            if (add_tls(c, s) != 0)
                return -1;
        } else {
            if (c->dir != NULL) {
                fprintf(stderr, "error: unexpected argument '%s'\n", s);
                return -1;
            }
            c->dir = s;
        }
    }
    return 0;
}

static int load_adv(const char *path, adv_list *adv)
{
    int nerr = 0;

    if (adv_load(path, adv, &nerr) != 0) {
        fprintf(stderr, "error: cannot read advisories file '%s'\n", path);
        return -1;
    }
    if (nerr > 0)
        fprintf(stderr, "warning: %d malformed advisory line(s) skipped\n", nerr);
    return 0;
}

static int load_blocklist(const char *path, spki_blocklist *bl)
{
    if (path != NULL) {
        if (spki_blocklist_load(path, bl) != 0) {
            fprintf(stderr, "error: cannot read blocklist '%s'\n", path);
            return -1;
        }
    } else {
        char def[600];

        if (spki_blocklist_load(data_file(DEFAULT_BLOCKLIST, def, sizeof def), bl) != 0)
            fprintf(stderr, "note: no SPKI blocklist at %s; only issuer-name rules are applied\n",
                    def);
    }
    return 0;
}

/* Follow same-site https redirects once, so the page settings come from the address visitors
   land on. New https hosts also get a certificate check when their origin host had one. */
static int follow_redirects(cli_args *c, const adv_list *adv, scan_report *rep)
{
    probe_target extra[PROBE_MAX_TARGETS];
    char via[PROBE_MAX_TARGETS][160];
    size_t n0 = rep->nhttp, nextra = 0, i, j;
    probe_result *grown;

    for (i = 0; i < n0 && c->nhttp + nextra < PROBE_MAX_TARGETS; i++) {
        probe_target t;
        int dup = 0;

        if (!probe_redirect_target(&rep->http[i], &t))
            continue;
        for (j = 0; j < c->nhttp && !dup; j++)
            dup = same_target(&c->http[j], &t);
        for (j = 0; j < nextra && !dup; j++)
            dup = same_target(&extra[j], &t);
        if (dup)
            continue;
        snprintf(via[nextra], sizeof via[nextra], "%s://%s:%u", rep->http[i].t.tls ? "https" : "http",
                 rep->http[i].t.host, (unsigned)rep->http[i].t.port);
        extra[nextra++] = t;
        for (j = 0; j < c->ntls; j++)
            if (strcasecmp(c->tls[j].host, rep->http[i].t.host) == 0) {
                char spec[160];

                host_port(spec, sizeof spec, &t);
                if (add_tls(c, spec) != 0)
                    fprintf(stderr, "note: certificate of %s not checked (target limit)\n",
                            t.host);
                break;
            }
    }
    if (nextra == 0)
        return 0;
    grown = realloc(rep->http, (n0 + nextra) * sizeof *grown);
    if (grown == NULL)
        return -1;
    rep->http = grown;
    memset(rep->http + n0, 0, nextra * sizeof *grown);
    if (probe_run(extra, nextra, &c->po, adv, rep->http + n0) != 0)
        return -1;
    for (i = 0; i < nextra; i++) {
        memcpy(rep->http[n0 + i].via, via[i], sizeof rep->http[n0 + i].via); /* same size */
        c->http[c->nhttp++] = extra[i];
    }
    rep->nhttp = n0 + nextra;
    return 0;
}

/* Runs the modules the arguments ask for. 0 ok, -1 out of memory. */
static int run(cli_args *c, const adv_list *adv, const spki_blocklist *bl, scan_report *rep)
{
    size_t i;

    if (c->dir != NULL && (c->cmd == CMD_SECRETS || c->cmd == CMD_ALL)) {
        rep->root = c->dir;
        rep->run_secrets = 1;
        rep->secrets_error = secret_scan_dir(c->dir, &rep->secrets) != 0;
    }
    if (c->dir != NULL && (c->cmd == CMD_PY || c->cmd == CMD_ALL)) {
        rep->root = c->dir;
        rep->run_py = 1;
        rep->py_error = py_scan(c->dir, adv, &rep->py) != 0;
    }
    if (c->nhttp > 0) {
        rep->http = calloc(c->nhttp, sizeof *rep->http);
        if (rep->http == NULL)
            return -1;
        rep->nhttp = c->nhttp;
        if (probe_run(c->http, c->nhttp, &c->po, adv, rep->http) != 0)
            return -1;
        if ((c->cmd == CMD_SITE || c->cmd == CMD_ALL) && follow_redirects(c, adv, rep) != 0)
            return -1;
    }
    if (c->ntls > 0) {
        rep->tls = calloc(c->ntls, sizeof *rep->tls);
        if (rep->tls == NULL)
            return -1;
        rep->ntls = c->ntls;
        for (i = 0; i < c->ntls; i++)
            tls_audit_host(c->tls[i].host, c->tls[i].port, c->po.timeout_ms, c->ca, adv, bl,
                           &rep->tls[i]); /* failures are recorded in the result */
    }
    return 0;
}

#ifdef _WIN32
/* Windows hands argv over in the ANSI code page (e.g. 0xEB for "ë"); the report is UTF-8.
   Returns a malloc'd UTF-8 copy, or NULL on failure (the caller keeps the original). */
static char *acp_to_utf8(const char *s)
{
    int wn = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0), n;
    wchar_t *w;
    char *u = NULL;

    if (wn <= 0 || (w = malloc((size_t)wn * sizeof *w)) == NULL)
        return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, wn);
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n > 0 && (u = malloc((size_t)n)) != NULL)
        WideCharToMultiByte(CP_UTF8, 0, w, -1, u, n, NULL, NULL);
    free(w);
    return u;
}
#endif

static int write_html(const scan_report *rep, const cli_args *c)
{
    char date[40];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    report_meta meta;
    FILE *f;
    int warnings;

    if (tm == NULL || strftime(date, sizeof date, "%d %B %Y", tm) == 0)
        snprintf(date, sizeof date, "(date unknown)");
    meta.client = c->client;
    meta.by = c->by;
    meta.date = date[0] == '0' ? date + 1 : date; /* "3 May", not "03 May" */
#ifdef _WIN32
    {
        char *client = c->client != NULL ? acp_to_utf8(c->client) : NULL;
        char *by = c->by != NULL ? acp_to_utf8(c->by) : NULL;

        if (client != NULL)
            meta.client = client;
        if (by != NULL)
            meta.by = by;
        f = fopen(c->html_path, "wb");
        warnings = f != NULL ? report_write_html(rep, &meta, f) : 0;
        free(client);
        free(by);
    }
#else
    f = fopen(c->html_path, "wb");
    warnings = f != NULL ? report_write_html(rep, &meta, f) : 0;
#endif
    if (f == NULL) {
        fprintf(stderr, "error: cannot write '%s'\n", c->html_path);
        return -1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "error: cannot write '%s'\n", c->html_path);
        return -1;
    }
    if (warnings > 0)
        fprintf(stderr, "report written to %s, but it is NOT ready to send: see the red box at "
                        "the top.\n",
                c->html_path);
    else
        fprintf(stderr, "report written to %s\n", c->html_path);
    return 0;
}

int main(int argc, char **argv)
{
    static cli_args c; /* large: keep it off the stack */
    static char adv_default[600];
    adv_list adv = {0};
    spki_blocklist bl = {0};
    scan_report rep;
    size_t i;
    int rc;

    memset(&c, 0, sizeof c);
    c.cmd = -1;
    for (i = 0; argc >= 2 && i < sizeof commands / sizeof commands[0]; i++)
        if (strcmp(argv[1], commands[i].name) == 0) {
            c.cmd = commands[i].cmd;
            c.opts = commands[i].opts;
        }
    if (c.cmd < 0) {
        usage();
        return 2;
    }
    c.adv_path = data_file(DEFAULT_ADV, adv_default, sizeof adv_default);
    c.po.timeout_ms = 5000;
    c.po.rate_ms = 200;
    c.po.threads = 8;
    if (parse_args(argc, argv, &c) != 0)
        return 2;

    if ((c.cmd == CMD_SECRETS || c.cmd == CMD_PY) && c.dir == NULL) {
        usage();
        return 2;
    }
    if (c.cmd == CMD_ALL && c.dir == NULL && c.nhttp + c.ntls == 0) {
        usage();
        return 2;
    }
    if ((c.cmd == CMD_HTTP || c.cmd == CMD_SITE) && c.nhttp == 0) {
        usage();
        return 2;
    }
    if (c.cmd == CMD_TLS && c.ntls == 0) {
        usage();
        return 2;
    }
    if ((c.client != NULL || c.by != NULL) && c.html_path == NULL) {
        fprintf(stderr, "error: --client and --by only apply to --html reports\n");
        return 2;
    }
    if (c.dir != NULL && !fs_is_dir(c.dir)) {
        fprintf(stderr, "error: '%s' is not a directory\n", c.dir);
        return 2;
    }
    if ((c.cmd == CMD_HTTP || c.cmd == CMD_SITE || c.cmd == CMD_TLS ||
         (c.cmd == CMD_ALL && c.nhttp + c.ntls > 0)) &&
        !c.owned) {
        fprintf(stderr,
                "refusing to run: pass --i-own-this to confirm you own these hosts or are "
                "authorized to test them.\n");
        return 2;
    }
    if (c.cmd != CMD_SECRETS && load_adv(c.adv_path, &adv) != 0)
        return 2;
    if (c.ntls > 0 && load_blocklist(c.bl_path, &bl) != 0) {
        adv_free(&adv);
        return 2;
    }

    memset(&rep, 0, sizeof rep);
    if (run(&c, &adv, &bl, &rep) != 0) {
        fprintf(stderr, "error: out of memory\n");
        rc = 2;
    } else {
        if (c.json)
            report_print_json(&rep, argv[1], stdout);
        else
            report_print_text(&rep, stdout);
        rc = report_exit_code(&rep);
        if (c.html_path != NULL && write_html(&rep, &c) != 0)
            rc = 2;
    }
    report_free(&rep);
    adv_free(&adv);
    spki_blocklist_free(&bl);
    if (c.nhttp + c.ntls > 0)
        net_cleanup();
    return rc;
}
