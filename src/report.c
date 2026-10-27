/* Run results as text (the modules' own printers) or as one JSON object. */
#include "report.h"

#include <stdlib.h>
#include <string.h>

/* ---------- exit codes and counts ---------- */

static int http_failed(const probe_result *p) { return !p->connected || p->status == 0; }

int report_tls_cert_flagged(const tls_cert_info *c)
{
    return (c->flags & (TLSF_BLOCKLISTED | TLSF_ISSUER_MATCH | TLSF_EXPIRED)) != 0;
}

static int tls_flagged_certs(const tls_result *t)
{
    int i, n = 0;

    for (i = 0; i < t->ncerts; i++)
        n += report_tls_cert_flagged(&t->certs[i]);
    return n;
}

int report_rc_secrets(const scan_report *r)
{
    if (!r->run_secrets)
        return -1;
    return r->secrets_error ? 2 : r->secrets.n > 0 ? 1 : 0;
}

int report_rc_py(const scan_report *r)
{
    if (!r->run_py)
        return -1;
    return r->py_error ? 2 : r->py.n > 0 ? 1 : 0;
}

int report_rc_http(const scan_report *r)
{
    size_t i, failed = 0;
    int hits = 0;

    if (r->nhttp == 0)
        return -1;
    for (i = 0; i < r->nhttp; i++) {
        hits += r->http[i].nhit;
        failed += http_failed(&r->http[i]);
    }
    return hits > 0 ? 1 : failed == r->nhttp ? 2 : 0;
}

int report_rc_tls(const scan_report *r)
{
    size_t i, failed = 0;
    int flagged = 0;

    if (r->ntls == 0)
        return -1;
    for (i = 0; i < r->ntls; i++) {
        flagged += tls_flagged_certs(&r->tls[i]);
        failed += !r->tls[i].connected;
    }
    return flagged > 0 ? 1 : failed == r->ntls ? 2 : 0;
}

int report_exit_code(const scan_report *r)
{
    int rc[4], i, any_err = 0;

    rc[0] = report_rc_secrets(r);
    rc[1] = report_rc_py(r);
    rc[2] = report_rc_http(r);
    rc[3] = report_rc_tls(r);
    for (i = 0; i < 4; i++) {
        if (rc[i] == 1)
            return 1;
        if (rc[i] == 2)
            any_err = 1;
    }
    return any_err ? 2 : 0;
}

unsigned long report_count_findings(const scan_report *r)
{
    unsigned long n = 0;
    size_t i;

    if (r->run_secrets)
        n += (unsigned long)r->secrets.n;
    if (r->run_py)
        n += (unsigned long)r->py.n;
    for (i = 0; i < r->nhttp; i++)
        n += (unsigned long)r->http[i].nhit;
    for (i = 0; i < r->ntls; i++)
        n += (unsigned long)tls_flagged_certs(&r->tls[i]);
    return n;
}

unsigned long report_count_settings(const scan_report *r, int level)
{
    unsigned long n = 0;
    size_t i;
    int j;

    for (i = 0; i < r->nhttp; i++)
        for (j = 0; j < r->http[i].nweb; j++)
            n += r->http[i].web[j].level == level;
    return n;
}

/* ---------- text ---------- */

static int modules_run(const scan_report *r)
{
    return r->run_secrets + r->run_py + (r->nhttp > 0) + (r->ntls > 0);
}

static void header(FILE *out, int multi, const char *name, const char *arg)
{
    if (!multi)
        return;
    if (arg != NULL)
        fprintf(out, "\n== %s: %s ==\n", name, arg);
    else
        fprintf(out, "\n== %s ==\n", name);
}

static const char *rc_word(int rc)
{
    return rc == 0 ? "clean" : rc == 1 ? "findings" : "error";
}

void report_print_text(const scan_report *r, FILE *out)
{
    int multi = modules_run(r) > 1;
    size_t i;

    if (r->run_secrets) {
        header(out, multi, "secrets", r->root);
        if (r->secrets_error)
            fprintf(out, "error: the secrets scan did not finish (out of memory?)\n");
        else
            secret_report_print(&r->secrets, out);
    }
    if (r->run_py) {
        header(out, multi, "python supply chain", r->root);
        if (r->py_error)
            fprintf(out, "error: the python scan did not finish (out of memory?)\n");
        else
            py_report_print(&r->py, out);
    }
    if (r->nhttp > 0) {
        int hits = 0, failed = 0;

        header(out, multi, "http banners and website settings", NULL);
        for (i = 0; i < r->nhttp; i++) {
            probe_print(&r->http[i], out);
            hits += r->http[i].nhit;
            failed += http_failed(&r->http[i]);
        }
        fprintf(out,
                "\n%d possible finding(s) across %d target(s) (%d without a result).\n"
                "These come from Server/X-Powered-By banners only: unconfirmed. Banners can be "
                "hidden or faked and distro packages back-port fixes without changing the "
                "version. GitLab does not announce its version in banners; check it in the admin "
                "area.\n"
                "Website settings: %lu important, %lu recommended, %lu tip(s) (not counted as "
                "findings in the exit code).\n",
                hits, (int)r->nhttp, failed, report_count_settings(r, WEB_IMPORTANT),
                report_count_settings(r, WEB_RECOMMENDED), report_count_settings(r, WEB_TIP));
    }
    if (r->ntls > 0) {
        header(out, multi, "tls certificates", NULL);
        for (i = 0; i < r->ntls; i++) {
            if (i > 0)
                fputc('\n', out);
            tls_result_print(&r->tls[i], out);
        }
    }
    if (multi) {
        fprintf(out, "\n== summary ==\n");
        if (r->run_secrets)
            fprintf(out, "secrets: %s\n", rc_word(report_rc_secrets(r)));
        if (r->run_py)
            fprintf(out, "python:  %s\n", rc_word(report_rc_py(r)));
        if (r->nhttp > 0)
            fprintf(out, "http:    %s\n", rc_word(report_rc_http(r)));
        if (r->ntls > 0)
            fprintf(out, "tls:     %s\n", rc_word(report_rc_tls(r)));
        fprintf(out, "%lu finding(s) in total, exit code %d.\n", report_count_findings(r),
                report_exit_code(r));
    }
}

/* ---------- JSON ---------- */

/* Length of the valid UTF-8 sequence at s (1-4), or 0 if it is not valid (overlong forms,
   surrogates and code points above U+10FFFF are rejected). Never reads past a NUL. */
int report_utf8_len(const unsigned char *s)
{
    unsigned char c = s[0], lo, hi;

    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return (s[1] & 0xC0) == 0x80 ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        lo = c == 0xE0 ? 0xA0 : 0x80;
        hi = c == 0xED ? 0x9F : 0xBF;
        if (s[1] < lo || s[1] > hi || (s[2] & 0xC0) != 0x80)
            return 0;
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        lo = c == 0xF0 ? 0x90 : 0x80;
        hi = c == 0xF4 ? 0x8F : 0xBF;
        if (s[1] < lo || s[1] > hi || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80)
            return 0;
        return 4;
    }
    return 0;
}

void report_json_string(FILE *out, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s != NULL ? s : "");
    int n;

    fputc('"', out);
    while (*p != '\0') {
        switch (*p) {
        case '"': fputs("\\\"", out); p++; continue;
        case '\\': fputs("\\\\", out); p++; continue;
        case '\n': fputs("\\n", out); p++; continue;
        case '\r': fputs("\\r", out); p++; continue;
        case '\t': fputs("\\t", out); p++; continue;
        default: break;
        }
        if (*p < 0x20 || *p == 0x7F) {
            fprintf(out, "\\u%04x", (unsigned)*p);
            p++;
            continue;
        }
        n = report_utf8_len(p);
        if (n == 0) {
            fputs("\\ufffd", out); /* e.g. a path in the ANSI code page */
            p++;
            continue;
        }
        fwrite(p, 1, (size_t)n, out);
        p += n;
    }
    fputc('"', out);
}

/* ,"key": */
static void key(FILE *out, int *first, const char *k)
{
    if (!*first)
        fputc(',', out);
    *first = 0;
    report_json_string(out, k);
    fputc(':', out);
}

/* comma between array elements */
static void key_less(FILE *out, int *first)
{
    if (!*first)
        fputc(',', out);
    *first = 0;
}

static void kv_str(FILE *out, int *first, const char *k, const char *v)
{
    key(out, first, k);
    report_json_string(out, v);
}

/* empty string -> null */
static void kv_opt(FILE *out, int *first, const char *k, const char *v)
{
    key(out, first, k);
    if (v == NULL || v[0] == '\0')
        fputs("null", out);
    else
        report_json_string(out, v);
}

static void kv_long(FILE *out, int *first, const char *k, long v)
{
    key(out, first, k);
    fprintf(out, "%ld", v);
}

static void kv_ulong(FILE *out, int *first, const char *k, unsigned long v)
{
    key(out, first, k);
    fprintf(out, "%lu", v);
}

static void kv_bool(FILE *out, int *first, const char *k, int v)
{
    key(out, first, k);
    fputs(v ? "true" : "false", out);
}

static void json_secrets(const scan_report *r, FILE *out)
{
    const secret_report *s = &r->secrets;
    int f = 1, g;
    size_t i;

    fputc('{', out);
    kv_str(out, &f, "status", rc_word(report_rc_secrets(r)));
    if (r->secrets_error) {
        kv_str(out, &f, "error", "the scan did not finish (out of memory?)");
        fputc('}', out);
        return;
    }
    kv_ulong(out, &f, "files_scanned", s->files_scanned);
    kv_ulong(out, &f, "files_skipped", s->files_skipped);
    kv_bool(out, &f, "truncated", s->truncated);
    key(out, &f, "findings");
    fputc('[', out);
    for (i = 0; i < s->n; i++) {
        const secret_hit *h = &s->h[i];

        if (i > 0)
            fputc(',', out);
        g = 1;
        fputc('{', out);
        kv_str(out, &g, "path", h->path);
        kv_long(out, &g, "line", h->line);
        kv_str(out, &g, "rule", h->rule);
        kv_opt(out, &g, "value_masked", h->masked);
        key(out, &g, "git_tracked");
        fputs(h->tracked == 1 ? "true" : h->tracked == 0 ? "false" : "null", out);
        fputc('}', out);
    }
    fputc(']', out);
    kv_str(out, &f, "note",
           "Values are masked. Findings are rule matches, not proof of a live secret.");
    fputc('}', out);
}

static void json_py(const scan_report *r, FILE *out)
{
    const py_report *p = &r->py;
    int f = 1, g;
    size_t i;

    fputc('{', out);
    kv_str(out, &f, "status", rc_word(report_rc_py(r)));
    if (r->py_error) {
        kv_str(out, &f, "error", "the scan did not finish (out of memory?)");
        fputc('}', out);
        return;
    }
    kv_ulong(out, &f, "packages_seen", p->packages_seen);
    kv_ulong(out, &f, "pinned_seen", p->pinned_seen);
    kv_ulong(out, &f, "pth_import_seen", p->pth_import_seen);
    key(out, &f, "findings");
    fputc('[', out);
    for (i = 0; i < p->n; i++) {
        const py_finding *x = &p->f[i];

        if (i > 0)
            fputc(',', out);
        g = 1;
        fputc('{', out);
        kv_str(out, &g, "severity", x->severity == 2 ? "affected" : "possible");
        kv_str(out, &g, "kind", x->kind);
        kv_str(out, &g, "path", x->path);
        key(out, &g, "line");
        if (x->line > 0)
            fprintf(out, "%d", x->line);
        else
            fputs("null", out);
        kv_opt(out, &g, "name", x->name);
        kv_opt(out, &g, "version", x->version);
        kv_str(out, &g, "detail", x->detail);
        fputc('}', out);
    }
    fputc(']', out);
    kv_str(out, &f, "note",
           "A clean result does not prove a machine is clean; it only checks the rules in the "
           "advisories file.");
    fputc('}', out);
}

static void json_http(const scan_report *r, FILE *out)
{
    int f = 1, g, h, j;
    size_t i;

    fputc('{', out);
    kv_str(out, &f, "status", rc_word(report_rc_http(r)));
    kv_str(out, &f, "evidence", "banner headers only (unconfirmed)");
    key(out, &f, "targets");
    fputc('[', out);
    for (i = 0; i < r->nhttp; i++) {
        const probe_result *p = &r->http[i];

        if (i > 0)
            fputc(',', out);
        g = 1;
        fputc('{', out);
        kv_str(out, &g, "host", p->t.host);
        kv_long(out, &g, "port", p->t.port);
        kv_str(out, &g, "scheme", p->t.tls ? "https" : "http");
        kv_bool(out, &g, "result", !http_failed(p));
        if (http_failed(p)) {
            kv_str(out, &g, "error", p->error[0] ? p->error : "unknown error");
            fputc('}', out);
            continue;
        }
        kv_long(out, &g, "http_status", p->status);
        kv_opt(out, &g, "platform", p->platform[0] ? web_platform_name(p->platform) : "");
        kv_opt(out, &g, "redirected_from", p->via);
        kv_opt(out, &g, "location", p->location);
        kv_opt(out, &g, "server", p->server);
        kv_opt(out, &g, "x_powered_by", p->powered_by);
        key(out, &g, "settings");
        fputc('[', out);
        for (j = 0; j < p->nweb; j++) {
            const web_info *w = web_check_info(p->web[j].id);

            if (j > 0)
                fputc(',', out);
            h = 1;
            fputc('{', out);
            kv_str(out, &h, "id", p->web[j].id);
            kv_str(out, &h, "level", web_level_name(p->web[j].level));
            kv_str(out, &h, "title",
                   w == NULL ? "" : p->web[j].level >= WEB_TIP ? w->title_bad : w->title_ok);
            kv_str(out, &h, "detail", p->web[j].detail);
            fputc('}', out);
        }
        fputc(']', out);
        key(out, &g, "possible_findings");
        fputc('[', out);
        for (j = 0; j < p->nhit; j++) {
            if (j > 0)
                fputc(',', out);
            h = 1;
            fputc('{', out);
            kv_str(out, &h, "product", p->hit[j].product);
            kv_str(out, &h, "version", p->hit[j].version);
            kv_str(out, &h, "header", p->hit[j].source);
            kv_str(out, &h, "fixed", p->hit[j].fixed);
            kv_opt(out, &h, "advisory_url", p->hit[j].url);
            fputc('}', out);
        }
        fputs("]}", out);
    }
    fputc(']', out);
    kv_str(out, &f, "note",
           "Banners can be hidden or faked and distro packages back-port fixes without changing "
           "the version. GitLab does not announce its version in banners.");
    fputc('}', out);
}

static void json_cert_flags(FILE *out, unsigned fl)
{
    static const struct {
        unsigned bit;
        const char *name;
    } names[] = {
        {TLSF_EXPIRED, "expired"},         {TLSF_EXPIRES_SOON, "expires_soon"},
        {TLSF_SELF_SIGNED, "self_signed"}, {TLSF_WEAK_KEY, "weak_key"},
        {TLSF_BLOCKLISTED, "blocklisted"}, {TLSF_ISSUER_MATCH, "advisory_issuer"},
    };
    size_t i;
    int first = 1;

    fputc('[', out);
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(fl & names[i].bit))
            continue;
        if (!first)
            fputc(',', out);
        first = 0;
        report_json_string(out, names[i].name);
    }
    fputc(']', out);
}

static void json_tls_target(const tls_result *t, FILE *out)
{
    int g = 1, h, i;

    fputc('{', out);
    kv_str(out, &g, "host", t->host);
    kv_long(out, &g, "port", t->port);
    kv_bool(out, &g, "result", t->connected);
    if (!t->connected) {
        kv_str(out, &g, "error", t->error[0] ? t->error : "unknown error");
        fputc('}', out);
        return;
    }
    kv_str(out, &g, "protocol", t->protocol);
    kv_str(out, &g, "cipher", t->cipher);
    kv_bool(out, &g, "weak_protocol", tls_protocol_is_weak(t->protocol));
    kv_opt(out, &g, "interception", t->interception);
    kv_bool(out, &g, "flagged", tls_flagged_certs(t) > 0);
    kv_long(out, &g, "trust_code", t->verify_code);
    kv_str(out, &g, "trust_text", t->verify_text);
    kv_bool(out, &g, "ocsp_stapled", t->ocsp_stapled);
    kv_str(out, &g, "ocsp_status", t->ocsp_status);
    key(out, &g, "certs");
    fputc('[', out);
    for (i = 0; i < t->ncerts; i++) {
        const tls_cert_info *c = &t->certs[i];

        if (i > 0)
            fputc(',', out);
        h = 1;
        fputc('{', out);
        kv_str(out, &h, "subject", c->subject);
        kv_str(out, &h, "issuer", c->issuer);
        kv_str(out, &h, "key_alg", c->key_alg);
        kv_long(out, &h, "key_bits", c->key_bits);
        kv_str(out, &h, "not_before", c->not_before);
        kv_str(out, &h, "not_after", c->not_after);
        kv_long(out, &h, "days_left", c->days_left);
        kv_str(out, &h, "spki_sha256", c->spki_sha256);
        kv_opt(out, &h, "ocsp_url", c->ocsp_url);
        kv_opt(out, &h, "crl_url", c->crl_url);
        key(out, &h, "flags");
        json_cert_flags(out, c->flags);
        kv_opt(out, &h, "advisory_match", (c->flags & TLSF_ISSUER_MATCH) ? c->matched : "");
        fputc('}', out);
    }
    fputs("]}", out);
}

static void json_tls(const scan_report *r, FILE *out)
{
    int f = 1;
    size_t i;

    fputc('{', out);
    kv_str(out, &f, "status", rc_word(report_rc_tls(r)));
    key(out, &f, "targets");
    fputc('[', out);
    for (i = 0; i < r->ntls; i++) {
        if (i > 0)
            fputc(',', out);
        json_tls_target(&r->tls[i], out);
    }
    fputc(']', out);
    kv_str(out, &f, "note",
           "Not checked: live OCSP/CRL lookups (URLs are only listed), the stapled OCSP "
           "signature, certificate transparency, and keys not in your blocklist. When "
           "'interception' is set the chain was re-signed locally and is not the server's.");
    fputc('}', out);
}

/* "summary": the client report's verdict (counts, warnings, issues), see report_summarize */
static void json_summary(const scan_report *r, FILE *out, int *f)
{
    report_summary *s = malloc(sizeof *s);
    int g = 1, h, i;

    if (s == NULL)
        return;
    report_summarize(r, s);
    key(out, f, "summary");
    fputc('{', out);
    kv_ulong(out, &g, "important", s->count[WEB_IMPORTANT]);
    kv_ulong(out, &g, "recommended", s->count[WEB_RECOMMENDED]);
    kv_ulong(out, &g, "tip", s->count[WEB_TIP]);
    kv_ulong(out, &g, "passed", s->count[WEB_OK]);
    kv_bool(out, &g, "ready_to_send", s->warnings == 0);
    key(out, &g, "warnings");
    fputc('[', out);
    h = 1;
    if (s->intercepted) {
        key_less(out, &h);
        report_json_string(out, "HTTPS inspection on this computer replaced the certificate. "
                                "Pause HTTPS scanning (for example Norton Safe Web) and run "
                                "the check again.");
    }
    if (s->failed_targets > 0) {
        key_less(out, &h);
        report_json_string(out, "An address could not be reached. Check the address and the "
                                "internet connection.");
    }
    if (s->unfinished) {
        key_less(out, &h);
        report_json_string(out, "The scan did not finish.");
    }
    fputc(']', out);
    key(out, &g, "issues");
    fputc('[', out);
    for (i = 0; i < s->nitems; i++) {
        h = 1;
        if (i > 0)
            fputc(',', out);
        fputc('{', out);
        kv_str(out, &h, "level", web_level_name(s->items[i].level));
        kv_str(out, &h, "site", s->items[i].site);
        kv_str(out, &h, "title", s->items[i].title);
        kv_str(out, &h, "fix", s->items[i].fix);
        kv_str(out, &h, "detail", s->items[i].detail);
        fputc('}', out);
    }
    fputs("]}", out);
    free(s);
}

void report_print_json(const scan_report *r, const char *command, FILE *out)
{
    int f = 1;

    fputc('{', out);
    kv_str(out, &f, "tool", "exposure-scanner");
    kv_str(out, &f, "version", SCANNER_VERSION);
    kv_str(out, &f, "command", command);
    if (r->root != NULL)
        kv_str(out, &f, "root", r->root);
    if (r->run_secrets) {
        key(out, &f, "secrets");
        json_secrets(r, out);
    }
    if (r->run_py) {
        key(out, &f, "python");
        json_py(r, out);
    }
    if (r->nhttp > 0) {
        key(out, &f, "http");
        json_http(r, out);
    }
    if (r->ntls > 0) {
        key(out, &f, "tls");
        json_tls(r, out);
    }
    kv_ulong(out, &f, "findings", report_count_findings(r));
    if (r->nhttp > 0) {
        int g = 1;

        key(out, &f, "settings_issues");
        fputc('{', out);
        kv_ulong(out, &g, "important", report_count_settings(r, WEB_IMPORTANT));
        kv_ulong(out, &g, "recommended", report_count_settings(r, WEB_RECOMMENDED));
        kv_ulong(out, &g, "tip", report_count_settings(r, WEB_TIP));
        fputc('}', out);
    }
    json_summary(r, out, &f);
    kv_long(out, &f, "exit_code", report_exit_code(r));
    fputs("}\n", out);
}

void report_free(scan_report *r)
{
    secret_report_free(&r->secrets);
    py_report_free(&r->py);
    free(r->http);
    free(r->tls);
    memset(r, 0, sizeof *r);
}
