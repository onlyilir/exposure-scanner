#include "http_probe.h"

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "net_compat.h"
#include "tls_audit.h"

#define HEADER_MAX 16384

static void copy_str(char *dst, size_t n, const char *src)
{
    size_t len = strlen(src);

    if (n == 0)
        return;
    if (len >= n)
        len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int ci_prefix(const char *s, const char *prefix)
{
    while (*prefix != '\0') {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix))
            return 0;
        s++;
        prefix++;
    }
    return 1;
}

/* ---------- target parsing ---------- */

static int parse_port(const char *s, size_t len, unsigned short *out)
{
    unsigned long v = 0;
    size_t i;

    if (len == 0 || len > 5)
        return -1;
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i]))
            return -1;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    if (v < 1 || v > 65535)
        return -1;
    *out = (unsigned short)v;
    return 0;
}

int probe_parse_target(const char *arg, probe_target *t)
{
    const char *p = arg;
    const char *end;
    size_t hl;
    size_t i;

    memset(t, 0, sizeof *t);
    if (arg == NULL)
        return -1;
    t->port = 80;
    if (ci_prefix(p, "https://")) {
        t->tls = 1;
        t->port = 443;
        p += 8;
    } else if (ci_prefix(p, "http://")) {
        p += 7;
    }
    if (*p == '[') { /* [ipv6]:port */
        const char *close = strchr(p, ']');

        if (close == NULL)
            return -1;
        hl = (size_t)(close - p - 1);
        if (hl == 0 || hl >= sizeof t->host)
            return -1;
        memcpy(t->host, p + 1, hl);
        t->host[hl] = '\0';
        p = close + 1;
        if (*p == ':') {
            p++;
            end = p;
            while (*end != '\0' && *end != '/' && *end != '?' && *end != '#')
                end++;
            if (parse_port(p, (size_t)(end - p), &t->port) != 0)
                return -1;
        } else if (*p != '\0' && *p != '/') {
            return -1;
        }
        return 0;
    }
    end = p;
    while (*end != '\0' && *end != ':' && *end != '/' && *end != '?' && *end != '#')
        end++;
    hl = (size_t)(end - p);
    if (hl == 0 || hl >= sizeof t->host)
        return -1;
    for (i = 0; i < hl; i++)
        if (!isalnum((unsigned char)p[i]) && p[i] != '.' && p[i] != '-' && p[i] != '_')
            return -1;
    memcpy(t->host, p, hl);
    t->host[hl] = '\0';
    if (*end == ':') {
        const char *q = end + 1;
        const char *e2 = q;

        while (*e2 != '\0' && *e2 != '/' && *e2 != '?' && *e2 != '#')
            e2++;
        if (parse_port(q, (size_t)(e2 - q), &t->port) != 0)
            return -1;
    }
    return 0;
}

/* ---------- banner parsing ---------- */

static const char *alias(const char *name)
{
    if (strcmp(name, "nodejs") == 0 || strcmp(name, "node.js") == 0)
        return "node";
    return name;
}

static int is_name_char(int c) { return isalnum(c) || c == '.' || c == '-' || c == '_'; }
static int is_ver_char(int c) { return isalnum(c) || c == '.' || c == '-' || c == '_' || c == '+' || c == '~'; }

static int add_tokens(const char *value, const char *source, banner_tok *out, int n, int max)
{
    const char *p = value;

    while (*p != '\0' && n < max) {
        if (isalpha((unsigned char)*p) && (p == value || !is_name_char((unsigned char)p[-1]))) {
            const char *s = p;
            size_t nl, vl, i;
            char name[32];

            while (is_name_char((unsigned char)*p))
                p++;
            nl = (size_t)(p - s);
            if (*p == '/' && isdigit((unsigned char)p[1]) && nl < sizeof name) {
                const char *v = p + 1;

                p = v;
                while (is_ver_char((unsigned char)*p))
                    p++;
                vl = (size_t)(p - v);
                if (vl < sizeof out[n].version) {
                    for (i = 0; i < nl; i++)
                        name[i] = (char)tolower((unsigned char)s[i]);
                    name[nl] = '\0';
                    copy_str(out[n].product, sizeof out[n].product, alias(name));
                    memcpy(out[n].version, v, vl);
                    out[n].version[vl] = '\0';
                    copy_str(out[n].source, sizeof out[n].source, source);
                    n++;
                }
            }
        } else {
            p++;
        }
    }
    return n;
}

int http_parse_banners(const char *headers, banner_tok *out, int max)
{
    char v[256];
    int n = 0;

    if (web_header_value(headers, "Server", v, sizeof v))
        n = add_tokens(v, "Server", out, n, max);
    if (web_header_value(headers, "X-Powered-By", v, sizeof v))
        n = add_tokens(v, "X-Powered-By", out, n, max);
    return n;
}

/* ---------- one probe ---------- */

static int looks_like_ip(const char *h)
{
    for (; *h != '\0'; h++)
        if (!isdigit((unsigned char)*h) && *h != '.' && *h != ':' && !isxdigit((unsigned char)*h))
            return 0;
    return 1;
}

static void match_hits(const banner_tok *tok, int ntok, const adv_list *adv, probe_result *res)
{
    int i;
    size_t k;

    for (i = 0; i < ntok; i++) {
        for (k = 0; adv != NULL && k < adv->n; k++) {
            const adv_entry *e = &adv->e[k];
            probe_hit *h;

            if (strcmp(e->module, "http") != 0 || strcmp(e->product, tok[i].product) != 0 ||
                adv_match(e, tok[i].version) != 1)
                continue;
            if (res->nhit >= PROBE_MAX_HITS)
                return;
            h = &res->hit[res->nhit++];
            copy_str(h->product, sizeof h->product, tok[i].product);
            copy_str(h->version, sizeof h->version, tok[i].version);
            copy_str(h->source, sizeof h->source, tok[i].source);
            copy_str(h->fixed, sizeof h->fixed, e->fixed);
            copy_str(h->url, sizeof h->url, e->url);
        }
    }
}

int probe_one(const probe_target *t, const probe_opts *o, const adv_list *adv, probe_result *res)
{
    char port[8];
    char req[512];
    char buf[HEADER_MAX + 1];
    size_t got = 0;
    net_sock s;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    banner_tok tok[PROBE_MAX_TOKENS];
    int ntok, status = 0;
    char *eoh;
    const char *hdr;

    memset(res, 0, sizeof *res);
    res->t = *t;
    snprintf(port, sizeof port, "%u", (unsigned)t->port);
    if (net_init() != 0) {
        copy_str(res->error, sizeof res->error, "network init failed");
        return -1;
    }
    s = net_connect(t->host, port, o->timeout_ms, res->error, sizeof res->error);
    if (s == NET_BAD)
        return -1;
    res->connected = 1;

    if (t->tls) {
        ctx = tls_new_client_ctx(NULL);
        if (ctx == NULL) {
            copy_str(res->error, sizeof res->error, "cannot create TLS context");
            net_close(s);
            return -1;
        }
        ssl = tls_handshake(ctx, s, looks_like_ip(t->host) ? NULL : t->host, 0, res->error,
                            sizeof res->error);
        if (ssl == NULL) {
            SSL_CTX_free(ctx);
            net_close(s);
            return -1;
        }
    }

    snprintf(req, sizeof req,
             "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: exposure-scanner (read-only check; "
             "+https://github.com/onlyilir/exposure-scanner)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
             t->host);
    if (ssl != NULL ? SSL_write(ssl, req, (int)strlen(req)) <= 0
                    : net_send_all(s, req, strlen(req)) != 0) {
        copy_str(res->error, sizeof res->error, "send failed");
        goto fail;
    }
    while (got < HEADER_MAX) {
        int r = ssl != NULL ? SSL_read(ssl, buf + got, (int)(HEADER_MAX - got))
                            : net_recv(s, buf + got, HEADER_MAX - got);

        if (r <= 0)
            break;
        got += (size_t)r;
        buf[got] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL || strstr(buf, "\n\n") != NULL)
            break;
    }
    buf[got] = '\0';
    if (got == 0) {
        copy_str(res->error, sizeof res->error, "no response");
        goto fail;
    }
    if (strncmp(buf, "HTTP/", 5) != 0 || sscanf(buf, "HTTP/%*d.%*d %d", &status) != 1) {
        copy_str(res->error, sizeof res->error, "not an HTTP response");
        goto fail;
    }
    res->status = status;
    eoh = strchr(buf, '\n'); /* skip the status line */
    hdr = eoh != NULL ? eoh + 1 : "";
    web_header_value(hdr, "Server", res->server, sizeof res->server);
    web_header_value(hdr, "X-Powered-By", res->powered_by, sizeof res->powered_by);
    web_header_value(hdr, "Location", res->location, sizeof res->location);
    ntok = http_parse_banners(hdr, tok, PROBE_MAX_TOKENS);
    match_hits(tok, ntok, adv, res);
    res->nweb = web_check_headers(hdr, t->tls, status, res->web, WEB_MAX_CHECKS);
    web_apply_preload(t->host, res->web, res->nweb);
    {
        const char *pf = web_detect_platform(hdr, t->host);

        copy_str(res->platform, sizeof res->platform, pf != NULL ? pf : "");
    }

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    net_close(s);
    return 0;

fail:
    if (ssl != NULL) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    net_close(s);
    return -1;
}

/* ---------- thread pool with a shared rate limit ---------- */

typedef struct {
    const probe_target *t;
    size_t n;
    const probe_opts *o;
    const adv_list *adv;
    probe_result *res;
    size_t next;
    pthread_mutex_t mu;      /* guards next */
    pthread_mutex_t rate_mu; /* guards next_slot */
    long long next_slot;
} pool_t;

static void rate_wait(pool_t *p)
{
    long long now, slot;

    if (p->o->rate_ms <= 0)
        return;
    pthread_mutex_lock(&p->rate_mu);
    now = net_now_ms();
    if (p->next_slot < now)
        p->next_slot = now;
    slot = p->next_slot;
    p->next_slot += p->o->rate_ms;
    pthread_mutex_unlock(&p->rate_mu);
    if (slot > now)
        net_sleep_ms(slot - now);
}

static void *worker(void *arg)
{
    pool_t *p = arg;

    for (;;) {
        size_t i;

        pthread_mutex_lock(&p->mu);
        i = p->next++;
        pthread_mutex_unlock(&p->mu);
        if (i >= p->n)
            break;
        rate_wait(p);
        probe_one(&p->t[i], p->o, p->adv, &p->res[i]);
    }
    return NULL;
}

int probe_run(const probe_target *t, size_t n, const probe_opts *o, const adv_list *adv,
              probe_result *res)
{
    pool_t p;
    pthread_t th[PROBE_MAX_THREADS];
    int nth = o->threads < 1 ? 1 : (o->threads > PROBE_MAX_THREADS ? PROBE_MAX_THREADS : o->threads);
    int started = 0, i;

    if (n > PROBE_MAX_TARGETS)
        return -1;
    if ((size_t)nth > n)
        nth = (int)n;
    if (n == 0)
        return 0;
    memset(&p, 0, sizeof p);
    p.t = t;
    p.n = n;
    p.o = o;
    p.adv = adv;
    p.res = res;
    pthread_mutex_init(&p.mu, NULL);
    pthread_mutex_init(&p.rate_mu, NULL);
    for (i = 0; i < nth; i++)
        if (pthread_create(&th[started], NULL, worker, &p) == 0)
            started++;
    if (started == 0)
        worker(&p); /* could not start any thread: do the work inline */
    for (i = 0; i < started; i++)
        pthread_join(th[i], NULL);
    pthread_mutex_destroy(&p.mu);
    pthread_mutex_destroy(&p.rate_mu);
    return 0;
}

static int same_site_host(const char *a, const char *b)
{
    if (strcasecmp(a, b) == 0)
        return 1;
    if (ci_prefix(a, "www.") && strcasecmp(a + 4, b) == 0)
        return 1;
    return ci_prefix(b, "www.") && strcasecmp(b + 4, a) == 0;
}

int probe_redirect_target(const probe_result *r, probe_target *out)
{
    probe_target t;

    if (r->status < 300 || r->status > 399 || !ci_prefix(r->location, "https://"))
        return 0;
    if (probe_parse_target(r->location, &t) != 0 || !same_site_host(t.host, r->t.host))
        return 0;
    if (t.tls == r->t.tls && t.port == r->t.port && strcasecmp(t.host, r->t.host) == 0)
        return 0; /* redirects to itself (another path); following would ask for / again */
    *out = t;
    return 1;
}

void probe_print(const probe_result *r, FILE *out)
{
    int i;

    fprintf(out, "%s:%u (%s)  ", r->t.host, (unsigned)r->t.port, r->t.tls ? "https" : "http");
    if (!r->connected || r->status == 0) {
        fprintf(out, "no result: %s\n", r->error[0] ? r->error : "unknown error");
        return;
    }
    fprintf(out, "HTTP %d\n", r->status);
    if (r->via[0])
        fprintf(out, "    (followed redirect from %s)\n", r->via);
    fprintf(out, "    Server: %s\n", r->server[0] ? r->server : "(hidden)");
    if (r->powered_by[0])
        fprintf(out, "    X-Powered-By: %s\n", r->powered_by);
    for (i = 0; i < r->nhit; i++)
        fprintf(out,
                "    POSSIBLE (unconfirmed): %s %s from the %s header is in an affected range; "
                "fixed: %s\n      %s\n",
                r->hit[i].product, r->hit[i].version, r->hit[i].source, r->hit[i].fixed,
                r->hit[i].url);
    for (i = 0; i < r->nweb; i++) {
        const web_info *w = web_check_info(r->web[i].id);
        int bad = r->web[i].level >= WEB_TIP;

        fprintf(out, "    [%s] %s: %s\n", web_level_name(r->web[i].level),
                w == NULL ? r->web[i].id : bad ? w->title_bad : w->title_ok, r->web[i].detail);
    }
}
