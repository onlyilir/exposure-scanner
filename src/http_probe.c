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
#define BODY_MAX (2u * 1024u * 1024u) /* home page or one script file */

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

typedef struct {
    int status;
    char *buf;     /* whole answer, owned */
    char *headers; /* after the status line, NUL-terminated at the empty line */
    char *body;
    size_t blen;
} http_resp;

/* "0\r\n\r\n"-style chunked body decoded in place; returns the new length */
static size_t dechunk(char *b, size_t n)
{
    size_t in = 0, out = 0;

    while (in < n) {
        char *end, *nl;
        unsigned long sz = strtoul(b + in, &end, 16);

        if (end == b + in || (nl = memchr(end, '\n', n - (size_t)(end - b))) == NULL)
            break;
        in = (size_t)(nl - b) + 1;
        if (sz == 0)
            break;
        if (sz > n - in)
            sz = (unsigned long)(n - in);
        memmove(b + out, b + in, sz);
        out += sz;
        in += sz;
        if (in < n && b[in] == '\r')
            in++;
        if (in < n && b[in] == '\n')
            in++;
    }
    b[out] = '\0';
    return out;
}

/* One GET on a new connection (Connection: close), read until the server closes or max body
   bytes. No Accept-Encoding, so the answer is never compressed. 0 when an HTTP answer was read. */
static int http_get(const probe_target *t, const char *path, int timeout_ms, size_t max, http_resp *r,
                    char *err, size_t errn, int *connected)
{
    char port[8], req[512], *eoh, *hdr;
    size_t got = 0, cap = HEADER_MAX + max + 1;
    net_sock s;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char te[64], cl[32];

    memset(r, 0, sizeof *r);
    snprintf(port, sizeof port, "%u", (unsigned)t->port);
    if (net_init() != 0) {
        copy_str(err, errn, "network init failed");
        return -1;
    }
    s = net_connect(t->host, port, timeout_ms, err, errn);
    if (s == NET_BAD)
        return -1;
    *connected = 1;
    if (t->tls) {
        ctx = tls_new_client_ctx(NULL);
        if (ctx == NULL) {
            copy_str(err, errn, "cannot create TLS context");
            net_close(s);
            return -1;
        }
        ssl = tls_handshake(ctx, s, looks_like_ip(t->host) ? NULL : t->host, 0, err, errn);
        if (ssl == NULL) {
            SSL_CTX_free(ctx);
            net_close(s);
            return -1;
        }
    }
    snprintf(req, sizeof req,
             "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: exposure-scanner (read-only check; "
             "+https://github.com/onlyilir/exposure-scanner)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
             path, t->host);
    if ((r->buf = malloc(cap)) == NULL) {
        copy_str(err, errn, "out of memory");
        goto fail;
    }
    if (ssl != NULL ? SSL_write(ssl, req, (int)strlen(req)) <= 0 : net_send_all(s, req, strlen(req)) != 0) {
        copy_str(err, errn, "send failed");
        goto fail;
    }
    while (got + 1 < cap) {
        size_t want = cap - 1 - got;
        int n = ssl != NULL ? SSL_read(ssl, r->buf + got, want > 65536 ? 65536 : (int)want)
                            : net_recv(s, r->buf + got, want > 65536 ? 65536 : want);

        if (n <= 0)
            break;
        got += (size_t)n;
    }
    r->buf[got] = '\0';
    if (got == 0) {
        copy_str(err, errn, "no response");
        goto fail;
    }
    if (strncmp(r->buf, "HTTP/", 5) != 0 || sscanf(r->buf, "HTTP/%*d.%*d %d", &r->status) != 1) {
        copy_str(err, errn, "not an HTTP response");
        goto fail;
    }
    hdr = strchr(r->buf, '\n'); /* skip the status line */
    hdr = hdr != NULL ? hdr + 1 : r->buf + got;
    if ((eoh = strstr(hdr, "\r\n\r\n")) != NULL) {
        r->body = eoh + 4;
        eoh[2] = '\0';
    } else if ((eoh = strstr(hdr, "\n\n")) != NULL) {
        r->body = eoh + 2;
        eoh[1] = '\0';
    } else {
        r->body = r->buf + got; /* headers only (cut short) */
    }
    r->headers = hdr;
    r->blen = (size_t)(r->buf + got - r->body);
    if (web_header_value(hdr, "Transfer-Encoding", te, sizeof te) && strstr(te, "chunked") != NULL)
        r->blen = dechunk(r->body, r->blen);
    else if (web_header_value(hdr, "Content-Length", cl, sizeof cl) && strtoul(cl, NULL, 10) < r->blen)
        r->body[r->blen = strtoul(cl, NULL, 10)] = '\0';
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    net_close(s);
    return 0;

fail:
    free(r->buf);
    r->buf = NULL;
    if (ssl != NULL) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    net_close(s);
    return -1;
}

static int still_wanted(const tech_list *l, const http_resp *home, const char *path)
{
    char paths[TECH_MAX_FOLLOWUPS][192];
    int n = tech_followups(l, home->body, home->blen, paths, TECH_MAX_FOLLOWUPS), i;

    for (i = 0; i < n; i++)
        if (strcmp(paths[i], path) == 0)
            return 1;
    return 0;
}

/* Level 2: a few public files for what the home page showed, until each version is exact */
static void follow_up(const probe_target *t, const probe_opts *o, const http_resp *home, probe_result *res)
{
    char paths[TECH_MAX_FOLLOWUPS][192];
    int n = tech_followups(&res->tech, home->body, home->blen, paths, TECH_MAX_FOLLOWUPS), i;

    for (i = 0; i < n; i++) {
        http_resp f;
        char err[96];
        int c = 0;

        if (!still_wanted(&res->tech, home, paths[i]))
            continue;
        if (o->rate_ms > 0)
            net_sleep_ms(o->rate_ms);
        res->fetched++;
        if (http_get(t, paths[i], o->timeout_ms, BODY_MAX, &f, err, sizeof err, &c) == 0) {
            tech_apply(paths[i], f.status, f.body, f.blen, &res->tech);
            free(f.buf);
        }
    }
}

int probe_one(const probe_target *t, const probe_opts *o, const adv_list *adv, probe_result *res)
{
    banner_tok tok[PROBE_MAX_TOKENS];
    int ntok;
    const char *hdr;
    http_resp r;

    memset(res, 0, sizeof *res);
    res->t = *t;
    if (http_get(t, "/", o->timeout_ms, BODY_MAX, &r, res->error, sizeof res->error, &res->connected) != 0)
        return -1;
    res->status = r.status;
    hdr = r.headers;
    web_header_value(hdr, "Server", res->server, sizeof res->server);
    web_header_value(hdr, "X-Powered-By", res->powered_by, sizeof res->powered_by);
    web_header_value(hdr, "Location", res->location, sizeof res->location);
    ntok = http_parse_banners(hdr, tok, PROBE_MAX_TOKENS);
    match_hits(tok, ntok, adv, res);
    res->nweb = web_check_headers(hdr, t->tls, r.status, res->web, WEB_MAX_CHECKS);
    web_apply_preload(t->host, res->web, res->nweb);
    {
        const char *pf = web_detect_platform(hdr, t->host);

        copy_str(res->platform, sizeof res->platform, pf != NULL ? pf : "");
    }
    tech_from_headers(hdr, &res->tech);
    if (r.status == 200 && r.blen > 0) {
        tech_from_html(r.body, r.blen, &res->tech);
        if (o->level2)
            follow_up(t, o, &r, res);
    }
    free(r.buf);
    return 0;
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
