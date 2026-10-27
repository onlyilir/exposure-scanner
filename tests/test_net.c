/* Network-module tests. LOCAL ONLY: every connection goes to a server this program starts on
   127.0.0.1. Usage: test_net [advisories.txt]
                     test_net --serve-redirect   (for cli_check.sh: prints the port of a plain
                     server that redirects to a local https server, serves one request each,
                     exits after 20 s at most) */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "../src/advisory.h"
#include "../src/http_probe.h"
#include "../src/net_compat.h"
#include "../src/tls_audit.h"

static int g_run, g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_run++;                                                             \
        if (!(cond)) {                                                       \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* ---------- local test server ---------- */

typedef struct {
    net_sock listener;
    unsigned short port;
    int nconn;       /* connections to serve, then exit */
    SSL_CTX *ctx;    /* NULL = plain HTTP */
    const char *reply;
    pthread_t th;
    volatile int done; /* set when nconn connections were served */
} server_t;

static const char *REPLY =
    "HTTP/1.1 200 OK\r\nServer: nginx/1.30.3\r\nX-Powered-By: PHP/8.2.34\r\n"
    "Content-Length: 0\r\nConnection: close\r\n\r\n";

static void *server_main(void *arg)
{
    server_t *sv = arg;
    int i;

    for (i = 0; i < sv->nconn; i++) {
        net_sock c = net_accept(sv->listener);
        char buf[2048];

        if (c == NET_BAD)
            break;
        if (sv->ctx != NULL) {
            SSL *ssl = SSL_new(sv->ctx);

            SSL_set_fd(ssl, (int)c);
            if (SSL_accept(ssl) == 1) {
                int n = SSL_read(ssl, buf, sizeof buf);

                if (n > 0)
                    SSL_write(ssl, sv->reply, (int)strlen(sv->reply));
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
        } else {
            if (net_recv(c, buf, sizeof buf) > 0)
                net_send_all(c, sv->reply, strlen(sv->reply));
        }
        net_close(c);
    }
    sv->done = 1;
    return NULL;
}

static int server_start(server_t *sv, int nconn, SSL_CTX *ctx, const char *reply)
{
    memset(sv, 0, sizeof *sv);
    sv->nconn = nconn;
    sv->ctx = ctx;
    sv->reply = reply;
    sv->listener = net_listen_local(&sv->port);
    if (sv->listener == NET_BAD)
        return -1;
    return pthread_create(&sv->th, NULL, server_main, sv);
}

static void server_stop(server_t *sv)
{
    pthread_join(sv->th, NULL);
    net_close(sv->listener);
}

/* Self-signed RSA-2048 certificate whose subject mentions the advisory issuer name. */
static SSL_CTX *make_server_ctx(void)
{
    EVP_PKEY *pk = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    X509_NAME *nm;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (pk == NULL || x == NULL || ctx == NULL)
        return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 30);
    X509_set_pubkey(x, pk);
    nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"eMudhra Test CA", -1,
                               -1, 0);
    X509_set_issuer_name(x, nm);
    X509_sign(x, pk, EVP_sha256());
    SSL_CTX_use_certificate(ctx, x);
    SSL_CTX_use_PrivateKey(ctx, pk);
    X509_free(x);
    EVP_PKEY_free(pk);
    return ctx;
}

/* ---------- tests ---------- */

static void test_targets(void)
{
    probe_target t;

    CHECK(probe_parse_target("example.com", &t) == 0 && strcmp(t.host, "example.com") == 0 &&
          t.port == 80 && t.tls == 0);
    CHECK(probe_parse_target("example.com:8080", &t) == 0 && t.port == 8080 && !t.tls);
    CHECK(probe_parse_target("https://example.com", &t) == 0 && t.port == 443 && t.tls);
    CHECK(probe_parse_target("https://example.com:8443/x?y=1", &t) == 0 && t.port == 8443 &&
          strcmp(t.host, "example.com") == 0);
    CHECK(probe_parse_target("HTTP://h:81/path", &t) == 0 && t.port == 81 && !t.tls);
    CHECK(probe_parse_target("[::1]:8080", &t) == 0 && strcmp(t.host, "::1") == 0 && t.port == 8080);
    CHECK(probe_parse_target("192.168.0.10", &t) == 0);
    CHECK(probe_parse_target("", &t) != 0);
    CHECK(probe_parse_target(":80", &t) != 0);
    CHECK(probe_parse_target("host:0", &t) != 0);
    CHECK(probe_parse_target("host:99999", &t) != 0);
    CHECK(probe_parse_target("host:abc", &t) != 0);
    CHECK(probe_parse_target("bad host", &t) != 0);
    CHECK(probe_parse_target("[::1", &t) != 0);
    CHECK(probe_parse_target(NULL, &t) != 0);
}

static void test_banners(void)
{
    banner_tok tok[PROBE_MAX_TOKENS];
    int n;

    n = http_parse_banners("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu) PHP/8.2.34\r\n"
                           "x-powered-by: Node.js/22.1.0\r\n\r\n",
                           tok, PROBE_MAX_TOKENS);
    CHECK(n == 3);
    CHECK(strcmp(tok[0].product, "apache") == 0 && strcmp(tok[0].version, "2.4.58") == 0);
    CHECK(strcmp(tok[1].product, "php") == 0 && strcmp(tok[1].version, "8.2.34") == 0);
    CHECK(strcmp(tok[2].product, "node") == 0); /* alias */
    CHECK(strcmp(tok[2].source, "X-Powered-By") == 0);
    CHECK(http_parse_banners("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", tok, PROBE_MAX_TOKENS) == 0);
    CHECK(http_parse_banners("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", tok,
                             PROBE_MAX_TOKENS) == 0);
    CHECK(http_parse_banners("HTTP/1.1 200 OK\r\nServer: a/1 b/2 c/3\r\n\r\n", tok, 2) == 2);
}

static int has_hit(const probe_result *r, const char *product)
{
    int i;

    for (i = 0; i < r->nhit; i++)
        if (strcmp(r->hit[i].product, product) == 0)
            return 1;
    return 0;
}

static void test_http(const adv_list *adv)
{
    server_t sv;
    probe_target t;
    probe_opts o;
    probe_result r;
    probe_result many[3];
    probe_target tt[3];
    unsigned short dead_port;
    net_sock tmp;
    int i;

    o.timeout_ms = 3000;
    o.rate_ms = 0;
    o.threads = 4;

    /* plain HTTP: nginx 1.30.3 and PHP 8.2.34 are both inside affected ranges */
    CHECK(server_start(&sv, 1, NULL, REPLY) == 0);
    memset(&t, 0, sizeof t);
    snprintf(t.host, sizeof t.host, "127.0.0.1");
    t.port = sv.port;
    CHECK(probe_one(&t, &o, adv, &r) == 0);
    server_stop(&sv);
    CHECK(r.connected && r.status == 200);
    CHECK(strcmp(r.server, "nginx/1.30.3") == 0);
    CHECK(has_hit(&r, "nginx") && has_hit(&r, "php"));

    /* the same over TLS */
    {
        SSL_CTX *sctx = make_server_ctx();

        CHECK(sctx != NULL);
        CHECK(server_start(&sv, 1, sctx, REPLY) == 0);
        t.port = sv.port;
        t.tls = 1;
        CHECK(probe_one(&t, &o, adv, &r) == 0);
        if (r.error[0] != '\0')
            printf("https probe error: %s\n", r.error);
        server_stop(&sv);
        CHECK(r.status == 200 && has_hit(&r, "nginx"));
        SSL_CTX_free(sctx);
        t.tls = 0;
    }

    /* fixed versions are not reported */
    CHECK(server_start(&sv, 1, NULL,
                       "HTTP/1.1 200 OK\r\nServer: nginx/1.30.4\r\nX-Powered-By: PHP/8.2.35\r\n\r\n") ==
          0);
    t.port = sv.port;
    CHECK(probe_one(&t, &o, adv, &r) == 0);
    server_stop(&sv);
    CHECK(r.status == 200 && r.nhit == 0);

    /* closed port: error, no crash */
    tmp = net_listen_local(&dead_port);
    net_close(tmp);
    t.port = dead_port;
    CHECK(probe_one(&t, &o, adv, &r) != 0 && !r.connected && r.error[0] != '\0');

    /* not HTTP */
    CHECK(server_start(&sv, 1, NULL, "garbage\r\n\r\n") == 0);
    t.port = sv.port;
    CHECK(probe_one(&t, &o, adv, &r) != 0 && r.status == 0);
    server_stop(&sv);

    /* thread pool + rate limit: 3 targets, 2 threads, 100 ms between starts */
    CHECK(server_start(&sv, 3, NULL, REPLY) == 0);
    for (i = 0; i < 3; i++)
        tt[i] = t;
    for (i = 0; i < 3; i++)
        tt[i].port = sv.port;
    o.threads = 2;
    o.rate_ms = 100;
    {
        long long t0 = net_now_ms();

        CHECK(probe_run(tt, 3, &o, adv, many) == 0);
        CHECK(net_now_ms() - t0 >= 180); /* slots at 0, 100, 200 ms */
    }
    server_stop(&sv);
    for (i = 0; i < 3; i++)
        CHECK(many[i].status == 200);
    CHECK(probe_run(tt, PROBE_MAX_TARGETS + 1, &o, adv, many) == -1);
}

static void test_blocklist(void)
{
    const char *path = "tmp_blocklist.txt";
    unsigned char raw[32];
    char b64[64], hex[65] = "";
    spki_blocklist bl = {0};
    FILE *f;
    int i;
    static const char dig[] = "0123456789abcdef";

    for (i = 0; i < 32; i++) {
        raw[i] = (unsigned char)(i * 7 + 3);
        hex[2 * i] = dig[raw[i] >> 4];
        hex[2 * i + 1] = dig[raw[i] & 15];
    }
    hex[64] = '\0';
    CHECK(EVP_EncodeBlock((unsigned char *)b64, raw, 32) == 44);
    f = fopen(path, "w");
    CHECK(f != NULL);
    if (f == NULL)
        return;
    fprintf(f, "# comment\n\nAAAA label with spaces\n%s  my-label\n"
               "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD x\n"
               "%s second\nnot-a-hash\n",
            b64, "0000000000000000000000000000000000000000000000000000000000000000");
    fclose(f);
    CHECK(spki_blocklist_load(path, &bl) == 0);
    CHECK(bl.n == 3); /* base64, uppercase hex, zeros */
    CHECK(spki_blocklist_has(&bl, hex));
    CHECK(spki_blocklist_has(&bl, "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"));
    CHECK(!spki_blocklist_has(&bl, "1111111111111111111111111111111111111111111111111111111111111111"));
    spki_blocklist_free(&bl);
    remove(path);
    CHECK(spki_blocklist_load("tmp_no_such_blocklist.txt", &bl) == -1);

    CHECK(tls_detect_interception("CN=Norton Web/Mail Shield Root,O=Norton Web/Mail Shield") != NULL);
    CHECK(tls_detect_interception("CN=ISRG Root X1,O=Internet Security Research Group") == NULL);
}

static void test_tls(const adv_list *adv)
{
    server_t sv;
    SSL_CTX *sctx = make_server_ctx();
    tls_result r;
    spki_blocklist bl = {0};
    const char *path = "tmp_blocklist2.txt";
    FILE *f;

    CHECK(sctx != NULL);
    CHECK(server_start(&sv, 2, sctx, REPLY) == 0);

    CHECK(tls_audit_host("127.0.0.1", sv.port, 3000, NULL, adv, NULL, &r) == 0);
    CHECK(r.connected && r.ncerts == 1);
    CHECK(strncmp(r.protocol, "TLSv1", 5) == 0);
    CHECK(strlen(r.certs[0].spki_sha256) == 64);
    CHECK(r.certs[0].flags & TLSF_ISSUER_MATCH); /* the subject name is kept either way */
    CHECK(strcmp(r.certs[0].matched, "eMudhra") == 0);
    CHECK(!(r.certs[0].flags & (TLSF_EXPIRED | TLSF_BLOCKLISTED | TLSF_WEAK_KEY)));
    CHECK(r.verify_code != 0); /* untrusted either way */
    CHECK(!r.ocsp_stapled);
    if (r.interception[0] != '\0') {
        /* A local HTTPS scanner (e.g. Norton Web/Mail Shield) re-signed even this loopback
           connection: the detector must say so, and the cert is no longer our own. */
        printf("note: TLS inspection active on this machine (%s); skipping own-cert checks\n",
               r.interception);
        CHECK(strlen(r.interception) > 0);
    } else {
        CHECK(strcmp(r.certs[0].key_alg, "RSA") == 0 && r.certs[0].key_bits == 2048);
        CHECK(r.certs[0].flags & TLSF_SELF_SIGNED);
        CHECK(r.certs[0].days_left >= 28 && r.certs[0].days_left <= 30);
    }

    f = fopen(path, "w");
    CHECK(f != NULL);
    if (f != NULL) {
        fprintf(f, "%s test-key\n", r.certs[0].spki_sha256);
        fclose(f);
    }
    CHECK(spki_blocklist_load(path, &bl) == 0);
    CHECK(tls_audit_host("127.0.0.1", sv.port, 3000, NULL, adv, &bl, &r) == 0);
    CHECK(r.certs[0].flags & TLSF_BLOCKLISTED);
    server_stop(&sv);
    spki_blocklist_free(&bl);
    remove(path);
    SSL_CTX_free(sctx);

    /* nothing listening / not TLS */
    {
        unsigned short port;
        net_sock l = net_listen_local(&port);

        net_close(l);
        CHECK(tls_audit_host("127.0.0.1", port, 1000, NULL, adv, NULL, &r) == -1);
        CHECK(!r.connected && r.error[0] != '\0');
    }
    CHECK(server_start(&sv, 1, NULL, "not tls at all\r\n") == 0);
    CHECK(tls_audit_host("127.0.0.1", sv.port, 2000, NULL, adv, NULL, &r) == -1);
    server_stop(&sv);
    CHECK(!r.connected);
}

/* Plain server -> 301 to https://127.0.0.1:<tls port>/ -> 200 with a few security headers. */
static int serve_redirect(void)
{
    static const char *page =
        "HTTP/1.1 200 OK\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000\r\n"
        "X-Content-Type-Options: nosniff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static server_t tls_sv, plain_sv; /* threads may still use them when we return */
    static char reply[256];
    SSL_CTX *ctx = make_server_ctx();
    long long end;

    if (ctx == NULL || server_start(&tls_sv, 1, ctx, page) != 0)
        return 2;
    snprintf(reply, sizeof reply,
             "HTTP/1.1 301 Moved Permanently\r\nLocation: https://127.0.0.1:%u/\r\n"
             "Content-Length: 0\r\nConnection: close\r\n\r\n",
             (unsigned)tls_sv.port);
    if (server_start(&plain_sv, 1, NULL, reply) != 0)
        return 2;
    printf("%u\n", (unsigned)plain_sv.port);
    fflush(stdout);
    end = net_now_ms() + 20000;
    while (!(tls_sv.done && plain_sv.done) && net_now_ms() < end)
        net_sleep_ms(50);
    return tls_sv.done && plain_sv.done ? 0 : 1;
}

int main(int argc, char **argv)
{
    adv_list adv = {0};
    int nerr = 0;

    if (net_init() != 0) {
        printf("net_init failed\n");
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "--serve-redirect") == 0)
        _Exit(serve_redirect()); /* do not wait for server threads stuck in accept */
    if (adv_load(argc > 1 ? argv[1] : "data/advisories.txt", &adv, &nerr) != 0 || nerr != 0) {
        printf("cannot load advisories cleanly\n");
        return 2;
    }
    test_targets();
    test_banners();
    test_blocklist();
    test_http(&adv);
    test_tls(&adv);
    adv_free(&adv);
    net_cleanup();
    printf("%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
