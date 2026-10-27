/* Tests for report.c, report_html.c and webcheck.c (exit codes, text/JSON/HTML output, website
   settings, redirect rules). No network.
   Usage: reporttests [advisories.txt]
          reporttests --check-json <file>   (exit 0 if the file holds exactly one valid JSON value)
          reporttests --sample-html <file>  (writes a demo client report from made-up data)
   Fake secrets are assembled from pieces so this file does not itself look like a leak. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#define RMDIR(p) _rmdir(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define MKDIR(p) mkdir((p), 0755)
#define RMDIR(p) rmdir(p)
#endif

#include "../src/advisory.h"
#include "../src/fsutil.h"
#include "../src/report.h"

static int g_run, g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_run++;                                                             \
        if (!(cond)) {                                                       \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

#define TMP_OUT "tmp_report_out.txt"

/* ---------- a strict little JSON checker (RFC 8259, UTF-8) ---------- */

typedef struct {
    const unsigned char *p, *end;
    int depth;
} jp;

static void ws(jp *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static int lit(jp *j, const char *s)
{
    size_t n = strlen(s);

    if ((size_t)(j->end - j->p) < n || memcmp(j->p, s, n) != 0)
        return -1;
    j->p += n;
    return 0;
}

static int hex4(const unsigned char *p)
{
    int i;

    for (i = 0; i < 4; i++)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f') ||
              (p[i] >= 'A' && p[i] <= 'F')))
            return -1;
    return 0;
}

static int str(jp *j)
{
    if (j->p >= j->end || *j->p != '"')
        return -1;
    j->p++;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = *j->p;

        if (c < 0x20)
            return -1;
        if (c == '\\') {
            if (j->end - j->p < 2)
                return -1;
            c = j->p[1];
            if (c == 'u') {
                if (j->end - j->p < 6 || hex4(j->p + 2) != 0)
                    return -1;
                j->p += 6;
            } else if (strchr("\"\\/bfnrt", c) != NULL && c != '\0') {
                j->p += 2;
            } else {
                return -1;
            }
        } else if (c < 0x80) {
            j->p++;
        } else {
            /* multi-byte: lead byte + continuation bytes, no overlong/surrogate/>U+10FFFF */
            int n = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3
                    : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
            int k;

            if (n == 0 || j->end - j->p < n)
                return -1;
            for (k = 1; k < n; k++)
                if ((j->p[k] & 0xC0) != 0x80)
                    return -1;
            if ((c == 0xE0 && j->p[1] < 0xA0) || (c == 0xED && j->p[1] > 0x9F) ||
                (c == 0xF0 && j->p[1] < 0x90) || (c == 0xF4 && j->p[1] > 0x8F))
                return -1;
            j->p += n;
        }
    }
    if (j->p >= j->end)
        return -1;
    j->p++;
    return 0;
}

static int num(jp *j)
{
    const unsigned char *s = j->p;

    if (j->p < j->end && *j->p == '-')
        j->p++;
    if (j->p >= j->end)
        return -1;
    if (*j->p == '0') {
        j->p++;
    } else if (*j->p >= '1' && *j->p <= '9') {
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
            j->p++;
    } else {
        return -1;
    }
    if (j->p < j->end && *j->p == '.') {
        j->p++;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9')
            return -1;
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
            j->p++;
    }
    if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
        j->p++;
        if (j->p < j->end && (*j->p == '+' || *j->p == '-'))
            j->p++;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9')
            return -1;
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
            j->p++;
    }
    return j->p > s ? 0 : -1;
}

static int value(jp *j);

static int container(jp *j, char close, int is_obj)
{
    j->p++; /* the opening bracket */
    if (++j->depth > 64)
        return -1;
    ws(j);
    if (j->p < j->end && *j->p == close) {
        j->p++;
        j->depth--;
        return 0;
    }
    for (;;) {
        ws(j);
        if (is_obj) {
            if (str(j) != 0)
                return -1;
            ws(j);
            if (j->p >= j->end || *j->p != ':')
                return -1;
            j->p++;
        }
        if (value(j) != 0)
            return -1;
        ws(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            continue;
        }
        if (j->p < j->end && *j->p == close) {
            j->p++;
            j->depth--;
            return 0;
        }
        return -1;
    }
}

static int value(jp *j)
{
    ws(j);
    if (j->p >= j->end)
        return -1;
    switch (*j->p) {
    case '{': return container(j, '}', 1);
    case '[': return container(j, ']', 0);
    case '"': return str(j);
    case 't': return lit(j, "true");
    case 'f': return lit(j, "false");
    case 'n': return lit(j, "null");
    default: return num(j);
    }
}

/* 0 when buf[0..n) is exactly one JSON value plus optional whitespace. */
static int json_valid(const char *buf, size_t n)
{
    jp j;

    j.p = (const unsigned char *)buf;
    j.end = j.p + n;
    j.depth = 0;
    if (value(&j) != 0)
        return -1;
    ws(&j);
    return j.p == j.end ? 0 : -1;
}

static char *read_all(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long n;

    if (f == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    *len = (size_t)n;
    return buf;
}

/* ---------- capture helpers ---------- */

static FILE *cap_open(void)
{
    FILE *f = fopen(TMP_OUT, "wb");

    if (f == NULL) {
        printf("cannot write %s\n", TMP_OUT);
        exit(2);
    }
    return f;
}

static char *cap_close(FILE *f, size_t *len)
{
    char *s;

    fclose(f);
    s = read_all(TMP_OUT, len);
    remove(TMP_OUT);
    if (s == NULL) {
        printf("cannot read %s\n", TMP_OUT);
        exit(2);
    }
    return s;
}

static char *json_of_string(const char *in)
{
    FILE *f = cap_open();
    size_t n;

    report_json_string(f, in);
    return cap_close(f, &n);
}

static int js_is(const char *in, const char *expect)
{
    char *s = json_of_string(in);
    int ok = strcmp(s, expect) == 0;

    if (!ok)
        printf("  json_string got %s, expected %s\n", s, expect);
    free(s);
    return ok;
}

static char *json_of(const scan_report *r, const char *cmd, size_t *n)
{
    FILE *f = cap_open();

    report_print_json(r, cmd, f);
    return cap_close(f, n);
}

static char *text_of(const scan_report *r, size_t *n)
{
    FILE *f = cap_open();

    report_print_text(r, f);
    return cap_close(f, n);
}

/* ---------- tests ---------- */

static void test_checker(void)
{
    static const char *const good[] = {"{}", "[]", "0", "-1.5e+3", "\"a\\u00e9\"", "true",
                                       " {\"a\":[1,2,{\"b\":null}]} \n", "\"\xc3\xa9\""};
    static const char *const bad[] = {"", "{", "{\"a\"}", "[1,]", "01", "\"\x01\"", "\"\\x\"",
                                      "\"\xe9\"", "\"\xc0\xaf\"", "\"\xed\xa0\x80\"", "{} {}",
                                      "tru", "{'a':1}"};
    size_t i;

    for (i = 0; i < sizeof good / sizeof good[0]; i++)
        CHECK(json_valid(good[i], strlen(good[i])) == 0);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(json_valid(bad[i], strlen(bad[i])) != 0);
}

static void test_json_string(void)
{
    CHECK(js_is("plain", "\"plain\""));
    CHECK(js_is("", "\"\""));
    CHECK(js_is(NULL, "\"\""));
    CHECK(js_is("a\"b\\c", "\"a\\\"b\\\\c\""));
    CHECK(js_is("C:\\Users\\x", "\"C:\\\\Users\\\\x\""));
    CHECK(js_is("\n\r\t", "\"\\n\\r\\t\""));
    CHECK(js_is("\x01\x1f\x7f", "\"\\u0001\\u001f\\u007f\""));
    CHECK(js_is("\xc3\xa9", "\"\xc3\xa9\""));                  /* e acute */
    CHECK(js_is("\xe2\x82\xac", "\"\xe2\x82\xac\""));          /* euro */
    CHECK(js_is("\xf0\x9f\x98\x80", "\"\xf0\x9f\x98\x80\""));  /* emoji */
    CHECK(js_is("caf\xe9", "\"caf\\ufffd\""));                 /* CP1252 byte */
    CHECK(js_is("\xc0\xaf", "\"\\ufffd\\ufffd\""));            /* overlong '/' */
    CHECK(js_is("\xed\xa0\x80", "\"\\ufffd\\ufffd\\ufffd\"")); /* surrogate */
    CHECK(js_is("\xf4\x90\x80\x80", "\"\\ufffd\\ufffd\\ufffd\\ufffd\"")); /* > U+10FFFF */
    CHECK(js_is("\xe2\x82", "\"\\ufffd\\ufffd\""));            /* cut short at the end */
    CHECK(js_is("\xf5x", "\"\\ufffdx\""));
}

static void test_protocols(void)
{
    CHECK(tls_protocol_is_weak("TLSv1") == 1); /* OpenSSL's name for TLS 1.0 */
    CHECK(tls_protocol_is_weak("TLSv1.1") == 1);
    CHECK(tls_protocol_is_weak("SSLv3") == 1);
    CHECK(tls_protocol_is_weak("TLSv1.2") == 0);
    CHECK(tls_protocol_is_weak("TLSv1.3") == 0);
    CHECK(tls_protocol_is_weak("") == 0);
}

/* ---------- website settings ---------- */

static int nweb;
static web_check webs[WEB_MAX_CHECKS];

static void wc(const char *headers, int https, int status)
{
    nweb = web_check_headers(headers, https, status, webs, WEB_MAX_CHECKS);
}

/* level of check id, -1 if absent */
static int lvl(const char *id)
{
    int i;

    for (i = 0; i < nweb; i++)
        if (strcmp(webs[i].id, id) == 0)
            return webs[i].level;
    return -1;
}

static const char *det(const char *id)
{
    int i;

    for (i = 0; i < nweb; i++)
        if (strcmp(webs[i].id, id) == 0)
            return webs[i].detail;
    return "";
}

static void test_webcheck(void)
{
    static const char *const ids[] = {"https_redirect", "hsts", "csp", "frame", "nosniff",
                                      "referrer", "cookies", "server_version", "powered_by",
                                      "redirect", "not_checked"};
    char v[64];
    size_t i;

    /* plain http */
    wc("Location: https://shop.example/\r\nServer: nginx\r\n\r\n", 0, 301);
    CHECK(lvl("https_redirect") == WEB_OK && lvl("hsts") == -1 && lvl("csp") == -1);
    CHECK(lvl("server_version") == WEB_OK && lvl("powered_by") == WEB_OK);
    wc("Server: nginx\r\n\r\n", 0, 200);
    CHECK(lvl("https_redirect") == WEB_IMPORTANT);
    wc("Location: http://www.shop.example/\r\n\r\n", 0, 302);
    CHECK(lvl("https_redirect") == WEB_IMPORTANT);
    CHECK(strstr(det("https_redirect"), "http://www.shop.example/") != NULL);

    /* a well-configured https page */
    wc("Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
       "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'\r\n"
       "x-content-type-options: NOSNIFF\r\n"
       "Referrer-Policy: strict-origin-when-cross-origin\r\n"
       "Set-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
       "Server: nginx\r\n\r\n",
       1, 200);
    CHECK(lvl("hsts") == WEB_OK && lvl("csp") == WEB_OK && lvl("frame") == WEB_OK);
    CHECK(lvl("nosniff") == WEB_OK && lvl("referrer") == WEB_OK && lvl("cookies") == WEB_OK);
    CHECK(lvl("server_version") == WEB_OK && lvl("powered_by") == WEB_OK);
    CHECK(lvl("https_redirect") == -1 && lvl("redirect") == -1 && lvl("not_checked") == -1);
    CHECK(strstr(det("cookies"), "abc123") == NULL);

    /* nothing set */
    wc("Server: Apache/2.4.58 (Ubuntu)\r\nX-Powered-By: PHP/8.2.1\r\n"
       "Set-Cookie: PHPSESSID=s3cr3tvalue; path=/\r\n"
       "Set-Cookie: pref=NotSecure; HttpOnly\r\n\r\n",
       1, 200);
    CHECK(lvl("hsts") == WEB_RECOMMENDED && lvl("csp") == WEB_TIP);
    CHECK(lvl("frame") == WEB_RECOMMENDED && lvl("nosniff") == WEB_RECOMMENDED);
    CHECK(lvl("referrer") == WEB_TIP);
    CHECK(lvl("server_version") == WEB_TIP && lvl("powered_by") == WEB_TIP);
    CHECK(lvl("cookies") == WEB_RECOMMENDED);
    CHECK(strstr(det("cookies"), "PHPSESSID") != NULL && strstr(det("cookies"), "pref") != NULL);
    CHECK(strstr(det("cookies"), "s3cr3tvalue") == NULL); /* names only, never values */
    CHECK(strstr(det("server_version"), "Apache/2.4.58") != NULL);

    /* cookies: Secure everywhere but HttpOnly missing is only a tip; http skips Secure */
    wc("Set-Cookie: a=1; Secure\r\n\r\n", 1, 200);
    CHECK(lvl("cookies") == WEB_TIP);
    wc("Set-Cookie: a=1; HttpOnly\r\n\r\n", 0, 200);
    CHECK(lvl("cookies") == WEB_OK);

    /* HSTS strength, quoting and case */
    wc("Strict-Transport-Security: max-age=300\r\n\r\n", 1, 200);
    CHECK(lvl("hsts") == WEB_TIP);
    wc("Strict-Transport-Security: max-age=0\r\n\r\n", 1, 200);
    CHECK(lvl("hsts") == WEB_RECOMMENDED);
    wc("strict-transport-security: MAX-AGE = \"63072000\"\r\n\r\n", 1, 200);
    CHECK(lvl("hsts") == WEB_OK);
    wc("Strict-Transport-Security: includeSubDomains\r\n\r\n", 1, 200);
    CHECK(lvl("hsts") == WEB_RECOMMENDED);

    /* framing and policies */
    wc("X-Frame-Options: ALLOW-FROM https://x.example\r\n\r\n", 1, 200);
    CHECK(lvl("frame") == WEB_RECOMMENDED);
    wc("X-Frame-Options: deny\r\nContent-Security-Policy-Report-Only: default-src 'self'\r\n"
       "Referrer-Policy: unsafe-url\r\n\r\n",
       1, 200);
    CHECK(lvl("frame") == WEB_OK && lvl("csp") == WEB_TIP && lvl("referrer") == WEB_TIP);

    /* https redirect and error responses skip the page checks */
    wc("Location: https://www.shop.example/\r\n\r\n", 1, 301);
    CHECK(lvl("redirect") == WEB_NOTE && lvl("hsts") == WEB_RECOMMENDED && lvl("csp") == -1);
    wc("Server: cloudflare\r\n\r\n", 1, 403);
    CHECK(lvl("not_checked") == WEB_NOTE && lvl("frame") == -1);

    /* headers end at the first empty line */
    wc("Server: nginx\r\n\r\nX-Frame-Options: DENY\r\n", 1, 200);
    CHECK(lvl("frame") == WEB_RECOMMENDED);
    wc("Server: nginx\n\nX-Frame-Options: DENY\n", 1, 200);
    CHECK(lvl("frame") == WEB_RECOMMENDED);
    wc("", 1, 200);
    CHECK(nweb > 0 && lvl("hsts") == WEB_RECOMMENDED);
    wc(NULL, 0, 200);
    CHECK(lvl("https_redirect") == WEB_IMPORTANT);

    /* server-controlled text with printf directives is copied literally */
    wc("Server: evil/1.0 %s%n%x\r\nX-Powered-By: 100%\r\nX-Frame-Options: %n%n\r\n"
       "Set-Cookie: %s%n=1\r\n\r\n",
       1, 200);
    CHECK(strcmp(det("server_version"), "evil/1.0 %s%n%x") == 0);
    CHECK(strcmp(det("powered_by"), "100%") == 0);
    CHECK(strcmp(det("frame"), "%n%n") == 0);
    CHECK(strcmp(det("cookies"), "without Secure: %s%n") == 0);

    /* whole-TLD HSTS preload (.dev/.app/.page): http and HSTS cannot fail there */
    CHECK(web_tld_preloaded("my-app.example-user.workers.dev") == 1);
    CHECK(web_tld_preloaded("SHOP.APP") == 1 && web_tld_preloaded("x.page") == 1);
    CHECK(web_tld_preloaded("dev.example.com") == 0);
    CHECK(web_tld_preloaded("example.devx") == 0 && web_tld_preloaded("example.de") == 0);
    CHECK(web_tld_preloaded("dev") == 0 && web_tld_preloaded("") == 0);
    wc("Server: cloudflare\r\n\r\n", 0, 200);
    web_apply_preload("site.workers.dev", webs, nweb);
    CHECK(lvl("https_redirect") == WEB_OK && strstr(det("https_redirect"), ".dev") != NULL);
    wc("Server: cloudflare\r\n\r\n", 1, 200);
    web_apply_preload("site.workers.dev", webs, nweb);
    CHECK(lvl("hsts") == WEB_OK && lvl("frame") == WEB_RECOMMENDED); /* only those two */
    wc("Server: cloudflare\r\n\r\n", 1, 200);
    web_apply_preload("shop.example", webs, nweb);
    CHECK(lvl("hsts") == WEB_RECOMMENDED);

    /* small output buffer: no overflow, count capped */
    CHECK(web_check_headers("", 1, 200, webs, 2) == 2);

    CHECK(web_header_value("A: 1\r\nB:   two  \r\n\r\n", "b", v, sizeof v) == 1 &&
          strcmp(v, "two") == 0);
    CHECK(web_header_value("AB: 1\r\n\r\n", "A", v, sizeof v) == 0 && v[0] == '\0');
    CHECK(web_header_value("A: 123456789\r\n", "A", v, 4) == 1 && strcmp(v, "123") == 0);

    for (i = 0; i < sizeof ids / sizeof ids[0]; i++)
        CHECK(web_check_info(ids[i]) != NULL);
    CHECK(web_check_info("nope") == NULL);
    CHECK(strcmp(web_level_name(WEB_IMPORTANT), "important") == 0);
    CHECK(strcmp(web_level_name(99), "unknown") == 0);
}

static int redir(const char *host, int tls, unsigned short port, int status, const char *loc,
                 probe_target *out)
{
    probe_result r;

    memset(&r, 0, sizeof r);
    snprintf(r.t.host, sizeof r.t.host, "%s", host);
    r.t.tls = tls;
    r.t.port = port;
    r.connected = 1;
    r.status = status;
    snprintf(r.location, sizeof r.location, "%s", loc);
    return probe_redirect_target(&r, out);
}

static int fix_has(const char *platform, const char *id, const char *needle)
{
    char out[400];

    if (!web_platform_fix(platform, id, out, sizeof out))
        return 0;
    if (strstr(out, needle) != NULL)
        return 1;
    printf("  fix for %s/%s lacks \"%s\": %s\n", platform, id, needle, out);
    return 0;
}

static int plat_is(const char *headers, const char *host, const char *want)
{
    const char *got = web_detect_platform(headers, host);

    if ((got == NULL && want == NULL) || (got != NULL && want != NULL && strcmp(got, want) == 0))
        return 1;
    printf("  platform for %s: %s, want %s\n", host, got ? got : "(none)", want ? want : "(none)");
    return 0;
}

static void test_platforms(void)
{
    char out[400];

    CHECK(plat_is("Server: GitHub.com\r\n\r\n", "shop.example", "github-pages"));
    CHECK(plat_is("Server: nginx\r\n\r\n", "me.github.io", "github-pages"));
    CHECK(plat_is("Server: cloudflare\r\n\r\n", "x.pages.dev", "cloudflare-static"));
    CHECK(plat_is("Server: cloudflare\r\n\r\n", "a.b.workers.dev", "cloudflare-static"));
    CHECK(plat_is("Server: cloudflare\r\n\r\n", "shop.example", "cloudflare"));
    CHECK(plat_is("X-Vercel-Id: fra1::abc\r\nServer: Vercel\r\n\r\n", "shop.example", "vercel"));
    CHECK(plat_is("Server: Netlify\r\n\r\n", "shop.example", "netlify"));
    CHECK(plat_is("x-wix-request-id: 1.2\r\n\r\n", "shop.example", "wix"));
    CHECK(plat_is("X-ShopId: 42\r\nServer: cloudflare\r\n\r\n", "shop.example", "shopify"));
    CHECK(plat_is("Server: Squarespace\r\n\r\n", "shop.example", "squarespace"));
    CHECK(plat_is("Server: Apache/2.4.58 (Ubuntu)\r\n\r\n", "shop.example", "apache"));
    CHECK(plat_is("Server: LiteSpeed\r\n\r\n", "shop.example", "litespeed"));
    CHECK(plat_is("Server: nginx/1.24.0\r\n\r\n", "shop.example", "nginx"));
    CHECK(plat_is("Server: Microsoft-IIS/10.0\r\n\r\n", "shop.example", "iis"));
    CHECK(plat_is("Server: gws\r\n\r\n", "shop.example", NULL));
    CHECK(plat_is("", "shop.example", NULL));
    CHECK(plat_is(NULL, NULL, NULL));
    CHECK(strcmp(web_platform_name("github-pages"), "GitHub Pages") == 0);
    CHECK(strcmp(web_platform_name("nope"), "nope") == 0 && web_platform_name(NULL) == NULL);

    /* GitHub Pages: no header settings; meta tags where they work; Enforce HTTPS */
    CHECK(fix_has("github-pages", "frame", "no setting"));
    CHECK(fix_has("github-pages", "nosniff", "can't be added inside the page"));
    CHECK(fix_has("github-pages", "referrer", "<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">"));
    CHECK(fix_has("github-pages", "csp", "<meta http-equiv=\"Content-Security-Policy\""));
    CHECK(fix_has("github-pages", "https_redirect", "Settings > Pages"));
    /* config-file and dashboard platforms get the exact line */
    CHECK(fix_has("cloudflare-static", "nosniff", "_headers") && fix_has("cloudflare-static", "nosniff", "X-Content-Type-Options: nosniff"));
    CHECK(fix_has("cloudflare", "https_redirect", "Always Use HTTPS"));
    CHECK(fix_has("cloudflare", "hsts", "Enable HSTS"));
    CHECK(fix_has("cloudflare", "frame", "Transform Rule") && fix_has("cloudflare", "frame", "X-Frame-Options to SAMEORIGIN"));
    CHECK(fix_has("vercel", "referrer", "vercel.json") && fix_has("vercel", "referrer", "\"Referrer-Policy\""));
    CHECK(fix_has("apache", "frame", "Header always set X-Frame-Options \"SAMEORIGIN\""));
    CHECK(fix_has("nginx", "nosniff", "add_header X-Content-Type-Options \"nosniff\" always;"));
    CHECK(fix_has("wix", "frame", "Ask Wix support"));
    /* general advice where nothing platform-specific was checked */
    CHECK(web_platform_fix("netlify", "frame", out, sizeof out) == 0);
    CHECK(web_platform_fix("apache", "csp", out, sizeof out) == 0);
    CHECK(web_platform_fix("cloudflare-static", "cookies", out, sizeof out) == 0);
    CHECK(web_platform_fix(NULL, "frame", out, sizeof out) == 0);
}

static void test_redirects(void)
{
    probe_target t;

    CHECK(redir("shop.example", 0, 80, 301, "https://www.shop.example/", &t) == 1);
    CHECK(strcmp(t.host, "www.shop.example") == 0 && t.tls == 1 && t.port == 443);
    CHECK(redir("shop.example", 0, 80, 308, "https://shop.example/", &t) == 1);
    CHECK(redir("www.shop.example", 1, 443, 302, "https://SHOP.example/", &t) == 1);
    CHECK(redir("shop.example", 1, 443, 301, "https://shop.example:8443/x", &t) == 1 &&
          t.port == 8443);
    /* never off-site */
    CHECK(redir("shop.example", 1, 443, 301, "https://evil.example/", &t) == 0);
    CHECK(redir("shop.example", 1, 443, 301, "https://www.shop.example.evil.example/", &t) == 0);
    CHECK(redir("shop.example", 1, 443, 301, "https://wwwshop.example/", &t) == 0);
    CHECK(redir("shop.example", 1, 443, 301, "https://notshop.example/", &t) == 0);
    /* not https, not a redirect, or back to itself */
    CHECK(redir("shop.example", 0, 80, 301, "http://www.shop.example/", &t) == 0);
    CHECK(redir("shop.example", 0, 80, 301, "/login", &t) == 0);
    CHECK(redir("shop.example", 0, 80, 200, "https://www.shop.example/", &t) == 0);
    CHECK(redir("shop.example", 1, 443, 301, "https://shop.example/en/", &t) == 0);
    CHECK(redir("shop.example", 0, 80, 301, "", &t) == 0);
}

static void set_cert(tls_cert_info *c, const char *subject, unsigned flags)
{
    memset(c, 0, sizeof *c);
    snprintf(c->subject, sizeof c->subject, "%s", subject);
    snprintf(c->issuer, sizeof c->issuer, "CN=Test \"Root\" CA");
    snprintf(c->key_alg, sizeof c->key_alg, "RSA");
    c->key_bits = 2048;
    snprintf(c->not_before, sizeof c->not_before, "Jan  1 00:00:00 2025 GMT");
    snprintf(c->not_after, sizeof c->not_after, "Jan  1 00:00:00 2026 GMT");
    c->days_left = (flags & TLSF_EXPIRED) ? -5 : 300;
    memset(c->spki_sha256, 'a', 64);
    c->flags = flags;
}

static void test_exit_codes(void)
{
    scan_report r;
    secret_hit sh;
    py_finding pf;
    probe_result pr[2];
    tls_result *tr = calloc(2, sizeof *tr);

    if (tr == NULL)
        exit(2);
    memset(&r, 0, sizeof r);
    CHECK(report_exit_code(&r) == 0);
    CHECK(report_rc_secrets(&r) == -1 && report_rc_tls(&r) == -1);
    CHECK(report_count_findings(&r) == 0);

    /* secrets: clean, findings, error */
    r.run_secrets = 1;
    CHECK(report_exit_code(&r) == 0);
    memset(&sh, 0, sizeof sh);
    r.secrets.h = &sh;
    r.secrets.n = 1;
    CHECK(report_rc_secrets(&r) == 1 && report_exit_code(&r) == 1);
    r.secrets.n = 0;
    r.secrets_error = 1;
    CHECK(report_rc_secrets(&r) == 2 && report_exit_code(&r) == 2);

    /* findings elsewhere win over an error */
    memset(&pf, 0, sizeof pf);
    r.run_py = 1;
    r.py.f = &pf;
    r.py.n = 1;
    CHECK(report_rc_py(&r) == 1 && report_exit_code(&r) == 1);
    CHECK(report_count_findings(&r) == 1);
    memset(&r, 0, sizeof r);

    /* http: one failed + one clean -> 0; both failed -> 2; a hit -> 1 */
    memset(pr, 0, sizeof pr);
    pr[1].connected = 1;
    pr[1].status = 200;
    r.http = pr;
    r.nhttp = 2;
    CHECK(report_rc_http(&r) == 0);
    pr[1].status = 0;
    CHECK(report_rc_http(&r) == 2);
    pr[1].status = 200;
    pr[1].nhit = 2;
    CHECK(report_rc_http(&r) == 1 && report_count_findings(&r) == 2);
    memset(&r, 0, sizeof r);

    /* tls: not connected -> 2; self-signed/expiring/weak key are notes, not findings */
    r.tls = tr;
    r.ntls = 1;
    CHECK(report_rc_tls(&r) == 2);
    tr[0].connected = 1;
    tr[0].ncerts = 1;
    set_cert(&tr[0].certs[0], "CN=a", TLSF_SELF_SIGNED | TLSF_EXPIRES_SOON | TLSF_WEAK_KEY);
    CHECK(report_rc_tls(&r) == 0 && report_count_findings(&r) == 0);
    set_cert(&tr[0].certs[0], "CN=a", TLSF_EXPIRED);
    CHECK(report_rc_tls(&r) == 1);
    set_cert(&tr[0].certs[0], "CN=a", TLSF_BLOCKLISTED);
    CHECK(report_rc_tls(&r) == 1);
    set_cert(&tr[0].certs[0], "CN=a", TLSF_ISSUER_MATCH);
    CHECK(report_rc_tls(&r) == 1 && report_count_findings(&r) == 1);
    /* second target failed: still 1 because the first has a finding */
    r.ntls = 2;
    CHECK(report_rc_tls(&r) == 1);
    free(tr);
}

static int has(const char *hay, const char *needle)
{
    if (strstr(hay, needle) != NULL)
        return 1;
    printf("  missing: %s\n", needle);
    return 0;
}

/* A report with every module, including awkward strings. Arrays are on the stack and
   handed to the report only for printing (not freed by report_free). */
static void test_json_full(void)
{
    scan_report r;
    secret_hit sh[2];
    py_finding pf;
    probe_result pr[2];
    tls_result *tr = calloc(2, sizeof *tr);
    char *s;
    size_t n;

    if (tr == NULL)
        exit(2);
    memset(&r, 0, sizeof r);
    memset(sh, 0, sizeof sh);
    memset(&pf, 0, sizeof pf);
    memset(pr, 0, sizeof pr);
    r.root = "C:\\proj\\caf\xe9";

    r.run_secrets = 1;
    snprintf(sh[0].path, sizeof sh[0].path, "C:\\proj\\a \"q\".env");
    sh[0].line = 3;
    snprintf(sh[0].rule, sizeof sh[0].rule, "aws-access-key");
    snprintf(sh[0].masked, sizeof sh[0].masked, "****MPLE");
    sh[0].tracked = 1;
    snprintf(sh[1].path, sizeof sh[1].path, "b.txt");
    sh[1].line = 1;
    snprintf(sh[1].rule, sizeof sh[1].rule, "secret-assignment");
    sh[1].tracked = -1; /* masked left empty */
    r.secrets.h = sh;
    r.secrets.n = 2;
    r.secrets.files_scanned = 7;

    r.run_py = 1;
    pf.severity = 2;
    snprintf(pf.kind, sizeof pf.kind, "installed-package");
    snprintf(pf.path, sizeof pf.path, "venv/Lib/site-packages/litellm-1.107.0.dist-info");
    snprintf(pf.name, sizeof pf.name, "litellm");
    snprintf(pf.version, sizeof pf.version, "1.107.0");
    snprintf(pf.detail, sizeof pf.detail, "tab\there, newline\nthere");
    r.py.f = &pf;
    r.py.n = 1;

    snprintf(pr[0].t.host, sizeof pr[0].t.host, "a.example");
    pr[0].t.port = 443;
    pr[0].t.tls = 1;
    pr[0].connected = 1;
    pr[0].status = 200;
    snprintf(pr[0].server, sizeof pr[0].server, "nginx/1.0.0");
    pr[0].nhit = 1;
    snprintf(pr[0].hit[0].product, sizeof pr[0].hit[0].product, "nginx");
    snprintf(pr[0].hit[0].version, sizeof pr[0].hit[0].version, "1.0.0");
    snprintf(pr[0].hit[0].source, sizeof pr[0].hit[0].source, "Server");
    snprintf(pr[0].hit[0].fixed, sizeof pr[0].hit[0].fixed, ">= 9.9.9");
    /* hsts, csp, frame, nosniff, referrer + server_version, powered_by: 3 recommended, 4 tips
       (powered_by is a tip only when present, so give it one) */
    pr[0].nweb = web_check_headers("Server: nginx/1.0.0\r\nX-Powered-By: x\r\n\r\n", 1, 200,
                                   pr[0].web, WEB_MAX_CHECKS);
    snprintf(pr[1].t.host, sizeof pr[1].t.host, "::1");
    pr[1].t.port = 8080;
    snprintf(pr[1].error, sizeof pr[1].error, "connection refused");
    r.http = pr;
    r.nhttp = 2;

    snprintf(tr[0].host, sizeof tr[0].host, "a.example");
    tr[0].port = 443;
    tr[0].connected = 1;
    snprintf(tr[0].protocol, sizeof tr[0].protocol, "TLSv1");
    snprintf(tr[0].cipher, sizeof tr[0].cipher, "AES128-SHA");
    snprintf(tr[0].verify_text, sizeof tr[0].verify_text, "ok");
    snprintf(tr[0].ocsp_status, sizeof tr[0].ocsp_status, "not stapled");
    tr[0].ncerts = 2;
    set_cert(&tr[0].certs[0], "CN=a.example", TLSF_EXPIRED | TLSF_SELF_SIGNED);
    set_cert(&tr[0].certs[1], "CN=Bad CA", TLSF_ISSUER_MATCH);
    snprintf(tr[0].certs[1].matched, sizeof tr[0].certs[1].matched, "eMudhra");
    snprintf(tr[1].host, sizeof tr[1].host, "b.example");
    tr[1].port = 8443;
    snprintf(tr[1].error, sizeof tr[1].error, "handshake failed");
    r.tls = tr;
    r.ntls = 2;

    s = json_of(&r, "all", &n);
    CHECK(json_valid(s, n) == 0);
    CHECK(n > 0 && s[n - 1] == '\n');
    CHECK(has(s, "{\"tool\":\"exposure-scanner\",\"version\":\"" SCANNER_VERSION "\""));
    CHECK(has(s, "\"command\":\"all\""));
    CHECK(has(s, "\"root\":\"C:\\\\proj\\\\caf\\ufffd\""));
    CHECK(has(s, "\"path\":\"C:\\\\proj\\\\a \\\"q\\\".env\""));
    CHECK(has(s, "\"value_masked\":\"****MPLE\",\"git_tracked\":true"));
    CHECK(has(s, "\"value_masked\":null,\"git_tracked\":null"));
    CHECK(has(s, "\"files_scanned\":7"));
    CHECK(has(s, "\"severity\":\"affected\""));
    CHECK(has(s, "\"line\":null"));
    CHECK(has(s, "tab\\there, newline\\nthere"));
    CHECK(has(s, "\"http_status\":200,\"platform\":null,\"redirected_from\":null,\"location\":null,"
                 "\"server\":\"nginx/1.0.0\",\"x_powered_by\":null,\"settings\":["));
    CHECK(has(s, "{\"id\":\"hsts\",\"level\":\"recommended\",\"title\":\"Browsers are not told"));
    CHECK(has(s, "{\"id\":\"server_version\",\"level\":\"tip\""));
    CHECK(has(s, "\"settings_issues\":{\"important\":0,\"recommended\":3,\"tip\":4}"));
    CHECK(has(s, "\"advisory_url\":null"));
    CHECK(has(s, "{\"host\":\"::1\",\"port\":8080,\"scheme\":\"http\",\"result\":false,"
                 "\"error\":\"connection refused\"}"));
    CHECK(has(s, "\"protocol\":\"TLSv1\",\"cipher\":\"AES128-SHA\",\"weak_protocol\":true"));
    CHECK(has(s, "\"interception\":null,\"flagged\":true"));
    CHECK(has(s, "\"issuer\":\"CN=Test \\\"Root\\\" CA\""));
    CHECK(has(s, "\"flags\":[\"expired\",\"self_signed\"],\"advisory_match\":null"));
    CHECK(has(s, "\"flags\":[\"advisory_issuer\"],\"advisory_match\":\"eMudhra\""));
    CHECK(has(s, "\"days_left\":-5"));
    CHECK(has(s, "{\"host\":\"b.example\",\"port\":8443,\"result\":false,"
                 "\"error\":\"handshake failed\"}"));
    /* 2 secrets + 1 py + 1 http hit + 2 flagged certs; settings do not count */
    CHECK(has(s, "\"findings\":6,\"settings_issues\":"));
    CHECK(has(s, ",\"exit_code\":1}"));
    /* the client report's verdict, for the desktop app */
    CHECK(has(s, "\"summary\":{\"important\":"));
    CHECK(has(s, "\"ready_to_send\":false,\"warnings\":[\"An address could not be reached."));
    CHECK(has(s, "\"issues\":[{\"level\":\"important\",\"site\":"));
    CHECK(has(s, "\"title\":\"Found an AWS access key in the code\""));
    CHECK(has(s, ".env, line 3, value ****MPLE, saved in git history\"}")); /* where, for the app */
    free(s);

    /* text: headers and a summary only when more than one module ran */
    s = text_of(&r, &n);
    CHECK(has(s, "== secrets: C:\\proj\\caf\xe9 =="));
    CHECK(has(s, "== tls certificates =="));
    CHECK(has(s, "!! weak protocol negotiated: TLSv1"));
    CHECK(has(s, "6 finding(s) in total, exit code 1."));
    free(s);
    r.run_secrets = r.run_py = 0;
    r.nhttp = 0;
    s = text_of(&r, &n);
    CHECK(strstr(s, "\n== ") == NULL);
    free(s);

    /* module errors */
    memset(&r, 0, sizeof r);
    r.run_secrets = r.secrets_error = 1;
    r.root = ".";
    s = json_of(&r, "secrets", &n);
    CHECK(json_valid(s, n) == 0);
    CHECK(has(s, "\"secrets\":{\"status\":\"error\",\"error\":"));
    CHECK(has(s, "\"exit_code\":2}"));
    free(s);
    free(tr);
}

/* ---------- HTML report ---------- */

static char *html_of(const scan_report *r, const report_meta *m, int *warnings, size_t *n)
{
    FILE *f = cap_open();

    *warnings = report_write_html(r, m, f);
    return cap_close(f, n);
}

static int count(const char *s, const char *needle)
{
    int c = 0;

    while ((s = strstr(s, needle)) != NULL) {
        c++;
        s += strlen(needle);
    }
    return c;
}

/* "<tag>" or "<tag attr...>" openings */
static int count_open(const char *s, const char *tag)
{
    char needle[16];
    size_t nl;
    int c = 0;

    nl = (size_t)snprintf(needle, sizeof needle, "<%s", tag);
    while ((s = strstr(s, needle)) != NULL) {
        if (s[nl] == '>' || s[nl] == ' ')
            c++;
        s += nl;
    }
    return c;
}

/* open/close tag counts match for the containers the report uses */
static int balanced(const char *s)
{
    static const char *const tags[] = {"html", "head", "body", "main", "header", "footer",
                                       "section", "div", "table", "tr", "td", "ul", "li",
                                       "h1", "h2", "h3", "h4", "span", "p", "b", "title",
                                       "style"};
    char close[16];
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof tags / sizeof tags[0]; i++) {
        snprintf(close, sizeof close, "</%s>", tags[i]);
        if (count_open(s, tags[i]) != count(s, close)) {
            printf("  unbalanced <%s>: %d open, %d close\n", tags[i], count_open(s, tags[i]),
                   count(s, close));
            ok = 0;
        }
    }
    return ok;
}

static void set_probe(probe_result *p, const char *host, int tls, int status,
                      const char *headers)
{
    memset(p, 0, sizeof *p);
    snprintf(p->t.host, sizeof p->t.host, "%s", host);
    p->t.tls = tls;
    p->t.port = tls ? 443 : 80;
    p->connected = 1;
    p->status = status;
    web_header_value(headers, "Server", p->server, sizeof p->server);
    web_header_value(headers, "X-Powered-By", p->powered_by, sizeof p->powered_by);
    web_header_value(headers, "Location", p->location, sizeof p->location);
    p->nweb = web_check_headers(headers, tls, status, p->web, WEB_MAX_CHECKS);
}

static void set_tls(tls_result *t, const char *host, long days_left, unsigned flags)
{
    memset(t, 0, sizeof *t);
    snprintf(t->host, sizeof t->host, "%s", host);
    t->port = 443;
    t->connected = 1;
    snprintf(t->protocol, sizeof t->protocol, "TLSv1.3");
    snprintf(t->cipher, sizeof t->cipher, "TLS_AES_256_GCM_SHA384");
    snprintf(t->verify_text, sizeof t->verify_text, "ok");
    snprintf(t->ocsp_status, sizeof t->ocsp_status, "not stapled");
    t->ncerts = 2;
    set_cert(&t->certs[0], "CN=rosas-bakery.example", flags);
    snprintf(t->certs[0].issuer, sizeof t->certs[0].issuer, "C=US, O=Let's Encrypt, CN=R11");
    snprintf(t->certs[0].not_after, sizeof t->certs[0].not_after, "Nov  1 08:00:00 2026 GMT");
    t->certs[0].days_left = days_left;
    set_cert(&t->certs[1], "C=US, O=Let's Encrypt, CN=R11", 0);
}

/* A realistic made-up small-business site: http and the bare domain forward to www, which
   runs an old PHP and sets few security headers; the certificate expires in 9 days. */
static void build_sample(scan_report *r, probe_result *pr, tls_result *tr)
{
    memset(r, 0, sizeof *r);
    set_probe(&pr[0], "rosas-bakery.example", 0, 301,
              "Location: https://rosas-bakery.example/\r\nServer: Apache\r\n\r\n");
    set_probe(&pr[1], "rosas-bakery.example", 1, 301,
              "Location: https://www.rosas-bakery.example/\r\nServer: Apache\r\n\r\n");
    set_probe(&pr[2], "www.rosas-bakery.example", 1, 200,
              "Server: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/8.2.20\r\n"
              "X-Content-Type-Options: nosniff\r\n"
              "Set-Cookie: PHPSESSID=0123456789abcdef; path=/\r\n\r\n");
    snprintf(pr[2].via, sizeof pr[2].via, "https://rosas-bakery.example:443");
    pr[2].nhit = 1;
    snprintf(pr[2].hit[0].product, sizeof pr[2].hit[0].product, "php");
    snprintf(pr[2].hit[0].version, sizeof pr[2].hit[0].version, "8.2.20");
    snprintf(pr[2].hit[0].source, sizeof pr[2].hit[0].source, "X-Powered-By");
    snprintf(pr[2].hit[0].fixed, sizeof pr[2].hit[0].fixed, "8.2.35,8.3.36,8.4.27,8.5.12");
    snprintf(pr[2].hit[0].url, sizeof pr[2].hit[0].url,
             "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w");
    r->http = pr;
    r->nhttp = 3;
    set_tls(&tr[0], "rosas-bakery.example", 9, TLSF_EXPIRES_SOON);
    set_tls(&tr[1], "www.rosas-bakery.example", 9, TLSF_EXPIRES_SOON);
    r->tls = tr;
    r->ntls = 2;
}

static void test_html(void)
{
    scan_report r;
    probe_result pr[3];
    tls_result *tr = calloc(2, sizeof *tr);
    report_meta m = {"Rosa's Bakery & <Caf\xe9>", "Sam \"Checks\"", "23 October 2026"};
    secret_hit sh;
    char *s;
    size_t n;
    int w;

    if (tr == NULL)
        exit(2);
    build_sample(&r, pr, tr);
    s = html_of(&r, &m, &w, &n);
    CHECK(w == 0);
    CHECK(strncmp(s, "<!doctype html>", 15) == 0);
    CHECK(balanced(s));
    CHECK(has(s, "<meta charset=\"utf-8\">"));
    CHECK(has(s, "<h1>Rosa&#39;s Bakery &amp; &lt;Caf\xEF\xBF\xBD&gt;</h1>"));
    CHECK(strstr(s, "<Caf") == NULL);
    CHECK(has(s, "Prepared by Sam &quot;Checks&quot;"));
    CHECK(has(s, "23 October 2026"));
    CHECK(strstr(s, "Not ready to send") == NULL);
    CHECK(strstr(s, "<link") == NULL && strstr(s, " src=") == NULL); /* no external files */
    CHECK(strstr(s, "<script") == NULL);
    /* the same certificate on the bare name and www. is listed once */
    CHECK(count(s, "The certificate expires in 9 days") == 2); /* card + site table row */
    CHECK(has(s, "<b>3</b><span>Recommended</span>"));
    CHECK(has(s, "<b>4</b><span>Tips</span>"));
    CHECK(has(s, "<b>4</b><span>Passed</span>"));
    /* one site: www. and the bare name are merged */
    CHECK(count(s, "<h3>rosas-bakery.example</h3>") == 1);
    CHECK(strstr(s, "<h3>www.") == NULL);
    /* important: old PHP + certificate expiring in 9 days */
    CHECK(has(s, "Possibly outdated software with a known security problem: PHP 8.2.20"));
    CHECK(has(s, "update to a fixed release (8.2.35, 8.3.36, 8.4.27, 8.5.12)."));
    CHECK(has(s, "The certificate expires in 9 days"));
    CHECK(has(s, "<b>2</b><span>Important</span>"));
    /* hsts missing on the bare-domain redirect and on www; frame + cookie flags */
    CHECK(has(s, "Browsers are not told to always use the secure version (HSTS)"));
    CHECK(has(s, "Other sites can show your pages inside theirs"));
    CHECK(has(s, "Some cookies are missing protection flags"));
    CHECK(strstr(s, "0123456789abcdef") == NULL);
    CHECK(has(s, "Visitors are sent to the secure (https) version"));
    CHECK(has(s, "Browsers are told not to guess file types"));
    CHECK(has(s, "This address forwards visitors to another address"));
    CHECK(has(s, "The certificate is trusted"));
    CHECK(has(s, "Why it matters:") && has(s, "What to do:"));
    CHECK(strstr(s, "Code check") == NULL);
    free(s);

    /* interception and a failed target make it "not ready to send" */
    snprintf(tr[1].interception, sizeof tr[1].interception, "Norton Web/Mail Shield");
    pr[0].connected = 0;
    pr[0].status = 0;
    snprintf(pr[0].error, sizeof pr[0].error, "connect timed out");
    s = html_of(&r, &m, &w, &n);
    CHECK(w == 2);
    CHECK(balanced(s));
    CHECK(has(s, "Not ready to send"));
    CHECK(has(s, "HTTPS inspection on this computer"));
    CHECK(has(s, "1 address could not be reached"));
    CHECK(has(s, "Could not check http://rosas-bakery.example"));
    free(s);

    /* code folder only, no meta names, clean */
    memset(&r, 0, sizeof r);
    r.run_secrets = r.run_py = 1;
    r.root = "C:\\code\\shop";
    m.client = NULL;
    m.by = NULL;
    s = html_of(&r, &m, &w, &n);
    CHECK(w == 0 && balanced(s));
    CHECK(has(s, "<h1>Safety check-up report</h1>"));
    CHECK(strstr(s, "Prepared by") == NULL);
    CHECK(has(s, "No problems found in the checks that were run."));
    CHECK(has(s, "No passwords, keys or tokens found") && has(s, "No known malicious Python packages"));
    CHECK(has(s, "<b>2</b><span>Passed</span>"));
    CHECK(strstr(s, "Results by website") == NULL);
    free(s);

    /* a secret: masked hint only, plus the git warning */
    memset(&sh, 0, sizeof sh);
    snprintf(sh.path, sizeof sh.path, "config/<prod>.env");
    sh.line = 4;
    snprintf(sh.rule, sizeof sh.rule, "aws-access-key");
    snprintf(sh.masked, sizeof sh.masked, "****MPLE");
    sh.tracked = 1;
    r.secrets.h = &sh;
    r.secrets.n = 1;
    s = html_of(&r, &m, &w, &n);
    CHECK(balanced(s));
    CHECK(has(s, "Found an AWS access key in the code"));
    CHECK(has(s, "config/&lt;prod&gt;.env, line 4, value ****MPLE, saved in git history"));
    CHECK(has(s, "git keeps the old value in its history"));
    CHECK(has(s, "1 important issue should be fixed soon."));
    free(s);
    r.secrets_error = 1;
    s = html_of(&r, &m, &w, &n);
    CHECK(w == 1 && has(s, "The code scan did not finish."));
    free(s);
    free(tr);
}

/* a GitHub Pages site: the report names the platform and gives advice the owner can follow */
static void test_platform_report(void)
{
    scan_report r;
    probe_result pr[2];
    report_meta m = {"GitHub Pages test", "Your Name", "24 October 2026"};
    char *s, *j;
    size_t n;
    int w;

    memset(&r, 0, sizeof r);
    set_probe(&pr[0], "example-user.github.io", 1, 200,
              "Server: GitHub.com\r\nStrict-Transport-Security: max-age=31556952\r\n\r\n");
    set_probe(&pr[1], "example-user.github.io", 0, 301,
              "Server: GitHub.com\r\nLocation: https://example-user.github.io/\r\n\r\n");
    snprintf(pr[0].platform, sizeof pr[0].platform, "%s", web_detect_platform("Server: GitHub.com\r\n\r\n", "example-user.github.io"));
    snprintf(pr[1].platform, sizeof pr[1].platform, "%s", pr[0].platform);
    r.http = pr;
    r.nhttp = 2;
    s = html_of(&r, &m, &w, &n);
    CHECK(w == 0 && balanced(s));
    CHECK(has(s, "Hosted on GitHub Pages"));
    CHECK(has(s, "GitHub Pages has no setting for this"));
    CHECK(has(s, "&lt;meta name=&quot;referrer&quot;"));
    CHECK(strstr(s, "Ask for the header X-Frame-Options") == NULL); /* general advice replaced */
    free(s);
    j = json_of(&r, "site", &n);
    CHECK(json_valid(j, n) == 0);
    CHECK(has(j, "\"platform\":\"GitHub Pages\""));
    CHECK(has(j, "\"fix\":\"GitHub Pages has no setting for this"));
    free(j);
}

/* ---------- real scan of a fixture directory ---------- */

static void put(const char *dir, const char *name, const char *text)
{
    char path[512];
    FILE *f;

    fs_join(path, sizeof path, dir, name);
    f = fopen(path, "wb");
    if (f == NULL) {
        printf("cannot write %s\n", path);
        exit(2);
    }
    fputs(text, f);
    fclose(f);
}

static void rm_tree(const char *dir)
{
    DIR *d;
    struct dirent *de;

    if (strstr(dir, "tmp_") == NULL)
        return;
    d = opendir(dir);
    if (d == NULL)
        return;
    while ((de = readdir(d)) != NULL) {
        char p[512];

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        fs_join(p, sizeof p, dir, de->d_name);
        if (fs_is_dir(p))
            rm_tree(p);
        else
            remove(p);
    }
    closedir(d);
    RMDIR(dir);
}

static void test_real_scan(const char *adv_path)
{
    const char *root = "tmp_report_fixture";
    const char *key_tail = "IOSFODNN7EXAMPLE";
    char sub[256], line[128], full[64];
    adv_list adv = {0};
    scan_report r;
    char *s;
    size_t n;
    int nerr = 0;

    rm_tree(root);
    MKDIR(root);
    fs_join(sub, sizeof sub, root, "sub dir");
    MKDIR(sub);
    snprintf(full, sizeof full, "%s%s", "AKIA", key_tail);
    snprintf(line, sizeof line, "aws_key = \"%s\"\n", full);
    put(sub, "conf.txt", line);
    put(root, "requirements.txt", "litellm==1.107.0\nrequests==2.0.0\n");

    if (adv_load(adv_path, &adv, &nerr) != 0) {
        printf("cannot load %s\n", adv_path);
        g_fail++;
        rm_tree(root);
        return;
    }
    memset(&r, 0, sizeof r);
    r.root = root;
    r.run_secrets = 1;
    r.secrets_error = secret_scan_dir(root, &r.secrets) != 0;
    r.run_py = 1;
    r.py_error = py_scan(root, &adv, &r.py) != 0;
    CHECK(!r.secrets_error && !r.py_error);
    CHECK(r.secrets.n == 1);
    CHECK(r.py.n >= 1);

    s = json_of(&r, "all", &n);
    CHECK(json_valid(s, n) == 0);
    CHECK(strstr(s, full) == NULL);     /* the secret itself is never written */
    CHECK(strstr(s, key_tail) == NULL);
    CHECK(has(s, "\"rule\":\"aws-access-key\""));
    CHECK(has(s, "sub dir"));
    CHECK(has(s, "\"name\":\"litellm\""));
    CHECK(has(s, "\"ready_to_send\":true"));
    CHECK(has(s, "\"site\":\"Code folder\""));
    CHECK(has(s, "\"exit_code\":1}"));
    free(s);
    s = text_of(&r, &n);
    CHECK(strstr(s, full) == NULL);
    free(s);

    report_free(&r);
    adv_free(&adv);
    rm_tree(root);
}

int main(int argc, char **argv)
{
    const char *adv = "data/advisories.txt";

    if (argc == 3 && strcmp(argv[1], "--check-json") == 0) {
        size_t n;
        char *s = read_all(argv[2], &n);
        int ok = s != NULL && json_valid(s, n) == 0;

        printf("%s: %s\n", argv[2], ok ? "valid JSON" : "INVALID JSON");
        free(s);
        return ok ? 0 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "--sample-html") == 0) {
        scan_report r;
        probe_result pr[3];
        tls_result *tr = calloc(2, sizeof *tr);
        report_meta m = {"Rosa's Bakery (sample)", "Your Name", "23 October 2026"};
        FILE *f = fopen(argv[2], "wb");

        if (tr == NULL || f == NULL)
            return 2;
        build_sample(&r, pr, tr);
        report_write_html(&r, &m, f);
        fclose(f);
        free(tr);
        printf("sample report written to %s\n", argv[2]);
        return 0;
    }
    if (argc > 1)
        adv = argv[1];
    test_checker();
    test_json_string();
    test_protocols();
    test_webcheck();
    test_redirects();
    test_platforms();
    test_exit_codes();
    test_json_full();
    test_html();
    test_platform_report();
    test_real_scan(adv);
    printf("report: %d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
