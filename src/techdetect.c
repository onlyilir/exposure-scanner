/* Software detection from what a website sends to any visitor. Sources for the footprints:
   WordPress  generator formats: get_the_generator() in wp-includes/general-template.php
              (html meta, rss2 <generator>, "comment" in wp-links-opml.php); core files carry
              ?ver=<WordPress version> (wp_default_scripts / wp_default_styles).
   Next.js    client runtime sets window.next = { version, appDir } (packages/next/src/client);
              confirmed on local builds of 15.5.4 (webpack) and 16.4.6 (Turbopack).
   Drupal     X-Generator / generator "Drupal <major>"; core libraries load with ?v=<version>;
              CHANGELOG.txt starts "Drupal x.y, date" (7.x root, 8/9 in core/).
   Joomla     administrator/manifests/files/joomla.xml <version>.
   Magento 2  /magento_version answers "Magento/<major.minor> (<edition>)".
   Ghost      generator "Ghost <major.minor>". */
#include "techdetect.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "webcheck.h"

#define HTML_MAX (2u * 1024u * 1024u)

static void copy_str(char *dst, size_t n, const char *src)
{
    if (n == 0)
        return;
    snprintf(dst, n, "%s", src != NULL ? src : "");
}

/* case-insensitive search in the first len bytes of a NUL-terminated buffer */
static const char *ci_find(const char *hay, size_t len, const char *needle)
{
    size_t nl = strlen(needle), i;

    if (nl == 0 || len < nl)
        return NULL;
    for (i = 0; i + nl <= len && hay[i] != '\0'; i++)
        if (strncasecmp(hay + i, needle, nl) == 0)
            return hay + i;
    return NULL;
}

tech_item *tech_find(tech_list *l, const char *product)
{
    int i;

    for (i = 0; i < l->n; i++)
        if (strcmp(l->t[i].product, product) == 0)
            return &l->t[i];
    return NULL;
}

static tech_item *add(tech_list *l, const char *product, int flags)
{
    tech_item *t = tech_find(l, product);

    if (t == NULL) {
        if (l->n >= TECH_MAX)
            return NULL;
        t = &l->t[l->n++];
        memset(t, 0, sizeof *t);
        copy_str(t->product, sizeof t->product, product);
    }
    t->flags |= flags;
    return t;
}

static int is_ver_char(int c)
{
    return isalnum(c) || c == '.' || c == '-' || c == '+' || c == '~' || c == '_';
}

/* version token at p ("7.4.3-4ubuntu2.29"); "" when p does not start with a digit */
static void read_ver(const char *p, char *out, size_t n)
{
    size_t i = 0;

    out[0] = '\0';
    if (p == NULL || !isdigit((unsigned char)*p))
        return;
    while (is_ver_char((unsigned char)p[i]) && i + 1 < n) {
        out[i] = p[i];
        i++;
    }
    while (i > 0 && (out[i - 1] == '.' || out[i - 1] == '-'))
        i--;
    out[i] = '\0';
}

/* keep the first, most certain version */
static void set_ver(tech_item *t, const char *v, int conf, const char *source)
{
    if (t == NULL || v == NULL || !isdigit((unsigned char)v[0]))
        return;
    if (t->version[0] != '\0' && conf <= t->conf)
        return;
    copy_str(t->version, sizeof t->version, v);
    t->conf = conf;
    copy_str(t->source, sizeof t->source, source);
}

static void set_seen(tech_item *t, const char *source)
{
    if (t != NULL && t->source[0] == '\0')
        copy_str(t->source, sizeof t->source, source);
}

static int dots(const char *v)
{
    int n = 0;

    for (; *v != '\0' && *v != '-' && *v != '+' && *v != '~'; v++)
        n += *v == '.';
    return n;
}

/* ---------- generator values (meta tag, X-Generator) ---------- */

static void generator(const char *v, const char *source, tech_list *l)
{
    char ver[40];

    while (*v == ' ')
        v++;
    if (strncasecmp(v, "WordPress", 9) == 0) {
        tech_item *t = add(l, "wordpress", TECH_SITE);

        read_ver(v + 10, ver, sizeof ver);
        set_seen(t, source);
        set_ver(t, ver, dots(ver) >= 1 ? TECH_EXACT : TECH_ESTIMATED, source);
    } else if (strncasecmp(v, "Drupal", 6) == 0) {
        tech_item *t = add(l, "drupal", TECH_SITE);

        read_ver(v + 7, ver, sizeof ver);
        set_seen(t, source);
        set_ver(t, ver, dots(ver) >= 1 ? TECH_EXACT : TECH_ESTIMATED, source);
    } else if (strncasecmp(v, "Joomla", 6) == 0) {
        tech_item *t = add(l, "joomla", TECH_SITE);
        const char *p = v + 6;

        if (*p == '!')
            p++;
        while (*p == ' ')
            p++;
        read_ver(p, ver, sizeof ver); /* "Joomla! 1.5 - ..." on old versions only */
        set_seen(t, source);
        set_ver(t, ver, TECH_ESTIMATED, source);
    } else if (strncasecmp(v, "Ghost", 5) == 0 && (v[5] == ' ' || v[5] == '\0')) {
        tech_item *t = add(l, "ghost", TECH_SITE);

        read_ver(v + 6, ver, sizeof ver);
        set_seen(t, source);
        set_ver(t, ver, dots(ver) >= 2 ? TECH_EXACT : TECH_ESTIMATED, source);
    } else if (strncasecmp(v, "Next.js", 7) == 0) {
        set_seen(add(l, "nextjs", TECH_SITE), source);
    }
}

/* ---------- headers ---------- */

static const char *distro_of(const char *word)
{
    static const char *const map[][2] = {
        {"ubuntu", "ubuntu"}, {"debian", "debian"}, {"centos", "centos"},
        {"red hat", "rhel"}, {"rhel", "rhel"}, {"rocky", "rocky"}, {"almalinux", "alma"},
        {"amazon", "amazon-linux"}, {"fedora", "fedora"}, {"win64", "windows"}, {"win32", "windows"}};
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strncasecmp(word, map[i][0], strlen(map[i][0])) == 0)
            return map[i][1];
    return NULL;
}

static const char *server_product(const char *name)
{
    static const char *const map[][2] = {
        {"apache", "apache"}, {"nginx", "nginx"}, {"microsoft-iis", "iis"}, {"php", "php"},
        {"openssl", "openssl"}, {"litespeed", "litespeed"}};
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcasecmp(name, map[i][0]) == 0)
            return map[i][1];
    return NULL;
}

/* PHP packages name their distribution: "7.4.3-4ubuntu2.29", "7.4.33-1+deb11u5", "8.2.7-1~deb12u1" */
static void php_suffix(tech_item *t, const char *ver)
{
    const char *d = strstr(ver, "deb");

    if (strstr(ver, "ubuntu") != NULL) {
        copy_str(t->os, sizeof t->os, "ubuntu");
    } else if (d != NULL && d > ver && (d[-1] == '+' || d[-1] == '~') && isdigit((unsigned char)d[3])) {
        size_t i = 0;

        copy_str(t->os, sizeof t->os, "debian");
        for (d += 3; isdigit((unsigned char)*d) && i + 1 < sizeof t->os_release; d++)
            t->os_release[i++] = *d;
        t->os_release[i] = '\0';
    }
}

/* "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16" */
static void server_tokens(const char *v, const char *source, tech_list *l)
{
    const char *p = v, *os = NULL;
    tech_item *found[8];
    int nf = 0, i;

    while (*p != '\0') {
        if (*p == '(') {
            const char *d = distro_of(p + 1);

            if (d != NULL && os == NULL)
                os = d;
            while (*p != '\0' && *p != ')')
                p++;
            continue;
        }
        if (isalpha((unsigned char)*p) && (p == v || p[-1] == ' ' || p[-1] == ',')) {
            char name[32], ver[40];
            size_t nl = 0;
            const char *prod;

            while ((isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '.') && nl + 1 < sizeof name)
                name[nl++] = *p++;
            name[nl] = '\0';
            prod = server_product(name);
            if (prod != NULL) {
                tech_item *t = add(l, prod, TECH_SERVER);

                set_seen(t, source);
                if (*p == '/') {
                    read_ver(p + 1, ver, sizeof ver);
                    if (t != NULL && strcmp(prod, "php") == 0 && ver[0] != '\0')
                        php_suffix(t, ver);
                    ver[strcspn(ver, "-+~")] = '\0';
                    set_ver(t, ver, TECH_EXACT, source);
                }
                if (t != NULL && nf < 8)
                    found[nf++] = t;
            }
            continue;
        }
        p++;
    }
    for (i = 0; i < nf; i++) {
        if (strcmp(found[i]->product, "iis") == 0)
            copy_str(found[i]->os, sizeof found[i]->os, "windows");
        else if (os != NULL && found[i]->os[0] == '\0')
            copy_str(found[i]->os, sizeof found[i]->os, os);
    }
}

static int has(const char *headers, const char *name)
{
    char v[8];

    return web_header_value(headers, name, v, sizeof v);
}

void tech_from_headers(const char *headers, tech_list *l)
{
    char v[256];

    if (web_header_value(headers, "Server", v, sizeof v))
        server_tokens(v, "Server header", l);
    if (web_header_value(headers, "X-Powered-By", v, sizeof v)) {
        server_tokens(v, "X-Powered-By header", l);
        if (ci_find(v, strlen(v), "Next.js") != NULL)
            set_seen(add(l, "nextjs", TECH_SITE), "X-Powered-By header");
        if (strncasecmp(v, "Express", 7) == 0)
            set_seen(add(l, "express", TECH_SERVER), "X-Powered-By header");
        if (strncasecmp(v, "ASP.NET", 7) == 0)
            set_seen(add(l, "aspnet", TECH_SERVER), "X-Powered-By header");
    }
    if (web_header_value(headers, "X-AspNet-Version", v, sizeof v)) {
        tech_item *t = add(l, "aspnet", TECH_SERVER);

        set_ver(t, v, TECH_EXACT, "X-AspNet-Version header");
        if (t != NULL)
            copy_str(t->os, sizeof t->os, "windows");
    }
    if (web_header_value(headers, "X-Generator", v, sizeof v))
        generator(v, "X-Generator header", l);
    if (has(headers, "X-Drupal-Cache") || has(headers, "X-Drupal-Dynamic-Cache"))
        set_seen(add(l, "drupal", TECH_SITE), "X-Drupal header");
    if (has(headers, "X-Magento-Tags") || has(headers, "X-Magento-Cache-Debug"))
        set_seen(add(l, "magento", TECH_SITE), "X-Magento header");
    if (has(headers, "X-Nextjs-Cache") || has(headers, "X-Nextjs-Prerender") ||
        has(headers, "X-Nextjs-Stale-Time") || has(headers, "X-Nextjs-Matched-Path"))
        set_seen(add(l, "nextjs", TECH_SITE), "x-nextjs header");
    if (web_header_value(headers, "Vary", v, sizeof v) &&
        (ci_find(v, strlen(v), "Next-Router-State-Tree") != NULL || ci_find(v, strlen(v), "RSC") != NULL))
        set_seen(add(l, "nextjs", TECH_SITE | TECH_APP_ROUTER), "Vary header");
}

/* ---------- home page ---------- */

/* value of attribute `name` inside one tag (tag .. end), unquoted or quoted */
static int attr(const char *tag, const char *end, const char *name, char *out, size_t n)
{
    size_t nl = strlen(name);
    const char *p;

    for (p = tag; p + nl < end; p++) {
        if (strncasecmp(p, name, nl) == 0 && (p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n') && p[nl] == '=') {
            const char *s = p + nl + 1;
            char q = (*s == '"' || *s == '\'') ? *s++ : 0;
            size_t i = 0;

            while (s < end && *s != '\0' && (q ? *s != q : (*s != ' ' && *s != '>')) && i + 1 < n)
                out[i++] = *s++;
            out[i] = '\0';
            return 1;
        }
    }
    return 0;
}

static void meta_generators(const char *html, size_t len, tech_list *l)
{
    const char *p = html, *stop = html + len;

    while (p < stop && (p = ci_find(p, (size_t)(stop - p), "<meta")) != NULL) {
        const char *end = memchr(p, '>', (size_t)(stop - p));
        char name[24], content[160];

        if (end == NULL)
            break;
        if (attr(p, end, "name", name, sizeof name) && strcasecmp(name, "generator") == 0 &&
            attr(p, end, "content", content, sizeof content))
            generator(content, "generator tag on the home page", l);
        p = end;
    }
}

/* WordPress core files are served with ?ver=<WordPress version> */
static void wp_core_files(const char *html, size_t len, tech_list *l)
{
    static const char *const files[] = {"wp-emoji-release.min.js?ver=", "block-library/style.min.css?ver=",
                                        "wp-embed.min.js?ver=", "dashicons.min.css?ver=",
                                        "comment-reply.min.js?ver=", "classic-themes.min.css?ver="};
    size_t i;

    for (i = 0; i < sizeof files / sizeof files[0]; i++) {
        const char *p = ci_find(html, len, files[i]);
        char ver[40];

        if (p == NULL)
            continue;
        read_ver(p + strlen(files[i]), ver, sizeof ver);
        if (dots(ver) >= 1) {
            set_ver(add(l, "wordpress", TECH_SITE), ver, TECH_ESTIMATED, "WordPress file versions on the home page");
            return;
        }
    }
}

void tech_from_html(const char *html, size_t len, tech_list *l)
{
    const char *p;

    if (html == NULL)
        return;
    if (len > HTML_MAX)
        len = HTML_MAX;
    meta_generators(html, len, l);

    if (ci_find(html, len, "/wp-content/") || ci_find(html, len, "/wp-includes/") || ci_find(html, len, "api.w.org"))
        set_seen(add(l, "wordpress", TECH_SITE), "WordPress files on the home page");
    if (tech_find(l, "wordpress") != NULL)
        wp_core_files(html, len, l);

    if (ci_find(html, len, "/_next/static/")) {
        tech_item *t = add(l, "nextjs", TECH_SITE);

        set_seen(t, "Next.js files on the home page");
        if (t != NULL && ci_find(html, len, "self.__next_f"))
            t->flags |= TECH_APP_ROUTER;
        if (t != NULL && ci_find(html, len, "__NEXT_DATA__"))
            t->flags |= TECH_PAGES;
    }

    if (ci_find(html, len, "/media/system/js/") || ci_find(html, len, "/media/jui/") ||
        ci_find(html, len, "joomla-script-options"))
        set_seen(add(l, "joomla", TECH_SITE), "Joomla files on the home page");

    if (ci_find(html, len, "drupal-settings-json") || ci_find(html, len, "data-drupal-") ||
        ci_find(html, len, "Drupal.settings"))
        set_seen(add(l, "drupal", TECH_SITE), "Drupal code on the home page");
    if ((p = ci_find(html, len, "/core/misc/drupal.js?v=")) != NULL) {
        char ver[40];

        read_ver(p + 23, ver, sizeof ver);
        if (dots(ver) >= 1)
            set_ver(add(l, "drupal", TECH_SITE), ver, TECH_EXACT, "Drupal file versions on the home page");
    } else if (ci_find(html, len, "Drupal.settings") && ci_find(html, len, "/misc/drupal.js")) {
        set_ver(add(l, "drupal", TECH_SITE), "7", TECH_ESTIMATED, "Drupal 7 code on the home page");
    }

    if (ci_find(html, len, "text/x-magento-init") || ci_find(html, len, "data-mage-init") ||
        ci_find(html, len, "Mage.Cookies"))
        set_seen(add(l, "magento", TECH_SITE), "Magento code on the home page");
    if (ci_find(html, len, "/skin/frontend/") && ci_find(html, len, "Mage.Cookies"))
        set_ver(add(l, "magento", TECH_SITE), "1", TECH_ESTIMATED, "Magento 1 files on the home page");

    if (ci_find(html, len, "ghost-portal") || ci_find(html, len, "/ghost/api/content"))
        set_seen(add(l, "ghost", TECH_SITE), "Ghost code on the home page");
}

/* ---------- level 2 ---------- */

static int add_path(char paths[][192], int n, int max, const char *path)
{
    int i;

    if (n >= max || strlen(path) >= 192)
        return n;
    for (i = 0; i < n; i++)
        if (strcmp(paths[i], path) == 0)
            return n;
    copy_str(paths[n], 192, path);
    return n + 1;
}

/* script files of this site under /_next/static/chunks/, the framework's own runtime skipped */
static int next_chunks(const char *html, size_t len, int pages, char paths[][192], int n, int max, int budget)
{
    static const char *const skip[] = {"polyfills", "webpack", "turbopack", "framework"};
    char found[16][192];
    int nf = 0, i, pass;
    const char *p = html, *stop = html + len;

    while (p < stop && nf < 16 && (p = ci_find(p, (size_t)(stop - p), "src=\"")) != NULL) {
        const char *s = p + 5, *e = memchr(s, '"', (size_t)(stop - s));
        size_t l2;

        p = s;
        if (e == NULL)
            break;
        l2 = (size_t)(e - s);
        if (l2 > 0 && l2 < 192 && s[0] == '/' && s[1] != '/') {
            char v[192];
            const char *base;
            size_t k;

            memcpy(v, s, l2);
            v[l2] = '\0';
            base = strrchr(v, '/') + 1;
            if (strstr(v, "/_next/static/chunks/") == NULL || strstr(v, ".js") == NULL)
                continue;
            for (k = 0; k < sizeof skip / sizeof skip[0]; k++)
                if (strncmp(base, skip[k], strlen(skip[k])) == 0)
                    break;
            if (k == sizeof skip / sizeof skip[0])
                copy_str(found[nf++], 192, v);
        }
    }
    /* Pages Router: the version is in main-*.js; App Router: in a shared chunk near the top */
    for (pass = 0; pass < 2; pass++)
        for (i = 0; i < nf && budget > 0; i++) {
            const char *b = strrchr(found[i], '/') + 1;
            int first = pages && strncmp(b, "main-", 5) == 0 && strncmp(b, "main-app", 8) != 0;
            int before = n;

            if (first != (pass == 0))
                continue;
            n = add_path(paths, n, max, found[i]);
            budget -= n > before;
        }
    return n;
}

int tech_followups(const tech_list *l, const char *html, size_t len, char paths[][192], int max)
{
    int i, n = 0;

    if (html != NULL && len > HTML_MAX)
        len = HTML_MAX;
    for (i = 0; i < l->n; i++) {
        const tech_item *t = &l->t[i];

        if (t->conf == TECH_EXACT)
            continue;
        if (strcmp(t->product, "wordpress") == 0) {
            n = add_path(paths, n, max, "/feed/");
            n = add_path(paths, n, max, "/wp-links-opml.php");
        } else if (strcmp(t->product, "nextjs") == 0 && html != NULL) {
            n = next_chunks(html, len, (t->flags & TECH_PAGES) != 0, paths, n, max, 3);
        } else if (strcmp(t->product, "joomla") == 0) {
            n = add_path(paths, n, max, "/administrator/manifests/files/joomla.xml");
        } else if (strcmp(t->product, "drupal") == 0) {
            if (t->version[0] == '\0' || strcmp(t->version, "7") == 0)
                n = add_path(paths, n, max, "/CHANGELOG.txt");
            if (t->version[0] == '\0' || atoi(t->version) >= 8)
                n = add_path(paths, n, max, "/core/CHANGELOG.txt");
        } else if (strcmp(t->product, "magento") == 0 && t->version[0] == '\0') {
            n = add_path(paths, n, max, "/magento_version");
        }
    }
    return n;
}

/* Pages Router bundles: version:function(){return B} ... let B="15.5.4" */
static int next_version(const char *body, size_t len, char *out, size_t n)
{
    const char *p = ci_find(body, len, "window.next={version:\"");
    char ident[16];
    size_t il = 0;

    if (p != NULL) {
        read_ver(p + 22, out, n);
        return out[0] != '\0';
    }
    if ((p = ci_find(body, len, "version:function(){return ")) != NULL)
        p += 26;
    else if ((p = ci_find(body, len, "version:()=>")) != NULL)
        p += 12;
    if (p == NULL) {
        /* Next.js 12: exports.version = "12.3.4" (minified t.version="..."), only trusted in the
           file that also sets window.next, so another library's version is never taken */
        const char *q;

        if (ci_find(body, len, "window.next={version:") == NULL)
            return 0;
        for (q = body; (q = ci_find(q, len - (size_t)(q - body), ".version=\"")) != NULL; q += 10) {
            read_ver(q + 10, out, n);
            if (dots(out) >= 2 && atoi(out) >= 9)
                return 1;
        }
        out[0] = '\0';
        return 0;
    }
    while ((isalnum((unsigned char)p[il]) || p[il] == '_' || p[il] == '$') && il + 3 < sizeof ident) {
        ident[il] = p[il];
        il++;
    }
    if (il == 0)
        return 0;
    ident[il++] = '=';
    ident[il++] = '"';
    ident[il] = '\0';
    for (p = body; (p = ci_find(p, len - (size_t)(p - body), ident)) != NULL; p += il) {
        if (p > body && strchr(" ,;({", p[-1]) != NULL) {
            read_ver(p + il, out, n);
            if (dots(out) >= 2)
                return 1;
        }
    }
    out[0] = '\0';
    return 0;
}

static const char *line_after(const char *body, size_t len, const char *needle)
{
    const char *p = ci_find(body, len, needle);

    return p != NULL ? p + strlen(needle) : NULL;
}

void tech_apply(const char *path, int status, const char *body, size_t len, tech_list *l)
{
    char ver[40];
    const char *p;

    if (status != 200 || body == NULL || len == 0)
        return;
    if (strcmp(path, "/feed/") == 0 && (p = line_after(body, len, "wordpress.org/?v=")) != NULL) {
        read_ver(p, ver, sizeof ver);
        set_ver(tech_find(l, "wordpress"), ver, TECH_EXACT, "the site's RSS feed");
    } else if (strcmp(path, "/wp-links-opml.php") == 0 &&
               (p = line_after(body, len, "generator=\"WordPress/")) != NULL) {
        read_ver(p, ver, sizeof ver);
        set_ver(tech_find(l, "wordpress"), ver, TECH_EXACT, "/wp-links-opml.php");
    } else if (strstr(path, "/_next/static/chunks/") != NULL) {
        if (next_version(body, len > HTML_MAX ? HTML_MAX : len, ver, sizeof ver))
            set_ver(tech_find(l, "nextjs"), ver, TECH_EXACT, "the site's main script");
    } else if (strcmp(path, "/administrator/manifests/files/joomla.xml") == 0 &&
               (p = line_after(body, len, "<version>")) != NULL) {
        read_ver(p, ver, sizeof ver);
        set_ver(tech_find(l, "joomla"), ver, TECH_EXACT, "Joomla's version file");
    } else if (strstr(path, "CHANGELOG.txt") != NULL) {
        /* the newest entry comes first: "Drupal 7.98, 2023-06-07" */
        size_t lim = len < 4096 ? len : 4096;

        for (p = body; p != NULL && (size_t)(p - body) < lim; p = memchr(p, '\n', lim - (size_t)(p - body))) {
            while (*p == '\n' || *p == '\r')
                p++;
            if (strncmp(p, "Drupal ", 7) == 0) {
                read_ver(p + 7, ver, sizeof ver);
                ver[strcspn(ver, ",")] = '\0';
                set_ver(tech_find(l, "drupal"), ver, dots(ver) >= 1 ? TECH_EXACT : TECH_ESTIMATED,
                        "Drupal's change log");
                break;
            }
        }
    } else if (strcmp(path, "/magento_version") == 0 && strncmp(body, "Magento/", 8) == 0) {
        read_ver(body + 8, ver, sizeof ver);
        set_ver(tech_find(l, "magento"), ver, TECH_ESTIMATED, "/magento_version");
    }
}

const char *tech_name(const char *product)
{
    static const char *const map[][2] = {
        {"wordpress", "WordPress"}, {"nextjs", "Next.js"}, {"joomla", "Joomla"}, {"drupal", "Drupal"},
        {"magento", "Magento"}, {"ghost", "Ghost"}, {"apache", "Apache"}, {"nginx", "nginx"},
        {"iis", "Microsoft IIS"}, {"php", "PHP"}, {"openssl", "OpenSSL"}, {"aspnet", "ASP.NET"},
        {"express", "Express (Node.js)"}, {"litespeed", "LiteSpeed"}};
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i][0], product) == 0)
            return map[i][1];
    return product;
}

const char *tech_conf_name(int conf)
{
    return conf == TECH_EXACT ? "exact" : conf == TECH_ESTIMATED ? "estimated" : "unknown";
}
