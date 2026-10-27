/* Website security settings from response headers (HTTPS redirect, HSTS, CSP, framing,
   nosniff, referrer policy, cookie flags, version disclosure). */
#include "webcheck.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define HSTS_MIN_AGE 15552000L /* 180 days, the usual recommended minimum */

static const web_info infos[] = {
    {"https_redirect", "Visitors are sent to the secure (https) version",
     "Visitors are not sent to the secure (https) version",
     "Someone who types your address without https:// gets an unencrypted page. On public "
     "Wi-Fi, other people could read or change what they see and send.",
     "Ask your web host or developer to redirect all http:// traffic to https://. Most hosting "
     "control panels have a \"Force HTTPS\" switch."},
    {"hsts", "Browsers are told to always use the secure version (HSTS)",
     "Browsers are not told to always use the secure version (HSTS)",
     "Without this setting, someone on the same network can push a visitor onto an unencrypted "
     "connection before the secure page loads.",
     "Ask for the Strict-Transport-Security header with a max-age of at least 15552000 (180 "
     "days). Only turn it on once the whole site works over https."},
    {"csp", "A content security policy is set", "No content security policy",
     "This setting limits which scripts may run on your pages. It is the main defense if "
     "harmful code gets in, for example through a hacked plugin or a comment form.",
     "Ask your developer to add a Content-Security-Policy header. It needs care so the site "
     "keeps working, so start with the report-only version."},
    {"frame", "Other sites cannot show your pages inside theirs",
     "Other sites can show your pages inside theirs",
     "A fake site can load your page invisibly and trick visitors into clicking buttons on it, "
     "such as \"buy\" or \"delete\". This is called clickjacking.",
     "Ask for the header X-Frame-Options: SAMEORIGIN, or frame-ancestors 'self' in the content "
     "security policy."},
    {"nosniff", "Browsers are told not to guess file types", "Browsers may guess file types",
     "If browsers guess, a file that looks harmless can sometimes be run as a script.",
     "Ask for the header X-Content-Type-Options: nosniff. It is a one-line change that is safe "
     "for almost every site."},
    {"referrer", "Links to other sites pass on only limited information",
     "No referrer policy is set",
     "When visitors click a link to another site, the full address of your page can be passed "
     "along, sometimes with private details in it.",
     "Ask for the header Referrer-Policy: strict-origin-when-cross-origin. Modern browsers "
     "already behave this way by default, so this is low priority."},
    {"cookies", "Cookies are protected", "Some cookies are missing protection flags",
     "Cookies without the Secure flag can travel over unencrypted connections, and cookies "
     "without HttpOnly can be read by scripts on the page. Login cookies need both.",
     "Ask your developer to set the Secure and HttpOnly flags on cookies, plus SameSite=Lax."},
    {"server_version", "The server does not reveal its software version",
     "The server reveals its software version",
     "Showing the exact version tells attackers which known weaknesses to try first.",
     "Ask your host to hide the version number (for example server_tokens off in nginx, or "
     "ServerTokens Prod in Apache)."},
    {"powered_by", "The site does not announce the technology behind it",
     "The site announces the technology behind it (X-Powered-By)",
     "Announcing the technology and its version helps attackers pick what to try.",
     "Ask your developer to remove the X-Powered-By header (for PHP: expose_php = Off)."},
    {"redirect", "This address forwards visitors to another address", "",
     "Page settings are checked at the address visitors end up on.", ""},
    {"not_checked", "Page settings could not be checked here", "",
     "The server answered with an error or blocked the check, so its page settings were not "
     "read.",
     "If this is your main address, check that it loads in a browser."},
};

const web_info *web_check_info(const char *id)
{
    size_t i;

    for (i = 0; i < sizeof infos / sizeof infos[0]; i++)
        if (strcmp(infos[i].id, id) == 0)
            return &infos[i];
    return NULL;
}

const char *web_level_name(int level)
{
    static const char *const names[] = {"ok", "note", "tip", "recommended", "important"};

    return level >= WEB_OK && level <= WEB_IMPORTANT ? names[level] : "unknown";
}

/* ---------- header access ---------- */

static int ci_prefix(const char *s, const char *prefix)
{
    for (; *prefix != '\0'; s++, prefix++)
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix))
            return 0;
    return 1;
}

static const char *ci_find(const char *hay, const char *needle)
{
    for (; *hay != '\0'; hay++)
        if (ci_prefix(hay, needle))
            return hay;
    return NULL;
}

/* Finds the next header called name at or after *pos; copies its trimmed value and moves *pos
   past that line. Stops at the empty line that ends the headers. 1 found, 0 no more. */
static int next_header(const char **pos, const char *name, char *out, size_t outlen)
{
    size_t nl = strlen(name);
    const char *line = *pos;

    while (*line != '\0') {
        const char *eol = strchr(line, '\n');
        size_t len = eol != NULL ? (size_t)(eol - line) : strlen(line);

        if (len == 0 || (len == 1 && line[0] == '\r'))
            break; /* end of headers */
        if (len > nl && ci_prefix(line, name) && line[nl] == ':') {
            const char *v = line + nl + 1;
            size_t vl = len - nl - 1;

            while (vl > 0 && (*v == ' ' || *v == '\t')) {
                v++;
                vl--;
            }
            while (vl > 0 && (v[vl - 1] == '\r' || v[vl - 1] == ' ' || v[vl - 1] == '\t'))
                vl--;
            if (outlen > 0) {
                if (vl >= outlen)
                    vl = outlen - 1;
                memcpy(out, v, vl);
                out[vl] = '\0';
            }
            *pos = eol != NULL ? eol + 1 : line + len;
            return 1;
        }
        if (eol == NULL)
            break;
        line = eol + 1;
    }
    *pos = line + strlen(line);
    return 0;
}

int web_header_value(const char *headers, const char *name, char *out, size_t outlen)
{
    const char *pos = headers;

    if (outlen > 0)
        out[0] = '\0';
    return next_header(&pos, name, out, outlen);
}

/* ---------- checks ---------- */

/* detail is a printf format; long header values are cut to fit on purpose */
static void add(web_check *out, int *n, int max, const char *id, int level, const char *fmt,
                ...)
{
    va_list ap;

    if (*n >= max)
        return;
    snprintf(out[*n].id, sizeof out[*n].id, "%s", id);
    out[*n].level = level;
    va_start(ap, fmt);
    vsnprintf(out[*n].detail, sizeof out[*n].detail, fmt, ap);
    va_end(ap);
    (*n)++;
}

/* max-age value of an HSTS header, -1 if absent or malformed */
static long hsts_max_age(const char *v)
{
    const char *p = ci_find(v, "max-age");
    char *end;
    long age;

    if (p == NULL)
        return -1;
    p += 7;
    while (*p == ' ')
        p++;
    if (*p != '=')
        return -1;
    p++;
    while (*p == ' ' || *p == '"')
        p++;
    if (!isdigit((unsigned char)*p))
        return -1;
    age = strtol(p, &end, 10);
    return age < 0 ? -1 : age;
}

/* Does the Server header carry a version ("nginx/1.24.0", "Apache/2.4.58 (Ubuntu)")? */
static int has_version(const char *v)
{
    const char *p;

    for (p = v; *p != '\0'; p++)
        if (*p == '/' && isdigit((unsigned char)p[1]))
            return 1;
    return 0;
}

/* Cookie attribute present? attrs = the part after the first ';'. */
static int cookie_has(const char *attrs, const char *flag)
{
    const char *p = attrs;
    size_t fl = strlen(flag);

    while (p != NULL && *p != '\0') {
        while (*p == ';' || *p == ' ' || *p == '\t')
            p++;
        if (ci_prefix(p, flag) && (p[fl] == '\0' || p[fl] == ';' || p[fl] == ' ' ||
                                   p[fl] == '=' || p[fl] == '\t'))
            return 1;
        p = strchr(p, ';');
    }
    return 0;
}

static void append_name(char *list, size_t n, const char *cookie)
{
    size_t used = strlen(list), nl = strcspn(cookie, "=;");

    if (nl > 32)
        nl = 32;
    if (used + nl + 3 >= n)
        return;
    if (used > 0) {
        strcat(list, ", ");
        used += 2;
    }
    memcpy(list + used, cookie, nl);
    list[used + nl] = '\0';
}


/* Header text is server-controlled: it only ever reaches add() through a "%s". */
static void check_cookies(const char *headers, int is_https, web_check *out, int *n, int max)
{
    const char *pos = headers;
    char v[1024], no_secure[120] = "", no_httponly[120] = "";
    int count = 0;

    while (next_header(&pos, "Set-Cookie", v, sizeof v)) {
        const char *attrs = strchr(v, ';');

        count++;
        if (attrs == NULL)
            attrs = "";
        if (is_https && !cookie_has(attrs, "Secure"))
            append_name(no_secure, sizeof no_secure, v); /* name only, never the value */
        if (!cookie_has(attrs, "HttpOnly"))
            append_name(no_httponly, sizeof no_httponly, v);
    }
    if (count == 0)
        return;
    if (no_secure[0] != '\0')
        add(out, n, max, "cookies", WEB_RECOMMENDED, "without Secure: %s", no_secure);
    else if (no_httponly[0] != '\0')
        add(out, n, max, "cookies", WEB_TIP, "without HttpOnly: %s", no_httponly);
    else
        add(out, n, max, "cookies", WEB_OK, "%d cookie(s), all with Secure and HttpOnly", count);
}

/* Page settings of a normal (2xx) https response. */
static void check_page(const char *headers, web_check *out, int *n, int max)
{
    char v[512], csp[512];
    int have_csp = web_header_value(headers, "Content-Security-Policy", csp, sizeof csp);

    if (have_csp)
        add(out, n, max, "csp", WEB_OK, "%s", csp);
    else if (web_header_value(headers, "Content-Security-Policy-Report-Only", v, sizeof v))
        add(out, n, max, "csp", WEB_TIP, "report-only (not enforced yet)");
    else
        add(out, n, max, "csp", WEB_TIP, "header missing");

    if (web_header_value(headers, "X-Frame-Options", v, sizeof v) &&
        (ci_prefix(v, "DENY") || ci_prefix(v, "SAMEORIGIN")))
        add(out, n, max, "frame", WEB_OK, "%s", v);
    else if (have_csp && ci_find(csp, "frame-ancestors") != NULL)
        add(out, n, max, "frame", WEB_OK, "frame-ancestors in the content security policy");
    else if (v[0] != '\0')
        add(out, n, max, "frame", WEB_RECOMMENDED, "%s", v);
    else
        add(out, n, max, "frame", WEB_RECOMMENDED, "no X-Frame-Options or frame-ancestors");

    if (web_header_value(headers, "X-Content-Type-Options", v, sizeof v) &&
        ci_prefix(v, "nosniff"))
        add(out, n, max, "nosniff", WEB_OK, "%s", v);
    else
        add(out, n, max, "nosniff", WEB_RECOMMENDED, "%s", v[0] ? v : "header missing");

    if (web_header_value(headers, "Referrer-Policy", v, sizeof v))
        add(out, n, max, "referrer",
            ci_find(v, "unsafe-url") != NULL || ci_find(v, "no-referrer-when-downgrade") != NULL
                ? WEB_TIP
                : WEB_OK,
            "%s", v);
    else
        add(out, n, max, "referrer", WEB_TIP, "header missing");
}

int web_check_headers(const char *headers, int is_https, int status, web_check *out, int max)
{
    char v[512], loc[256];
    int n = 0, redirect = status >= 300 && status < 400;

    if (headers == NULL)
        headers = "";
    web_header_value(headers, "Location", loc, sizeof loc);

    if (!is_https) {
        if (redirect && ci_prefix(loc, "https://"))
            add(out, &n, max, "https_redirect", WEB_OK, "HTTP %d to %s", status, loc);
        else
            add(out, &n, max, "https_redirect", WEB_IMPORTANT, "HTTP %d%s%s", status,
                loc[0] ? " to " : "", loc);
    } else {
        if (web_header_value(headers, "Strict-Transport-Security", v, sizeof v)) {
            long age = hsts_max_age(v);

            add(out, &n, max, "hsts",
                age >= HSTS_MIN_AGE ? WEB_OK : age > 0 ? WEB_TIP : WEB_RECOMMENDED, "%s", v);
        } else {
            add(out, &n, max, "hsts", WEB_RECOMMENDED, "header missing");
        }
        if (redirect)
            add(out, &n, max, "redirect", WEB_NOTE, "HTTP %d to %s", status,
                loc[0] ? loc : "(none)");
        else if (status >= 400 || status < 200)
            add(out, &n, max, "not_checked", WEB_NOTE, "HTTP %d", status);
        else
            check_page(headers, out, &n, max);
    }
    check_cookies(headers, is_https, out, &n, max);

    if (web_header_value(headers, "Server", v, sizeof v) && has_version(v))
        add(out, &n, max, "server_version", WEB_TIP, "%s", v);
    else
        add(out, &n, max, "server_version", WEB_OK, "%s", v[0] ? v : "no Server header");
    if (web_header_value(headers, "X-Powered-By", v, sizeof v))
        add(out, &n, max, "powered_by", WEB_TIP, "%s", v);
    else
        add(out, &n, max, "powered_by", WEB_OK, "no X-Powered-By header");
    return n;
}

/* Whole TLDs on the browsers' HSTS preload list. Verified 2026-10-24:
   https://hstspreload.org/api/v2/status?domain=dev (and app, page) -> "preloaded";
   https://www.registry.google/domains/dev/ -> "HTTPS required on all connections to .dev
   websites and pages". Add a TLD only with the same kind of primary source. */
static const char *const preloaded_tlds[] = {"dev", "app", "page"};

int web_tld_preloaded(const char *host)
{
    const char *dot = strrchr(host, '.');
    size_t i;

    if (dot == NULL || dot == host)
        return 0;
    for (i = 0; i < sizeof preloaded_tlds / sizeof preloaded_tlds[0]; i++)
        if (strcasecmp(dot + 1, preloaded_tlds[i]) == 0)
            return 1;
    return 0;
}

void web_apply_preload(const char *host, web_check *checks, int n)
{
    const char *tld;
    int i;

    if (!web_tld_preloaded(host))
        return;
    tld = strrchr(host, '.');
    for (i = 0; i < n; i++) {
        web_check *c = &checks[i];

        if (c->level < WEB_TIP)
            continue;
        if (strcmp(c->id, "https_redirect") == 0) {
            c->level = WEB_OK;
            snprintf(c->detail, sizeof c->detail,
                     "browsers never open %s addresses over http (whole-domain HSTS preload)",
                     tld);
        } else if (strcmp(c->id, "hsts") == 0) {
            c->level = WEB_OK;
            snprintf(c->detail, sizeof c->detail,
                     "header missing, but browsers already force https for every %s address",
                     tld);
        }
    }
}

/* ---------- hosting platforms ---------- */

/* Advice per platform, checked 2026-10-24 against: Cloudflare Pages/Workers "_headers" docs,
   Cloudflare "Always Use HTTPS", "HSTS" and response header Transform Rules docs, Vercel
   vercel.json docs, GitHub "Securing your GitHub Pages site with HTTPS" (no header settings),
   MDN X-Frame-Options (meta has no effect; Apache/nginx lines), MDN Referrer-Policy (meta),
   MDN Content-Security-Policy (meta). Netlify, LiteSpeed and IIS are recognised but keep the
   general advice until their docs are checked. */
static const struct {
    const char *id, *name;
} platforms[] = {
    {"github-pages", "GitHub Pages"},
    {"cloudflare-static", "Cloudflare Pages or Workers"},
    {"cloudflare", "Cloudflare"},
    {"vercel", "Vercel"},
    {"netlify", "Netlify"},
    {"wix", "Wix"},
    {"squarespace", "Squarespace"},
    {"shopify", "Shopify"},
    {"apache", "Apache"},
    {"litespeed", "LiteSpeed"},
    {"nginx", "nginx"},
    {"iis", "Microsoft IIS"},
};

static int ci_suffix(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);

    return a >= b && strcasecmp(s + a - b, suffix) == 0;
}

static int has_header(const char *headers, const char *name)
{
    char v[8];

    return web_header_value(headers, name, v, sizeof v);
}

const char *web_detect_platform(const char *headers, const char *host)
{
    char server[128];

    if (headers == NULL)
        headers = "";
    if (host == NULL)
        host = "";
    web_header_value(headers, "Server", server, sizeof server);
    if (ci_suffix(host, ".github.io") || strcasecmp(server, "GitHub.com") == 0)
        return "github-pages";
    if (ci_suffix(host, ".pages.dev") || ci_suffix(host, ".workers.dev"))
        return "cloudflare-static";
    if (has_header(headers, "X-Vercel-Id") || strcasecmp(server, "Vercel") == 0)
        return "vercel";
    if (has_header(headers, "X-NF-Request-Id") || strcasecmp(server, "Netlify") == 0)
        return "netlify";
    if (has_header(headers, "X-Wix-Request-Id") || strcasecmp(server, "Pepyaka") == 0)
        return "wix";
    if (has_header(headers, "X-ShopId") || has_header(headers, "X-Shopify-Stage"))
        return "shopify";
    if (strcasecmp(server, "Squarespace") == 0)
        return "squarespace";
    if (strcasecmp(server, "cloudflare") == 0)
        return "cloudflare";
    if (ci_prefix(server, "Apache"))
        return "apache";
    if (ci_prefix(server, "LiteSpeed"))
        return "litespeed";
    if (ci_prefix(server, "nginx"))
        return "nginx";
    if (ci_prefix(server, "Microsoft-IIS"))
        return "iis";
    return NULL;
}

const char *web_platform_name(const char *platform)
{
    size_t i;

    for (i = 0; platform != NULL && i < sizeof platforms / sizeof platforms[0]; i++)
        if (strcmp(platforms[i].id, platform) == 0)
            return platforms[i].name;
    return platform;
}

/* the header line a check asks for; NULL for checks without a single fixed value */
static int wanted_header(const char *id, const char **name, const char **value)
{
    static const char *const map[][3] = {
        {"frame", "X-Frame-Options", "SAMEORIGIN"},
        {"nosniff", "X-Content-Type-Options", "nosniff"},
        {"referrer", "Referrer-Policy", "strict-origin-when-cross-origin"},
        {"hsts", "Strict-Transport-Security", "max-age=31536000"},
    };
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i][0], id) == 0) {
            *name = map[i][1];
            *value = map[i][2];
            return 1;
        }
    return 0;
}

int web_platform_fix(const char *platform, const char *id, char *out, size_t n)
{
    const char *h = NULL, *v = NULL;
    int header = wanted_header(id, &h, &v);

    if (platform == NULL || n == 0)
        return 0;
    if (strcmp(platform, "github-pages") == 0) {
        if (strcmp(id, "https_redirect") == 0)
            snprintf(out, n, "In the site's GitHub repository, open Settings > Pages and tick Enforce HTTPS.");
        else if (strcmp(id, "referrer") == 0)
            snprintf(out, n, "GitHub Pages can't send this header, but each page can set it: add "
                             "<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\"> inside <head>.");
        else if (strcmp(id, "csp") == 0)
            snprintf(out, n, "GitHub Pages can't send this header, but each page can carry a policy in a "
                             "<meta http-equiv=\"Content-Security-Policy\" content=\"...\"> tag inside <head>. "
                             "Build it carefully so the site keeps working.");
        else if (strcmp(id, "frame") == 0 || strcmp(id, "nosniff") == 0 || strcmp(id, "hsts") == 0)
            snprintf(out, n, "GitHub Pages has no setting for this, and it can't be added inside the page. "
                             "To get it, put the site on your own domain behind a service such as Cloudflare "
                             "and add it there, or move to a host that allows custom headers (for example "
                             "Cloudflare Pages). On GitHub Pages alone this can stay as it is.");
        else
            return 0;
        return 1;
    }
    if (strcmp(platform, "cloudflare-static") == 0 && header) {
        snprintf(out, n, "Add a plain text file named _headers next to index.html in the folder you upload. "
                         "Put /* on the first line and, indented below it, %s: %s. Then upload the site again.", h, v);
        return 1;
    }
    if (strcmp(platform, "cloudflare") == 0) {
        if (strcmp(id, "https_redirect") == 0)
            snprintf(out, n, "In the Cloudflare dashboard, open SSL/TLS > Edge Certificates and turn on Always Use HTTPS.");
        else if (strcmp(id, "hsts") == 0)
            snprintf(out, n, "In the Cloudflare dashboard, open SSL/TLS > Edge Certificates and, under HTTP Strict "
                             "Transport Security (HSTS), choose Enable HSTS. Only do this once the whole site works over https.");
        else if (header)
            snprintf(out, n, "In the Cloudflare dashboard, add a response header Transform Rule (under Rules) that "
                             "sets the header %s to %s.", h, v);
        else
            return 0;
        return 1;
    }
    if (strcmp(platform, "vercel") == 0 && header) {
        snprintf(out, n, "In vercel.json, add under \"headers\" an entry with \"source\": \"/(.*)\" and the header "
                         "{\"key\": \"%s\", \"value\": \"%s\"}. Then deploy again.", h, v);
        return 1;
    }
    if (strcmp(platform, "apache") == 0 && header) {
        snprintf(out, n, "Add this line to the site's .htaccess file, or ask your host to add it: "
                         "Header always set %s \"%s\"", h, v);
        return 1;
    }
    if (strcmp(platform, "nginx") == 0 && header) {
        snprintf(out, n, "Ask your host or developer to add this line to the nginx configuration: "
                         "add_header %s \"%s\" always;", h, v);
        return 1;
    }
    if ((strcmp(platform, "wix") == 0 || strcmp(platform, "squarespace") == 0 ||
         strcmp(platform, "shopify") == 0) &&
        (header || strcmp(id, "csp") == 0)) {
        const char *name = web_platform_name(platform);

        snprintf(out, n, "%s controls these settings for the sites it hosts, so site owners usually can't add "
                         "them. Ask %s support whether it can be turned on.", name, name);
        return 1;
    }
    return 0;
}
