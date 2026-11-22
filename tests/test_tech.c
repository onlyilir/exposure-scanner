/* Software detection (techdetect), the local security data (vulndb) and how the client report
   grades them. No network: answers and data are written out here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/report.h"
#include "../src/techdetect.h"
#include "../src/version.h"
#include "../src/vulndb.h"

static int run, failed;

#define CHECK(cond, what)                                                        \
    do {                                                                         \
        run++;                                                                   \
        if (!(cond)) {                                                           \
            failed++;                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, what);       \
        }                                                                        \
    } while (0)

static const tech_item *find(tech_list *l, const char *p) { return tech_find(l, p); }

static int ver_order(const char *a, const char *b)
{
    ver_t x, y;

    return ver_parse(a, &x) == 0 && ver_parse(b, &y) == 0 ? ver_cmp(&x, &y) : 99;
}

static void test_versions(void)
{
    char fixed[40];

    CHECK(ver_order("15.5.0-canary.3", "15.5.0") < 0, "canary sorts below the release");
    CHECK(ver_order("2.4.7-p1", "2.4.7") > 0, "-p1 patch release sorts above the release");
    CHECK(ver_order("2.4.7-p1", "2.4.7-p2") < 0, "-p1 below -p2");
    CHECK(ver_order("2.4.7-p3", "2.4.8") < 0, "-p3 below the next release");

    CHECK(vdb_range_match(">=6.9,<6.9.5;>=7.0,<7.0.2", "7.0.1", fixed, sizeof fixed) == 1, "7.0.1 in range");
    CHECK(strcmp(fixed, "7.0.2") == 0, "fixed version of the matching branch");
    CHECK(vdb_range_match(">=6.9,<6.9.5;>=7.0,<7.0.2", "7.0.2", fixed, sizeof fixed) == 0, "7.0.2 fixed");
    CHECK(vdb_range_match(">=6.9,<6.9.5;>=7.0,<7.0.2", "6.8.3", fixed, sizeof fixed) == 0, "6.8 unaffected");
    CHECK(vdb_range_match("=4.7.1", "4.7.1", fixed, sizeof fixed) == 1 && fixed[0] == '\0', "exact version");
    CHECK(vdb_range_match("<=1.2", "1.2", fixed, sizeof fixed) == 1, "inclusive end");
    CHECK(vdb_range_match(">=0", "0.1", fixed, sizeof fixed) == 1, "open range");
    CHECK(vdb_range_match(">2.0,<2.4.7-p2", "2.4.7-p1", fixed, sizeof fixed) == 1, "Magento patch inside");
    CHECK(vdb_range_match(">=1.0,<2.0", "abc", fixed, sizeof fixed) == -1, "not a version");
    CHECK(vdb_range_match(";;", "1.0", fixed, sizeof fixed) == 0, "empty alternatives never match");
}

static void test_headers(void)
{
    tech_list l;
    const tech_item *t;

    memset(&l, 0, sizeof l);
    tech_from_headers("Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16\r\n", &l);
    t = find(&l, "apache");
    CHECK(t && strcmp(t->version, "2.4.6") == 0 && strcmp(t->os, "centos") == 0, "Apache with CentOS tag");
    t = find(&l, "openssl");
    CHECK(t && strcmp(t->version, "1.0.2k") == 0 && strcmp(t->os, "centos") == 0, "OpenSSL in the same label");
    t = find(&l, "php");
    CHECK(t && strcmp(t->version, "5.4.16") == 0 && t->conf == TECH_EXACT, "PHP in the Server label");

    memset(&l, 0, sizeof l);
    tech_from_headers("Server: nginx\r\nX-Powered-By: PHP/7.4.33-1+deb11u5\r\n", &l);
    t = find(&l, "php");
    CHECK(t && strcmp(t->version, "7.4.33") == 0 && strcmp(t->os, "debian") == 0 &&
              strcmp(t->os_release, "11") == 0, "Debian release from the PHP package suffix");
    t = find(&l, "nginx");
    CHECK(t && t->version[0] == '\0', "nginx without a version");

    memset(&l, 0, sizeof l);
    tech_from_headers("Server: Microsoft-IIS/8.5\r\nX-Powered-By: ASP.NET\r\nX-AspNet-Version: 4.0.30319\r\n", &l);
    t = find(&l, "iis");
    CHECK(t && strcmp(t->version, "8.5") == 0 && strcmp(t->os, "windows") == 0, "IIS means Windows");
    CHECK(find(&l, "aspnet") && strcmp(find(&l, "aspnet")->version, "4.0.30319") == 0, "ASP.NET version");

    memset(&l, 0, sizeof l);
    tech_from_headers("X-Generator: Drupal 10 (https://www.drupal.org)\r\nVary: RSC, Next-Router-State-Tree\r\n", &l);
    t = find(&l, "drupal");
    CHECK(t && strcmp(t->version, "10") == 0 && t->conf == TECH_ESTIMATED, "Drupal major from X-Generator");
    t = find(&l, "nextjs");
    CHECK(t && (t->flags & TECH_APP_ROUTER), "Next.js App Router from Vary");
}

#define GEN_WP "<meta content=\"WordPress 6.8.3\" name=\"generator\" />"
#define DRUPAL10 "<script type=\"application/json\" data-drupal-selector=\"drupal-settings-json\">" \
                 "</script><script src=\"/core/misc/drupal.js?v=10.4.2\"></script>"
#define GHOST "<meta name=generator content=\"Ghost 5.82\">"

static void test_html_and_followups(void)
{
    static const char wp[] =
        "<html><head><meta name=\"viewport\" content=\"x\">"
        "<link rel='stylesheet' href='https://shop.example/wp-includes/css/dist/block-library/style.min.css?ver=7.0.1'>"
        "<script src='https://shop.example/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>"
        "<link rel=\"https://api.w.org/\" href=\"https://shop.example/wp-json/\"></head></html>";
    static const char app[] =
        "<html><body><script src=\"/_next/static/chunks/webpack-aec87d84c0ed8017.js\" async></script>"
        "<script src=\"/_next/static/chunks/4bd1b696-c023c6e3521b1417.js\" async></script>"
        "<script src=\"/_next/static/chunks/255-4efeec91c7871d79.js\" async></script>"
        "<script src=\"/_next/static/chunks/main-app-2be1537d10988d1b.js\" async></script>"
        "<script src=\"https://cdn.other.example/_next/static/chunks/x.js\"></script>"
        "<script>self.__next_f.push([1,\"\"])</script></body></html>";
    static const char pages[] =
        "<script src=\"/_next/static/chunks/polyfills-42372ed130431b0a.js\" nomodule></script>"
        "<script src=\"/_next/static/chunks/framework-1.js\"></script>"
        "<script src=\"/_next/static/chunks/main-ee883a14fa4836f3.js\"></script>"
        "<script id=\"__NEXT_DATA__\" type=\"application/json\">{}</script>";
    char paths[TECH_MAX_FOLLOWUPS][192];
    tech_list l;
    const tech_item *t;
    int n;

    memset(&l, 0, sizeof l);
    tech_from_html(wp, strlen(wp), &l);
    t = find(&l, "wordpress");
    CHECK(t && strcmp(t->version, "7.0.1") == 0 && t->conf == TECH_ESTIMATED, "WordPress version from core files");
    n = tech_followups(&l, wp, strlen(wp), paths, TECH_MAX_FOLLOWUPS);
    CHECK(n == 2 && strcmp(paths[0], "/feed/") == 0 && strcmp(paths[1], "/wp-links-opml.php") == 0,
          "WordPress follow-ups: feed and OPML");
    tech_apply("/feed/", 200, "<rss><channel><generator>https://wordpress.org/?v=7.0.1</generator>", 60, &l);
    t = find(&l, "wordpress");
    CHECK(t && t->conf == TECH_EXACT && strcmp(t->source, "the site's RSS feed") == 0, "feed makes it exact");
    CHECK(tech_followups(&l, wp, strlen(wp), paths, TECH_MAX_FOLLOWUPS) == 0, "nothing left to fetch");

    memset(&l, 0, sizeof l);
    tech_from_html(GEN_WP, strlen(GEN_WP), &l);
    t = find(&l, "wordpress");
    CHECK(t && strcmp(t->version, "6.8.3") == 0 && t->conf == TECH_EXACT, "generator tag, attributes reversed");

    memset(&l, 0, sizeof l);
    tech_from_html(app, strlen(app), &l);
    t = find(&l, "nextjs");
    CHECK(t && (t->flags & TECH_APP_ROUTER) && t->version[0] == '\0', "Next.js App Router, version unknown");
    n = tech_followups(&l, app, strlen(app), paths, TECH_MAX_FOLLOWUPS);
    CHECK(n == 3 && strstr(paths[0], "4bd1b696") && strstr(paths[1], "/255-") && strstr(paths[2], "main-app"),
          "Next.js chunks in page order, runtime and other hosts skipped");
    tech_apply(paths[1], 200, "r()}window.next={version:\"15.5.4\",appDir:!0},(\"function\"", 55, &l);
    t = find(&l, "nextjs");
    CHECK(t && strcmp(t->version, "15.5.4") == 0 && t->conf == TECH_EXACT, "App Router version from a chunk");

    memset(&l, 0, sizeof l);
    tech_from_html(pages, strlen(pages), &l);
    n = tech_followups(&l, pages, strlen(pages), paths, TECH_MAX_FOLLOWUPS);
    CHECK(n == 1 && strstr(paths[0], "main-ee883a14") != NULL, "Pages Router: main chunk only, framework skipped");
    tech_apply(paths[0], 200, "let n=r(6450);window.next={version:n.version};version:function(){return B}});"
               "let B=\"14.2.3\",H=(0,b.default)()", 110, &l);
    t = find(&l, "nextjs");
    CHECK(t && strcmp(t->version, "14.2.3") == 0, "Pages Router version through the getter");

    /* Next.js 12 (seen in a real 12.3.4 build): t.version="12.3.4" next to window.next={version:n.version} */
    memset(&l, 0, sizeof l);
    tech_from_html(pages, strlen(pages), &l);
    tech_apply(paths[0], 200, "x.version=\"3.1.0\";k=r(745);t.version=\"12.3.4\",t.router=p;"
               "window.next={version:n.version,get router(){return n.router}}", 120, &l);
    t = find(&l, "nextjs");
    CHECK(t && strcmp(t->version, "12.3.4") == 0, "Next.js 12 exports.version, other version strings skipped");
    memset(&l, 0, sizeof l);
    tech_from_html(pages, strlen(pages), &l);
    tech_apply(paths[0], 200, "lib.version=\"12.3.4\";", 21, &l);
    CHECK(find(&l, "nextjs")->version[0] == '\0', "a .version string without window.next is not taken");

    memset(&l, 0, sizeof l);
    tech_from_html(DRUPAL10, strlen(DRUPAL10), &l);
    t = find(&l, "drupal");
    CHECK(t && strcmp(t->version, "10.4.2") == 0 && t->conf == TECH_EXACT, "Drupal version from core file");

    memset(&l, 0, sizeof l);
    tech_from_html("<script>jQuery.extend(Drupal.settings, {})</script><script src=\"/misc/drupal.js?q1\">", 80, &l);
    t = find(&l, "drupal");
    CHECK(t && strcmp(t->version, "7") == 0, "Drupal 7 footprint");
    n = tech_followups(&l, "", 0, paths, TECH_MAX_FOLLOWUPS);
    CHECK(n == 1 && strcmp(paths[0], "/CHANGELOG.txt") == 0, "Drupal 7 change log");
    tech_apply("/CHANGELOG.txt", 200, "\nDrupal 7.98, 2023-06-07\n-----", 30, &l);
    CHECK(strcmp(find(&l, "drupal")->version, "7.98") == 0, "Drupal 7 version from the change log");

    memset(&l, 0, sizeof l);
    tech_from_html("<script src=\"/media/system/js/core.js\"></script>", 48, &l);
    tech_apply("/administrator/manifests/files/joomla.xml", 200, "<extension><version>4.4.2</version>", 36, &l);
    CHECK(find(&l, "joomla") && strcmp(find(&l, "joomla")->version, "4.4.2") == 0, "Joomla manifest");
    tech_apply("/administrator/manifests/files/joomla.xml", 404, "<version>9.9.9</version>", 25, &l);
    CHECK(strcmp(find(&l, "joomla")->version, "4.4.2") == 0, "a 404 answer is ignored");

    memset(&l, 0, sizeof l);
    tech_from_html("<script type=\"text/x-magento-init\">{}</script>", 46, &l);
    tech_apply("/magento_version", 200, "Magento/2.4 (Community)", 23, &l);
    t = find(&l, "magento");
    CHECK(t && strcmp(t->version, "2.4") == 0 && t->conf == TECH_ESTIMATED, "Magento major.minor");

    memset(&l, 0, sizeof l);
    tech_from_html(GHOST, strlen(GHOST), &l);
    CHECK(find(&l, "ghost") && strcmp(find(&l, "ghost")->version, "5.82") == 0, "Ghost generator, unquoted name");

    memset(&l, 0, sizeof l);
    tech_from_html("<p>Plain page about /wp-contentment and _next steps</p>", 55, &l);
    CHECK(l.n == 0, "no false footprints");
}

static const char DATA[] =
    "G\t2026-11-16T07:17:14Z\t4\n"
    "V\twordpress\tCVE-2026-60137\tmedium\t5.9\t1\t>=6.8,<6.8.6;>=6.9,<6.9.5;>=7.0,<7.0.2\t6.8.6,6.9.5,7.0.2\t"
    "https://nvd.nist.gov/vuln/detail/CVE-2026-60137\tSQL injection\n"
    "V\twordpress\tCVE-2026-63030\tcritical\t9.8\t1\t>=6.9,<6.9.5;>=7.0,<7.0.2\t6.9.5,7.0.2\t"
    "https://nvd.nist.gov/vuln/detail/CVE-2026-63030\tREST API batch route confusion\n"
    "V\twordpress\tCVE-2017-1001000\thigh\t7.5\t0\t=4.7.0;=4.7.1\t-\thttps://nvd.nist.gov/x\tREST API content injection\n"
    "V\tnextjs\tGHSA-9qr9-h5gf-34mp\tcritical\t-\t0\t>=15.5.0-canary.0,<15.5.7;>=16.0.0-canary.0,<16.0.7\t15.5.7,16.0.7\t"
    "https://osv.dev/vulnerability/GHSA-9qr9-h5gf-34mp\tRCE in React flight protocol\n"
    "V\twordpress\tCVE-2019-17669\tcritical\t9.8\t0\t<5.2.4\t5.2.4\thttps://nvd.nist.gov/x\tunbounded NVD range\n"
    "S\twordpress\t4.9.35\toutdated\n"
    "S\twordpress\t7.0.1\tinsecure\n"
    "S\twordpress\t7.1.4\tlatest\n"
    "E\twordpress\t7.1\tno\t-\t7.1.4\n"
    "E\twordpress\t7.0\tno\t-\t7.0.5\n"
    "E\tphp\t8.3\t2027-12-31\t-\t8.3.36\n"
    "E\tphp\t7.4\t2022-11-28\t-\t7.4.33\n"
    "E\tnextjs\t16\tno\t-\t16.4.6\n"
    "E\tnextjs\t15\tno\t-\t15.5.28\n"
    "E\tubuntu\t22.04\t2027-06-01\t2032-04-21\t22.04.5\n"
    "E\tubuntu\t20.04\t2025-05-29\t2030-04-02\t20.04.6\n"
    "E\tubuntu\t18.04\t2023-05-31\t2028-04-01\t18.04.6\n"
    "E\tcentos\t7\t2024-06-30\tno\t7 (2009)\n"
    "E\twindows-server\t2016\t2027-01-12\t2030-01-12\t10.0.14393\n"
    "E\twindows-server\t2012-r2\t2023-10-10\t2026-10-13\t6.3.9600\n"
    "M\tapache\t2.4.41\tubuntu\t20.04\n"
    "M\tnginx\t1.18.0\tubuntu\t20.04\n"
    "M\tnginx\t1.18.0\tubuntu\t22.04\n"
    "M\tapache\t2.4.6\trhel\t7\n"
    "M\tphp\t7.4.3\tubuntu\t20.04\n";

static tech_item item(const char *product, const char *ver, int conf, int flags, const char *os)
{
    tech_item t;

    memset(&t, 0, sizeof t);
    snprintf(t.product, sizeof t.product, "%s", product);
    snprintf(t.version, sizeof t.version, "%s", ver);
    snprintf(t.os, sizeof t.os, "%s", os);
    snprintf(t.source, sizeof t.source, "test");
    t.conf = conf;
    t.flags = flags;
    return t;
}

static void test_assess(void)
{
    vulndb db;
    vdb_assess a;
    tech_item t;

    memset(&db, 0, sizeof db);
    CHECK(vdb_load_text(&db, DATA) == 0, "load data");
    CHECK(strcmp(db.generated, "2026-11-16") == 0 && db.nvuln == 4, "G line read");
    vdb_set_today("2026-11-16");

    t = item("wordpress", "7.0.1", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 2 && a.worst == VDB_SEV_CRITICAL && a.kev, "WordPress 7.0.1: two holes, critical, in use");
    CHECK(strcmp(a.fix_to, "7.0.2") == 0, "fix to 7.0.2");
    CHECK(strcmp(a.top[0].id, "CVE-2026-63030") == 0, "critical first");
    CHECK(strcmp(a.wp_status, "insecure") == 0, "WordPress.org status");
    CHECK(strcmp(a.cycle, "7.0") == 0 && a.eol == 0 && strcmp(a.newest, "7.0.5") == 0, "7.0 line still supported");

    t = item("wordpress", "7.1.4", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 0 && a.known && strcmp(a.wp_status, "latest") == 0, "latest WordPress is clean");

    t = item("wordpress", "4.7.1", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 1 && a.fix_to[0] == '\0', "exact-version hole without a fixed bound");

    /* WordPress backports fixes to older lines: "every version before 5.2.4" says nothing about 4.9.x */
    t = item("wordpress", "5.2.0", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 1 && strcmp(a.top[0].id, "CVE-2019-17669") == 0, "unbounded range counts on its own line");
    t = item("wordpress", "4.9.30", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 0, "unbounded range from a later line is skipped (backports)");
    t = item("wordpress", "4.9.35", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 0 && strcmp(a.wp_status, "outdated") == 0, "WordPress.org's outdated-but-patched verdict wins");

    t = item("nextjs", "15.5.4", TECH_EXACT, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 1 && strcmp(a.fix_to, "15.5.7") == 0 && strcmp(a.newest, "15.5.28") == 0, "Next.js 15.5.4");

    t = item("php", "7.4.3", TECH_EXACT, TECH_SERVER, "ubuntu");
    vdb_assess_item(&db, &t, &a);
    CHECK(strcmp(a.os_name, "Ubuntu 20.04") == 0 && a.os_eol == 1 && a.os_ext == 1, "Ubuntu 20.04: paid support only");
    CHECK(a.eol == 1, "PHP 7.4 itself is end of life");

    t = item("nginx", "1.18.0", TECH_EXACT, TECH_SERVER, "ubuntu");
    vdb_assess_item(&db, &t, &a);
    CHECK(strcmp(a.os_name, "Ubuntu 20.04 or 22.04") == 0 && a.os_eol == 0, "ambiguous release: newest decides");

    t = item("apache", "2.4.6", TECH_EXACT, TECH_SERVER, "centos");
    vdb_assess_item(&db, &t, &a);
    CHECK(strcmp(a.os_name, "CentOS 7") == 0 && a.os_eol == 1 && a.os_ext == 0, "CentOS 7 ended");

    t = item("iis", "8.5", TECH_EXACT, TECH_SERVER, "windows");
    vdb_assess_item(&db, &t, &a);
    CHECK(strcmp(a.os_name, "Windows Server 2012 R2") == 0 && a.os_eol == 1 && a.os_ext == 0,
          "IIS 8.5: Windows Server 2012 R2, paid updates over too");

    t = item("iis", "10.0", TECH_EXACT, TECH_SERVER, "windows");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.os_eol == -1 && strcmp(a.os_eol_date, "2027-01-12") == 0, "IIS 10: only the 2016 date");

    t = item("drupal", "10", TECH_ESTIMATED, TECH_SITE, "");
    vdb_assess_item(&db, &t, &a);
    CHECK(a.nhole == 0, "a bare major version is not matched against holes");

    vdb_set_today(NULL);
    vdb_free(&db);
}

static void test_report(void)
{
    vulndb db;
    scan_report r;
    probe_result p;
    report_summary s;
    char *json = NULL;
    size_t jlen = 0;
    FILE *f;
    int i, wp = 0, os = 0, note = 0;

    memset(&db, 0, sizeof db);
    vdb_load_text(&db, DATA);
    vdb_set_today("2026-11-16");
    memset(&p, 0, sizeof p);
    snprintf(p.t.host, sizeof p.t.host, "shop.example");
    p.t.port = 443;
    p.t.tls = 1;
    p.connected = 1;
    p.status = 200;
    p.tech.t[0] = item("wordpress", "7.0.1", TECH_EXACT, TECH_SITE, "");
    p.tech.t[1] = item("php", "7.4.3", TECH_EXACT, TECH_SERVER, "ubuntu");
    p.tech.n = 2;
    p.fetched = 2;
    memset(&r, 0, sizeof r);
    r.http = &p;
    r.nhttp = 1;
    r.db = &db;

    report_summarize(&r, &s);
    for (i = 0; i < s.nitems; i++) {
        if (strstr(s.items[i].title, "WordPress 7.0.1 has 2 known security holes, 2 used by attackers") &&
            s.items[i].level == WEB_IMPORTANT && strstr(s.items[i].fix, "7.0.2"))
            wp = 1;
        if (strstr(s.items[i].title, "Ubuntu 20.04, which is past its normal support") &&
            s.items[i].level == WEB_RECOMMENDED)
            os = 1;
    }
    CHECK(wp, "report: WordPress holes are Important with the fixed version");
    CHECK(os, "report: Ubuntu 20.04 is Recommended (paid support only)");
    CHECK(report_software_holes(&r, &p) == 2, "two holes count as findings");
    CHECK(report_rc_http(&r) == 1, "http exit code 1 with known holes");

#ifdef _WIN32
    f = tmpfile();
#else
    f = open_memstream(&json, &jlen);
#endif
    if (f != NULL) {
        long size;

        report_print_json(&r, "site", f);
#ifdef _WIN32
        fflush(f);
        size = ftell(f);
        json = malloc((size_t)size + 1);
        rewind(f);
        jlen = json != NULL ? fread(json, 1, (size_t)size, f) : 0;
        if (json != NULL)
            json[jlen] = '\0';
#else
        (void)size;
#endif
        fclose(f);
    }
    CHECK(json != NULL && strstr(json, "\"software\":[{\"product\":\"wordpress\"") != NULL, "JSON software list");
    CHECK(json != NULL && strstr(json, "\"known_holes\":2") != NULL && strstr(json, "\"fix_to\":\"7.0.2\""),
          "JSON holes and fixed version");
    CHECK(json != NULL && strstr(json, "\"os\":\"Ubuntu 20.04\"") != NULL, "JSON operating system");
    CHECK(json != NULL && strstr(json, "\"security_data\":{\"generated\":\"2026-11-16\"") != NULL, "JSON data date");
    free(json);

    /* without security data the software is still listed */
    r.db = NULL;
    report_summarize(&r, &s);
    note = report_software_holes(&r, &p) == 0 && report_rc_http(&r) == 0;
    CHECK(note, "no data: no holes, no findings");

    vdb_set_today(NULL);
    vdb_free(&db);
}

static int level_of(const mail_result *r, const char *id)
{
    web_check c[MAIL_MAX_CHECKS];
    int n = mail_grade(r, c, MAIL_MAX_CHECKS), k;

    for (k = 0; k < n; k++)
        if (strcmp(c[k].id, id) == 0)
            return c[k].level;
    return -1;
}

static void test_mail(void)
{
    mail_result r;

    CHECK(mail_wanted("shop.example") && mail_wanted("www.bakery.co.uk"), "real domains are checked");
    CHECK(!mail_wanted("127.0.0.1") && !mail_wanted("localhost") && !mail_wanted("::1"), "addresses skipped");
    CHECK(!mail_wanted("shop-demo.workers.dev") && !mail_wanted("demo.github.io") &&
              !mail_wanted("shop.pages.dev"), "shared hosting domains skipped");

    memset(&r, 0, sizeof r);
    snprintf(r.domain, sizeof r.domain, "shop.example");
    r.answered = 1;
    r.has_mx = 1;
    CHECK(level_of(&r, "spf") == WEB_RECOMMENDED && level_of(&r, "dmarc") == WEB_RECOMMENDED,
          "no SPF, no DMARC on a mail domain");
    CHECK(level_of(&r, "dkim") == WEB_NOTE, "DKIM not found is only a note");

    r.nspf = 1;
    snprintf(r.spf, sizeof r.spf, "v=spf1 include:_spf.google.com ~all");
    snprintf(r.dmarc, sizeof r.dmarc, "v=DMARC1; p=reject; rua=mailto:d@shop.example");
    snprintf(r.dkim, sizeof r.dkim, "google");
    CHECK(level_of(&r, "spf") == WEB_OK && level_of(&r, "dmarc") == WEB_OK && level_of(&r, "dkim") == WEB_OK,
          "well protected domain passes");

    snprintf(r.spf, sizeof r.spf, "v=spf1 include:mall.example +all");
    CHECK(level_of(&r, "spf") == WEB_IMPORTANT, "+all lets anyone send");
    snprintf(r.spf, sizeof r.spf, "v=spf1 a mx all");
    CHECK(level_of(&r, "spf") == WEB_IMPORTANT, "a bare all means +all");
    snprintf(r.spf, sizeof r.spf, "v=spf1 include:smallbiz.example ?all");
    CHECK(level_of(&r, "spf") == WEB_RECOMMENDED, "?all is neutral");
    snprintf(r.spf, sizeof r.spf, "v=spf1 include:smallbiz.example");
    CHECK(level_of(&r, "spf") == WEB_TIP, "no all rule");
    snprintf(r.spf, sizeof r.spf, "v=spf1 redirect=_spf.example");
    CHECK(level_of(&r, "spf") == WEB_OK, "redirect counts");
    r.nspf = 2;
    CHECK(level_of(&r, "spf") == WEB_RECOMMENDED, "two SPF records are invalid");

    snprintf(r.dmarc, sizeof r.dmarc, "v=DMARC1;p=none");
    CHECK(level_of(&r, "dmarc") == WEB_TIP, "p=none only monitors");
    snprintf(r.dmarc, sizeof r.dmarc, "v=DMARC1; rua=mailto:x@y");
    CHECK(level_of(&r, "dmarc") == WEB_RECOMMENDED, "DMARC without a policy");

    memset(&r, 0, sizeof r);
    r.answered = 1;
    CHECK(level_of(&r, "spf") == WEB_TIP && level_of(&r, "dkim") == -1, "domain without email: SPF tip only");
    r.answered = 0;
    CHECK(level_of(&r, "mail_dns") == WEB_NOTE && level_of(&r, "spf") == -1, "no DNS answer: one note");
}

/* monthly monitoring: this month's issues against last month's (--since) */
static void test_since(void)
{
    vulndb db;
    scan_report r;
    probe_result p;
    report_summary s;
    report_meta meta = {"Shop", NULL, "16 November 2026", 1};
    const char *prev = "tmp_since_prev.txt", *html = "tmp_since.html";
    FILE *f = fopen(prev, "wb");
    char page[65536];
    size_t got;
    int i, new_os = 0, still_wp = 0;

    if (f == NULL) {
        CHECK(0, "write the previous issues file");
        return;
    }
    /* last month: WordPress 7.0.0 had holes (now 7.0.1: still open, numbers differ), a referrer
       tip that is gone (fixed), and the same tip listed twice (counted once) */
    fputs("important\tshop.example\tWordPress 7.0.0 has 5 known security holes, 3 used by attackers\n"
          "tip\tshop.example\tNo referrer policy is set\n"
          "tip\tshop.example\tNo referrer policy is set\n"
          "note\tshop.example\tSoftware found: WordPress 7.0.0\n"
          "garbage line without tabs\n", f);
    fclose(f);

    memset(&db, 0, sizeof db);
    vdb_load_text(&db, DATA);
    vdb_set_today("2026-11-16");
    memset(&p, 0, sizeof p);
    snprintf(p.t.host, sizeof p.t.host, "shop.example");
    p.t.port = 443;
    p.t.tls = 1;
    p.connected = 1;
    p.status = 200;
    p.tech.t[0] = item("wordpress", "7.0.1", TECH_EXACT, TECH_SITE, "");
    p.tech.t[1] = item("php", "7.4.3", TECH_EXACT, TECH_SERVER, "ubuntu");
    p.tech.n = 2;
    memset(&r, 0, sizeof r);
    r.http = &p;
    r.nhttp = 1;
    r.db = &db;
    r.since_items = prev;
    r.since_date = "16 October 2026";

    report_summarize(&r, &s);
    CHECK(s.since && s.nfixed == 1 && s.nstill == 1, "one fixed (counted once), one still open");
    CHECK(s.nnew == 1, "the Ubuntu item is new");
    CHECK(strstr(s.fixed[0], "No referrer policy is set (shop.example)") != NULL, "fixed issue named");
    for (i = 0; i < s.nitems; i++) {
        if (strstr(s.items[i].title, "Ubuntu 20.04") && s.items[i].is_new)
            new_os = 1;
        if (strstr(s.items[i].title, "WordPress 7.0.1") && !s.items[i].is_new)
            still_wp = 1;
    }
    CHECK(new_os && still_wp, "new and still-open items flagged per issue");

    /* a certificate problem (added after the website items) is compared too: 21 days then, 9 now */
    {
        tls_result tr;

        if ((f = fopen(prev, "wb")) != NULL) {
            fputs("recommended\tshop.example\tThe certificate expires in 21 days\n", f);
            fclose(f);
        }
        memset(&tr, 0, sizeof tr);
        snprintf(tr.host, sizeof tr.host, "shop.example");
        tr.port = 443;
        tr.connected = 1;
        tr.ncerts = 1;
        tr.certs[0].days_left = 9;
        tr.certs[0].flags = TLSF_EXPIRES_SOON;
        snprintf(tr.certs[0].not_after, sizeof tr.certs[0].not_after, "Nov 25 10:00:00 2026 GMT");
        r.tls = &tr;
        r.ntls = 1;
        report_summarize(&r, &s);
        CHECK(s.nfixed == 0 && s.nstill >= 1, "certificate issue still open, not counted as fixed");
        r.tls = NULL;
        r.ntls = 0;
    }

    if ((f = fopen(html, "wb")) != NULL) {
        report_write_html(&r, &meta, f);
        fclose(f);
    }
    f = fopen(html, "rb");
    got = f != NULL ? fread(page, 1, sizeof page - 1, f) : 0;
    if (f != NULL)
        fclose(f);
    page[got] = '\0';
    CHECK(strstr(page, "Monthly Website Safety Check-up") != NULL, "monthly heading");
    CHECK(strstr(page, "Since the last check-up (16 October 2026)") != NULL, "since section with date");
    CHECK(strstr(page, "<b>1</b><span>Fixed</span>") != NULL, "fixed tile");
    CHECK(strstr(page, "<span class=\"badge new\">New</span>") != NULL, "new badge on a card");

    /* no previous file: no comparison */
    r.since_items = "tmp_no_such_since.txt";
    report_summarize(&r, &s);
    CHECK(!s.since, "a missing file means no since section");

    remove(prev);
    remove(html);
    vdb_set_today(NULL);
    vdb_free(&db);
}

int main(void)
{
    test_since();
    test_mail();
    test_versions();
    test_headers();
    test_html_and_followups();
    test_assess();
    test_report();
    printf("tech tests: %d checks, %d failed\n", run, failed);
    return failed ? 1 : 0;
}
