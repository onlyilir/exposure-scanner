/* libFuzzer target for everything that reads data a website or DNS server controls: response
   headers, the home page and follow-up files (techdetect), header checks and platform
   recognition (webcheck), chunked bodies (http_probe), version strings and ranges (version,
   vulndb), security data lines (vulndb) and email records (maildns). Built and run by
   scripts/fuzz.sh with clang -fsanitize=fuzzer,address,undefined. No network. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/http_probe.h"
#include "../src/maildns.h"
#include "../src/techdetect.h"
#include "../src/version.h"
#include "../src/vulndb.h"
#include "../src/webcheck.h"

static const char *const FOLLOW[] = {"/feed/", "/wp-links-opml.php", "/_next/static/chunks/main-1.js",
                                     "/_next/static/chunks/255-1.js", "/administrator/manifests/files/joomla.xml",
                                     "/CHANGELOG.txt", "/core/CHANGELOG.txt", "/magento_version"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf = malloc(size + 1), *copy = malloc(size + 1), *chunk = malloc(size + 1);
    const char *headers, *body;
    char paths[TECH_MAX_FOLLOWUPS][192], fixed[40];
    tech_list l;
    web_check checks[WEB_MAX_CHECKS];
    mail_result mr;
    web_check mc[MAIL_MAX_CHECKS];
    vulndb db;
    ver_t v;
    size_t i, blen;
    int n;

    if (buf == NULL || copy == NULL || chunk == NULL) {
        free(buf);
        free(copy);
        free(chunk);
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';
    memcpy(copy, buf, size + 1);
    memcpy(chunk, buf, size + 1);

    /* headers, an empty line, then the body (the way an HTTP answer arrives) */
    headers = buf;
    body = "";
    {
        char *sep = strstr(buf, "\n\n");

        if (sep != NULL) {
            *sep = '\0';
            body = sep + 2;
        }
    }
    blen = strlen(body);

    memset(&l, 0, sizeof l);
    tech_from_headers(headers, &l);
    tech_from_html(body, blen, &l);
    n = tech_followups(&l, body, blen, paths, TECH_MAX_FOLLOWUPS);
    for (i = 0; i < (size_t)n; i++)
        tech_apply(paths[i], 200, body, blen, &l);
    for (i = 0; i < sizeof FOLLOW / sizeof FOLLOW[0]; i++)
        tech_apply(FOLLOW[i], 200, body, blen, &l);

    web_check_headers(headers, 1, 200, checks, WEB_MAX_CHECKS);
    web_check_headers(headers, 0, 301, checks, WEB_MAX_CHECKS);
    web_detect_platform(headers, "shop.example");

    http_dechunk(chunk, size);

    ver_parse(headers, &v);
    vdb_range_match(body, headers, fixed, sizeof fixed);

    /* the security data parser and assessment, with the input as data lines */
    memset(&db, 0, sizeof db);
    if (vdb_load_text(&db, copy) == 0)
        for (i = 0; i < (size_t)l.n; i++) {
            vdb_assess a;

            vdb_assess_item(&db, &l.t[i], &a);
        }
    vdb_free(&db);

    memset(&mr, 0, sizeof mr);
    snprintf(mr.domain, sizeof mr.domain, "shop.example");
    mr.answered = 1;
    mr.has_mx = (int)(size & 1);
    mr.nspf = 1 + (int)((size >> 1) & 1);
    snprintf(mr.spf, sizeof mr.spf, "%s", headers);
    snprintf(mr.dmarc, sizeof mr.dmarc, "%s", body);
    snprintf(mr.dkim, sizeof mr.dkim, "%.20s", body);
    mail_grade(&mr, mc, MAIL_MAX_CHECKS);
    mail_wanted(headers);

    free(buf);
    free(copy);
    free(chunk);
    return 0;
}
