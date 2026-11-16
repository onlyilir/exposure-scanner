#ifndef TECHDETECT_H
#define TECHDETECT_H

#include <stddef.h>

/* Which software a website runs, read from one ordinary answer (headers and the home page) plus a
   few public files that every visitor's browser could load (level 2). Pure functions: no network.

   Level 1  headers + home page: generator tags, framework footprints (/wp-content/, /_next/),
            core file versions (?ver=), server labels (Server, X-Powered-By, X-Generator).
   Level 2  tech_followups() names up to TECH_MAX_FOLLOWUPS public files for what level 1 found
            (WordPress feed, Next.js script chunks, Joomla's manifest, Drupal's change log,
            Magento's version file); tech_apply() reads their answers. */

#define TECH_MAX 10
#define TECH_MAX_FOLLOWUPS 5

enum { TECH_UNKNOWN = 0, TECH_ESTIMATED, TECH_EXACT }; /* how sure the version is */

#define TECH_APP_ROUTER 1 /* Next.js App Router: React Server Components */
#define TECH_SITE 2       /* a site builder or framework (holes come from the security data) */
#define TECH_SERVER 4     /* server software or language runtime, from a header */
#define TECH_PAGES 8      /* Next.js Pages Router */

typedef struct {
    char product[16]; /* wordpress nextjs joomla drupal magento ghost | apache nginx iis php openssl
                         aspnet express litespeed */
    char version[40]; /* "" when hidden */
    int conf;         /* TECH_UNKNOWN / TECH_ESTIMATED / TECH_EXACT */
    int flags;
    char source[64];  /* where it was seen, for the report: "generator tag", "Server header" */
    char os[16];      /* distribution tag next to it: ubuntu debian centos rhel rocky alma
                         amazon-linux fedora windows, or "" */
    char os_release[8]; /* release when the tag itself says it ("11" from PHP's "+deb11u5") */
} tech_item;

typedef struct {
    tech_item t[TECH_MAX];
    int n;
} tech_list;

/* headers = raw header block after the status line */
void tech_from_headers(const char *headers, tech_list *l);
/* body of the home page (any length; only the first 2 MB are read) */
void tech_from_html(const char *html, size_t len, tech_list *l);

/* Same-site paths worth one GET each, for what was found and is not yet exact. Returns count. */
int tech_followups(const tech_list *l, const char *html, size_t len, char paths[][192], int max);
/* Read one follow-up answer (status 200 only; others are ignored). */
void tech_apply(const char *path, int status, const char *body, size_t len, tech_list *l);

tech_item *tech_find(tech_list *l, const char *product);
const char *tech_name(const char *product);    /* "WordPress", "Next.js", ... */
const char *tech_conf_name(int conf);           /* "exact", "estimated", "unknown" */

#endif
