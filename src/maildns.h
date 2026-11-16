#ifndef MAILDNS_H
#define MAILDNS_H

#include <stddef.h>

#include "webcheck.h"

/* Email spoofing protection of a domain, from its public DNS records only (no request to the
   website or its mail server):
     SPF    TXT  <domain>            "v=spf1 ..."  which servers may send its email (RFC 7208)
     DMARC  TXT  _dmarc.<domain>     "v=DMARC1; p=..."  what receivers do with fakes (RFC 7489)
     DKIM   TXT  <sel>._domainkey.<domain> at common selector names (RFC 6376); selectors are
            private, so not finding one is not proof there is none
     MX     whether the domain receives email at all */

#define MAIL_MAX_CHECKS 4

typedef struct {
    char domain[128];
    int answered;        /* the resolver answered at least one lookup */
    int has_mx;
    int nspf;            /* v=spf1 records (more than one makes SPF invalid) */
    char spf[300];
    char dmarc[300];
    char dkim[160];      /* selectors found, comma-separated */
    char error[96];
} mail_result;

/* 1 when the name is worth a mail check: a registrable-looking domain, not an IP address, not
   localhost and not a hosting platform's shared domain (pages.dev, github.io, ...). */
int mail_wanted(const char *host);

/* DNS lookups through the system resolver. Always fills r; 0 when anything answered. */
int mail_check(const char *domain, mail_result *r);

/* Grades the records into checks with ids "spf", "dmarc", "dkim", or one "mail_dns" when the
   lookups failed (levels as in webcheck.h). Pure: tests feed it records. Returns the count. */
int mail_grade(const mail_result *r, web_check *out, int max);

typedef struct {
    const char *id;
    const char *title_ok;   /* WEB_OK */
    const char *title_note; /* WEB_NOTE */
    const char *title_bad;  /* WEB_TIP and up */
    const char *why;
    const char *fix;
} mail_info;

const mail_info *mail_check_info(const char *id); /* NULL for an unknown id */
const char *mail_title(const web_check *c);        /* the title for c's level */

#endif
