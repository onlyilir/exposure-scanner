#include "maildns.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#ifdef _WIN32
#include <windows.h>
#include <windns.h>
#else
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#endif

static void copy_str(char *dst, size_t n, const char *src)
{
    if (n > 0)
        snprintf(dst, n, "%s", src != NULL ? src : "");
}

/* ---------- which names ---------- */

int mail_wanted(const char *host)
{
    /* shared domains of hosting platforms: the site owner does not control their email records */
    static const char *const shared[] = {
        ".pages.dev", ".workers.dev", ".github.io", ".vercel.app", ".netlify.app", ".herokuapp.com",
        ".azurewebsites.net", ".web.app", ".firebaseapp.com", ".myshopify.com", ".wixsite.com",
        ".squarespace.com", ".blogspot.com", ".wordpress.com", ".onrender.com", ".fly.dev"};
    size_t i, hl = strlen(host);
    const char *p;
    int alpha = 0;

    if (strchr(host, '.') == NULL || strcasecmp(host, "localhost") == 0 || strchr(host, ':') != NULL)
        return 0;
    for (p = host; *p != '\0'; p++)
        alpha |= isalpha((unsigned char)*p);
    if (!alpha)
        return 0; /* IPv4 address */
    for (i = 0; i < sizeof shared / sizeof shared[0]; i++) {
        size_t sl = strlen(shared[i]);

        if (hl > sl && strcasecmp(host + hl - sl, shared[i]) == 0)
            return 0;
    }
    return 1;
}

/* ---------- DNS ---------- */

typedef void (*txt_fn)(const char *txt, void *ctx);

#ifdef _WIN32
/* -1 when the resolver gave no answer, 0 when it answered (with or without records) */
static int lookup_txt(const char *name, txt_fn fn, void *ctx)
{
    DNS_RECORDA *rec = NULL, *p;
    DNS_STATUS st = DnsQuery_A(name, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *)(void *)&rec, NULL);

    if (st == DNS_ERROR_RCODE_NAME_ERROR || st == DNS_INFO_NO_RECORDS)
        return 0;
    if (st != 0)
        return -1;
    for (p = rec; p != NULL; p = p->pNext) {
        char buf[1024];
        size_t o = 0;
        DWORD i;

        if (p->wType != DNS_TYPE_TEXT || p->Flags.S.Section != DnsSectionAnswer)
            continue;
        for (i = 0; i < p->Data.TXT.dwStringCount; i++) {
            const char *s = p->Data.TXT.pStringArray[i];
            size_t l = s != NULL ? strlen(s) : 0;

            if (o + l >= sizeof buf)
                l = sizeof buf - 1 - o;
            memcpy(buf + o, s, l);
            o += l;
        }
        buf[o] = '\0';
        fn(buf, ctx);
    }
    DnsRecordListFree((PDNS_RECORD)(void *)rec, DnsFreeRecordList);
    return 0;
}

static int lookup_mx(const char *name, int *has)
{
    DNS_RECORDA *rec = NULL, *p;
    DNS_STATUS st = DnsQuery_A(name, DNS_TYPE_MX, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *)(void *)&rec, NULL);

    *has = 0;
    if (st == DNS_ERROR_RCODE_NAME_ERROR || st == DNS_INFO_NO_RECORDS)
        return 0;
    if (st != 0)
        return -1;
    for (p = rec; p != NULL; p = p->pNext) /* a "null MX" (RFC 7505, exchange ".") means no email */
        if (p->wType == DNS_TYPE_MX && p->Data.MX.pNameExchange != NULL &&
            strcmp(p->Data.MX.pNameExchange, ".") != 0 && p->Data.MX.pNameExchange[0] != '\0')
            *has = 1;
    DnsRecordListFree((PDNS_RECORD)(void *)rec, DnsFreeRecordList);
    return 0;
}
#else
static int lookup_txt(const char *name, txt_fn fn, void *ctx)
{
    unsigned char ans[8192];
    ns_msg msg;
    int n = res_query(name, ns_c_in, ns_t_txt, ans, sizeof ans), i;

    if (n < 0)
        return h_errno == HOST_NOT_FOUND || h_errno == NO_DATA ? 0 : -1;
    if (ns_initparse(ans, n, &msg) != 0)
        return -1;
    for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
        ns_rr rr;
        const unsigned char *d;
        int len, o = 0;
        char buf[1024];
        size_t b = 0;

        if (ns_parserr(&msg, ns_s_an, i, &rr) != 0 || ns_rr_type(rr) != ns_t_txt)
            continue;
        d = ns_rr_rdata(rr);
        len = ns_rr_rdlen(rr);
        while (o < len) {
            int l = d[o++];

            if (o + l > len)
                break;
            if (b + (size_t)l < sizeof buf) {
                memcpy(buf + b, d + o, (size_t)l);
                b += (size_t)l;
            }
            o += l;
        }
        buf[b] = '\0';
        fn(buf, ctx);
    }
    return 0;
}

static int lookup_mx(const char *name, int *has)
{
    unsigned char ans[4096];
    ns_msg msg;
    int n = res_query(name, ns_c_in, ns_t_mx, ans, sizeof ans);

    *has = 0;
    if (n < 0)
        return h_errno == HOST_NOT_FOUND || h_errno == NO_DATA ? 0 : -1;
    if (ns_initparse(ans, n, &msg) != 0)
        return -1;
    *has = ns_msg_count(msg, ns_s_an) > 0;
    return 0;
}
#endif

static int starts_ci(const char *s, const char *prefix)
{
    return strncasecmp(s, prefix, strlen(prefix)) == 0;
}

static void on_spf(const char *txt, void *ctx)
{
    mail_result *r = ctx;

    if (starts_ci(txt, "v=spf1") && (txt[6] == ' ' || txt[6] == '\0')) {
        if (r->nspf++ == 0)
            copy_str(r->spf, sizeof r->spf, txt);
    }
}

static void on_dmarc(const char *txt, void *ctx)
{
    mail_result *r = ctx;

    if (starts_ci(txt, "v=DMARC1") && r->dmarc[0] == '\0')
        copy_str(r->dmarc, sizeof r->dmarc, txt);
}

typedef struct {
    mail_result *r;
    const char *sel;
} dkim_ctx;

static void on_dkim(const char *txt, void *ctx)
{
    dkim_ctx *d = ctx;
    const char *p = strstr(txt, "p=");

    /* a key with an empty p= is revoked */
    if (p != NULL && p[2] != '\0' && p[2] != ';' && strstr(d->r->dkim, d->sel) == NULL) {
        size_t l = strlen(d->r->dkim);

        snprintf(d->r->dkim + l, sizeof d->r->dkim - l, "%s%s", l ? ", " : "", d->sel);
    }
}

int mail_check(const char *domain, mail_result *r)
{
    /* selector names that common email services use (Google, Microsoft 365, Mailchimp,
       Zoho, Fastmail, iCloud, Amazon SES and generic defaults) */
    static const char *const sel[] = {"google", "selector1", "selector2", "k1", "k2", "s1", "s2",
                                      "default", "dkim", "mail", "smtp", "zoho", "fm1", "sig1",
                                      "mandrill", "amazonses", "protonmail"};
    char name[300];
    size_t i;
    int ok = 0;

    memset(r, 0, sizeof *r);
    copy_str(r->domain, sizeof r->domain, domain);
    ok |= lookup_txt(domain, on_spf, r) == 0;
    snprintf(name, sizeof name, "_dmarc.%s", domain);
    ok |= lookup_txt(name, on_dmarc, r) == 0;
    ok |= lookup_mx(domain, &r->has_mx) == 0;
    for (i = 0; ok && i < sizeof sel / sizeof sel[0]; i++) {
        dkim_ctx d;

        d.r = r;
        d.sel = sel[i];
        snprintf(name, sizeof name, "%s._domainkey.%s", sel[i], domain);
        lookup_txt(name, on_dkim, &d);
    }
    r->answered = ok;
    if (!ok)
        copy_str(r->error, sizeof r->error, "the DNS lookups got no answer");
    return ok ? 0 : -1;
}

/* ---------- grading ---------- */

static void add(web_check *out, int *n, int max, const char *id, int level, const char *detail)
{
    if (*n >= max)
        return;
    copy_str(out[*n].id, sizeof out[*n].id, id);
    out[*n].level = level;
    copy_str(out[*n].detail, sizeof out[*n].detail, detail);
    (*n)++;
}

/* the final "all" rule of an SPF record: '+', '-', '~', '?' or 0 when there is none */
static char spf_all(const char *spf)
{
    const char *p = spf;

    while ((p = strstr(p, "all")) != NULL) {
        char q = p > spf ? p[-1] : ' ';
        int end = p[3] == '\0' || p[3] == ' ';

        if (end && (q == ' ' || strchr("+-~?", q) != NULL))
            return q == ' ' ? '+' : q;
        p += 3;
    }
    return strstr(spf, "redirect=") != NULL ? 'r' : 0;
}

/* "p=reject" -> "reject" */
static void tag(const char *rec, const char *name, char *out, size_t n)
{
    const char *p = rec;
    size_t nl = strlen(name), i = 0;

    out[0] = '\0';
    while ((p = strstr(p, name)) != NULL) {
        if ((p == rec || p[-1] == ';' || p[-1] == ' ') && p[nl] == '=') {
            p += nl + 1;
            while (*p == ' ')
                p++;
            while (p[i] != '\0' && p[i] != ';' && p[i] != ' ' && i + 1 < n) {
                out[i] = (char)tolower((unsigned char)p[i]);
                i++;
            }
            out[i] = '\0';
            return;
        }
        p += nl;
    }
}

int mail_grade(const mail_result *r, web_check *out, int max)
{
    char d[200], p[16];
    int n = 0;

    if (!r->answered) {
        add(out, &n, max, "mail_dns", WEB_NOTE, r->error[0] ? r->error : "no answer");
        return n;
    }
    if (r->nspf == 0) {
        add(out, &n, max, "spf", r->has_mx ? WEB_RECOMMENDED : WEB_TIP,
            r->has_mx ? "no SPF record" : "no SPF record; the domain receives no email, so \"v=spf1 -all\" fits");
    } else if (r->nspf > 1) {
        snprintf(d, sizeof d, "%d SPF records; receivers treat that as having none", r->nspf);
        add(out, &n, max, "spf", WEB_RECOMMENDED, d);
    } else {
        char all = spf_all(r->spf);

        snprintf(d, sizeof d, "%.199s", r->spf);
        add(out, &n, max, "spf", all == '+' ? WEB_IMPORTANT : all == '?' ? WEB_RECOMMENDED
                                 : all == 0 ? WEB_TIP : WEB_OK, d);
    }
    if (r->dmarc[0] == '\0') {
        snprintf(d, sizeof d, "no record at _dmarc.%s", r->domain);
        add(out, &n, max, "dmarc", WEB_RECOMMENDED, d);
    } else {
        tag(r->dmarc, "p", p, sizeof p);
        snprintf(d, sizeof d, "%.199s", r->dmarc);
        add(out, &n, max, "dmarc", strcmp(p, "reject") == 0 || strcmp(p, "quarantine") == 0 ? WEB_OK
                                   : strcmp(p, "none") == 0 ? WEB_TIP : WEB_RECOMMENDED, d);
    }
    if (r->dkim[0] != '\0') {
        snprintf(d, sizeof d, "key found for: %s", r->dkim);
        add(out, &n, max, "dkim", WEB_OK, d);
    } else if (r->has_mx || (r->nspf > 0 && strcasecmp(r->spf, "v=spf1 -all") != 0)) {
        /* a domain that sends no email ("v=spf1 -all", no MX) needs no signing key */
        add(out, &n, max, "dkim", WEB_NOTE,
            "none at the common names; services may use their own, so this is not proof DKIM is missing");
    }
    return n;
}

static const mail_info INFO[] = {
    {"spf", "Only listed servers may send this domain's email (SPF)", "",
     "Anyone can send email that claims to come from this domain (SPF is missing or weak)",
     "Without a strict SPF record, scammers can send email that looks like it comes from your business, "
     "for example fake invoices to your customers.",
     "Ask whoever runs your email (for example Google Workspace or Microsoft 365) for the SPF record to "
     "add to your domain's DNS. It should end in -all (or ~all), never +all or ?all."},
    {"dmarc", "Fake emails in this domain's name are rejected (DMARC)", "",
     "Fake emails in this domain's name are not blocked (DMARC)",
     "DMARC tells Gmail, Outlook and other providers to refuse email that fakes your address. Without "
     "p=quarantine or p=reject they still deliver it.",
     "Add a TXT record at _dmarc.<your domain>: start with v=DMARC1; p=none; rua=mailto:<your address> "
     "to receive reports, then move to p=quarantine and finally p=reject once real email passes."},
    {"dkim", "This domain's email is signed (DKIM)", "No email signing key found at the usual names (DKIM)",
     "No email signing key found (DKIM)",
     "A DKIM signature proves an email really came from your domain and was not changed.",
     "Turn on DKIM signing in your email service and publish the key it gives you in DNS."},
    {"mail_dns", "", "Email protection could not be checked", "Email protection could not be checked",
     NULL, ""},
};

const mail_info *mail_check_info(const char *id)
{
    size_t i;

    for (i = 0; i < sizeof INFO / sizeof INFO[0]; i++)
        if (strcmp(INFO[i].id, id) == 0)
            return &INFO[i];
    return NULL;
}

const char *mail_title(const web_check *c)
{
    const mail_info *m = mail_check_info(c->id);

    if (m == NULL)
        return c->id;
    return c->level == WEB_OK ? m->title_ok : c->level == WEB_NOTE ? m->title_note : m->title_bad;
}
