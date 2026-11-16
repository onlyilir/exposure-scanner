/* Client-facing "Website Safety Check-up" report: plain language, one self-contained HTML page
   (no external files) that prints to PDF from any browser. Results are grouped per website
   (www. and the bare name count as one site), worst level first. */
#include "report.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_LISTED_SECRETS 50
#define SITE_WEB 16

typedef struct {
    char key[128]; /* host without a leading "www." */
    char platform[24]; /* hosting platform id, from the https answer when there is one */
    web_check web[SITE_WEB];
    int nweb;
    tech_list tech; /* software, merged across the site's addresses */
    int fetched;
} site;

typedef struct {
    int level;
    int site; /* index into the site table, -1 = the code folder */
    char title[200];
    char detail[300];
    const char *why;
    char fix[360];
} item;

typedef struct {
    site *s;
    int ns, cap_s;
    item *v;
    size_t n, cap;
    int oom;
    /* operator warnings */
    int intercepted, failed_targets, unfinished;
    const vulndb *db;
} model;

/* ---------- building ---------- */

/* snprintf for display text, where cutting a long path or header short is intended */
static void setf(char *dst, size_t n, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(dst, n, fmt, ap);
    va_end(ap);
}

static const char *site_key(const char *host)
{
    return strncasecmp(host, "www.", 4) == 0 && host[4] != '\0' ? host + 4 : host;
}

static int find_site(model *m, const char *host)
{
    const char *k = site_key(host);
    int i;

    for (i = 0; i < m->ns; i++)
        if (strcasecmp(m->s[i].key, k) == 0)
            return i;
    if (m->ns == m->cap_s) {
        int cap = m->cap_s ? m->cap_s * 2 : 4;
        site *s = realloc(m->s, (size_t)cap * sizeof *s);

        if (s == NULL) {
            m->oom = 1;
            return -1;
        }
        m->s = s;
        m->cap_s = cap;
    }
    memset(&m->s[m->ns], 0, sizeof m->s[m->ns]);
    snprintf(m->s[m->ns].key, sizeof m->s[m->ns].key, "%s", k);
    return m->ns++;
}

/* New item with a formatted title, or NULL when memory ran out or a website already has an
   item with that title (e.g. one certificate seen on both the bare name and www.). Code-folder
   items (site_idx -1) are never merged: each hit is its own finding. */
static item *add_item(model *m, int level, int site_idx, const char *fmt, ...)
{
    char title[200];
    va_list ap;
    size_t i;
    item *it;

    va_start(ap, fmt);
    vsnprintf(title, sizeof title, fmt, ap);
    va_end(ap);
    for (i = 0; site_idx >= 0 && i < m->n; i++)
        if (m->v[i].site == site_idx && strcmp(m->v[i].title, title) == 0)
            return NULL;
    if (m->n == m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 32;
        item *v = realloc(m->v, cap * sizeof *v);

        if (v == NULL) {
            m->oom = 1;
            return NULL;
        }
        m->v = v;
        m->cap = cap;
    }
    it = &m->v[m->n++];
    memset(it, 0, sizeof *it);
    it->level = level;
    it->site = site_idx;
    memcpy(it->title, title, sizeof title);
    return it;
}

/* keep the worst result per check id across the site's addresses */
static void merge_web(site *s, const web_check *w)
{
    int i;

    for (i = 0; i < s->nweb; i++)
        if (strcmp(s->web[i].id, w->id) == 0) {
            if (w->level > s->web[i].level)
                s->web[i] = *w;
            return;
        }
    if (s->nweb < SITE_WEB)
        s->web[s->nweb++] = *w;
}

static const char *const WHY_VERSION =
    "The server reports a version with a published security problem. Version numbers can be "
    "hidden or kept old while fixes are applied, so this needs confirming with your host.";
static const char *const WHY_TRUST =
    "Visitors may see a security warning instead of your site, and some apps will refuse to "
    "connect.";
static const char *const WHY_EXPIRY =
    "When the certificate expires, browsers show a full-page warning and most visitors leave.";
static const char *const WHY_PROTOCOL =
    "Old encryption versions have known weaknesses, and modern browsers are dropping support "
    "for them.";
static const char *const WHY_KEY = "A short key is easier to break than current standards allow.";
static const char *const WHY_CA =
    "The company that issued this certificate had its signing keys stolen, so browsers are "
    "withdrawing trust in certificates from it.";
static const char *const WHY_SECRET =
    "Anyone who sees this file can use the key or password, for example to run up bills or "
    "read data in the account it belongs to.";
static const char *const WHY_PACKAGE =
    "This software version was published by attackers and steals passwords and keys from the "
    "computer it is installed on.";

static const char *pl(unsigned long n, const char *one, const char *many)
{
    return n == 1 ? one : many;
}

/* advisory product ids as people write them */
static const char *product_name(const char *id)
{
    static const char *const map[][2] = {
        {"php", "PHP"}, {"node", "Node.js"}, {"gitlab", "GitLab"}, {"nginx", "nginx"}};
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i][0], id) == 0)
            return map[i][1];
    return id;
}

/* "8.2.35,8.3.36" -> "8.2.35, 8.3.36" */
static void spaced_list(char *dst, size_t n, const char *src)
{
    size_t o = 0;

    for (; *src != '\0' && o + 2 < n; src++) {
        dst[o++] = *src;
        if (*src == ',' && src[1] != ' ')
            dst[o++] = ' ';
    }
    dst[o] = '\0';
}

static void merge_tech(tech_list *l, const tech_item *t);

static void add_http(model *m, const probe_result *p)
{
    int si = find_site(m, p->t.host), j;
    char fixed[200];
    item *it;

    if (si < 0)
        return;
    if (!p->connected || p->status == 0) {
        m->failed_targets++;
        it = add_item(m, WEB_NOTE, si, "Could not check %s://%s", p->t.tls ? "https" : "http",
                      p->t.host);
        if (it != NULL)
            setf(it->detail, sizeof it->detail, "%s", p->error[0] ? p->error : "no answer");
        return;
    }
    for (j = 0; j < p->nweb; j++)
        merge_web(&m->s[si], &p->web[j]);
    for (j = 0; j < p->tech.n; j++)
        merge_tech(&m->s[si].tech, &p->tech.t[j]);
    m->s[si].fetched += p->fetched;
    if (p->platform[0] != '\0' && (p->t.tls || m->s[si].platform[0] == '\0'))
        setf(m->s[si].platform, sizeof m->s[si].platform, "%s", p->platform);
    for (j = 0; j < p->nhit; j++) {
        it = add_item(m, WEB_IMPORTANT, si,
                      "Possibly outdated software with a known security problem: %s %s",
                      product_name(p->hit[j].product), p->hit[j].version);
        if (it == NULL)
            continue;
        setf(it->detail, sizeof it->detail, "Reported in the %s header. Advisory: %s",
                 p->hit[j].source, p->hit[j].url[0] ? p->hit[j].url : "see advisories file");
        it->why = WHY_VERSION;
        spaced_list(fixed, sizeof fixed, p->hit[j].fixed);
        setf(it->fix, sizeof it->fix,
                 "Ask your host to confirm the version and update to a fixed release (%s).",
                 fixed);
    }
}

static void add_web_items(model *m)
{
    int si, j;

    for (si = 0; si < m->ns; si++) {
        const site *s = &m->s[si];
        int page_checked = 0;

        const char *pf = s->platform[0] != '\0' ? s->platform : NULL;
        item *it;

        for (j = 0; j < s->nweb; j++)
            if (strcmp(s->web[j].id, "csp") == 0)
                page_checked = 1;
        if (pf != NULL && (it = add_item(m, WEB_NOTE, si, "Hosted on %s", web_platform_name(pf))) != NULL)
            setf(it->detail, sizeof it->detail, "recognised from the server's answer; the advice below is for %s",
                 web_platform_name(pf));
        for (j = 0; j < s->nweb; j++) {
            const web_check *w = &s->web[j];
            const web_info *info = web_check_info(w->id);

            if (info == NULL || (page_checked && strcmp(w->id, "not_checked") == 0))
                continue;
            it = add_item(m, w->level, si, "%s",
                          w->level >= WEB_TIP ? info->title_bad : info->title_ok);
            if (it == NULL)
                continue;
            setf(it->detail, sizeof it->detail, "%s", w->detail);
            it->why = info->why;
            /* advice the owner can follow on their platform, else the general advice */
            if (!web_platform_fix(pf, w->id, it->fix, sizeof it->fix))
                setf(it->fix, sizeof it->fix, "%s", info->fix);
        }
    }
}

/* ---------- software the site runs (techdetect.h + vulndb.h) ---------- */

static const char *const WHY_HOLES =
    "Attackers run automated tools that find sites on versions with published holes and break in, "
    "often within days of the news. Some holes let them change pages or take over the site "
    "without a password.";
static const char *const WHY_EOL =
    "Its makers no longer fix security problems in this version, so every hole found from now on "
    "stays open.";
static const char *const WHY_OS =
    "The server's operating system no longer gets security updates, so holes in it and in the "
    "software it runs stay open.";
static const char *const WHY_HIDDEN =
    "Most break-ins use holes that already have a fix, on sites that have not installed it yet.";

/* keep the most certain version of each product across the site's addresses */
static void merge_tech(tech_list *l, const tech_item *t)
{
    int i;

    for (i = 0; i < l->n; i++)
        if (strcmp(l->t[i].product, t->product) == 0) {
            tech_item *o = &l->t[i];
            int flags = o->flags | t->flags;

            if (t->version[0] != '\0' && (o->version[0] == '\0' || t->conf > o->conf)) {
                char os[16], rel[8];

                memcpy(os, o->os, sizeof os);
                memcpy(rel, o->os_release, sizeof rel);
                *o = *t;
                if (o->os[0] == '\0') {
                    memcpy(o->os, os, sizeof os);
                    memcpy(o->os_release, rel, sizeof rel);
                }
            } else if (o->os[0] == '\0') {
                memcpy(o->os, t->os, sizeof o->os);
                memcpy(o->os_release, t->os_release, sizeof o->os_release);
            }
            o->flags = flags;
            return;
        }
    if (l->n < TECH_MAX)
        l->t[l->n++] = *t;
}

/* "2025-05-31" -> "31 May 2025" */
static void nice_date(const char *iso, char *out, size_t n)
{
    static const char *const mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int y, mo, d;

    if (sscanf(iso, "%d-%d-%d", &y, &mo, &d) == 3 && mo >= 1 && mo <= 12)
        setf(out, n, "%d %s %d", d, mon[mo - 1], y);
    else
        setf(out, n, "%s", iso);
}

static int years_ago(const char *iso, int years)
{
    char limit[16];
    int y, mo, d;

    if (iso[0] == '\0' || sscanf(vdb_today(), "%d-%d-%d", &y, &mo, &d) != 3)
        return 0;
    setf(limit, sizeof limit, "%04d-%02d-%02d", y - years, mo, d);
    return strcmp(iso, limit) <= 0;
}

static void ver_label(const tech_item *t, char *out, size_t n)
{
    if (t->version[0] == '\0')
        setf(out, n, "%s", tech_name(t->product));
    else
        setf(out, n, "%s %s%s", tech_name(t->product), t->version, t->conf == TECH_EXACT ? "" : " (estimated)");
}

static void append(char *out, size_t n, const char *fmt, const char *a)
{
    size_t l = strlen(out);

    setf(out + l, n - l, fmt, a);
}

static void update_advice(const tech_item *t, const vdb_assess *a, char *out, size_t n)
{
    const char *to = a->fix_to[0] ? a->fix_to : a->newest;
    const char *p = t->product;

    if (to[0] == '\0')
        setf(out, n, "Update %s to its newest version.", tech_name(p));
    else if (strcmp(p, "wordpress") == 0)
        setf(out, n, "Update WordPress to %s or later (Dashboard > Updates) and turn on automatic updates "
             "for WordPress itself.", to);
    else if (strcmp(p, "nextjs") == 0)
        setf(out, n, "Ask the developer to update Next.js to %s or later, rebuild and redeploy the site.", to);
    else if (strcmp(p, "drupal") == 0)
        setf(out, n, "Update Drupal core to %s or later (Reports > Available updates) and follow Drupal's "
             "security announcements.", to);
    else if (strcmp(p, "joomla") == 0)
        setf(out, n, "Update Joomla to %s or later (System > Update > Joomla).", to);
    else if (strcmp(p, "magento") == 0)
        setf(out, n, "Install Adobe's security update: Magento %s or later.", to);
    else
        setf(out, n, "Update %s to %s or later.", tech_name(p), to);
    if (a->newest[0] != '\0' && a->fix_to[0] != '\0' && strcmp(a->newest, a->fix_to) != 0)
        append(out, n, " The newest in this line is %s.", a->newest);
    if (t->conf != TECH_EXACT)
        append(out, n, " The version was estimated from %s; confirm it in the site's admin area.", t->source);
}

static void site_item(model *m, int si, const tech_item *t)
{
    char label[80], d1[24];
    vdb_assess a;
    item *it;

    vdb_assess_item(m->db, t, &a);
    ver_label(t, label, sizeof label);
    if (t->version[0] == '\0') {
        if ((it = add_item(m, WEB_TIP, si, "%s found; its version is hidden", tech_name(t->product))) != NULL) {
            setf(it->detail, sizeof it->detail, "seen in: %s", t->source);
            it->why = WHY_HIDDEN;
            setf(it->fix, sizeof it->fix, "Check in the site's admin area that %s has no pending updates%s%s.",
                 tech_name(t->product), a.newest[0] ? "; the newest version is " : "", a.newest);
        }
        return;
    }
    if (a.nhole > 0) {
        int level = a.kev || a.worst >= VDB_SEV_HIGH ? WEB_IMPORTANT
                  : a.worst == VDB_SEV_LOW ? WEB_TIP : WEB_RECOMMENDED;
        char det[300] = "";
        int k;

        if (t->conf != TECH_EXACT && !a.kev && level > WEB_TIP)
            level--;
        if (a.nkev > 0)
            it = add_item(m, level, si, "%s %s %lu known security %s, %lu used by attackers", label,
                          t->conf == TECH_EXACT ? "has" : "may have", a.nhole, a.nhole == 1 ? "hole" : "holes",
                          a.nkev);
        else
            it = add_item(m, level, si, "%s %s %lu known security %s", label,
                          t->conf == TECH_EXACT ? "has" : "may have", a.nhole, a.nhole == 1 ? "hole" : "holes");
        if (it != NULL) {
            for (k = 0; k < a.ntop && strlen(det) < 200; k++) {
                size_t l = strlen(det);

                setf(det + l, sizeof det - l, "%s%s (%s%s)", k ? "; " : "", a.top[k].id,
                     vdb_sev_name(a.top[k].sev), a.top[k].kev ? ", used by attackers" : "");
            }
            setf(it->detail, sizeof it->detail, "%s%s. Seen in: %s", det,
                 a.nhole > (unsigned long)a.ntop ? " and more" : "", t->source);
            it->why = WHY_HOLES;
            update_advice(t, &a, it->fix, sizeof it->fix);
        }
    } else if (strcmp(a.wp_status, "insecure") == 0) {
        if ((it = add_item(m, WEB_RECOMMENDED, si, "WordPress.org lists %s as insecure", label)) != NULL) {
            setf(it->detail, sizeof it->detail, "seen in: %s", t->source);
            it->why = WHY_HOLES;
            update_advice(t, &a, it->fix, sizeof it->fix);
        }
    } else if (a.known && a.eol != 1) {
        if ((it = add_item(m, WEB_OK, si, "%s: no known security holes", label)) != NULL)
            setf(it->detail, sizeof it->detail, "checked against the security data from %s; seen in: %s",
                 m->db != NULL && m->db->generated[0] ? m->db->generated : "the app", t->source);
    }
    if (a.eol == 1) {
        nice_date(a.eol_date, d1, sizeof d1);
        if ((it = add_item(m, years_ago(a.eol_date, 2) ? WEB_IMPORTANT : WEB_RECOMMENDED, si,
                           "%s %s no longer gets security fixes", tech_name(t->product), a.cycle)) != NULL) {
            setf(it->detail, sizeof it->detail, "support ended%s%s; seen in: %s", d1[0] ? " on " : "", d1, t->source);
            it->why = WHY_EOL;
            setf(it->fix, sizeof it->fix, "Move to a supported version of %s%s%s.", tech_name(t->product),
                 a.newest[0] ? ", for example " : "", a.newest);
        }
    }
}

/* server software: when a distribution tag says which operating system, its support decides */
static void server_item(model *m, int si, const tech_item *t)
{
    char label[80], d1[24], d2[24];
    vdb_assess a;
    item *it;

    vdb_assess_item(m->db, t, &a);
    ver_label(t, label, sizeof label);
    if (a.os_name[0] != '\0' && a.os_eol == 1) {
        nice_date(a.os_eol_date, d1, sizeof d1);
        nice_date(a.os_ext_date, d2, sizeof d2);
        it = add_item(m, a.os_ext ? WEB_RECOMMENDED : WEB_IMPORTANT, si,
                      a.os_ext ? "The server runs %s, which is past its normal support"
                               : "The server runs %s, which no longer gets security updates", a.os_name);
        if (it != NULL) {
            setf(it->detail, sizeof it->detail, "worked out from %s in the %s; support ended%s%s%s%s", label,
                 t->source, d1[0] ? " on " : "", d1, a.os_ext ? "; paid extended support runs until " : "",
                 a.os_ext ? d2 : "");
            it->why = WHY_OS;
            setf(it->fix, sizeof it->fix, "%s", a.os_ext
                 ? "Ask your host whether paid extended security updates are active for this server, and plan "
                   "the move to a supported release."
                 : "Ask your host to move the site to a server with a supported operating system.");
        }
    } else if (a.os_name[0] != '\0' && a.os_eol == 0) {
        nice_date(a.os_eol_date, d1, sizeof d1);
        if ((it = add_item(m, WEB_OK, si, "The server's operating system still gets updates")) != NULL)
            setf(it->detail, sizeof it->detail, "%s, worked out from %s%s%s", a.os_name, label,
                 d1[0] ? "; supported until " : "", d1);
    } else if (strcmp(t->product, "iis") == 0 && strcmp(t->version, "10.0") == 0 && a.os_eol_date[0]) {
        nice_date(a.os_eol_date, d1, sizeof d1);
        if ((it = add_item(m, WEB_TIP, si, "Check which Windows Server version runs the site")) != NULL) {
            setf(it->detail, sizeof it->detail, "%s means Windows Server 2016 or newer; 2016 gets updates until %s",
                 label, d1);
            setf(it->fix, sizeof it->fix, "If the server runs Windows Server 2016, plan the move to a newer "
                 "version before %s.", d1);
        }
    } else if (t->version[0] != '\0' && a.eol == 1 && a.os_name[0] == '\0') {
        int level = strcmp(t->product, "php") != 0 ? WEB_TIP
                  : years_ago(a.eol_date, 2) ? WEB_IMPORTANT : WEB_RECOMMENDED;

        nice_date(a.eol_date, d1, sizeof d1);
        if ((it = add_item(m, level, si, "%s %s no longer gets security fixes from its makers",
                           tech_name(t->product), a.cycle)) != NULL) {
            setf(it->detail, sizeof it->detail, "%s in the %s; support ended%s%s", label, t->source,
                 d1[0] ? " on " : "", d1);
            it->why = WHY_EOL;
            setf(it->fix, sizeof it->fix, "Ask your host to update %s to a supported version%s%s. If it comes "
                 "with the server's operating system, its vendor may still patch it: ask them to confirm.",
                 tech_name(t->product), a.newest[0] ? " such as " : "", a.newest);
        }
    }
}

static void add_software(model *m)
{
    int si, i;

    for (si = 0; si < m->ns; si++) {
        const site *s = &m->s[si];
        char label[80], list[220] = "";
        item *it;

        if (s->tech.n == 0)
            continue;
        for (i = 0; i < s->tech.n; i++) {
            ver_label(&s->tech.t[i], label, sizeof label);
            append(list, sizeof list, i ? ", %s" : "%s", label);
        }
        if ((it = add_item(m, WEB_NOTE, si, "Software found: %s", list)) != NULL) {
            if (s->fetched > 0)
                setf(it->detail, sizeof it->detail, "read from the home page, its headers and %d more public %s",
                     s->fetched, s->fetched == 1 ? "file" : "files");
            else
                setf(it->detail, sizeof it->detail, "read from the home page and its headers");
        }
        for (i = 0; i < s->tech.n; i++) {
            if (s->tech.t[i].flags & TECH_SITE)
                site_item(m, si, &s->tech.t[i]);
            else
                server_item(m, si, &s->tech.t[i]);
        }
    }
}

static void add_tls(model *m, const tls_result *t)
{
    int si = find_site(m, t->host), i, expired = 0, weak = 0, ca = 0;
    const tls_cert_info *leaf;
    item *it;

    if (si < 0)
        return;
    if (!t->connected) {
        m->failed_targets++;
        it = add_item(m, WEB_NOTE, si, "The secure connection to %s could not be checked",
                      t->host);
        if (it != NULL)
            setf(it->detail, sizeof it->detail, "port %u: %s", (unsigned)t->port,
                     t->error[0] ? t->error : "no answer");
        return;
    }
    if (t->interception[0] != '\0') {
        m->intercepted = 1;
        it = add_item(m, WEB_NOTE, si, "Certificate not checked");
        if (it != NULL)
            setf(it->detail, sizeof it->detail,
                     "HTTPS scanning on the checking computer (%s) swapped the site's certificate",
                     t->interception);
        return;
    }
    if (t->ncerts == 0)
        return;
    leaf = &t->certs[0];

    if (t->verify_code == 0) {
        it = add_item(m, WEB_OK, si, "The certificate is trusted");
        if (it != NULL)
            setf(it->detail, sizeof it->detail, "Issued by %s", leaf->issuer);
    } else if ((it = add_item(m, WEB_IMPORTANT, si,
                              "The certificate did not pass the trust check")) != NULL) {
        setf(it->detail, sizeof it->detail, "%s (code %ld)", t->verify_text, t->verify_code);
        it->why = WHY_TRUST;
        setf(it->fix, sizeof it->fix,
                 "Ask your host to install a certificate from a trusted provider (for example "
                 "Let's Encrypt) and to include the full certificate chain.");
    }

    for (i = 0; i < t->ncerts; i++) {
        expired |= (t->certs[i].flags & TLSF_EXPIRED) != 0;
        weak |= (t->certs[i].flags & TLSF_WEAK_KEY) != 0;
        ca |= (t->certs[i].flags & (TLSF_ISSUER_MATCH | TLSF_BLOCKLISTED)) != 0;
    }
    if (expired) {
        if ((it = add_item(m, WEB_IMPORTANT, si, "A certificate has expired")) != NULL) {
            setf(it->detail, sizeof it->detail, "Site certificate valid until %s",
                     leaf->not_after);
            it->why = WHY_EXPIRY;
            setf(it->fix, sizeof it->fix,
                     "Ask your host to renew the certificate now and to turn on automatic "
                     "renewal.");
        }
    } else if (leaf->flags & TLSF_EXPIRES_SOON) {
        it = leaf->days_left <= 0
                 ? add_item(m, WEB_IMPORTANT, si, "The certificate expires today")
                 : add_item(m, WEB_IMPORTANT, si, "The certificate expires in %ld %s",
                            leaf->days_left, pl((unsigned long)leaf->days_left, "day", "days"));
        if (it != NULL) {
            setf(it->detail, sizeof it->detail, "Valid until %s", leaf->not_after);
            it->why = WHY_EXPIRY;
            setf(it->fix, sizeof it->fix,
                     "Ask your host to renew it before that date and to turn on automatic "
                     "renewal.");
        }
    } else if ((it = add_item(m, WEB_OK, si, "The certificate is valid for %ld more %s",
                              leaf->days_left,
                              pl((unsigned long)leaf->days_left, "day", "days"))) != NULL) {
        setf(it->detail, sizeof it->detail, "Valid until %s", leaf->not_after);
    }

    if (!tls_protocol_is_weak(t->protocol)) {
        it = add_item(m, WEB_OK, si, "The connection uses modern encryption");
    } else if ((it = add_item(m, WEB_IMPORTANT, si,
                              "The site uses an outdated encryption version")) != NULL) {
        it->why = WHY_PROTOCOL;
        setf(it->fix, sizeof it->fix,
                 "Ask your host to turn on TLS 1.2 and TLS 1.3 and turn off older versions.");
    }
    if (it != NULL)
        setf(it->detail, sizeof it->detail, "%s, %s", t->protocol, t->cipher);
    if (weak && (it = add_item(m, WEB_RECOMMENDED, si, "The certificate uses a weak key")) != NULL) {
        setf(it->detail, sizeof it->detail, "%s %d bits", leaf->key_alg, leaf->key_bits);
        it->why = WHY_KEY;
        setf(it->fix, sizeof it->fix,
                 "Ask your host for a new certificate with an RSA key of at least 2048 bits, or "
                 "an ECDSA key.");
    }
    if (ca && (it = add_item(m, WEB_IMPORTANT, si,
                             "The certificate comes from an authority whose keys were "
                             "compromised")) != NULL) {
        setf(it->detail, sizeof it->detail, "Issuer: %s", leaf->issuer);
        it->why = WHY_CA;
        setf(it->fix, sizeof it->fix,
                 "Ask your host to replace the certificate with one from a different provider.");
    }
}

static const char *rule_name(const char *rule)
{
    static const char *const map[][2] = {
        {"aws-access-key", "an AWS access key"},
        {"github-token", "a GitHub token"},
        {"stripe-live-key", "a live Stripe key"},
        {"google-api-key", "a Google API key"},
        {"slack-token", "a Slack token"},
        {"private-key", "a private key"},
        {"url-credentials", "a password inside a web address"},
        {"secret-assignment", "a password or secret"},
    };
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i][0], rule) == 0)
            return map[i][1];
    return "a secret";
}

static void add_code(model *m, const scan_report *r)
{
    size_t i;
    item *it;

    if (r->secrets_error || r->py_error)
        m->unfinished++;
    /* clean results count as passes, like the website checks */
    if (r->run_secrets && !r->secrets_error && r->secrets.n == 0 &&
        (it = add_item(m, WEB_OK, -1, "No passwords, keys or tokens found")) != NULL)
        setf(it->detail, sizeof it->detail, "%lu %s read, %lu skipped (images, programs, very large files)",
             r->secrets.files_scanned, pl(r->secrets.files_scanned, "file", "files"),
             r->secrets.files_skipped);
    if (r->run_py && !r->py_error && r->py.n == 0 &&
        (it = add_item(m, WEB_OK, -1, "No known malicious Python packages")) != NULL)
        setf(it->detail, sizeof it->detail, "%lu installed, %lu listed for install",
             r->py.packages_seen, r->py.pinned_seen);
    for (i = 0; r->run_secrets && i < r->secrets.n && i < MAX_LISTED_SECRETS; i++) {
        const secret_hit *h = &r->secrets.h[i];

        it = add_item(m, WEB_IMPORTANT, -1, "Found %s in the code", rule_name(h->rule));
        if (it == NULL)
            return;
        setf(it->detail, sizeof it->detail, "%s, line %d, value %s%s", h->path, h->line,
                 h->masked[0] ? h->masked : "****",
                 h->tracked == 1 ? ", saved in git history" : "");
        it->why = WHY_SECRET;
        setf(it->fix, sizeof it->fix,
                 "Change this key or password at the service it belongs to, then move it out of "
                 "the code into a private settings file.%s",
                 h->tracked == 1 ? " Deleting it from the file is not enough: git keeps the "
                                   "old value in its history."
                                 : "");
    }
    if (r->run_secrets && r->secrets.n > MAX_LISTED_SECRETS &&
        (it = add_item(m, WEB_NOTE, -1, "%lu more %s not listed here",
                       (unsigned long)(r->secrets.n - MAX_LISTED_SECRETS),
                       pl((unsigned long)(r->secrets.n - MAX_LISTED_SECRETS), "secret",
                          "secrets"))) != NULL)
        setf(it->detail, sizeof it->detail, "See the full scan output");
    for (i = 0; r->run_py && i < r->py.n; i++) {
        const py_finding *f = &r->py.f[i];
        int ioc = strcmp(f->kind, "ioc-file") == 0, high = f->severity == 2 || ioc;
        int level = high ? WEB_IMPORTANT : WEB_RECOMMENDED;

        if (ioc)
            it = add_item(m, level, -1, "A file left by a known malicious package was found");
        else if (strcmp(f->kind, "pth-suspicious") == 0)
            it = add_item(m, level, -1, "A suspicious Python start-up file was found");
        else if (f->severity == 2)
            it = add_item(m, level, -1, "A known malicious package is installed: %s %s",
                          f->name, f->version);
        else
            it = add_item(m, level, -1,
                          "A known malicious package version is listed for install: %s %s",
                          f->name, f->version);
        if (it == NULL)
            return;
        if (f->line > 0)
            setf(it->detail, sizeof it->detail, "%s:%d. %s", f->path, f->line, f->detail);
        else
            setf(it->detail, sizeof it->detail, "%s. %s", f->path, f->detail);
        it->why = WHY_PACKAGE;
        setf(it->fix, sizeof it->fix, "%s",
                 high ? "Remove the package, install a safe version, and change every password "
                        "and key that was stored on this computer."
                      : "Change the listed version to a safe one before anyone installs it.");
    }
}

/* ---------- output ---------- */

static void esc(FILE *out, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s != NULL ? s : "");
    int n;

    while (*p != '\0') {
        switch (*p) {
        case '&': fputs("&amp;", out); p++; continue;
        case '<': fputs("&lt;", out); p++; continue;
        case '>': fputs("&gt;", out); p++; continue;
        case '"': fputs("&quot;", out); p++; continue;
        case '\'': fputs("&#39;", out); p++; continue;
        default: break;
        }
        if (*p < 0x20 || *p == 0x7F) {
            fputc(' ', out);
            p++;
            continue;
        }
        n = report_utf8_len(p);
        if (n == 0) {
            fputs("\xEF\xBF\xBD", out); /* U+FFFD */
            p++;
            continue;
        }
        fwrite(p, 1, (size_t)n, out);
        p += n;
    }
}

static const char *level_label(int level)
{
    static const char *const names[] = {"Passed", "Note", "Tip", "Recommended", "Important"};

    return level >= WEB_OK && level <= WEB_IMPORTANT ? names[level] : "";
}

static const char *level_class(int level)
{
    static const char *const names[] = {"ok", "note", "tip", "rec", "imp"};

    return level >= WEB_OK && level <= WEB_IMPORTANT ? names[level] : "note";
}

static const char *where(const model *m, const item *it)
{
    return it->site < 0 ? "Code folder" : m->s[it->site].key;
}

static const char CSS[] =
    ":root{--ink:#1d2433;--muted:#5b6475;--line:#e3e6ec;--bg:#ffffff;--soft:#f6f7f9;"
    "--imp:#b42318;--imp-bg:#fef3f2;--rec:#b54708;--rec-bg:#fffaeb;--tip:#175cd3;"
    "--tip-bg:#eff8ff;--ok:#067647;--ok-bg:#ecfdf3;--note:#475467;--note-bg:#f2f4f7}"
    "*{box-sizing:border-box}"
    "body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 \"Segoe UI\",system-ui,"
    "-apple-system,Roboto,Helvetica,Arial,sans-serif}"
    ".page{max-width:860px;margin:0 auto;padding:40px 24px 56px}"
    ".eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);"
    "font-weight:600}"
    "h1{font-size:28px;line-height:1.2;margin:6px 0 4px}"
    "h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}"
    "h3{font-size:16px;margin:22px 0 8px}"
    ".meta{color:var(--muted);margin:0}"
    ".warn{margin:24px 0 0;padding:14px 16px;border:2px solid var(--imp);border-radius:8px;"
    "background:var(--imp-bg);color:var(--imp)}"
    ".warn strong{display:block;margin-bottom:4px}"
    ".warn ul{margin:6px 0 0;padding-left:20px}"
    ".verdict{margin-top:28px;padding:18px 20px;border-radius:10px;background:var(--soft)}"
    ".verdict p{margin:0 0 14px;font-size:17px;font-weight:600}"
    ".tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}"
    ".tile{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px}"
    ".tile b{display:block;font-size:24px;line-height:1.1}"
    ".tile span{font-size:13px;color:var(--muted)}"
    ".tile.imp b{color:var(--imp)}.tile.rec b{color:var(--rec)}.tile.tip b{color:var(--tip)}"
    ".tile.ok b{color:var(--ok)}"
    ".card{border:1px solid var(--line);border-left:4px solid var(--note);border-radius:8px;"
    "padding:12px 16px;margin:0 0 12px;break-inside:avoid}"
    ".card.imp{border-left-color:var(--imp)}.card.rec{border-left-color:var(--rec)}"
    ".card.tip{border-left-color:var(--tip)}"
    ".card h4{margin:6px 0 6px;font-size:15px}"
    ".card p{margin:4px 0}"
    ".label{font-weight:600}"
    ".tech{font:12px/1.45 Consolas,\"Cascadia Mono\",monospace;color:var(--muted);"
    "overflow-wrap:anywhere;margin-top:6px}"
    ".badge{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;"
    "border-radius:999px;white-space:nowrap}"
    ".badge.imp{background:var(--imp-bg);color:var(--imp)}"
    ".badge.rec{background:var(--rec-bg);color:var(--rec)}"
    ".badge.tip{background:var(--tip-bg);color:var(--tip)}"
    ".badge.ok{background:var(--ok-bg);color:var(--ok)}"
    ".badge.note{background:var(--note-bg);color:var(--note)}"
    ".where{color:var(--muted);font-size:13px;margin-left:6px}"
    "table{width:100%;border-collapse:collapse;font-size:14px}"
    "td{padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}"
    "td:first-child{width:118px}"
    "td .tech{margin-top:2px}"
    "tr{break-inside:avoid}"
    "ul.plain{padding-left:20px;margin:6px 0}"
    "footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);"
    "font-size:13px}"
    "@media (max-width:600px){.tiles{grid-template-columns:repeat(2,1fr)}"
    "td:first-child{width:auto}}"
    "@page{size:A4;margin:14mm}"
    "@media print{.page{padding:0;max-width:none}"
    "*{-webkit-print-color-adjust:exact;print-color-adjust:exact}h2{break-after:avoid}}";

static void card(FILE *out, const model *m, const item *it)
{
    fprintf(out, "<div class=\"card %s\"><span class=\"badge %s\">%s</span>",
            level_class(it->level), level_class(it->level), level_label(it->level));
    fputs("<span class=\"where\">", out);
    esc(out, where(m, it));
    fputs("</span><h4>", out);
    esc(out, it->title);
    fputs("</h4>", out);
    if (it->why != NULL) {
        fputs("<p><span class=\"label\">Why it matters:</span> ", out);
        esc(out, it->why);
        fputs("</p>", out);
    }
    if (it->fix[0] != '\0') {
        fputs("<p><span class=\"label\">What to do:</span> ", out);
        esc(out, it->fix);
        fputs("</p>", out);
    }
    if (it->detail[0] != '\0') {
        fputs("<div class=\"tech\">Technical detail: ", out);
        esc(out, it->detail);
        fputs("</div>", out);
    }
    fputs("</div>\n", out);
}

static void row(FILE *out, const item *it)
{
    fprintf(out, "<tr><td><span class=\"badge %s\">%s</span></td><td>", level_class(it->level),
            level_label(it->level));
    esc(out, it->title);
    if (it->detail[0] != '\0') {
        fputs("<div class=\"tech\">", out);
        esc(out, it->detail);
        fputs("</div>", out);
    }
    fputs("</td></tr>\n", out);
}

/* worst first, notes last */
static const int ORDER[] = {WEB_IMPORTANT, WEB_RECOMMENDED, WEB_TIP, WEB_OK, WEB_NOTE};

static void write_page(const model *m, const scan_report *r, const report_meta *meta, FILE *out,
                       int warnings)
{
    unsigned long cnt[WEB_IMPORTANT + 1] = {0};
    size_t i;
    int k, si, any;

    for (i = 0; i < m->n; i++)
        cnt[m->v[i].level]++;

    fputs("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>",
          out);
    esc(out, meta->client != NULL && meta->client[0] ? meta->client : "Safety check-up");
    fputs(" - Safety Check-up</title><style>", out);
    fputs(CSS, out);
    fputs("</style></head><body><main class=\"page\">\n<header><div class=\"eyebrow\">"
          "Website Safety Check-up</div><h1>",
          out);
    esc(out, meta->client != NULL && meta->client[0] ? meta->client : "Safety check-up report");
    fputs("</h1><p class=\"meta\">", out);
    esc(out, meta->date);
    if (meta->by != NULL && meta->by[0]) {
        fputs(" &middot; Prepared by ", out);
        esc(out, meta->by);
    }
    fputs("</p></header>\n", out);

    if (warnings > 0) {
        fputs("<div class=\"warn\"><strong>Not ready to send: fix these and run the check-up "
              "again.</strong><ul>",
              out);
        if (m->intercepted)
            fputs("<li>HTTPS scanning on this computer (an antivirus or network filter) swapped the "
                  "site's certificate, so certificate results are missing. Turn off only that "
                  "feature in the antivirus (not the antivirus itself), or use another computer or "
                  "network.</li>",
                  out);
        if (m->failed_targets > 0)
            fprintf(out, "<li>%d %s could not be reached. Check the address and your "
                         "connection.</li>",
                    m->failed_targets,
                    pl((unsigned long)m->failed_targets, "address", "addresses"));
        if (m->unfinished > 0)
            fputs("<li>The code scan did not finish.</li>", out);
        if (m->oom)
            fputs("<li>The report ran out of memory and is incomplete.</li>", out);
        fputs("</ul></div>\n", out);
    }

    fputs("<section class=\"verdict\"><p>", out);
    if (cnt[WEB_IMPORTANT] > 0)
        fprintf(out, "%lu important %s should be fixed soon.", cnt[WEB_IMPORTANT],
                pl(cnt[WEB_IMPORTANT], "issue", "issues"));
    else if (cnt[WEB_RECOMMENDED] > 0)
        fprintf(out, "No urgent problems found. %lu %s recommended.", cnt[WEB_RECOMMENDED],
                pl(cnt[WEB_RECOMMENDED], "improvement is", "improvements are"));
    else if (cnt[WEB_TIP] > 0)
        fputs("No urgent problems found. A few optional tips are listed below.", out);
    else
        fputs("No problems found in the checks that were run.", out);
    fprintf(out,
            "</p><div class=\"tiles\"><div class=\"tile imp\"><b>%lu</b><span>Important</span>"
            "</div><div class=\"tile rec\"><b>%lu</b><span>Recommended</span></div>"
            "<div class=\"tile tip\"><b>%lu</b><span>Tips</span></div><div class=\"tile ok\">"
            "<b>%lu</b><span>Passed</span></div></div></section>\n",
            cnt[WEB_IMPORTANT], cnt[WEB_RECOMMENDED], cnt[WEB_TIP], cnt[WEB_OK]);

    fputs("<h2>What to fix, most urgent first</h2>\n", out);
    any = 0;
    for (k = 0; k < 3; k++)
        for (i = 0; i < m->n; i++)
            if (m->v[i].level == ORDER[k]) {
                card(out, m, &m->v[i]);
                any = 1;
            }
    if (!any)
        fputs("<p>Nothing to fix in the checks that were run.</p>\n", out);

    if (m->ns > 0) {
        fputs("<h2>Results by website</h2>\n", out);
        for (si = 0; si < m->ns; si++) {
            fputs("<h3>", out);
            esc(out, m->s[si].key);
            fputs("</h3><table>\n", out);
            for (k = 0; k < 5; k++)
                for (i = 0; i < m->n; i++)
                    if (m->v[i].site == si && m->v[i].level == ORDER[k])
                        row(out, &m->v[i]);
            fputs("</table>\n", out);
        }
    }

    if (r->run_secrets || r->run_py) {
        fputs("<h2>Code check</h2>\n<p>", out);
        if (r->run_secrets && !r->secrets_error)
            fprintf(out, "Files read for passwords, keys and tokens: %lu (%lu skipped: images, "
                         "programs and very large files). ",
                    r->secrets.files_scanned, r->secrets.files_skipped);
        if (r->run_py && !r->py_error)
            fprintf(out, "Python packages compared with known malicious releases: %lu installed, "
                         "%lu listed for install.",
                    r->py.packages_seen, r->py.pinned_seen);
        fputs("</p>\n<table>\n", out);
        any = 0;
        for (k = 0; k < 5; k++)
            for (i = 0; i < m->n; i++)
                if (m->v[i].site < 0 && m->v[i].level == ORDER[k]) {
                    row(out, &m->v[i]);
                    any = 1;
                }
        if (!any)
            fputs("<tr><td><span class=\"badge ok\">Passed</span></td><td>No passwords, keys or "
                  "known malicious packages were found.</td></tr>\n",
                  out);
        fputs("</table>\n<p>Found values are never copied into this report; only a masked hint "
              "such as ****ABCD is shown.</p>\n",
              out);
    }

    fputs("<h2>What this check-up covered</h2>\n<ul class=\"plain\">", out);
    if (r->nhttp > 0)
        fputs("<li>Whether visitors are sent to the secure (https) version of the site.</li>"
              "<li>The security settings the site sends with its pages: HSTS, content security "
              "policy, protection against framing, file-type guessing, referrer policy and "
              "cookie flags.</li>"
              "<li>Software versions the server reveals, compared with published security "
              "problems.</li>",
              out);
    if (r->ntls > 0)
        fputs("<li>The site's certificate: whether it is trusted, when it expires, its key "
              "strength and the encryption version.</li>",
              out);
    if (r->run_secrets)
        fputs("<li>Passwords, keys and tokens left in the code.</li>", out);
    if (r->run_py)
        fputs("<li>Python packages with known malicious versions.</li>", out);
    fputs("</ul>\n<h3>Not covered</h3><ul class=\"plain\"><li>Pages behind a login, and anything "
          "that needs a password.</li><li>Attempts to break in (a penetration test).</li>"
          "<li>Plugins, themes and other software the server does not announce.</li>"
          "<li>Live certificate revocation checks.</li><li>Anything not listed on the signed "
          "permission form.</li></ul>\n",
          out);

    fputs("<footer>This report covers only the checks listed above and the addresses on the "
          "permission form, at the time of the check. A clean result is not a guarantee that a "
          "site is secure. ",
          out);
    if (meta->by != NULL && meta->by[0]) {
        fputs("Prepared by ", out);
        esc(out, meta->by);
        fputs(", ", out);
    }
    esc(out, meta->date);
    fputs(".</footer>\n</main></body></html>\n", out);
}

/* email spoofing protection, under the website of the same name */
static void add_mail(model *m, const scan_report *r)
{
    size_t i;

    for (i = 0; i < r->nmail; i++) {
        const mail_result *mr = &r->mail[i];
        web_check c[MAIL_MAX_CHECKS];
        int si = find_site(m, mr->domain), n, k;

        if (si < 0)
            continue;
        n = mail_grade(mr, c, MAIL_MAX_CHECKS);
        for (k = 0; k < n; k++) {
            const mail_info *info = mail_check_info(c[k].id);
            item *it = add_item(m, c[k].level, si, "%s", mail_title(&c[k]));

            if (it == NULL || info == NULL)
                continue;
            setf(it->detail, sizeof it->detail, "%s", c[k].detail);
            if (c[k].level >= WEB_TIP) {
                it->why = info->why;
                setf(it->fix, sizeof it->fix, "%s", info->fix);
            }
        }
    }
}

/* operator warnings ("not ready to send"); returns how many */
static int build_model(const scan_report *r, model *m)
{
    size_t i;

    memset(m, 0, sizeof *m);
    m->db = r->db;
    for (i = 0; i < r->nhttp; i++)
        add_http(m, &r->http[i]);
    add_web_items(m);
    add_software(m);
    add_mail(m, r);
    for (i = 0; i < r->ntls; i++)
        add_tls(m, &r->tls[i]);
    add_code(m, r);
    return m->intercepted + (m->failed_targets > 0) + m->unfinished + m->oom;
}

int report_write_html(const scan_report *r, const report_meta *meta, FILE *out)
{
    model m;
    int warnings = build_model(r, &m);

    write_page(&m, r, meta, out, warnings);
    free(m.s);
    free(m.v);
    return warnings;
}

void report_summarize(const scan_report *r, report_summary *s)
{
    model m;
    size_t i;
    int k;

    memset(s, 0, sizeof *s);
    s->warnings = build_model(r, &m);
    s->intercepted = m.intercepted;
    s->failed_targets = m.failed_targets;
    s->unfinished = m.unfinished || m.oom;
    for (i = 0; i < m.n; i++)
        s->count[m.v[i].level]++;
    for (k = 0; k < 3; k++) /* issues only, worst first, the same order as the report */
        for (i = 0; i < m.n && s->nitems < SUMMARY_MAX_ITEMS; i++)
            if (m.v[i].level == ORDER[k]) {
                summary_item *it = &s->items[s->nitems++];

                it->level = m.v[i].level;
                setf(it->site, sizeof it->site, "%s", where(&m, &m.v[i]));
                setf(it->title, sizeof it->title, "%s", m.v[i].title);
                setf(it->fix, sizeof it->fix, "%s", m.v[i].fix);
                setf(it->detail, sizeof it->detail, "%s", m.v[i].detail);
            }
    free(m.s);
    free(m.v);
}
