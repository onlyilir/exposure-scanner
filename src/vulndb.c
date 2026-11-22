#include "vulndb.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "version.h"

static char g_today[12];

static void copy_str(char *dst, size_t n, const char *src)
{
    if (n > 0)
        snprintf(dst, n, "%s", src != NULL ? src : "");
}

void vdb_set_today(const char *iso)
{
    copy_str(g_today, sizeof g_today, iso);
}

const char *vdb_today(void)
{
    if (g_today[0] == '\0') {
        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);

        if (tm == NULL || strftime(g_today, sizeof g_today, "%Y-%m-%d", tm) == 0)
            copy_str(g_today, sizeof g_today, "2000-01-01");
    }
    return g_today;
}

/* ---------- loading ---------- */

static int index_lines(vulndb *db)
{
    size_t i = 0, n = 0;
    char **line;

    for (i = 0; i < db->len; i += strlen(db->text + i) + 1)
        n += db->text[i] != '\0' && db->text[i + 1] == '\t';
    line = realloc(db->line, (n ? n : 1) * sizeof *line);
    if (line == NULL)
        return -1;
    db->line = line;
    db->n = 0;
    for (i = 0; i < db->len; i += strlen(db->text + i) + 1) {
        char *l = db->text + i;

        if (l[0] == '\0' || l[1] != '\t')
            continue;
        if (l[0] == 'G') {
            copy_str(db->generated, 11, l + 2);
            db->nvuln = strtoul(strchr(l + 2, '\t') != NULL ? strchr(l + 2, '\t') + 1 : "0", NULL, 10);
        } else if (strchr("VSEM", l[0]) != NULL) {
            db->line[db->n++] = l;
        }
    }
    return 0;
}

int vdb_load_text(vulndb *db, const char *text)
{
    size_t add = strlen(text), i;
    char *t = realloc(db->text, db->len + add + 1);

    if (t == NULL)
        return -1;
    db->text = t;
    memcpy(t + db->len, text, add + 1);
    for (i = db->len; i < db->len + add; i++)
        if (t[i] == '\n' || t[i] == '\r')
            t[i] = '\0';
    db->len += add + 1;
    return index_lines(db);
}

int vdb_load(vulndb *db, const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long size;
    int rc;

    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || size > 64L * 1024 * 1024 ||
        fseek(f, 0, SEEK_SET) != 0 || (buf = malloc((size_t)size + 1)) == NULL) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    buf[size] = '\0';
    rc = vdb_load_text(db, buf);
    free(buf);
    return rc;
}

void vdb_free(vulndb *db)
{
    free(db->text);
    free(db->line);
    memset(db, 0, sizeof *db);
}

/* field idx (0 = record type) of a tab-separated line */
static void field(const char *line, int idx, char *out, size_t n)
{
    size_t i = 0;

    while (idx > 0 && *line != '\0')
        if (*line++ == '\t')
            idx--;
    while (line[i] != '\0' && line[i] != '\t' && i + 1 < n) {
        out[i] = line[i];
        i++;
    }
    out[i] = '\0';
}

static int is_rec(const char *line, char type, const char *product)
{
    size_t pl = strlen(product);

    return line[0] == type && strncmp(line + 2, product, pl) == 0 && line[2 + pl] == '\t';
}

/* ---------- ranges ---------- */

/* one bound; lt gets x of "<x", up gets x of "<x" or "<=x", *lower is set by ">=", ">" and "=" */
static int holds(const ver_t *v, const char *c, char *lt, size_t ltn, char *up, size_t upn, int *lower)
{
    ver_t b;
    int op, cmp;

    if (strncmp(c, ">=", 2) == 0) op = 0, c += 2;
    else if (strncmp(c, "<=", 2) == 0) op = 1, c += 2;
    else if (*c == '>') op = 2, c++;
    else if (*c == '<') op = 3, c++;
    else if (*c == '=') op = 4, c++;
    else return 0;
    if (ver_parse(c, &b) != 0)
        return 0;
    cmp = ver_cmp(v, &b);
    if (op == 3)
        copy_str(lt, ltn, c);
    if (op == 1 || op == 3)
        copy_str(up, upn, c);
    else
        *lower = 1;
    switch (op) {
    case 0: return cmp >= 0;
    case 1: return cmp <= 0;
    case 2: return cmp > 0;
    case 3: return cmp < 0;
    default: return cmp == 0;
    }
}

/* the matching alternative's upper bound and whether it has a lower one, for backport checks */
static int range_match(const char *ranges, const char *version, char *fixed, size_t fixed_len,
                       char *upper, size_t upper_len, int *bounded_below)
{
    ver_t v;
    const char *p = ranges;

    if (fixed_len > 0)
        fixed[0] = '\0';
    if (upper_len > 0)
        upper[0] = '\0';
    *bounded_below = 0;
    if (ver_parse(version, &v) != 0)
        return -1;
    while (*p != '\0') {
        size_t al = strcspn(p, ";");
        char alt[512], lt[40] = "", up[40] = "";
        int ok = 1, any = 0, lower = 0;

        if (al < sizeof alt) {
            char *c = alt;

            memcpy(alt, p, al);
            alt[al] = '\0';
            while (ok && *c != '\0') { /* every ','-separated bound must hold */
                size_t cl = strcspn(c, ",");
                int last = c[cl] == '\0';

                c[cl] = '\0';
                if (cl > 0) {
                    any = 1;
                    ok = holds(&v, c, lt, sizeof lt, up, sizeof up, &lower);
                }
                c += cl + !last;
            }
            if (ok && any) {
                copy_str(fixed, fixed_len, lt);
                copy_str(upper, upper_len, up);
                *bounded_below = lower;
                return 1;
            }
        }
        p += al;
        if (*p == ';')
            p++;
    }
    return 0;
}

int vdb_range_match(const char *ranges, const char *version, char *fixed, size_t fixed_len)
{
    char up[40];
    int lower;

    return range_match(ranges, version, fixed, fixed_len, up, sizeof up, &lower);
}

/* WordPress backports security fixes to its older release lines (4.7.39 has the fixes of
   6.x). NVD often records only "every version before 5.2.4" though, so such an entry says
   nothing about a version on an older line: it is skipped there. Entries that name the line
   (">=4.9,<4.9.25") or the exact version still count. */
static int backported_line(const char *product, const char *version, const char *upper, int bounded_below)
{
    ver_t v, u;

    if (strcmp(product, "wordpress") != 0 || bounded_below || upper[0] == '\0' ||
        ver_parse(version, &v) != 0 || ver_parse(upper, &u) != 0 || v.count < 2 || u.count < 2)
        return 0;
    return v.part[0] < u.part[0] || (v.part[0] == u.part[0] && v.part[1] < u.part[1]);
}

/* ---------- assessment ---------- */

static int sev_of(const char *s)
{
    if (strcmp(s, "critical") == 0) return VDB_SEV_CRITICAL;
    if (strcmp(s, "high") == 0) return VDB_SEV_HIGH;
    if (strcmp(s, "medium") == 0) return VDB_SEV_MEDIUM;
    if (strcmp(s, "low") == 0) return VDB_SEV_LOW;
    return VDB_SEV_UNKNOWN;
}

const char *vdb_sev_name(int sev)
{
    static const char *const n[] = {"unknown", "low", "medium", "high", "critical"};

    return sev >= 0 && sev <= VDB_SEV_CRITICAL ? n[sev] : "unknown";
}

static int dots(const char *v)
{
    int n = 0;

    for (; *v != '\0' && *v != '-'; v++)
        n += *v == '.';
    return n;
}

static int ver_less(const char *a, const char *b)
{
    ver_t x, y;

    return ver_parse(a, &x) == 0 && ver_parse(b, &y) == 0 && ver_cmp(&x, &y) < 0;
}

/* worst first; holes in active use first */
static int rank(const vdb_hit *h)
{
    return h->kev * 10 + h->sev;
}

static void holes(const vulndb *db, const char *product, const char *version, vdb_assess *a)
{
    size_t i;

    for (i = 0; i < db->n; i++) {
        const char *l = db->line[i];
        char ranges[1024], fixed[40], upper[40], sev[16], kev[4];
        vdb_hit h;
        int j, lower;

        if (!is_rec(l, 'V', product))
            continue;
        a->known = 1;
        field(l, 6, ranges, sizeof ranges);
        if (range_match(ranges, version, fixed, sizeof fixed, upper, sizeof upper, &lower) != 1 ||
            backported_line(product, version, upper, lower))
            continue;
        memset(&h, 0, sizeof h);
        field(l, 2, h.id, sizeof h.id);
        field(l, 3, sev, sizeof sev);
        field(l, 5, kev, sizeof kev);
        field(l, 8, h.url, sizeof h.url);
        field(l, 9, h.summary, sizeof h.summary);
        h.sev = sev_of(sev);
        h.kev = kev[0] == '1';
        copy_str(h.fixed, sizeof h.fixed, fixed);
        a->nhole++;
        if (h.sev > a->worst)
            a->worst = h.sev;
        a->kev |= h.kev;
        a->nkev += (unsigned long)h.kev;
        if (fixed[0] != '\0' && (a->fix_to[0] == '\0' || ver_less(a->fix_to, fixed)))
            copy_str(a->fix_to, sizeof a->fix_to, fixed);
        /* insert into the worst-first list */
        for (j = a->ntop; j > 0 && rank(&a->top[j - 1]) < rank(&h); j--)
            if (j < VDB_TOP)
                a->top[j] = a->top[j - 1];
        if (j < VDB_TOP) {
            a->top[j] = h;
            if (a->ntop < VDB_TOP)
                a->ntop++;
        }
    }
}

static int state(const char *date)
{
    if (strcmp(date, "yes") == 0)
        return 1;
    if (strcmp(date, "no") == 0)
        return 0;
    if (isdigit((unsigned char)date[0]))
        return strcmp(date, vdb_today()) <= 0;
    return -1;
}

/* paid or extended support still running: a future date, or "yes" without one */
static int ext_active(const char *ext)
{
    return strcmp(ext, "yes") == 0 || (isdigit((unsigned char)ext[0]) && state(ext) == 0);
}

/* the release line a version belongs to: the longest cycle that starts it ("7.4" for "7.4.3",
   "1.0.2" for "1.0.2k") */
static const char *cycle_line(const vulndb *db, const char *product, const char *version)
{
    const char *best = NULL;
    size_t i, bl = 0;

    for (i = 0; i < db->n; i++) {
        const char *l = db->line[i];
        char cyc[40];
        size_t cl;

        if (!is_rec(l, 'E', product))
            continue;
        field(l, 2, cyc, sizeof cyc);
        cl = strlen(cyc);
        if (cl > bl && strncmp(version, cyc, cl) == 0 &&
            (version[cl] == '\0' || version[cl] == '.' || isalpha((unsigned char)version[cl]))) {
            best = l;
            bl = cl;
        }
    }
    return best;
}

static const char *named_cycle(const vulndb *db, const char *product, const char *cycle)
{
    size_t i;

    for (i = 0; i < db->n; i++) {
        char cyc[40];

        if (!is_rec(db->line[i], 'E', product))
            continue;
        field(db->line[i], 2, cyc, sizeof cyc);
        if (strcmp(cyc, cycle) == 0)
            return db->line[i];
    }
    return NULL;
}

static void own_eol(const vulndb *db, const char *product, const char *version, vdb_assess *a)
{
    const char *l = cycle_line(db, product, version);
    char eol[24];
    size_t i;

    if (l == NULL) {
        for (i = 0; i < db->n; i++) /* endoflife.date lists the newest line first */
            if (is_rec(db->line[i], 'E', product)) {
                field(db->line[i], 5, a->newest, sizeof a->newest);
                break;
            }
        return;
    }
    a->known = 1;
    field(l, 2, a->cycle, sizeof a->cycle);
    field(l, 3, eol, sizeof eol);
    field(l, 5, a->newest, sizeof a->newest);
    a->eol = state(eol);
    copy_str(a->eol_date, sizeof a->eol_date, isdigit((unsigned char)eol[0]) ? eol : "");
}

static const char *os_label(const char *os)
{
    static const char *const map[][2] = {
        {"ubuntu", "Ubuntu"}, {"debian", "Debian"}, {"centos", "CentOS"}, {"rhel", "Red Hat Enterprise Linux"},
        {"rocky", "Rocky Linux"}, {"alma", "AlmaLinux"}, {"amazon-linux", "Amazon Linux"},
        {"fedora", "Fedora"}, {"windows", "Windows"}};
    size_t i;

    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(map[i][0], os) == 0)
            return map[i][1];
    return os;
}

/* OS release: from the tag itself, else from which releases shipped this upstream version */
static void os_eol(const vulndb *db, const tech_item *t, vdb_assess *a)
{
    const char *family = strcmp(t->os, "ubuntu") == 0 || strcmp(t->os, "debian") == 0 ? t->os
                       : (strcmp(t->os, "centos") == 0 || strcmp(t->os, "rhel") == 0 ||
                          strcmp(t->os, "rocky") == 0 || strcmp(t->os, "alma") == 0) ? "rhel" : NULL;
    char rel[3][16], up[40];
    const char *line;
    int nrel = 0, i;
    size_t k;

    a->os_eol = -1;
    if (strcmp(t->os, "windows") == 0 && strcmp(t->product, "iis") == 0) {
        /* IIS ships with Windows and follows its support (learn.microsoft.com/lifecycle) */
        static const char *const iis[][3] = {
            {"5.0", "2000", "Windows 2000 Server"}, {"6.0", "2003-sp2", "Windows Server 2003"},
            {"7.0", "2008-sp2", "Windows Server 2008"}, {"7.5", "2008-r2-sp1", "Windows Server 2008 R2"},
            {"8.0", "2012", "Windows Server 2012"}, {"8.5", "2012-r2", "Windows Server 2012 R2"},
            {"10.0", "2016", "Windows Server 2016 or newer"}};
        char eol[24], ext[24];

        for (k = 0; k < sizeof iis / sizeof iis[0]; k++)
            if (strcmp(t->version, iis[k][0]) == 0)
                break;
        if (k == sizeof iis / sizeof iis[0])
            return;
        copy_str(a->os_name, sizeof a->os_name, iis[k][2]);
        if ((line = named_cycle(db, "windows-server", iis[k][1])) == NULL)
            return;
        field(line, 3, eol, sizeof eol);
        field(line, 4, ext, sizeof ext);
        a->os_eol = state(eol);
        a->os_ext = a->os_eol == 1 && ext_active(ext);
        copy_str(a->os_eol_date, sizeof a->os_eol_date, isdigit((unsigned char)eol[0]) ? eol : "");
        copy_str(a->os_ext_date, sizeof a->os_ext_date, isdigit((unsigned char)ext[0]) ? ext : "");
        if (k == sizeof iis / sizeof iis[0] - 1 && a->os_eol == 0)
            a->os_eol = -1; /* 2016 or a newer, supported Windows: only the date is worth a note */
        return;
    }
    if (t->os[0] == '\0' || strcmp(t->os, "windows") == 0)
        return;
    if (t->os_release[0] != '\0') {
        copy_str(rel[nrel++], sizeof rel[0], t->os_release);
    } else if (family != NULL && t->version[0] != '\0') {
        copy_str(up, sizeof up, t->version);
        up[strcspn(up, "-+~")] = '\0';
        for (k = 0; k < db->n && nrel < 3; k++) {
            char p[16], v[40], d[16], r[16];

            if (db->line[k][0] != 'M')
                continue;
            field(db->line[k], 1, p, sizeof p);
            field(db->line[k], 2, v, sizeof v);
            field(db->line[k], 3, d, sizeof d);
            field(db->line[k], 4, r, sizeof r);
            if (strcmp(p, t->product) != 0 || strcmp(v, up) != 0 || strcmp(d, family) != 0)
                continue;
            for (i = 0; i < nrel && strcmp(rel[i], r) != 0; i++)
                ;
            if (i == nrel)
                copy_str(rel[nrel++], sizeof rel[0], r);
        }
    }
    if (nrel == 0) {
        copy_str(a->os_name, sizeof a->os_name, os_label(t->os));
        return;
    }
    /* oldest first in the name; the newest candidate decides: no alarm unless every possible
       release is out of support */
    for (i = 0; i < nrel; i++) {
        int j;

        for (j = i + 1; j < nrel; j++)
            if (ver_less(rel[j], rel[i])) {
                char tmp[16];

                memcpy(tmp, rel[i], sizeof tmp);
                memcpy(rel[i], rel[j], sizeof tmp);
                memcpy(rel[j], tmp, sizeof tmp);
            }
    }
    snprintf(a->os_name, sizeof a->os_name, "%s %s", os_label(t->os), rel[0]);
    for (i = 1; i < nrel; i++) {
        size_t ol = strlen(a->os_name);

        snprintf(a->os_name + ol, sizeof a->os_name - ol, " or %s", rel[i]);
    }
    if ((line = named_cycle(db, t->os, rel[nrel - 1])) != NULL) {
        char eol[24], ext[24];

        field(line, 3, eol, sizeof eol);
        field(line, 4, ext, sizeof ext);
        a->os_eol = state(eol);
        a->os_ext = a->os_eol == 1 && ext_active(ext);
        copy_str(a->os_eol_date, sizeof a->os_eol_date, isdigit((unsigned char)eol[0]) ? eol : "");
        copy_str(a->os_ext_date, sizeof a->os_ext_date, isdigit((unsigned char)ext[0]) ? ext : "");
    }
}

void vdb_assess_item(const vulndb *db, const tech_item *t, vdb_assess *a)
{
    static const char *const eol_name[][2] = {{"apache", "apache"}, {"nginx", "nginx"}, {"php", "php"},
                                              {"openssl", "openssl"}, {"wordpress", "wordpress"},
                                              {"drupal", "drupal"}, {"joomla", "joomla"},
                                              {"magento", "magento"}, {"nextjs", "nextjs"}};
    size_t k;

    memset(a, 0, sizeof *a);
    a->eol = -1;
    a->os_eol = -1;
    if (db == NULL || t == NULL)
        return;
    if (t->version[0] != '\0') {
        /* a bare major ("10") or major.minor from a hint would match far too many holes */
        if (t->conf == TECH_EXACT || dots(t->version) >= 2)
            holes(db, t->product, t->version, a);
        if (strcmp(t->product, "wordpress") == 0)
            for (k = 0; k < db->n; k++) {
                char v[40];

                if (!is_rec(db->line[k], 'S', "wordpress"))
                    continue;
                field(db->line[k], 2, v, sizeof v);
                if (strcmp(v, t->version) == 0) {
                    field(db->line[k], 3, a->wp_status, sizeof a->wp_status);
                    break;
                }
            }
        /* WordPress.org's own verdict wins: "latest" and "outdated" have no open security hole */
        if (t->conf == TECH_EXACT && (strcmp(a->wp_status, "latest") == 0 || strcmp(a->wp_status, "outdated") == 0)) {
            a->nhole = a->nkev = 0;
            a->worst = a->kev = a->ntop = 0;
            a->fix_to[0] = '\0';
        }
    }
    for (k = 0; k < sizeof eol_name / sizeof eol_name[0]; k++)
        if (strcmp(eol_name[k][0], t->product) == 0) {
            if (t->version[0] != '\0')
                own_eol(db, eol_name[k][1], t->version, a);
            else
                own_eol(db, eol_name[k][1], "-", a);
            break;
        }
    if (!a->known)
        for (k = 0; k < db->n; k++)
            if (is_rec(db->line[k], 'V', t->product)) {
                a->known = 1;
                break;
            }
    os_eol(db, t, a);
}
