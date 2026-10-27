#include "pysupply.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include "fsutil.h"

#define MAX_DEPTH 14
#define LINE_BUF 2048

/* ---------- helpers ---------- */

void py_normalize_name(const char *in, char *out, size_t n)
{
    size_t o = 0;
    int dash = 0;

    if (n == 0)
        return;
    for (; *in != '\0' && o + 1 < n; in++) {
        if (*in == '_' || *in == '.' || *in == '-') {
            if (!dash)
                out[o++] = '-';
            dash = 1;
        } else {
            out[o++] = (char)tolower((unsigned char)*in);
            dash = 0;
        }
    }
    out[o] = '\0';
}

int py_parse_requirement_line(const char *line, char *name, size_t nn, char *ver, size_t vn)
{
    const char *p = line;
    size_t i = 0;

    while (isspace((unsigned char)*p))
        p++;
    if (!isalnum((unsigned char)*p))
        return 0; /* comment, option (-r, -e, --hash) or empty */
    while ((isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-') && i + 1 < nn)
        name[i++] = *p++;
    name[i] = '\0';
    if (isalnum((unsigned char)*p))
        return 0; /* name too long */
    if (*p == '[') { /* extras */
        while (*p != '\0' && *p != ']')
            p++;
        if (*p != ']')
            return 0;
        p++;
    }
    while (*p == ' ' || *p == '\t')
        p++;
    if (strncmp(p, "===", 3) == 0)
        p += 3;
    else if (strncmp(p, "==", 2) == 0)
        p += 2;
    else
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    i = 0;
    while (*p != '\0' && !isspace((unsigned char)*p) && *p != ';' && *p != ',' && *p != '#' &&
           *p != '\\' && i + 1 < vn)
        ver[i++] = *p++;
    ver[i] = '\0';
    return i > 0 && isdigit((unsigned char)ver[0]);
}

int py_pth_line_class(const char *line)
{
    static const char *const bad[] = {"exec(", "eval(", "base64", "subprocess", "urllib",
                                      "requests", "socket", "http://", "https://",
                                      "os.system", "__import__", "compile(", "popen", NULL};
    int i;

    while (isspace((unsigned char)*line))
        line++;
    if (strncmp(line, "import ", 7) != 0 && strncmp(line, "import\t", 7) != 0)
        return 0;
    for (i = 0; bad[i] != NULL; i++)
        if (strstr(line, bad[i]) != NULL)
            return 2;
    return 1;
}

/* Copy with truncation (these strings are display data; cutting them short is fine). */
static void copy_str(char *dst, size_t n, const char *src)
{
    size_t len = strlen(src);

    if (n == 0)
        return;
    if (len >= n)
        len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int add_finding(py_report *r, int sev, const char *kind, const char *path, int line,
                       const char *name, const char *ver, const char *detail)
{
    py_finding *f;

    if (r->n == r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 16;
        py_finding *nf = realloc(r->f, ncap * sizeof *nf);

        if (nf == NULL)
            return -1;
        r->f = nf;
        r->cap = ncap;
    }
    f = &r->f[r->n++];
    memset(f, 0, sizeof *f);
    f->severity = sev;
    copy_str(f->kind, sizeof f->kind, kind);
    copy_str(f->path, sizeof f->path, path);
    f->line = line;
    copy_str(f->name, sizeof f->name, name);
    copy_str(f->version, sizeof f->version, ver);
    copy_str(f->detail, sizeof f->detail, detail);
    return 0;
}

static int check_pkg(const adv_list *adv, py_report *r, const char *name, const char *ver,
                     const char *path, int line, int installed)
{
    char norm[64];
    size_t i;

    py_normalize_name(name, norm, sizeof norm);
    for (i = 0; i < adv->n; i++) {
        const adv_entry *e = &adv->e[i];
        char prod[64];
        char detail[600];

        if (strcmp(e->module, "py") != 0)
            continue;
        py_normalize_name(e->product, prod, sizeof prod);
        if (strcmp(prod, norm) != 0 || adv_match(e, ver) != 1)
            continue;
        snprintf(detail, sizeof detail, "in affected range; safe: %s; see %s", e->fixed, e->url);
        if (add_finding(r, installed ? 2 : 1, installed ? "installed-package" : "locked-package",
                        path, line, name, ver, detail) != 0)
            return -1;
    }
    return 0;
}

/* ---------- installed packages ---------- */

static void trim_nl(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

static int handle_dist(const char *distdir, const char *dirname, const adv_list *adv,
                       py_report *r)
{
    char name[64] = "", ver[40] = "";
    char file[1024];
    FILE *f;
    char line[LINE_BUF];
    int lines = 0;

    if (fs_join(file, sizeof file, distdir, fs_has_suffix_ci(dirname, ".egg-info")
                                                ? "PKG-INFO" : "METADATA") == 0 &&
        (f = fopen(file, "r")) != NULL) {
        while (lines++ < 200 && fgets(line, sizeof line, f) != NULL) {
            trim_nl(line);
            if (line[0] == '\0')
                break; /* end of headers */
            if (strncmp(line, "Name: ", 6) == 0 && name[0] == '\0')
                copy_str(name, sizeof name, line + 6);
            else if (strncmp(line, "Version: ", 9) == 0 && ver[0] == '\0')
                copy_str(ver, sizeof ver, line + 9);
        }
        fclose(f);
    }
    if (name[0] == '\0' || ver[0] == '\0') { /* fall back to "name-1.2.3.dist-info" */
        char stem[128];
        char *dot, *dash;

        copy_str(stem, sizeof stem, dirname);
        dot = strrchr(stem, '.'); /* drop ".dist-info" / ".egg-info" */
        if (dot != NULL)
            *dot = '\0';
        dash = strchr(stem, '-');
        if (dash != NULL && isdigit((unsigned char)dash[1])) {
            *dash = '\0';
            copy_str(name, sizeof name, stem);
            copy_str(ver, sizeof ver, dash + 1);
        }
    }
    if (name[0] == '\0' || ver[0] == '\0')
        return 0;
    r->packages_seen++;
    return check_pkg(adv, r, name, ver, distdir, 0, 1);
}

/* ---------- .pth and IOC files in site-packages ---------- */

static int handle_pth(const char *path, py_report *r)
{
    FILE *f = fopen(path, "r");
    char line[LINE_BUF];
    int lineno = 0;

    if (f == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        int cls;

        lineno++;
        cls = py_pth_line_class(line);
        if (cls == 1)
            r->pth_import_seen++;
        else if (cls == 2) {
            trim_nl(line);
            if (add_finding(r, 1, "pth-suspicious", path, lineno, "", "",
                            "import line in .pth runs code at every Python start and contains "
                            "exec/network markers; inspect the file") != 0) {
                fclose(f);
                return -1;
            }
        }
    }
    fclose(f);
    return 0;
}

static int is_ioc_name(const adv_list *adv, const char *name, const adv_entry **hit)
{
    size_t i;

    for (i = 0; i < adv->n; i++) {
        const adv_entry *e = &adv->e[i];
        char buf[192];
        char *tok, *save;

        if (strcmp(e->module, "pyioc") != 0)
            continue;
        snprintf(buf, sizeof buf, "%s", e->fixed);
        for (tok = buf; tok != NULL; tok = save) {
            save = strchr(tok, ';');
            if (save != NULL)
                *save++ = '\0';
            if (tok[0] != '\0' && strcmp(tok, name) == 0) {
                *hit = e;
                return 1;
            }
        }
    }
    return 0;
}

/* ---------- requirements / lock files ---------- */

static int scan_requirements(const char *path, const adv_list *adv, py_report *r)
{
    FILE *f = fopen(path, "r");
    char line[LINE_BUF];
    char name[64], ver[40];
    int lineno = 0;

    if (f == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        lineno++;
        if (py_parse_requirement_line(line, name, sizeof name, ver, sizeof ver)) {
            r->pinned_seen++;
            if (check_pkg(adv, r, name, ver, path, lineno, 0) != 0) {
                fclose(f);
                return -1;
            }
        }
    }
    fclose(f);
    return 0;
}

/* poetry.lock and uv.lock: [[package]] blocks with name = "x" / version = "y". */
static int scan_lock(const char *path, const adv_list *adv, py_report *r)
{
    FILE *f = fopen(path, "r");
    char line[LINE_BUF];
    char name[64] = "", ver[40] = "";
    int lineno = 0;

    if (f == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *q1, *q2;

        lineno++;
        if (strncmp(line, "[[package]]", 11) == 0) {
            name[0] = ver[0] = '\0';
            continue;
        }
        if (strncmp(line, "name = \"", 8) == 0 || strncmp(line, "version = \"", 11) == 0) {
            int is_name = line[0] == 'n';

            q1 = strchr(line, '"');
            q2 = q1 != NULL ? strchr(q1 + 1, '"') : NULL;
            if (q1 == NULL || q2 == NULL)
                continue;
            *q2 = '\0';
            snprintf(is_name ? name : ver, is_name ? sizeof name : sizeof ver, "%s", q1 + 1);
            if (name[0] != '\0' && ver[0] != '\0') {
                r->pinned_seen++;
                if (check_pkg(adv, r, name, ver, path, lineno, 0) != 0) {
                    fclose(f);
                    return -1;
                }
                name[0] = ver[0] = '\0';
            }
        }
    }
    fclose(f);
    return 0;
}

/* ---------- walk ---------- */

static int is_requirements_name(const char *n)
{
    return strncmp(n, "requirements", 12) == 0 && fs_has_suffix_ci(n, ".txt");
}

static int walk(const char *dir, int depth, const adv_list *adv, py_report *r)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int rc = 0;
    int in_site = strcmp(fs_basename(dir), "site-packages") == 0;

    if (d == NULL)
        return 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        char path[1024];
        const char *n = de->d_name;

        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0)
            continue;
        if (fs_join(path, sizeof path, dir, n) != 0)
            continue;
        if (fs_is_dir(path)) {
            if (fs_has_suffix_ci(n, ".dist-info") || fs_has_suffix_ci(n, ".egg-info"))
                rc = handle_dist(path, n, adv, r);
            else if (strcmp(n, "node_modules") != 0 && strcmp(n, ".git") != 0 &&
                     strcmp(n, "__pycache__") != 0 && depth < MAX_DEPTH)
                rc = walk(path, depth + 1, adv, r);
            continue;
        }
        if (in_site) {
            const adv_entry *e = NULL;

            if (fs_has_suffix_ci(n, ".pth"))
                rc = handle_pth(path, r);
            if (rc == 0 && is_ioc_name(adv, n, &e)) {
                char detail[600];

                snprintf(detail, sizeof detail,
                         "file name matches an incident indicator (%s); verify, see %s",
                         e->product, e->url);
                rc = add_finding(r, 1, "ioc-file", path, 0, e->product, "", detail);
            }
        }
        if (rc == 0) {
            if (is_requirements_name(n))
                rc = scan_requirements(path, adv, r);
            else if (strcmp(n, "poetry.lock") == 0 || strcmp(n, "uv.lock") == 0)
                rc = scan_lock(path, adv, r);
        }
    }
    closedir(d);
    return rc;
}

int py_scan(const char *root, const adv_list *adv, py_report *r)
{
    if (!fs_is_dir(root))
        return -1;
    return walk(root, 0, adv, r);
}

void py_report_free(py_report *r)
{
    free(r->f);
    memset(r, 0, sizeof *r);
}

void py_report_print(const py_report *r, FILE *out)
{
    size_t i;
    unsigned long high = 0;

    for (i = 0; i < r->n; i++) {
        const py_finding *f = &r->f[i];

        if (f->severity == 2)
            high++;
        fprintf(out, "[%s] %s", f->severity == 2 ? "AFFECTED" : "POSSIBLE", f->kind);
        if (f->name[0] != '\0')
            fprintf(out, "  %s %s", f->name, f->version);
        fprintf(out, "\n    %s", f->path);
        if (f->line > 0)
            fprintf(out, ":%d", f->line);
        fprintf(out, "\n    %s\n", f->detail);
    }
    fprintf(out, "\n%lu installed package(s) read, %lu pinned requirement(s) read, "
                 "%lu benign-looking .pth import line(s), %lu finding(s) (%lu affected)\n",
            r->packages_seen, r->pinned_seen, r->pth_import_seen, (unsigned long)r->n, high);
    fprintf(out, "A clean result does not prove a machine is clean; it only checks the rules in "
                 "data/advisories.txt.\n");
}
