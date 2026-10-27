#include "secret_scan.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include "fsutil.h"
#include "gitindex.h"

#define LINE_BUF 4096
#define MAX_FILE_BYTES (1024 * 1024)
#define MAX_DEPTH 32
#define TRACKED_UNSET (-3)

/* ---------- value helpers ---------- */

static void mask_value(const char *v, size_t len, char *out, size_t n)
{
    if (len >= 12 && n >= 9)
        snprintf(out, n, "****%.4s", v + len - 4);
    else
        snprintf(out, n, "****");
}

static int starts_with_ci(const char *s, size_t len, const char *prefix)
{
    size_t i, lp = strlen(prefix);

    if (lp > len)
        return 0;
    for (i = 0; i < lp; i++)
        if (tolower((unsigned char)s[i]) != prefix[i])
            return 0;
    return 1;
}

static int equals_ci(const char *s, size_t len, const char *word)
{
    return strlen(word) == len && starts_with_ci(s, len, word);
}

/* Template/placeholder/code-looking values that are not real secrets. */
static int is_placeholder(const char *v, size_t len)
{
    static const char *const prefixes[] = {
        "your", "change", "xxx", "example", "placeholder", "todo", "process.env",
        "os.environ", "getenv", "env.", "***", "${", "$", "<", "{{", "%", "null",
        "none", "true", "false", NULL};
    static const char *const exact[] = {"password", "passwd", "secret", "token", "pass", NULL};
    int i;

    for (i = 0; prefixes[i] != NULL; i++)
        if (starts_with_ci(v, len, prefixes[i]))
            return 1;
    for (i = 0; exact[i] != NULL; i++)
        if (equals_ci(v, len, exact[i]))
            return 1;
    return 0;
}

/* ---------- token rules ---------- */

static int ok_upper_digit(int c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }
static int ok_alnum(int c) { return isalnum(c) != 0; }
static int ok_alnum_us(int c) { return isalnum(c) || c == '_'; }
static int ok_urlsafe(int c) { return isalnum(c) || c == '_' || c == '-'; }

static int find_prefixed(const char *line, const char *prefix, size_t min_tail, int exact,
                         int (*ok)(int), char *masked, size_t mn)
{
    size_t pl = strlen(prefix);
    const char *p = line;

    while ((p = strstr(p, prefix)) != NULL) {
        size_t idx = (size_t)(p - line);
        const char *t = p + pl;
        size_t run = 0;
        int boundary = idx == 0 || !isalnum((unsigned char)line[idx - 1]);

        while (t[run] != '\0' && ok((unsigned char)t[run]))
            run++;
        if (boundary && (exact ? (run == min_tail && !isalnum((unsigned char)t[run]))
                               : run >= min_tail)) {
            mask_value(p, pl + run, masked, mn);
            return 1;
        }
        p += pl;
    }
    return 0;
}

static int find_any_prefix(const char *line, const char *const *prefixes, size_t min_tail,
                           int (*ok)(int), char *masked, size_t mn)
{
    int i;

    for (i = 0; prefixes[i] != NULL; i++)
        if (find_prefixed(line, prefixes[i], min_tail, 0, ok, masked, mn))
            return 1;
    return 0;
}

static int find_private_key(const char *line)
{
    const char *p = strstr(line, "-----BEGIN ");

    return p != NULL && strstr(p, "PRIVATE KEY-----") != NULL;
}

static int find_url_creds(const char *line, char *masked, size_t mn)
{
    const char *p = strstr(line, "://");

    while (p != NULL) {
        const char *start = p + 3;
        const char *q = start;

        while (*q != '\0' && *q != '/' && *q != '@' && !isspace((unsigned char)*q) &&
               *q != '"' && *q != '\'')
            q++;
        if (*q == '@') {
            const char *colon = memchr(start, ':', (size_t)(q - start));

            if (colon != NULL) {
                const char *pw = colon + 1;
                size_t len = (size_t)(q - pw);

                if (len >= 3 && !is_placeholder(pw, len)) {
                    mask_value(pw, len, masked, mn);
                    return 1;
                }
            }
        }
        p = strstr(p + 3, "://");
    }
    return 0;
}

static int find_assignment(const char *line, char *masked, size_t mn)
{
    static const char *const keys[] = {"password", "passwd", "secret", "token", "api_key",
                                       "apikey", "api-key", "private_key", "access_key", NULL};
    char low[LINE_BUF];
    size_t i, L = strlen(line);
    int k;

    if (L >= sizeof low)
        return 0;
    for (i = 0; i <= L; i++)
        low[i] = (char)tolower((unsigned char)line[i]);

    for (k = 0; keys[k] != NULL; k++) {
        const char *p = strstr(low, keys[k]);

        while (p != NULL) {
            const char *q = line + (p - low) + strlen(keys[k]);
            const char *v;
            size_t len;

            while (isalnum((unsigned char)*q) || *q == '_' || *q == '-' || *q == '.')
                q++;
            if (*q == '"' || *q == '\'')
                q++;
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q == '=') {
                q++;
                if (*q == '=')
                    goto next; /* comparison, not assignment */
                if (*q == '>')
                    q++;
            } else if (*q == ':') {
                q++;
            } else {
                goto next;
            }
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q == '"' || *q == '\'')
                q++;
            v = q;
            while (*q != '\0' && *q != '"' && *q != '\'' && !isspace((unsigned char)*q) &&
                   *q != ',' && *q != ';' && *q != '#')
                q++;
            len = (size_t)(q - v);
            if (len >= 8 && !is_placeholder(v, len) && memchr(v, '(', len) == NULL &&
                memchr(v, ')', len) == NULL) {
                mask_value(v, len, masked, mn);
                return 1;
            }
        next:
            p = strstr(p + 1, keys[k]);
        }
    }
    return 0;
}

int secret_scan_line(const char *line, line_hit *out, int max)
{
    static const char *const gh[] = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", NULL};
    static const char *const stripe[] = {"sk_live_", "rk_live_", NULL};
    static const char *const slack[] = {"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", NULL};
    int n = 0;

#define TRY(cond, name)                                                          \
    do {                                                                         \
        if (n < max) {                                                           \
            out[n].masked[0] = '\0';                                             \
            if (cond) {                                                          \
                out[n].rule = (name);                                            \
                n++;                                                             \
            }                                                                    \
        }                                                                        \
    } while (0)
#define M out[n].masked, sizeof out[n].masked

    TRY(find_prefixed(line, "AKIA", 16, 1, ok_upper_digit, M) ||
            find_prefixed(line, "ASIA", 16, 1, ok_upper_digit, M),
        "aws-access-key");
    TRY(find_any_prefix(line, gh, 36, ok_alnum, M) ||
            find_prefixed(line, "github_pat_", 22, 0, ok_alnum_us, M),
        "github-token");
    TRY(find_any_prefix(line, stripe, 16, ok_alnum, M), "stripe-live-key");
    TRY(find_prefixed(line, "AIza", 35, 1, ok_urlsafe, M), "google-api-key");
    TRY(find_any_prefix(line, slack, 10, ok_urlsafe, M), "slack-token");
    TRY(find_private_key(line), "private-key");
    TRY(find_url_creds(line, M), "url-credentials");
    if (n == 0)
        TRY(find_assignment(line, M), "secret-assignment");
#undef M
#undef TRY
    return n;
}

/* ---------- reporting ---------- */

static int add_hit(secret_report *r, const char *path, int line, const char *rule,
                   const char *masked, int tracked)
{
    secret_hit *h;

    if (r->n >= SECRET_MAX_HITS) {
        r->truncated = 1;
        return 0;
    }
    if (r->n == r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 32;
        secret_hit *nh = realloc(r->h, ncap * sizeof *nh);

        if (nh == NULL)
            return -1;
        r->h = nh;
        r->cap = ncap;
    }
    h = &r->h[r->n++];
    snprintf(h->path, sizeof h->path, "%s", path);
    h->line = line;
    snprintf(h->rule, sizeof h->rule, "%s", rule);
    snprintf(h->masked, sizeof h->masked, "%s", masked);
    h->tracked = tracked;
    return 0;
}

void secret_report_free(secret_report *r)
{
    free(r->h);
    memset(r, 0, sizeof *r);
}

void secret_report_print(const secret_report *r, FILE *out)
{
    size_t i;
    unsigned long tracked = 0;

    for (i = 0; i < r->n; i++) {
        const secret_hit *h = &r->h[i];
        const char *flag = h->tracked == 1 ? "  [TRACKED BY GIT]"
                           : h->tracked == -1 ? "  [git status unknown]" : "";

        if (h->tracked == 1)
            tracked++;
        fprintf(out, "%s:%d  %s  value=%s%s\n", h->path, h->line, h->rule,
                h->masked[0] ? h->masked : "-", flag);
    }
    fprintf(out, "\n%lu file(s) scanned, %lu skipped, %lu finding(s), %lu tracked by git%s\n",
            r->files_scanned, r->files_skipped, (unsigned long)r->n, tracked,
            r->truncated ? " (hit limit reached, output truncated)" : "");
    fprintf(out, "Values are masked. Findings are rule matches, not proof of a live secret.\n");
}

/* ---------- file walking ---------- */

static int is_env_file(const char *name)
{
    if (strncmp(name, ".env", 4) != 0)
        return 0;
    return !(fs_has_suffix_ci(name, ".example") || fs_has_suffix_ci(name, ".sample") ||
             fs_has_suffix_ci(name, ".template") || fs_has_suffix_ci(name, ".dist"));
}

static int env_assignment_has_value(const char *line)
{
    const char *eq, *v, *q;

    while (isspace((unsigned char)*line))
        line++;
    if (*line == '#' || *line == '\0')
        return 0;
    if (strncmp(line, "export ", 7) == 0)
        line += 7;
    eq = strchr(line, '=');
    if (eq == NULL || eq == line)
        return 0;
    v = eq + 1;
    while (*v == ' ' || *v == '\t' || *v == '"' || *v == '\'')
        v++;
    q = v;
    while (*q != '\0' && !isspace((unsigned char)*q) && *q != '"' && *q != '\'' && *q != '#')
        q++;
    return q > v && !is_placeholder(v, (size_t)(q - v));
}

static int scan_file(const char *path, const char *name, int in_git, secret_report *r)
{
    long long size;
    FILE *f;
    unsigned char head[4096];
    size_t hn;
    char line[LINE_BUF];
    int lineno = 0, cont = 0;
    int env = is_env_file(name);
    int env_line = 0;
    int tracked = in_git ? -2 : TRACKED_UNSET;

    if (!fs_is_file(path, &size) || size > MAX_FILE_BYTES) {
        r->files_skipped++;
        return 0;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        r->files_skipped++;
        return 0;
    }
    hn = fread(head, 1, sizeof head, f);
    if (memchr(head, 0, hn) != NULL) { /* binary */
        fclose(f);
        r->files_skipped++;
        return 0;
    }
    rewind(f);
    r->files_scanned++;

    while (fgets(line, sizeof line, f) != NULL) {
        size_t len = strlen(line);
        int full = len > 0 && line[len - 1] == '\n';
        line_hit hits[4];
        int nh, i;

        if (cont) { /* tail of an over-long line */
            cont = !full;
            continue;
        }
        lineno++;
        if (!full && !feof(f))
            cont = 1;

        nh = secret_scan_line(line, hits, 4);
        for (i = 0; i < nh; i++) {
            if (tracked == TRACKED_UNSET)
                tracked = gitidx_tracked(path);
            if (add_hit(r, path, lineno, hits[i].rule, hits[i].masked, tracked) != 0) {
                fclose(f);
                return -1;
            }
        }
        if (env && env_line == 0 && env_assignment_has_value(line))
            env_line = lineno;
    }
    fclose(f);
    if (env && env_line > 0) {
        if (tracked == TRACKED_UNSET)
            tracked = gitidx_tracked(path);
        if (add_hit(r, path, env_line, "env-file", "", tracked) != 0)
            return -1;
    }
    return 0;
}

static int skip_dir(const char *name)
{
    static const char *const skip[] = {"node_modules", "__pycache__", "site-packages", ".venv",
                                       "venv", NULL};
    int i;

    for (i = 0; skip[i] != NULL; i++)
        if (strcmp(name, skip[i]) == 0)
            return 1;
    return 0;
}

static int walk(const char *dir, int depth, secret_report *r)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int rc = 0;

    if (d == NULL)
        return 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        char path[1024];

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (fs_join(path, sizeof path, dir, de->d_name) != 0)
            continue;
        if (fs_is_dir(path)) {
            if (strcmp(de->d_name, ".git") == 0) {
                char cfg[1024];

                if (fs_join(cfg, sizeof cfg, path, "config") == 0)
                    rc = scan_file(cfg, "config", 1, r);
            } else if (!skip_dir(de->d_name) && depth < MAX_DEPTH) {
                rc = walk(path, depth + 1, r);
            }
        } else {
            rc = scan_file(path, de->d_name, 0, r);
        }
    }
    closedir(d);
    return rc;
}

int secret_scan_dir(const char *root, secret_report *r)
{
    if (!fs_is_dir(root))
        return -1;
    return walk(root, 0, r);
}
