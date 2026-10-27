/* Tests for secret_scan, gitindex and pysupply. No network. Usage: test_scan [advisories.txt]
   Fake secrets are assembled from pieces so this file does not itself look like a leak. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#define RMDIR(p) _rmdir(p)
#else
#include <unistd.h>
#define MKDIR(p) mkdir((p), 0755)
#define RMDIR(p) rmdir(p)
#endif

#include "../src/advisory.h"
#include "../src/fsutil.h"
#include "../src/gitindex.h"
#include "../src/pysupply.h"
#include "../src/secret_scan.h"

static int g_run, g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_run++;                                                             \
        if (!(cond)) {                                                       \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* ---------- fixture helpers ---------- */

static void mk(const char *dir) { MKDIR(dir); }

static void put(const char *dir, const char *name, const void *data, size_t len)
{
    char path[512];
    FILE *f;

    fs_join(path, sizeof path, dir, name);
    f = fopen(path, "wb");
    if (f == NULL) {
        printf("cannot write %s\n", path);
        exit(2);
    }
    fwrite(data, 1, len, f);
    fclose(f);
}

static void puts_(const char *dir, const char *name, const char *text)
{
    put(dir, name, text, strlen(text));
}

/* Remove a tree we created. Refuses anything not named tmp_*. */
static void rm_tree(const char *dir)
{
    DIR *d;
    struct dirent *de;

    if (strncmp(fs_basename(dir), "tmp_", 4) != 0 && strstr(dir, "tmp_") == NULL)
        return;
    d = opendir(dir);
    if (d == NULL)
        return;
    while ((de = readdir(d)) != NULL) {
        char p[512];

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        fs_join(p, sizeof p, dir, de->d_name);
        if (fs_is_dir(p))
            rm_tree(p);
        else
            remove(p);
    }
    closedir(d);
    RMDIR(dir);
}

/* ---------- line rules ---------- */

static int rule_is(const char *line, const char *rule)
{
    line_hit h[4];
    int n = secret_scan_line(line, h, 4);

    return n >= 1 && strcmp(h[0].rule, rule) == 0;
}

static int no_hit(const char *line)
{
    line_hit h[4];

    return secret_scan_line(line, h, 4) == 0;
}

static void test_lines(void)
{
    line_hit h[4];
    char s[256];

    CHECK(rule_is("key=" "AKIA" "IOSFODNN7EXAMPLE", "aws-access-key"));
    CHECK(no_hit("AKIA" "IOSFODNN7EXAMP"));   /* too short */
    CHECK(no_hit("akia" "iosfodnn7example"));
    CHECK(rule_is("t=" "ghp_" "0123456789abcdefghijklmnopqrstuvwxyz", "github-token"));
    CHECK(no_hit("t=" "ghp_" "0123456789abcdefghijklmnopqrstuvwx")); /* 34 chars */
    CHECK(rule_is("sk_" "live_" "abcdefghijklmnopqrstuvwx", "stripe-live-key"));
    CHECK(no_hit("sk_" "test_" "abcdefghijklmnopqrstuvwx"));
    CHECK(rule_is("AIza" "SyA1234567890abcdefghijklmnopqrstuv", "google-api-key"));
    CHECK(rule_is("xox" "b-1234567890-abcdefghij", "slack-token"));
    CHECK(rule_is("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"));
    CHECK(no_hit("-----BEGIN CERTIFICATE-----"));
    CHECK(rule_is("url = https://bob:pa55w0rdX@example.com/r.git", "url-credentials"));
    CHECK(no_hit("url = https://bob@example.com/r.git"));
    CHECK(no_hit("url = https://bob:password@example.com/r.git"));

    CHECK(rule_is("PASSWORD: \"hunter2hunter2\"", "secret-assignment"));
    CHECK(rule_is("api_key => 'abcdefgh12345'", "secret-assignment"));
    CHECK(rule_is("db_password = \"hunter2hunter2xyz\"", "secret-assignment"));
    CHECK(no_hit("password = \"${DB_PASS}\""));
    CHECK(no_hit("password = os.environ[\"X\"]"));
    CHECK(no_hit("if password == \"something_long\""));
    CHECK(no_hit("password=short"));
    CHECK(no_hit("token = get_token()"));
    CHECK(no_hit("secret = your-secret-here"));
    CHECK(no_hit("nothing to see here"));

    /* masking: never the value, last 4 only for values of 12+ chars */
    snprintf(s, sizeof s, "db_password = \"hunter2hunter2xyz\"");
    CHECK(secret_scan_line(s, h, 4) == 1);
    CHECK(strcmp(h[0].masked, "****2xyz") == 0);
    CHECK(secret_scan_line("password=abcdefgh", h, 4) == 1 && strcmp(h[0].masked, "****") == 0);

    /* two different rules on one line, and the max limit is respected */
    CHECK(secret_scan_line("AKIA" "IOSFODNN7EXAMPLE https://u:pa55w0rdX@h/", h, 4) == 2);
    CHECK(secret_scan_line("AKIA" "IOSFODNN7EXAMPLE https://u:pa55w0rdX@h/", h, 1) == 1);
}

/* ---------- directory scan ---------- */

static const secret_hit *find_hit(const secret_report *r, const char *path_suffix,
                                  const char *rule)
{
    size_t i;

    for (i = 0; i < r->n; i++)
        if (strcmp(r->h[i].rule, rule) == 0 && fs_has_suffix_ci(r->h[i].path, path_suffix))
            return &r->h[i];
    return NULL;
}

static void test_dir_scan(void)
{
    const char *root = "tmp_scan_test";
    char p[512], q[512];
    secret_report r;
    unsigned char bin[64];
    char *big;
    size_t i;
    /* v2 git index with one entry "tracked.txt" */
    unsigned char idx[12 + 72 + 20];

    rm_tree(root);
    mk(root);
    puts_(root, ".env", "PORT=3000\nAPI_TOKEN=abcdef0123456789abcd\n");
    puts_(root, ".env.example", "API_TOKEN=your-token-here\n");
    puts_(root, "aws.txt", "key=" "AKIA" "IOSFODNN7EXAMPLE\n");

    fs_join(p, sizeof p, root, "src");
    mk(p);
    puts_(p, "app.py", "db_password = \"hunter2hunter2xyz\"\n");

    fs_join(p, sizeof p, root, "node_modules");
    mk(p);
    puts_(p, "leak.txt", "password = \"hunter2hunter2xyz\"\n");

    memset(bin, 0, sizeof bin);
    memcpy(bin + 8, "password = \"hunter2hunter2xyz\"", 30);
    put(root, "bin.dat", bin, sizeof bin);

    fs_join(p, sizeof p, root, ".git");
    mk(p);
    puts_(p, "config", "[remote \"origin\"]\n\turl = https://bob:s3cretpassw0rd@example.com/r.git\n");

    /* over-long first line, secret on line 2 */
    big = malloc(10001);
    CHECK(big != NULL);
    if (big != NULL) {
        memset(big, 'a', 10000);
        big[10000] = '\0';
        fs_join(p, sizeof p, root, "long");
        mk(p);
        {
            char buf[10100];
            snprintf(buf, sizeof buf, "%s\ndb_password = \"hunter2hunter2xyz\"\n", big);
            puts_(p, "f.txt", buf);
        }
        free(big);
    }

    /* a fake repo: tracked.txt is in the index, untracked.txt is not */
    fs_join(p, sizeof p, root, "repo");
    mk(p);
    fs_join(q, sizeof q, p, ".git");
    mk(q);
    memset(idx, 0, sizeof idx);
    memcpy(idx, "DIRC", 4);
    idx[7] = 2;  /* version 2 */
    idx[11] = 1; /* one entry */
    idx[12 + 61] = 11; /* flags: name length */
    memcpy(idx + 12 + 62, "tracked.txt", 11);
    put(q, "index", idx, sizeof idx);
    puts_(p, "tracked.txt", "db_password = \"hunter2hunter2xyz\"\n");
    puts_(p, "untracked.txt", "db_password = \"hunter2hunter2xyz\"\n");

    memset(&r, 0, sizeof r);
    CHECK(secret_scan_dir(root, &r) == 0);

    CHECK(find_hit(&r, "tmp_scan_test/.env", "env-file") != NULL);
    CHECK(find_hit(&r, "tmp_scan_test/.env", "secret-assignment") != NULL);
    CHECK(find_hit(&r, ".env.example", "env-file") == NULL);
    CHECK(find_hit(&r, ".env.example", "secret-assignment") == NULL);
    CHECK(find_hit(&r, "aws.txt", "aws-access-key") != NULL);
    CHECK(find_hit(&r, "app.py", "secret-assignment") != NULL);
    CHECK(find_hit(&r, ".git/config", "url-credentials") != NULL);
    CHECK(find_hit(&r, "leak.txt", "secret-assignment") == NULL); /* node_modules skipped */
    CHECK(find_hit(&r, "bin.dat", "secret-assignment") == NULL);  /* binary skipped */
    {
        const secret_hit *lh = find_hit(&r, "f.txt", "secret-assignment");
        const secret_hit *t = find_hit(&r, "repo/tracked.txt", "secret-assignment");
        const secret_hit *u = find_hit(&r, "repo/untracked.txt", "secret-assignment");

        CHECK(lh != NULL && lh->line == 2);
        CHECK(t != NULL && t->tracked == 1);
        CHECK(u != NULL && u->tracked == 0);
    }
    CHECK(r.files_skipped >= 1);

    /* no hit may contain any part of a secret value */
    for (i = 0; i < r.n; i++) {
        CHECK(strstr(r.h[i].masked, "hunter") == NULL);
        CHECK(strstr(r.h[i].masked, "s3cret") == NULL);
        CHECK(strstr(r.h[i].masked, "IOSFOD") == NULL);
        CHECK(strlen(r.h[i].masked) <= 8);
    }
    secret_report_free(&r);

    memset(&r, 0, sizeof r);
    CHECK(secret_scan_dir("tmp_does_not_exist", &r) == -1);
    secret_report_free(&r);
    rm_tree(root);
}

/* ---------- python module ---------- */

static void test_py(const char *adv_path)
{
    const char *root = "tmp_py_test";
    char site[512], d1[512], d2[512], d3[512], tmp[512];
    char name[64], ver[40];
    adv_list adv = {0};
    py_report r;
    size_t i;
    int nerr = 0, inst = 0, locked = 0, pth = 0, ioc = 0;

    py_normalize_name("Foo_Bar.baz", name, sizeof name);
    CHECK(strcmp(name, "foo-bar-baz") == 0);
    py_normalize_name("LiteLLM", name, sizeof name);
    CHECK(strcmp(name, "litellm") == 0);

    CHECK(py_parse_requirement_line("litellm==1.107.0", name, sizeof name, ver, sizeof ver) &&
          strcmp(name, "litellm") == 0 && strcmp(ver, "1.107.0") == 0);
    CHECK(py_parse_requirement_line("  LiteLLM[proxy]==1.107.0 ; python_version>'3'", name,
                                    sizeof name, ver, sizeof ver) &&
          strcmp(ver, "1.107.0") == 0);
    CHECK(py_parse_requirement_line("foo===2.0", name, sizeof name, ver, sizeof ver));
    CHECK(!py_parse_requirement_line("litellm>=1.0", name, sizeof name, ver, sizeof ver));
    CHECK(!py_parse_requirement_line("# comment", name, sizeof name, ver, sizeof ver));
    CHECK(!py_parse_requirement_line("-r other.txt", name, sizeof name, ver, sizeof ver));
    CHECK(!py_parse_requirement_line("foo==", name, sizeof name, ver, sizeof ver));
    CHECK(!py_parse_requirement_line("foo==abc", name, sizeof name, ver, sizeof ver));

    CHECK(py_pth_line_class("/some/path\n") == 0);
    CHECK(py_pth_line_class("# import x") == 0);
    CHECK(py_pth_line_class("import os") == 1);
    CHECK(py_pth_line_class("import base64; exec(base64.b64decode('x'))") == 2);

    CHECK(adv_load(adv_path, &adv, &nerr) == 0);

    rm_tree(root);
    mk(root);
    fs_join(d1, sizeof d1, root, "venv");
    mk(d1);
    fs_join(d2, sizeof d2, d1, "Lib");
    mk(d2);
    fs_join(site, sizeof site, d2, "site-packages");
    mk(site);

    fs_join(d3, sizeof d3, site, "litellm-1.107.0.dist-info");
    mk(d3);
    puts_(d3, "METADATA", "Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n\nbody\n");
    fs_join(d3, sizeof d3, site, "requests-2.31.0.dist-info");
    mk(d3);
    puts_(d3, "METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n");
    fs_join(d3, sizeof d3, site, "litellm-1.107.0.egg-info"); /* no metadata: name fallback */
    mk(d3);
    fs_join(d3, sizeof d3, site, "good-1.0.dist-info");
    mk(d3);
    puts_(d3, "METADATA", "Name: litellm\nVersion: 1.106.2\n");
    puts_(site, "cook.pth", "import base64; exec(base64.b64decode('x'))\n");
    puts_(site, "benign.pth", "import os\n/some/path\n");

    puts_(root, "requirements.txt", "litellm==1.107.0\nrequests==2.31.0\nlitellm>=1.0\n");
    puts_(root, "poetry.lock",
          "[[package]]\nname = \"litellm\"\nversion = \"1.106.2\"\n\n"
          "[[package]]\nname = \"litellm\"\nversion = \"1.107.0\"\n");

    memset(&r, 0, sizeof r);
    CHECK(py_scan(root, &adv, &r) == 0);
    for (i = 0; i < r.n; i++) {
        if (strcmp(r.f[i].kind, "installed-package") == 0)
            inst++;
        else if (strcmp(r.f[i].kind, "locked-package") == 0)
            locked++;
        else if (strcmp(r.f[i].kind, "pth-suspicious") == 0)
            pth++;
        else if (strcmp(r.f[i].kind, "ioc-file") == 0)
            ioc++;
    }
    CHECK(inst == 2);   /* dist-info + egg-info fallback; the 1.106.2 one is clean */
    CHECK(locked == 2); /* requirements.txt line 1 + poetry.lock second block */
    CHECK(pth == 1);    /* cook.pth only */
    CHECK(ioc == 1);    /* cook.pth by file name */
    CHECK(r.n == 6);
    CHECK(r.packages_seen == 4);
    CHECK(r.pinned_seen == 4);
    CHECK(r.pth_import_seen == 1); /* benign.pth */
    py_report_free(&r);

    memset(&r, 0, sizeof r);
    CHECK(py_scan("tmp_does_not_exist", &adv, &r) == -1);
    py_report_free(&r);

    adv_free(&adv);
    snprintf(tmp, sizeof tmp, "%s", root);
    rm_tree(tmp);
}

int main(int argc, char **argv)
{
    test_lines();
    test_dir_scan();
    test_py(argc > 1 ? argv[1] : "data/advisories.txt");
    printf("%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
