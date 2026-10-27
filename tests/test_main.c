/* Unit tests: version compare + advisory parser. No network. Usage: test_main [advisories.txt] */
#include <stdio.h>
#include <string.h>

#include "../src/advisory.h"
#include "../src/version.h"

static int g_run, g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_run++;                                                             \
        if (!(cond)) {                                                       \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

static int cmp(const char *a, const char *b)
{
    ver_t x, y;
    if (ver_parse(a, &x) != 0 || ver_parse(b, &y) != 0)
        return 99;
    return ver_cmp(&x, &y);
}

static void test_version(void)
{
    ver_t v;

    CHECK(cmp("1.2.3", "1.2.3") == 0);
    CHECK(cmp("1.2.3", "1.2.4") < 0);
    CHECK(cmp("1.10.0", "1.9.9") > 0);          /* numeric, not string compare */
    CHECK(cmp("1.2", "1.2.0") == 0);            /* missing parts are 0 */
    CHECK(cmp("v8.2.35", "8.2.35") == 0);       /* leading v */
    CHECK(cmp("18.11.13", "19.0") < 0);
    CHECK(cmp("1.0.0rc1", "1.0.0") < 0);        /* pre-release below release */
    CHECK(cmp("1.0.0-beta2", "1.0.0-rc1") == 0); /* both pre, same numbers */
    CHECK(cmp("8.2.35-1ubuntu2", "8.2.35") == 0); /* distro suffix ignored */
    CHECK(cmp("1.31.2", "1.31.10") < 0);
    CHECK(cmp("  2.0", "2.0.0") == 0);

    CHECK(ver_parse("", &v) == -1);
    CHECK(ver_parse("abc", &v) == -1);
    CHECK(ver_parse(NULL, &v) == -1);
    CHECK(ver_parse("1.2.3.4.5.6.7.8.9", &v) == -1); /* too many parts */
    CHECK(ver_parse("99999999999999999999999999", &v) == -1); /* overflow */
    CHECK(ver_parse("1.2.", &v) == 0 && v.count == 2);
}

static int any_match(const adv_list *l, const char *module, const char *product, const char *ver)
{
    size_t i;
    for (i = 0; i < l->n; i++) {
        const adv_entry *e = &l->e[i];
        if (strcmp(e->module, module) == 0 && strcmp(e->product, product) == 0 &&
            adv_match(e, ver) == 1)
            return 1;
    }
    return 0;
}

static void test_real_data(const char *path)
{
    adv_list l = {0};
    int nerr = -1;

    CHECK(adv_load(path, &l, &nerr) == 0);
    CHECK(nerr == 0);
    CHECK(l.n >= 8);

    /* PHP2Shell */
    CHECK(any_match(&l, "http", "php", "8.2.34"));
    CHECK(!any_match(&l, "http", "php", "8.2.35"));
    CHECK(!any_match(&l, "http", "php", "8.2.40"));
    CHECK(any_match(&l, "http", "php", "8.3.35"));
    CHECK(!any_match(&l, "http", "php", "8.3.36"));
    CHECK(any_match(&l, "http", "php", "8.4.26"));
    CHECK(!any_match(&l, "http", "php", "8.4.27"));
    CHECK(any_match(&l, "http", "php", "8.5.11"));
    CHECK(!any_match(&l, "http", "php", "8.5.12"));
    CHECK(any_match(&l, "http", "php", "7.4.33"));
    CHECK(any_match(&l, "http", "php", "5.4.0"));
    CHECK(any_match(&l, "http", "php", "8.1.30"));

    /* GitLab */
    CHECK(any_match(&l, "http", "gitlab", "7.0"));
    CHECK(any_match(&l, "http", "gitlab", "18.11.12"));
    CHECK(!any_match(&l, "http", "gitlab", "18.11.13"));
    CHECK(any_match(&l, "http", "gitlab", "19.0.9"));
    CHECK(!any_match(&l, "http", "gitlab", "19.0.10"));
    CHECK(any_match(&l, "http", "gitlab", "19.5.0"));
    CHECK(!any_match(&l, "http", "gitlab", "19.5.1"));
    CHECK(!any_match(&l, "http", "gitlab", "19.3.6"));
    CHECK(any_match(&l, "http", "gitlab", "19.3.5"));

    /* Node.js */
    CHECK(any_match(&l, "http", "node", "20.11.0"));
    CHECK(any_match(&l, "http", "node", "22.23.3"));
    CHECK(!any_match(&l, "http", "node", "22.23.4"));
    CHECK(!any_match(&l, "http", "node", "22.24.0"));
    CHECK(any_match(&l, "http", "node", "23.5.0"));
    CHECK(any_match(&l, "http", "node", "24.22.0"));
    CHECK(!any_match(&l, "http", "node", "24.22.1"));
    CHECK(any_match(&l, "http", "node", "26.12.0"));
    CHECK(!any_match(&l, "http", "node", "26.12.1"));

    /* LiteLLM */
    CHECK(any_match(&l, "py", "litellm", "1.107.0"));
    CHECK(!any_match(&l, "py", "litellm", "1.106.2"));
    CHECK(!any_match(&l, "py", "litellm", "1.107.1"));

    /* nginx */
    CHECK(any_match(&l, "http", "nginx", "1.30.3"));
    CHECK(!any_match(&l, "http", "nginx", "1.30.4"));
    CHECK(any_match(&l, "http", "nginx", "1.31.2"));
    CHECK(!any_match(&l, "http", "nginx", "1.31.3"));

    /* non-version rules never match; unparsable version reports -1 */
    CHECK(!any_match(&l, "tls", "issuer-name", "1.0"));
    CHECK(!any_match(&l, "pyioc", "litellm", "1.0"));
    CHECK(l.n > 0 && adv_match(&l.e[0], "not-a-version") == -1);

    adv_free(&l);
    CHECK(l.e == NULL && l.n == 0);
}

static void test_parser(void)
{
    const char *tmp = "test_tmp_adv.txt";
    adv_list l = {0};
    adv_entry e;
    char err[64];
    int nerr = -1;
    FILE *f;

    CHECK(adv_parse_line("# comment", 1, &e, err, sizeof err) == 1);
    CHECK(adv_parse_line("   ", 1, &e, err, sizeof err) == 1);
    CHECK(adv_parse_line("a|b|*|f|u", 1, &e, err, sizeof err) == 0 && e.any == 1);
    CHECK(adv_parse_line("a|b|-|f|u", 1, &e, err, sizeof err) == 0 && e.any == 0 && e.n_alts == 0);
    CHECK(adv_parse_line("a|b|>=1.0 <2.0; ==3.1|f|u", 1, &e, err, sizeof err) == 0 && e.n_alts == 2);
    CHECK(adv_match(&e, "1.5") == 1 && adv_match(&e, "2.0") == 0 && adv_match(&e, "3.1.0") == 1);
    CHECK(adv_match(&e, "3.1.1") == 0);
    CHECK(adv_parse_line("a|b|<1.0|f", 1, &e, err, sizeof err) == -1);        /* 4 fields */
    CHECK(adv_parse_line("a|b|<1.0|f|u|extra", 1, &e, err, sizeof err) == -1); /* 6 fields */
    CHECK(adv_parse_line("a|b|~1.0|f|u", 1, &e, err, sizeof err) == -1);      /* bad op */
    CHECK(adv_parse_line("a|b|<x|f|u", 1, &e, err, sizeof err) == -1);        /* bad version */
    CHECK(adv_parse_line("a|b|<1.0;|f|u", 1, &e, err, sizeof err) == -1);     /* empty alt */
    CHECK(adv_parse_line("||<1.0|f|u", 1, &e, err, sizeof err) == -1);        /* empty module */
    CHECK(adv_parse_line("a|b|<1 <2 <3 <4 <5|f|u", 1, &e, err, sizeof err) == -1); /* >4 constraints */

    f = fopen(tmp, "w");
    CHECK(f != NULL);
    if (f != NULL) {
        fputs("# header\n\nok|p|<2.0|1.0|u\nbroken line\nok|q|*|x|u\nbad|r|<z|x|u\n", f);
        fclose(f);
        CHECK(adv_load(tmp, &l, &nerr) == 0);
        CHECK(l.n == 2 && nerr == 2);
        adv_free(&l);
        remove(tmp);
    }
    CHECK(adv_load("does_not_exist.txt", &l, &nerr) == -1);
}

int main(int argc, char **argv)
{
    test_version();
    test_parser();
    test_real_data(argc > 1 ? argv[1] : "data/advisories.txt");
    printf("%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
