/* Accuracy check of the security data against WordPress.org's own verdicts: every WordPress
   version WordPress.org lists as "latest" should have no known hole in our data (otherwise we
   would raise false alarms), and every "insecure" one should have at least one (otherwise the
   report falls back to "WordPress.org lists it as insecure" without naming the hole).
   Usage: accuracy_data [data/vulndb.txt]   Prints the disagreements; exit 1 if any "latest"
   version would get a hole. */
#include <stdio.h>
#include <string.h>

#include "../src/vulndb.h"

int main(int argc, char **argv)
{
    vulndb db;
    size_t i;
    int latest = 0, latest_bad = 0, insecure = 0, insecure_none = 0, outdated = 0, outdated_holes = 0;

    memset(&db, 0, sizeof db);
    if (vdb_load(&db, argc > 1 ? argv[1] : "data/vulndb.txt") != 0) {
        fprintf(stderr, "cannot read the security data\n");
        return 2;
    }
    for (i = 0; i < db.n; i++) {
        const char *l = db.line[i];
        char ver[40], status[16];
        tech_item t;
        vdb_assess a;
        const char *p;
        size_t k;

        if (strncmp(l, "S\twordpress\t", 12) != 0)
            continue;
        p = l + 12;
        for (k = 0; p[k] != '\0' && p[k] != '\t' && k + 1 < sizeof ver; k++)
            ver[k] = p[k];
        ver[k] = '\0';
        snprintf(status, sizeof status, "%s", p[k] == '\t' ? p + k + 1 : "");
        memset(&t, 0, sizeof t);
        snprintf(t.product, sizeof t.product, "wordpress");
        snprintf(t.version, sizeof t.version, "%s", ver);
        t.conf = TECH_EXACT;
        t.flags = TECH_SITE;
        vdb_assess_item(&db, &t, &a);
        if (strcmp(status, "latest") == 0) {
            latest++;
            if (a.nhole > 0) {
                latest_bad++;
                printf("FALSE ALARM? %s is WordPress.org's latest but matches %lu hole(s), first %s (%s)\n", ver,
                       a.nhole, a.top[0].id, vdb_sev_name(a.top[0].sev));
            }
        } else if (strcmp(status, "insecure") == 0) {
            insecure++;
            if (a.nhole == 0) {
                insecure_none++;
                if (insecure_none <= 15)
                    printf("NO NAMED HOLE: %s is insecure per WordPress.org; report falls back to its verdict\n", ver);
            }
        } else if (strcmp(status, "outdated") == 0) {
            outdated++;
            outdated_holes += a.nhole > 0;
            if (a.nhole > 0)
                printf("OUTDATED WITH HOLES: %s matches %lu, e.g. %s (%s, fixed %s)\n", ver, a.nhole, a.top[0].id,
                       vdb_sev_name(a.top[0].sev), a.top[0].fixed[0] ? a.top[0].fixed : "-");
        }
    }
    printf("latest: %d versions, %d with holes | insecure: %d versions, %d without a named hole | "
           "outdated: %d versions, %d with holes\n",
           latest, latest_bad, insecure, insecure_none, outdated, outdated_holes);
    vdb_free(&db);
    return latest_bad > 0;
}
