#ifndef VULNDB_H
#define VULNDB_H

#include <stddef.h>

#include "techdetect.h"

/* Local security data, read from two tab-separated text files:
     vulndb.txt  (app/VulnData.cs, refreshed online)
       G  generated-utc  count
       V  product  id  severity  score  kev(0/1)  ranges  fixed  url  summary
          ranges: alternatives split by ';', each a ','-list of >=x >x <=x <x =x  (e.g. ">=15.0,<15.5.7")
       S  wordpress  version  latest|outdated|insecure        (WordPress.org's own table)
       E  product  cycle  eol  extended  latest                (endoflife.date; eol = date|yes|no|-)
     os_map.txt  (scripts/Make-OsMap.ps1)
       M  product  upstream-version  distro  release
   No network: lookups only. */

enum { VDB_SEV_UNKNOWN = 0, VDB_SEV_LOW, VDB_SEV_MEDIUM, VDB_SEV_HIGH, VDB_SEV_CRITICAL };

typedef struct {
    char *text;   /* both files, owned; lines end in NUL */
    size_t len;
    char **line;  /* pointers into text: V, S, E and M lines only */
    size_t n;
    char generated[24]; /* "2026-11-16" or "" */
    unsigned long nvuln;
} vulndb;

/* Append a file. 0 ok, -1 unreadable. Call vdb_free when done (also after a failure). */
int vdb_load(vulndb *db, const char *path);
/* Same from memory (tests). */
int vdb_load_text(vulndb *db, const char *text);
void vdb_free(vulndb *db);

/* 1 when version satisfies the range text, 0 when not, -1 when version is not a version. When it
   matches and the alternative has a "<x" bound, x is copied to fixed (else fixed is ""). */
int vdb_range_match(const char *ranges, const char *version, char *fixed, size_t fixed_len);

/* "YYYY-MM-DD" used for end-of-life decisions; NULL = today (UTC). For tests. */
void vdb_set_today(const char *iso);
const char *vdb_today(void);

#define VDB_TOP 4

typedef struct {
    char id[40];
    int sev;
    int kev;
    char fixed[40];
    char url[160];
    char summary[160];
} vdb_hit;

/* What the data says about one detected product. */
typedef struct {
    int known;           /* the security data covers this product */
    unsigned long nhole; /* matching known holes */
    int worst;           /* VDB_SEV_* of the worst one */
    int kev;             /* at least one is being used by attackers (CISA KEV) */
    unsigned long nkev;  /* how many */
    vdb_hit top[VDB_TOP];/* worst first, attacker-used first */
    int ntop;
    char fix_to[40];     /* lowest version that fixes every matching hole in this branch, "" if none */
    char wp_status[12];  /* WordPress.org: latest, outdated, insecure, or "" */
    /* end of life of the product's own release line */
    char cycle[40];
    int eol;             /* 1 ended, 0 supported, -1 unknown */
    char eol_date[24];
    char newest[40];     /* newest version in that line, or of the product */
    /* the operating system it runs on (server software with a distribution tag, IIS) */
    char os_name[40];    /* "Ubuntu 20.04", "Ubuntu 20.04 or 22.04", "Windows Server 2012 R2" */
    int os_eol;          /* 1 ended, 0 supported, -1 unknown */
    int os_ext;          /* 1 when only paid extended support still covers it */
    char os_eol_date[24];
    char os_ext_date[24];
} vdb_assess;

void vdb_assess_item(const vulndb *db, const tech_item *t, vdb_assess *a);

const char *vdb_sev_name(int sev); /* "critical" ... "unknown" */

#endif
