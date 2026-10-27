#ifndef FSUTIL_H
#define FSUTIL_H

#include <stddef.h>

/* dst = a + '/' + b (no doubled separator). 0 ok, -1 if it does not fit. */
int fs_join(char *dst, size_t n, const char *a, const char *b);
int fs_is_dir(const char *path);
/* Regular file? Stores its size in *size when size != NULL. */
int fs_is_file(const char *path, long long *size);
/* Absolute path of in; 0 ok, -1 failure. */
int fs_abs_path(const char *in, char *out, size_t n);
/* Part after the last '/' or '\\'. */
const char *fs_basename(const char *path);
/* Case-insensitive ASCII suffix test. */
int fs_has_suffix_ci(const char *s, const char *suffix);

#endif
