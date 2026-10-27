#ifndef GITINDEX_H
#define GITINDEX_H

/* Is the file tracked by git? Reads the repository's .git/index directly (no git process).
   Returns 1 tracked, 0 inside a repo but not tracked, -1 index unreadable or unsupported
   (index v4), -2 not inside a git repo. */
int gitidx_tracked(const char *file);

#endif
