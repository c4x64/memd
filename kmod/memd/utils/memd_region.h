#ifndef MEMD_REGION_H
#define MEMD_REGION_H

#include <linux/types.h>

/* PTE-mapped unsafe regions, tracked per session pid so socket release
 * can drop them. Split from the signal-hook unit (upstream keeps this
 * beside its kretprobe machinery; we never install hooks, so the list
 * lives here alone). Locking + list + allocator match upstream exactly.
 */
int memd_region_init(void);
void memd_region_cleanup(void);
int memd_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page);
int memd_del_unsafe_region(pid_t pid);

/* Enhanced API */
int memd_find_region(uintptr_t addr, void *out);
int memd_region_iterate(int (*callback)(void *area, void *data), void *data);
int memd_get_region_stats(u64 *total_pages, u32 *region_count);
int memd_set_session_quota(pid_t session, u32 max_regions);

struct unsafe_region_area {
    u64 addr;
    u32 nums_page;
    uid_t uid;
    pid_t session_pid;
    u32 prot;
    u32 flags;
    u64 start_time;
    u64 access_count;
};

#endif /* MEMD_REGION_H */
