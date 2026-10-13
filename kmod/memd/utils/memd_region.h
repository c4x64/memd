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

/* Full struct lives in memd_region.c (single definition — a stale
 * member-less duplicate here broke every matrix build with
 * "redefinition", and the header copy then shadowed rb_node/list).
 * No external user touches fields (find/iterate use void *). */
struct unsafe_region_area;

#endif /* MEMD_REGION_H */
