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

#endif /* MEMD_REGION_H */
