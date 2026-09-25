#ifndef WUWA_REGION_H
#define WUWA_REGION_H

#include <linux/types.h>

/* PTE-mapped unsafe regions, tracked per session pid so socket release
 * can drop them. Split from the signal-hook unit (upstream keeps this
 * beside its kretprobe machinery; we never install hooks, so the list
 * lives here alone). Locking + list + allocator match upstream exactly.
 */
int wuwa_region_init(void);
void wuwa_region_cleanup(void);
int wuwa_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page);
int wuwa_del_unsafe_region(pid_t pid);

#endif /* WUWA_REGION_H */
