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
 *
 * Caller contract: install/uninstall are idempotent (repeat install
 * returns 0 via hook_active; repeat uninstall returns 0). Concurrent
 * install vs uninstall are serialized by the syshook mutex. On a
 * failed uninstall the bookkeeping (and hook_active) is retained, so
 * a later uninstall retries with the saved orig pointers instead of
 * leaking a still-hooked table.
 */
int memd_hide_install(void);
int memd_hide_uninstall(void);
int memd_hide_active(void);

#endif /* MEMD_SYSHOOK_H */
/* kmod/memd/inlinehook/memd_syshook.h[∂] */
