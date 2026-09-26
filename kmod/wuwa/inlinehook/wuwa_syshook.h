#ifndef WUWA_SYSHOOK_H
#define WUWA_SYSHOOK_H

/* getdents64 pointer-swap hiding (no kernel-text writes, ever).
 *
 * Install is explicit via ioctl (userspace gates on CFI status first:
 * on enforcing kernels an indirect call through the table would trap,
 * so install is refused there by policy, not attempted). Resolution is
 * fully runtime: the sys_call_table is located by scanning for its
 * pointer-run signature + prologue validation, no kallsyms, no per-build
 * data. Anything unresolved -> explicit NO-GO, feature stays inactive,
 * the module still serves R/W (hiding is never load-bearing).
 *
 * rmmod always restores the original entry first (dangling table entry
 * after unload would panic the next getdents64).
 */
int wuwa_hide_install(void);
int wuwa_hide_uninstall(void);
int wuwa_hide_active(void);

#endif /* WUWA_SYSHOOK_H */
