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
 *
 * Owner-modification policy: uninstall restores the saved orig only
 * when the live slot still points at our replacement (or already
 * equals the saved orig). If the owner repointed the slot after
 * install, uninstall refuses with -EBUSY and keeps the bookkeeping:
 * restoring the stale saved pointer would clobber the owner's live
 * entry, while adopting the modified value would republish a pointer
 * we did not author (and cannot vouch for). Same rule at install:
 * the slot must still hold the snapshotted orig, else -EBUSY.
 *
 * Owner-divergence recovery: when the owner permanently repoints a
 * slot (live never returns to our replacement or the saved orig),
 * uninstall keeps refusing with -EBUSY and filtering for that table
 * stays silently lost (never a crash). Install-while-active stays a
 * no-op on purpose, so no repair attempt can cut a stacked
 * third-party hook out of the chain. Recovery is rmmod + insmod +
 * install, which re-snapshots the owner's new entry as orig; rmmod
 * itself logs the -EBUSY and unloads (safe while nothing chains back
 * into us, which no callee can fence).
 *
 * Scoping rule: hidden entries are keyed (pid, active pid-ns) at
 * add/del, and the filldir filter matches against the READER's
 * active ns (task_active_pid_ns(current), borrowed under RCU: no
 * ref taken, no sleep, valid across the set's spinlock because the
 * RCU section is held and current pins its own ns). A container
 * reader therefore matches container entries; an init-ns reader
 * yields &init_pid_ns, identical to the old hardcoded check (no
 * regression for the init-ns case). An unresolvable (NULL) reader
 * ns fails closed at the call site (the entry is hidden).
 *
 * Uninstall write robustness (fail-closed at rmmod): install proved
 * the table writable, so a restore write/readback that fails anyway
 * means something changed under us — a transient extable fault or
 * stale TLB (a retry helps), an owner racing the slot (re-classified
 * as -EBUSY, safe: the slot no longer points at us), or a hostile
 * environment now trapping descriptor/entry stores (hypervisor/RKP
 * write-protecting page tables after install) or emulating them
 * (store "succeeds" yet readback still shows our pointer). The write
 * path already retries its entry store internally; uninstall adds a
 * bounded outer retry (3 write+readback attempts, no sleeps, no
 * unbounded loops) and re-reads the live slot after every failure so
 * a raced slot reports -EBUSY instead of -EIO.
 *
 * Residual risk, stated plainly: __exit returns void and cannot fail
 * or refuse rmmod — refusing would mean spinning in __exit, which
 * strands the unloader rather than the module, and pinning the
 * module is impossible once __exit runs (the text is freed on return
 * regardless). So a persistent -EIO means the table still points at
 * memd_iterate_shared when our text is freed: the next /proc readdir
 * through that table jumps into freed memory and panics. No
 * in-kernel fail-closed move remains at that point (no safe stub
 * exists to point the slot at: NULL faults, and any borrowed kernel
 * iterate would be a pointer we did not author and cannot verify on
 * obscured kernels). The defense is therefore: bounded retry, kept
 * bookkeeping on failure so a later pre-unload uninstall can retry,
 * and an EMERG log at exit naming the consequence (avoid /proc
 * listings, reboot). -EBUSY at exit, by contrast, is safe to unload:
 * the slot points at the owner's entry, not at us.
 */
int memd_hide_install(void);
int memd_hide_uninstall(void);
int memd_hide_active(void);

#endif /* MEMD_SYSHOOK_H */
/* kmod/memd/inlinehook/memd_syshook.h[∂] */
