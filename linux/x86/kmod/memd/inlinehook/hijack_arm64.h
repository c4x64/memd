#ifndef MEMD_HIJACK_ARM64_H
#define MEMD_HIJACK_ARM64_H

#include <linux/compiler.h>
#include <linux/types.h>

#define INSTRUCTION_SIZE (4)
#define HIJACK_INST_NUM (6)
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define HOOK_TARGET_OFFSET (0)

int init_arch(void);

__nocfi int hook_write_range(void *target, void *source, int size);

struct memd_trampoline;

/* Caller contract (enforced where possible, documented where not):
 *
 * - Double install on the same target fails closed with -EBUSY via
 *   the trampoline-list check inside memd_install_inline_hook (a
 *   second layer, the patched B/B-cond-class word check in
 *   check_target_can_hijack(), would independently refuse with
 *   -EINVAL). Concurrent installs for one target are serialized
 *   inside (g_install_lock); callers must still not interleave
 *   install/remove across threads expecting ordering.
 * - B range: the branch is PC-relative with PC = the patched word
 *   (target, offset 0), never a page base. Handlers outside
 *   [-128MB, +128MB-4] are refused with -ERANGE.
 * - Huge (block-mapped) text is not split, by final determination
 *   (no guard, none needed): the install path performs no pmd/pud
 *   walk at all — only extable-guarded per-word loads
 *   (memd_target_read32) plus the delegated write in
 *   aarch64_insn_write — so it can never reach a leaf pmd/pud entry
 *   and there is nothing to refuse on. Word loads work on RX block
 *   mappings; splitting a block would need version-unstable table
 *   layouts, so delegate-and-fail-closed replaces refusal-or-corrupt.
 *   No pmd_leaf/pud_leaf import (kept out deliberately: their
 *   generic-macro status across the 5.10+ matrix is not certain
 *   enough to spend a dependency on a check with no reachable site).
 * - *orig receives the trampoline entry (call target for the saved
 *   prologue + jump-back). Pass orig to memd_remove_inline_hook for
 *   the same target; after remove returns, orig dangles and must not
 *   be used again (a second remove is a silent no-op, never a UAF).
 *   Installing with orig == NULL is permanent: the entry stays listed
 *   but no handle exists to remove it, so prefer passing orig.
 * - Dead target (owning module unloaded before remove, or pages
 *   recycled to a new owner): remove refuses without writing. The
 *   live first word must still equal the installed branch (recomputed
 *   from the entry); an unmapped target fails the guarded read and a
 *   recycled one fails the compare, so stale prologue bytes can never
 *   corrupt the new owner. The entry is retained for a later retry.
 *   Callers must still prefer removing before the owner unloads.
 * - Every successful create pairs with exactly one free: install
 *   failure destroys the trampoline; remove frees only after the
 *   restore write succeeds (on restore failure the entry is re-linked
 *   and still reachable, so a later remove can retry).
 */
struct memd_trampoline *memd_create_trampoline(void *target, void *handler, size_t hook_size);
void memd_destroy_trampoline(struct memd_trampoline *tramp);
int memd_install_inline_hook(void *target, void *handler, void **orig);
void memd_remove_inline_hook(void *target, void *orig);

#endif // MEMD_HIJACK_ARM64_H
/* kmod/memd/inlinehook/hijack_arm64.h[∂] */
