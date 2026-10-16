#ifndef ANDROID_MEMD_HIJACK_ARM64_H
#define ANDROID_MEMD_HIJACK_ARM64_H

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
 * - Double install on the same target fails closed with -EINVAL: the
 *   first install leaves a B/B-cond-class word at target, which
 *   check_target_can_hijack() refuses. Concurrent installs for one
 *   target are serialized inside (g_install_lock); callers must still
 *   not interleave install/remove across threads expecting ordering.
 * - B range: the branch is PC-relative with PC = the patched word
 *   (target, offset 0), never a page base. Handlers outside
 *   [-128MB, +128MB-4] are refused with -ERANGE.
 * - Huge (block-mapped) text is not split: target reads are
 *   extable-guarded per word (XO/unmapped edges fail closed) and the
 *   write stays owned by aarch64_insn_write. Splitting a block would
 *   need version-unstable table layouts, so refusal-or-corrupt is
 *   replaced by delegate-and-fail-closed.
 * - *orig receives the trampoline entry (call target for the saved
 *   prologue + jump-back). Pass orig to memd_remove_inline_hook for
 *   the same target; after remove returns, orig dangles and must not
 *   be used again (a second remove is a silent no-op, never a UAF).
 *   Installing with orig == NULL is permanent: the entry stays listed
 *   but no handle exists to remove it, so prefer passing orig.
 * - Every successful create pairs with exactly one free: install
 *   failure destroys the trampoline; remove frees only after the
 *   restore write succeeds (on restore failure the entry is re-linked
 *   and still reachable, so a later remove can retry).
 */
struct memd_trampoline *memd_create_trampoline(void *target, void *handler, size_t hook_size);
void memd_destroy_trampoline(struct memd_trampoline *tramp);
int memd_install_inline_hook(void *target, void *handler, void **orig);
void memd_remove_inline_hook(void *target, void *orig);

#endif // ANDROID_MEMD_HIJACK_ARM64_H
/* kmod/memd/inlinehook/hijack_arm64.h[∂] */
