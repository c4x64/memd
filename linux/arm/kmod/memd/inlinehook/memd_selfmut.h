#ifndef MEMD_SELFMUT_H
#define MEMD_SELFMUT_H

#include <linux/types.h>
#include <linux/kernel.h>

/* Self-mutation framework: patch the module's own .text at runtime.
 * Uses the .init.text window on hardened kernels (CONFIG_STRICT_MODULE_RWX)
 * and falls back to direct PTE manipulation on legacy kernels.
 * Every patch is verified before init returns. */

/* Maximum number of tracked patches for cleanup on unload. */
#define MEMD_SELFMUT_MAX_PATCHES 64

/* Patch types. */
#define MEMD_PATCH_BRANCH  0  /* arm64 B instruction */
#define MEMD_PATCH_NOP     1  /* arm64 NOP */
#define MEMD_PATCH_MOV     2  /* arm64 MOVZ/MOVK */
#define MEMD_PATCH_RAW     3  /* raw 4-byte instruction */

struct memd_patch_record {
    void     *target;       /* address patched */
    u32       original;     /* original instruction */
    u32       replacement;  /* replacement instruction */
    int       type;         /* MEMD_PATCH_* */
    int       verified;     /* 1 if read-back confirmed */
    int       active;       /* 1 if currently applied */
};

/* Initialize the self-mutation framework. Must be called from .init.text
 * or module_init before any patching. Returns 0 on success, negative errno. */
int memd_selfmut_init(void);

/* Patch a 4-byte instruction at target with a raw replacement.
 * Handles page permission flip, icache flush, and verification.
 * Returns 0 on success, negative errno on failure. */
int memd_selfmut_patch_raw(void *target, u32 replacement);

/* Patch target to branch to destination (arm64 B instruction). */
int memd_selfmut_patch_branch(void *target, void *destination);

/* Patch target to NOP. */
int memd_selfmut_patch_nop(void *target);

/* Patch target with MOVZ (16-bit immediate, shift 0/16/32/48). */
int memd_selfmut_patch_movz(void *target, u16 imm, int shift);

/* Revert a single patch to its original instruction. */
int memd_selfmut_revert(void *target);

/* Revert all active patches. Called from module_exit. */
void memd_selfmut_revert_all(void);

/* Query whether a patch is active at the given address. */
int memd_selfmut_is_patched(void *target);

/* Get the number of active patches. */
int memd_selfmut_patch_count(void);

/* Verify all patches by reading back instructions. Returns 0 if all
 * verified, negative count of mismatches. */
int memd_selfmut_verify_all(void);

/* Get the kernel's KASLR slide (0 if not KASLR). */
unsigned long memd_selfmut_kaslr_slide(void);

/* Translate a compile-time address to runtime address. */
void *memd_selfmut_runtime_addr(void *compile_addr);

/* Flush instruction cache for a range (ARM64). */
void memd_selfmut_icache_flush(void *addr, size_t len);

/* Set page permissions RW/RO for a range. Returns 0 on success. */
int memd_selfmut_make_rw(void *addr, size_t len);
int memd_selfmut_make_ro(void *addr, size_t len);

/* Check if kernel has CONFIG_STRICT_MODULE_RWX. */
int memd_selfmut_strict_rwx(void);

/* Get framework status string for diagnostics. */
const char *memd_selfmut_status(void);

/* ---- Extended patch types ---- */

/* Patch type: replace function with a trampoline to another function. */
int memd_selfmut_trampoline(void *target, void *destination, void **tramp_out);

/* Patch type: NOP a range of instructions. */
int memd_selfmut_nop_range(void *start, size_t len);

/* Patch type: write a custom 4-byte instruction. */
int memd_selfmut_write_insn(void *target, u32 insn);

/* ---- Patch chain management ---- */
struct memd_patch_chain;

int memd_selfmut_chain_init(struct memd_patch_chain *chain);
int memd_selfmut_chain_add(struct memd_patch_chain *chain, void *target,
                           u32 replacement);
int memd_selfmut_chain_apply(struct memd_patch_chain *chain);
int memd_selfmut_chain_revert(struct memd_patch_chain *chain);

/* ---- Statistics ---- */
struct memd_selfmut_stats {
    int total_patches;
    int active_patches;
    int verified_patches;
    int reverted_patches;
    unsigned long kaslr_slide;
    int strict_rwx;
};

void memd_selfmut_get_stats(struct memd_selfmut_stats *stats);

/* ---- Diagnostics ---- */
void memd_selfmut_dump_patches(void);

/* ---- Init-window patching (for .init.text usage) ---- */
int memd_selfmut_patch_init(void *target, u32 replacement);

/* ---- ARM64 instruction encoding ---- */
u32 memd_encode_branch(s64 offset);
u32 memd_encode_branch_link(s64 offset);
u32 memd_encode_nop(void);
u32 memd_encode_ret(void);

/* ---- Batch operations ---- */
int memd_selfmut_patch_batch(void **targets, u32 *replacements, int count);

#endif /* MEMD_SELFMUT_H */
/* kmod/memd/inlinehook/memd_selfmut.h[∂] */