#include "hijack_arm64.h"

#include "memd_common.h"
#include "memd_utils.h"

#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

int (*aarch64_insn_write_ptr)(void *, u32) = NULL;
void (*flush_icache_range_ptr)(unsigned long, unsigned long) = NULL;

#define INST_UNKNOWN     0
#define INST_B           1
#define INST_BL          2
#define INST_B_COND      3
#define INST_ADR         4
#define INST_ADRP        5
#define INST_CBZ_CBNZ    6
#define INST_TBZ_TBNZ    7
#define INST_LDR         8
#define INST_LDRV        9
#define INST_LDRSW       10
#define INST_LDR_LIT     26
#define INST_STR_LIT     11
#define INST_LDRSTR_REG  27
#define INST_MRS         12
#define INST_MSR         13
#define INST_RET         14
#define INST_BLR         15
#define INST_BR          16
#define INST_MOV         17
#define INST_ADD_SUB_IMM 18
#define INST_ADD_SUB_REG 19
#define INST_ADD_IMM     20
#define INST_SUB_IMM     21
#define INST_MOVZ        22
#define INST_MOVN        23
#define INST_MOVK        24
#define INST_CSEL        25

struct memd_trampoline {
    void *code;
    size_t size;
    void *target;
    void *handler;
    struct list_head list;
};

static LIST_HEAD(g_trampoline_list);
static DEFINE_SPINLOCK(g_trampoline_lock);

/* Serializes install/uninstall for the same target. Check-then-patch
 * must be atomic: two concurrent installs would both pass the
 * can-hijack test, both write the branch, and orphan one trampoline
 * (its jump-back still valid, but remove-by-target frees only the
 * first match). Sleepable lock: create/vmalloc and insn writes sleep,
 * so a spinlock would be wrong here. Nest order is always
 * g_install_lock -> g_trampoline_lock. */
static DEFINE_MUTEX(g_install_lock);

/* Guarded single-word load from a hook target. Plain dereference faults
 * (oops) on execute-only or unmapped text; the extable guard turns it
 * into -EFAULT. Version-robust by construction: no page-table layouts,
 * only the fault handler. Block (huge-page) text is NOT refused here:
 * word loads work on RX block mappings, and the write itself stays
 * owned by aarch64_insn_write (splitting a block would need
 * version-unstable table surgery + per-kernel BBM sequences, so a
 * refusal policy would just disable hooks on block-mapped kernels
 * while the arch helper already handles them). */
static int memd_target_read32(void *target, unsigned long offset, u32 *out)
 {
    unsigned int v;

    if (!target || !out)
        return -EINVAL;
    if (memd_safe_read32((const char *)target + offset, &v))
        return -EFAULT;
    *out = (u32)v;
    return 0;
}

/* Best-effort resolution: insn-write/icache helpers exist only where the
 * kernel lets kallsyms resolution succeed. Always returns 0 — callers
 * (hook_write_range, cfi_bypass) fail closed per-op when unresolved, so
 * plain memory R/W works on kernels that export nothing extra. */
int init_arch(void)
 {
    aarch64_insn_write_ptr = (void *)kallsyms_lookup_name_ex("aarch64_insn_write");
    flush_icache_range_ptr = (void *)kallsyms_lookup_name_ex("caches_clean_inval_pou");
    if (!flush_icache_range_ptr) {
        flush_icache_range_ptr = (void *)kallsyms_lookup_name_ex("__flush_icache_range");
    }
    if (!aarch64_insn_write_ptr || !flush_icache_range_ptr)
        memd_err("insn-write helpers unresolved (CFI path unavailable)\n");
    return 0;
}

__nocfi int hook_write_range(void *target, void *source, int size)
  {
     int ret = 0, i;

     if (!aarch64_insn_write_ptr || !flush_icache_range_ptr)
         return -ENODEV;
     for (i = 0; i < size; i = i + INSTRUCTION_SIZE) {
         ret = aarch64_insn_write_ptr((char *)target + i, *(u32 *)((char *)source + i));
        if (ret) {
            goto out;
        }
    }
    flush_icache_range_ptr((unsigned long)target, (unsigned long)target + size);

    out:
        return ret;
}

static int get_instruction_type(uint32_t instruction)
 {
    if ((instruction & 0xfc000000) == 0x14000000) return INST_B;
    if ((instruction & 0xfc000000) == 0x94000000) return INST_BL;
    if ((instruction & 0xff000000) == 0x54000000) return INST_B_COND;
    if ((instruction & 0x9f000000) == 0x10000000) return INST_ADR;
    if ((instruction & 0x9f000000) == 0x90000000) return INST_ADRP;
    if ((instruction & 0x7e000000) == 0x34000000) return INST_CBZ_CBNZ;
    if ((instruction & 0x7e000000) == 0x36000000) return INST_TBZ_TBNZ;
    if ((instruction & 0xbf000000) == 0x18000000) return INST_LDR;
    if ((instruction & 0x3f000000) == 0x1c000000) return INST_LDRV;
    if ((instruction & 0xff000000) == 0x98000000) return INST_LDRSW;
    if ((instruction & 0xfc000000) == 0x58000000) return INST_LDR_LIT;
    if ((instruction & 0xfc000000) == 0x5c000000) return INST_STR_LIT;
    if ((instruction & 0xffe00000) == 0xf9000000) return INST_LDRSTR_REG;
    if ((instruction & 0xfffff000) == 0xd5032000) return INST_MRS;
    if ((instruction & 0xfffff000) == 0xd5132000) return INST_MSR;
    if ((instruction & 0xfffffc00) == 0xd65f0000) return INST_RET;
    if ((instruction & 0xfffffc00) == 0xd63f0000) return INST_BLR;
    if ((instruction & 0xfc000000) == 0xd4000000) return INST_BR;
    if ((instruction & 0xfe000000) == 0xaa000000) return INST_MOV;
    if ((instruction & 0xffe0fc00) == 0x8b000000) return INST_ADD_SUB_IMM;
    if ((instruction & 0xffe0fc00) == 0xcb000000) return INST_ADD_SUB_REG;
    if ((instruction & 0xfff0fc00) == 0x91000000) return INST_ADD_IMM;
    if ((instruction & 0xfff0fc00) == 0xd1000000) return INST_SUB_IMM;
    if ((instruction & 0xff800000) == 0xd2800000) return INST_MOVZ;
    if ((instruction & 0xff800000) == 0x92800000) return INST_MOVN;
    if ((instruction & 0xff800000) == 0xf2800000) return INST_MOVK;
    if ((instruction & 0xfffffc00) == 0x1ac00000) return INST_CSEL;
    return INST_UNKNOWN;
}

static bool check_instruction_can_hijack(uint32_t instruction)
 {
    bool ret = true;
    int type = get_instruction_type(instruction);

    switch (type) {
        case INST_ADR:
        case INST_ADRP:
        case INST_B:
        case INST_BL:
        case INST_B_COND:
        case INST_CBZ_CBNZ:
        case INST_TBZ_TBNZ:
        case INST_LDR:
        case INST_LDRV:
        case INST_LDRSW:
        case INST_LDR_LIT:
        case INST_STR_LIT:
        case INST_MRS:
        case INST_MSR:
        case INST_RET:
        case INST_BLR:
        case INST_BR:
            ret = false;
            break;
        default:
            ret = true;
            break;
    }

    if (!ret) {
        memd_warn("instruction %x (type %d) cannot be hijacked!\n", instruction, type);
    }
    return ret;
}

static int calculate_trampoline_size(void *target, size_t hook_size, size_t *out)
  {
     size_t i;
     size_t size;
     int type;
     u32 insn;
     int ret;

     if (!target || !out)
         return -EINVAL;

     /* Copied prologue plus the fixed jump-back epilogue (MOVZ + 3x
      * MOVK + BR = 20 bytes, full 64-bit, no literal pool). The old
      * code omitted the epilogue and overflowed the 32-byte
      * allocation by 8 bytes on every hook. */
     size = hook_size + 20;
     for (i = 0; i < hook_size; i += INSTRUCTION_SIZE) {
         ret = memd_target_read32(target, (unsigned long)i, &insn);
         if (ret)
             return ret;
         type = get_instruction_type((uint32_t)insn);

        if (type == INST_B || type == INST_BL || type == INST_B_COND ||
            type == INST_CBZ_CBNZ || type == INST_TBZ_TBNZ ||
            type == INST_ADR || type == INST_ADRP) {
            size += 8;
        }
    }

    *out = ALIGN(size, 16);
    return 0;
}

struct memd_trampoline *memd_create_trampoline(void *target, void *handler, size_t hook_size)
 {
    struct memd_trampoline *tramp;
    void *tramp_code;
    size_t tramp_size = 0;
    size_t i;
    u32 insn;
    int ret;

    if (!target || !hook_size)
        return NULL;
    ret = calculate_trampoline_size(target, hook_size, &tramp_size);
    if (ret)
        return NULL;

    tramp = kzalloc(sizeof(*tramp), GFP_KERNEL);
    if (!tramp)
        return NULL;

    tramp_code = memd_vmalloc_exec(tramp_size);
    if (!tramp_code) {
        kfree(tramp);
        return NULL;
    }

    tramp->code = tramp_code;
    tramp->size = tramp_size;
    tramp->target = target;
    tramp->handler = handler;

    /* Guarded prologue copy: plain memcpy faults (oops) on
     * execute-only or unmapped text and on a huge-page boundary whose
     * neighbour is not readable. Per-word extable reads fail closed;
     * partial copies are unwound below (one free per alloc). */
    for (i = 0; i < hook_size; i += INSTRUCTION_SIZE) {
        ret = memd_target_read32(target, (unsigned long)i, &insn);
        if (ret) {
            vfree(tramp_code);
            kfree(tramp);
            return NULL;
        }
        memcpy((char *)tramp_code + i, &insn, INSTRUCTION_SIZE);
    }

    /* Jump back to target + hook_size (past the patched B). The old
     * code jumped to target itself (infinite handler loop), used X0
     * (clobbers the first argument), used 0xF0000000 bases (not
     * MOVZ/MOVK) with 20-bit chunks at shifts 0/20/40 (truncates and
     * overflows the imm16 field), and dropped bits 48+. Full 64-bit
     * address via X16 (IP1 scratch): MOVZ + 3x MOVK + BR X16. */
    {
        unsigned long resume = (unsigned long)target + hook_size;
        u32 epilogue[5];
        epilogue[0] = (u32)(0xD2800000UL | (((resume >> 0) & 0xFFFFUL) << 5) | 16UL);
        epilogue[1] = (u32)(0xF2A00000UL | (((resume >> 16) & 0xFFFFUL) << 5) | 16UL);
        epilogue[2] = (u32)(0xF2C00000UL | (((resume >> 32) & 0xFFFFUL) << 5) | 16UL);
        epilogue[3] = (u32)(0xF2E00000UL | (((resume >> 48) & 0xFFFFUL) << 5) | 16UL);
        epilogue[4] = (u32)0xD61F0200UL;
        ret = hook_write_range((char *)tramp_code + hook_size, epilogue, 20);
    }

    if (ret) {
        vfree(tramp_code);
        kfree(tramp);
        return NULL;
    }

    tramp->target = target;
    tramp->handler = handler;

    spin_lock(&g_trampoline_lock);
    list_add(&tramp->list, &g_trampoline_list);
    spin_unlock(&g_trampoline_lock);

    return tramp;
}

void memd_destroy_trampoline(struct memd_trampoline *tramp)
 {
    if (!tramp)
        return;

    spin_lock(&g_trampoline_lock);
    list_del(&tramp->list);
    spin_unlock(&g_trampoline_lock);

    if (tramp->code)
        vfree(tramp->code);
    kfree(tramp);
}

bool check_target_can_hijack(void *target)
 {
    int offset;
    u32 insn;

    /* Unaligned text cannot hold AArch64 insns; NULL faults below.
     * Guarded reads (not direct dereference): XO/unmapped/huge-edge
     * text fails closed instead of oopsing. */
    if (!target || ((uintptr_t)target & (INSTRUCTION_SIZE - 1)))
        return false;
    for (offset = 0; offset < HOOK_TARGET_OFFSET + HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
        if (memd_target_read32(target, (unsigned long)offset, &insn))
            return false;
        if (!check_instruction_can_hijack((uint32_t)insn))
            return false;
    }
    return true;
}

int memd_install_inline_hook(void *target, void *handler, void **orig)
  {
     struct memd_trampoline *tramp;
     struct memd_trampoline *t;
     struct memd_trampoline *tmp;
     size_t hook_size = HIJACK_SIZE;
     long delta;
     u32 branch_insn;
     int ret;

     if (!target || !handler)
         return -EINVAL;
     if (((uintptr_t)target & 3UL) || ((uintptr_t)handler & 3UL))
         return -EINVAL;

     mutex_lock(&g_install_lock);

     /* Double install fails closed with -EBUSY: the list is the
      * ground truth (the patched-B refusal below is only a
      * backstop). Serialized by g_install_lock; nested spinlock
      * order matches memd_remove_inline_hook. */
     spin_lock(&g_trampoline_lock);
     list_for_each_entry_safe(t, tmp, &g_trampoline_list, list) {
         if (t->target == target) {
             spin_unlock(&g_trampoline_lock);
             mutex_unlock(&g_install_lock);
             return -EBUSY;
         }
     }
     spin_unlock(&g_trampoline_lock);

     if (!check_target_can_hijack(target)) {
         mutex_unlock(&g_install_lock);
         return -EINVAL;
     }

     /* B carries a signed 26-bit word offset (+-128MB). Mask the
      * immediate and refuse out-of-range handlers instead of writing
      * a truncated branch (vmalloc and kernel text are often
      * farther apart than that). PC base is the branch word itself
      * (target): AArch64 has no Thumb state and the patched word sits
      * at offset 0 of the overwritten range, so no page alignment is
      * applied. Bounds are [-128MB, +128MB-4]: imm26 spans
      * [-2^25, 2^25-1] words. */
     delta = (long)(uintptr_t)handler - (long)(uintptr_t)target;
     if ((delta & 3L) || delta < -(128L << 20) || delta > ((128L << 20) - 4L)) {
         mutex_unlock(&g_install_lock);
         return -ERANGE;
     }
     branch_insn = (u32)0x14000000UL | (u32)(((unsigned long)delta >> 2) & 0x03FFFFFFUL);

     tramp = memd_create_trampoline(target, handler, hook_size);
     if (!tramp) {
         mutex_unlock(&g_install_lock);
         return -ENOMEM;
     }

     ret = hook_write_range(target, &branch_insn, INSTRUCTION_SIZE);
     if (ret) {
         /* Never leave an orphan trampoline for a hook that did not
          * land (its jump-back would target the unpatched code). */
         memd_destroy_trampoline(tramp);
         mutex_unlock(&g_install_lock);
         return ret;
     }

     if (orig)
         *orig = tramp->code;

     mutex_unlock(&g_install_lock);
     return 0;
 }

void memd_remove_inline_hook(void *target, void *orig)
  {
     struct memd_trampoline *tramp, *tmp;
     struct memd_trampoline *found = NULL;
     int ret = 0;

     /* Without the saved bytes we cannot restore; freeing the
      * trampoline while the patched B still points at the handler
      * would leave orig callers jumping into freed exec memory.
      * Fail closed (hook stays, no crash). */
     if (!target || !orig)
         return;

     mutex_lock(&g_install_lock);

     /* Lookup BEFORE any write, and only restore when orig is the live
      * trampoline code for this target. A second remove with a stale
      * (vfree'd) orig finds no entry or fails the equality check, so
      * the dangling pointer is never dereferenced (no UAF read). A
      * recycled target with a fresh hook can never match a stale orig
      * either, so cross-wiring text with garbage is refused. */
     spin_lock(&g_trampoline_lock);
     list_for_each_entry_safe(tramp, tmp, &g_trampoline_list, list) {
         if (tramp->target == target) {
             found = tramp;
             break;
         }
     }
     if (!found || found->code != orig) {
         spin_unlock(&g_trampoline_lock);
         mutex_unlock(&g_install_lock);
         return;
     }
     /* Unlink under the lock, then patch and free without holding it:
      * memd_destroy_trampoline takes the same lock, so calling it
      * inside list_for_each_entry_safe deadlocked. The entry stays
      * allocated until the free below, so the restore reads live
      * memory (orig == found->code by the check above). */
     list_del(&found->list);
     spin_unlock(&g_trampoline_lock);

     ret = hook_write_range(target, orig, HIJACK_SIZE);
     if (ret) {
         /* Restore failed: the branch still points at the handler, so
          * re-link the entry instead of freeing a live trampoline out
          * from under it (next remove retries; nothing leaks, the
          * entry is still reachable from the list). */
         spin_lock(&g_trampoline_lock);
         list_add(&found->list, &g_trampoline_list);
         spin_unlock(&g_trampoline_lock);
         mutex_unlock(&g_install_lock);
         return;
     }

     if (found->code)
         vfree(found->code);
     kfree(found);
     mutex_unlock(&g_install_lock);
 }
/* kmod/memd/inlinehook/hijack_arm64.c[∂] */
