#include "hijack_arm64.h"

#include "memd_common.h"
#include "memd_utils.h"

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

static int calculate_trampoline_size(void *target, size_t hook_size)
  {
     size_t i;
     size_t size;
     uint32_t *ptr = target;

     /* Copied prologue plus the fixed jump-back epilogue (MOVZ + 3x
      * MOVK + BR = 20 bytes, full 64-bit, no literal pool). The old
      * code omitted the epilogue and overflowed the 32-byte
      * allocation by 8 bytes on every hook. */
     size = hook_size + 20;
     for (i = 0; i < hook_size; i += INSTRUCTION_SIZE) {
         int type = get_instruction_type(ptr[i / 4]);

        if (type == INST_B || type == INST_BL || type == INST_B_COND ||
            type == INST_CBZ_CBNZ || type == INST_TBZ_TBNZ ||
            type == INST_ADR || type == INST_ADRP) {
            size += 8;
        }
    }

    return ALIGN(size, 16);
}

struct memd_trampoline *memd_create_trampoline(void *target, void *handler, size_t hook_size)
 {
    struct memd_trampoline *tramp;
    void *tramp_code;
    size_t tramp_size;
    int ret;

    tramp_size = calculate_trampoline_size(target, hook_size);

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

    memcpy(tramp_code, target, hook_size);

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
    int offset = 0;
    for (; offset < HOOK_TARGET_OFFSET + HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
        if (!check_instruction_can_hijack(*(uint32_t *)((char *)target + offset)))
            return false;
    }
    return true;
}

int memd_install_inline_hook(void *target, void *handler, void **orig)
  {
     struct memd_trampoline *tramp;
     size_t hook_size = HIJACK_SIZE;
     long delta;
     u32 branch_insn;
     int ret;

     if (!check_target_can_hijack(target))
         return -EINVAL;

     /* B carries a signed 26-bit word offset (+-128MB). Mask the
      * immediate and refuse out-of-range handlers instead of writing
      * a truncated branch (vmalloc and kernel text are often
      * farther apart than that). */
     delta = (long)(uintptr_t)handler - (long)(uintptr_t)target;
     if ((delta & 3L) || delta < -(128L << 20) || delta > ((128L << 20) - 4L))
         return -ERANGE;
     branch_insn = (u32)0x14000000UL | (u32)(((unsigned long)delta >> 2) & 0x03FFFFFFUL);

     tramp = memd_create_trampoline(target, handler, hook_size);
     if (!tramp)
         return -ENOMEM;

     ret = hook_write_range(target, &branch_insn, INSTRUCTION_SIZE);
     if (ret) {
         /* Never leave an orphan trampoline for a hook that did not
          * land (its jump-back would target the unpatched code). */
         memd_destroy_trampoline(tramp);
         return ret;
     }

     if (orig)
         *orig = tramp->code;

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
     ret = hook_write_range(target, orig, HIJACK_SIZE);
     if (ret)
         return;

     /* Unlink under the lock, then free without holding it:
      * memd_destroy_trampoline takes the same lock, so calling it
      * inside list_for_each_entry_safe deadlocked. Only drop the
      * trampoline when the restore above succeeded (otherwise orig
      * callers would jump into freed exec memory). */
     spin_lock(&g_trampoline_lock);
     list_for_each_entry_safe(tramp, tmp, &g_trampoline_list, list) {
         if (tramp->target == target) {
             list_del(&tramp->list);
             found = tramp;
             break;
         }
     }
     spin_unlock(&g_trampoline_lock);

     if (found) {
         if (found->code)
             vfree(found->code);
         kfree(found);
     }
 }
/* kmod/memd/inlinehook/hijack_arm64.c[∂] */
