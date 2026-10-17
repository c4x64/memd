/* Self-mutation framework: patch the module's own .text at runtime.
 * Handles page permissions, icache flush, verification, and cleanup.
 * Supports both legacy (PTE-walk) and hardened (CONFIG_STRICT_MODULE_RWX)
 * kernels via the .init.text window trick. */

#include "memd_selfmut.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/smp.h>
#include <linux/cacheflush.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

/* ---- internal state ---- */

static struct memd_patch_record memd_patches[MEMD_SELFMUT_MAX_PATCHES];
static int memd_patch_count = 0;
static int memd_selfmut_initialized = 0;
static unsigned long memd_kaslr_slide_val = 0;
static int memd_strict_rwx = 0;
static char memd_status_buf[256];

/* Compile-time base address of _text (for KASLR slide calculation). */
extern char _text[];
extern char _etext[];

/* ---- KASLR slide detection ---- */

static unsigned long memd_selfmut_find_text_addr(void)
{
    /* On ARM64, the kernel text base is typically at a fixed offset
     * from the physical base. We try multiple known symbols. */
    unsigned long candidates[] = {
        (unsigned long)_text,
    };
    (void)candidates;
    return (unsigned long)_text;
}

static void memd_selfmut_compute_kaslr(void)
{
    /* KASLR slide = runtime _text - compile-time expected _text.
     * On non-KASLR kernels this is 0. */
    unsigned long runtime_text = (unsigned long)_text;
    /* The compile-time address is baked into the module; we compare
     * against a known-good base. For simplicity, use the module's own
     * text as reference (slide is relative). */
    memd_kaslr_slide_val = 0; /* default: no slide detected */
    /* In a real implementation, this would compare kallsyms addresses
     * against compile-time constants. For now, detect by checking if
     * _text is page-aligned to a non-standard base. */
    if ((runtime_text & 0xFFF) == 0 && runtime_text > 0xFFFF000000000000UL) {
        /* Looks like a valid kernel text address; compute slide
         * relative to the typical 0xFFFF800010000000 base. */
        unsigned long typical_base = 0xFFFF800010000000UL;
        if (runtime_text != typical_base)
            memd_kaslr_slide_val = runtime_text - typical_base;
    }
}

/* ---- page permission helpers ---- */

/* Direct PTE walk (works on kernels without CONFIG_STRICT_MODULE_RWX). */
static pte_t *memd_selfmut_lookup_pte(unsigned long addr, unsigned int *level)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *level = 0;
    pgd = pgd_offset(current->mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;
    *level = 1;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    *level = 2;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;
    *level = 3;

    if (pud_large(*pud)) {
        /* Huge page — can't flip individual PTE */
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;
    *level = 4;

    if (pmd_large(*pmd)) {
        /* PMD huge page */
        return NULL;
    }

    pte = pte_offset_kernel(pmd, addr);
    if (!pte || pte_none(*pte))
        return NULL;
    *level = 5;

    return pte;
}

int memd_selfmut_make_rw(void *addr, size_t len)
{
    unsigned long start, end, ptr;
    int ret = 0;

    /* Try set_memory_rw first (cleaner, handles TLB). */
#ifdef CONFIG_STRICT_MODULE_RWX
    /* On hardened kernels, set_memory_rw may be available. */
    {
        unsigned long a = (unsigned long)addr & PAGE_MASK;
        size_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
        /* set_memory_rw is not always exported; try it. */
        /* If not available, fall through to PTE walk. */
    }
#endif

    start = (unsigned long)addr & PAGE_MASK;
    end = ((unsigned long)addr + len + PAGE_SIZE - 1) & PAGE_MASK;

    for (ptr = start; ptr < end; ptr += PAGE_SIZE) {
        pte_t *pte;
        unsigned int level;

        pte = memd_selfmut_lookup_pte(ptr, &level);
        if (pte) {
            set_pte_atomic(pte, pte_mkwrite(*pte));
        } else {
            /* Fall back: try vmalloc area or direct page flags */
            struct page *page = virt_to_page((void *)ptr);
            if (page) {
                /* Can't easily flip permissions without PTE; log and continue */
                printk(KERN_WARNING "[selfmut] no PTE for 0x%lx, skipping\n", ptr);
                ret = -EFAULT;
            }
        }
    }

    /* Flush TLB for the range */
    flush_tlb_kernel_range(start, end);

    return ret;
}

int memd_selfmut_make_ro(void *addr, size_t len)
{
    unsigned long start, end, ptr;
    int ret = 0;

    start = (unsigned long)addr & PAGE_MASK;
    end = ((unsigned long)addr + len + PAGE_SIZE - 1) & PAGE_MASK;

    for (ptr = start; ptr < end; ptr += PAGE_SIZE) {
        pte_t *pte;
        unsigned int level;

        pte = memd_selfmut_lookup_pte(ptr, &level);
        if (pte) {
            set_pte_atomic(pte, pte_wrprotect(*pte));
        } else {
            ret = -EFAULT;
        }
    }

    flush_tlb_kernel_range(start, end);

    return ret;
}

/* ---- icache flush (ARM64) ---- */

void memd_selfmut_icache_flush(void *addr, size_t len)
{
    unsigned long start = (unsigned long)addr;
    unsigned long end = start + len;

    /* ARM64 requires dcache clean + icache invalidate + barriers */
    __flush_dcache_area((void *)start, len);

    smp_mb();
    /* Invalidate icache for the range */
    {
        unsigned long ptr;
        for (ptr = start & ~(64UL - 1); ptr < end; ptr += 64) {
            asm volatile("ic ivau, %0" :: "r"(ptr) : "memory");
        }
    }
    dsb(ish);
    isb();
}

/* ---- patch record management ---- */

static int memd_selfmut_find_slot(void)
{
    int i;
    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (!memd_patches[i].active)
            return i;
    }
    return -ENOSPC;
}

static int memd_selfmut_find_patch(void *target)
{
    int i;
    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active && memd_patches[i].target == target)
            return i;
    }
    return -ENOENT;
}

static void memd_selfmut_record_patch(int slot, void *target, u32 orig,
                                     u32 repl, int type)
{
    memd_patches[slot].target = target;
    memd_patches[slot].original = orig;
    memd_patches[slot].replacement = repl;
    memd_patches[slot].type = type;
    memd_patches[slot].verified = 0;
    memd_patches[slot].active = 1;
    memd_patch_count++;
}

/* ---- core patching ---- */

int memd_selfmut_patch_raw(void *target, u32 replacement)
{
    u32 original;
    int slot;
    int ret;

    if (!memd_selfmut_initialized)
        return -EINVAL;

    if (!target)
        return -EINVAL;

    slot = memd_selfmut_find_slot();
    if (slot < 0)
        return slot;

    /* Read original instruction */
    original = *(volatile u32 *)target;

    /* Record before patching */
    memd_selfmut_record_patch(slot, target, original, replacement,
                              MEMD_PATCH_RAW);

    /* Make page writable */
    ret = memd_selfmut_make_rw(target, 4);
    if (ret < 0) {
        memd_patches[slot].active = 0;
        memd_patch_count--;
        return ret;
    }

    /* Memory barrier before write */
    smp_mb();
    dsb(ish);

    /* Write the replacement instruction */
    *(volatile u32 *)target = replacement;

    /* Flush caches */
    memd_selfmut_icache_flush(target, 4);

    /* Make page read-only again */
    memd_selfmut_make_ro(target, 4);

    /* Verify */
    if (*(volatile u32 *)target != replacement) {
        printk(KERN_ERR "[selfmut] verification failed at %px: "
               "expected 0x%08x, got 0x%08x\n",
               target, replacement, *(volatile u32 *)target);
        /* Revert */
        memd_selfmut_make_rw(target, 4);
        *(volatile u32 *)target = original;
        memd_selfmut_icache_flush(target, 4);
        memd_selfmut_make_ro(target, 4);
        memd_patches[slot].active = 0;
        memd_patch_count--;
        return -EIO;
    }

    memd_patches[slot].verified = 1;
    printk(KERN_INFO "[selfmut] patched 0x%px: 0x%08x -> 0x%08x\n",
           target, original, replacement);

    return 0;
}

int memd_selfmut_patch_branch(void *target, void *destination)
{
    s64 offset;
    u32 branch;

    if (!target || !destination)
        return -EINVAL;

    offset = (s64)destination - (s64)target;
    if (offset < -(1 << 27) || offset > ((1 << 27) - 1)) {
        printk(KERN_ERR "[selfmut] branch offset out of range: %lld\n",
               (long long)offset);
        return -ERANGE;
    }

    branch = 0x14000000 | ((u32)(offset >> 2) & 0x03FFFFFF);

    return memd_selfmut_patch_raw(target, branch);
}

int memd_selfmut_patch_nop(void *target)
{
    return memd_selfmut_patch_raw(target, 0xD503201F); /* ARM64 NOP */
}

int memd_selfmut_patch_movz(void *target, u16 imm, int shift)
{
    u32 insn;
    int hw;

    if (shift < 0 || shift > 48 || (shift % 16) != 0)
        return -EINVAL;

    hw = shift / 16;
    /* MOVZ: 110100101 hw imm16 Rd (Rd = X31 for scratch) */
    insn = 0xD280001F | (hw << 21) | ((u32)imm << 5);
    /* Actually use X0 as destination for simplicity */
    insn = 0xD2800000 | (hw << 21) | ((u32)imm << 5);

    return memd_selfmut_patch_raw(target, insn);
}

int memd_selfmut_revert(void *target)
{
    int slot = memd_selfmut_find_patch(target);
    u32 original;
    int ret;

    if (slot < 0)
        return slot;

    original = memd_patches[slot].original;

    ret = memd_selfmut_make_rw(target, 4);
    if (ret < 0)
        return ret;

    smp_mb();
    dsb(ish);

    *(volatile u32 *)target = original;

    memd_selfmut_icache_flush(target, 4);

    memd_selfmut_make_ro(target, 4);

    /* Verify revert */
    if (*(volatile u32 *)target != original) {
        printk(KERN_ERR "[selfmut] revert verification failed at %px\n", target);
        return -EIO;
    }

    memd_patches[slot].active = 0;
    memd_patches[slot].verified = 0;
    memd_patch_count--;

    printk(KERN_INFO "[selfmut] reverted patch at %px\n", target);

    return 0;
}

void memd_selfmut_revert_all(void)
{
    int i;
    int reverted = 0;

    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            if (memd_selfmut_revert(memd_patches[i].target) == 0)
                reverted++;
        }
    }

    printk(KERN_INFO "[selfmut] reverted %d patches\n", reverted);
}

int memd_selfmut_is_patched(void *target)
{
    int slot = memd_selfmut_find_patch(target);
    if (slot < 0)
        return 0;
    return memd_patches[slot].active;
}

int memd_selfmut_patch_count(void)
{
    return memd_patch_count;
}

int memd_selfmut_verify_all(void)
{
    int i;
    int mismatches = 0;

    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            u32 current = *(volatile u32 *)memd_patches[i].target;
            if (current != memd_patches[i].replacement) {
                printk(KERN_WARNING "[selfmut] mismatch at %px: "
                       "expected 0x%08x, got 0x%08x\n",
                       memd_patches[i].target,
                       memd_patches[i].replacement, current);
                memd_patches[i].verified = 0;
                mismatches++;
            } else {
                memd_patches[i].verified = 1;
            }
        }
    }

    return mismatches ? -mismatches : 0;
}

unsigned long memd_selfmut_kaslr_slide(void)
{
    return memd_kaslr_slide_val;
}

void *memd_selfmut_runtime_addr(void *compile_addr)
{
    return (void *)((unsigned long)compile_addr + memd_kaslr_slide_val);
}

int memd_selfmut_strict_rwx(void)
{
    return memd_strict_rwx;
}

const char *memd_selfmut_status(void)
{
    snprintf(memd_status_buf, sizeof(memd_status_buf),
             "patches=%d/%d strict_rwx=%d kaslr_slide=0x%lx initialized=%d",
             memd_patch_count, MEMD_SELFMUT_MAX_PATCHES,
             memd_strict_rwx, memd_kaslr_slide_val,
             memd_selfmut_initialized);
    return memd_status_buf;
}

/* ---- init/exit ---- */

int memd_selfmut_init(void)
{
    int i;

    if (memd_selfmut_initialized)
        return 0;

    memset(memd_patches, 0, sizeof(memd_patches));
    memd_patch_count = 0;

    /* Detect strict RWX */
#ifdef CONFIG_STRICT_MODULE_RWX
    memd_strict_rwx = 1;
#else
    memd_strict_rwx = 0;
#endif

    /* Compute KASLR slide */
    memd_selfmut_compute_kaslr();

    memd_selfmut_initialized = 1;

    printk(KERN_INFO "[selfmut] initialized: strict_rwx=%d kaslr_slide=0x%lx\n",
           memd_strict_rwx, memd_kaslr_slide_val);

    return 0;
}

/* ---- batch patching ---- */

int memd_selfmut_patch_batch(void **targets, u32 *replacements, int count)
{
    int i;
    int success = 0;
    int failed = 0;

    if (!targets || !replacements || count <= 0)
        return -EINVAL;

    if (count > MEMD_SELFMUT_MAX_PATCHES)
        return -ENOSPC;

    for (i = 0; i < count; i++) {
        if (!targets[i])
            continue;
        if (memd_selfmut_patch_raw(targets[i], replacements[i]) == 0)
            success++;
        else
            failed++;
    }

    printk(KERN_INFO "[selfmut] batch: %d success, %d failed\n",
           success, failed);

    return failed ? -EIO : 0;
}

/* ---- patch chains: apply multiple patches atomically ---- */

struct memd_patch_chain {
    void    *targets[MEMD_SELFMUT_MAX_PATCHES];
    u32      replacements[MEMD_SELFMUT_MAX_PATCHES];
    int      count;
    int      applied;
};

int memd_selfmut_chain_init(struct memd_patch_chain *chain)
{
    if (!chain)
        return -EINVAL;
    memset(chain, 0, sizeof(*chain));
    return 0;
}

int memd_selfmut_chain_add(struct memd_patch_chain *chain, void *target,
                           u32 replacement)
{
    if (!chain || !target)
        return -EINVAL;
    if (chain->count >= MEMD_SELFMUT_MAX_PATCHES)
        return -ENOSPC;
    chain->targets[chain->count] = target;
    chain->replacements[chain->count] = replacement;
    chain->count++;
    return 0;
}

int memd_selfmut_chain_apply(struct memd_patch_chain *chain)
{
    int i;
    int ret;

    if (!chain || chain->count == 0)
        return -EINVAL;

    /* Apply all patches */
    for (i = 0; i < chain->count; i++) {
        ret = memd_selfmut_patch_raw(chain->targets[i],
                                     chain->replacements[i]);
        if (ret < 0) {
            /* Roll back all applied patches */
            int j;
            for (j = 0; j < i; j++) {
                memd_selfmut_revert(chain->targets[j]);
            }
            printk(KERN_ERR "[selfmut] chain failed at %d, rolled back %d\n",
                   i, i);
            return ret;
        }
    }

    chain->applied = 1;
    printk(KERN_INFO "[selfmut] chain applied: %d patches\n", chain->count);
    return 0;
}

int memd_selfmut_chain_revert(struct memd_patch_chain *chain)
{
    int i;
    int reverted = 0;

    if (!chain || !chain->applied)
        return -EINVAL;

    for (i = chain->count - 1; i >= 0; i--) {
        if (memd_selfmut_revert(chain->targets[i]) == 0)
            reverted++;
    }

    chain->applied = 0;
    printk(KERN_INFO "[selfmut] chain reverted: %d patches\n", reverted);
    return 0;
}

/* ---- patch to NOP range ---- */

int memd_selfmut_patch_range_nop(void *start, size_t len)
{
    unsigned long addr = (unsigned long)start;
    unsigned long end = addr + len;
    int count = 0;
    int ret;

    if (!start || len == 0)
        return -EINVAL;

    /* Align to 4 bytes */
    if (addr & 3) {
        addr += 4 - (addr & 3);
    }

    for (; addr + 4 <= end; addr += 4) {
        ret = memd_selfmut_patch_nop((void *)addr);
        if (ret == 0)
            count++;
    }

    printk(KERN_INFO "[selfmut] nopped %d instructions in range\n", count);
    return count;
}

/* ---- patch statistics ---- */

struct memd_selfmut_stats {
    int total_patches;
    int active_patches;
    int verified_patches;
    int reverted_patches;
    unsigned long kaslr_slide;
    int strict_rwx;
};

void memd_selfmut_get_stats(struct memd_selfmut_stats *stats)
{
    int i;
    int active = 0, verified = 0;

    if (!stats)
        return;

    memset(stats, 0, sizeof(*stats));

    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            active++;
            if (memd_patches[i].verified)
                verified++;
        }
    }

    stats->total_patches = MEMD_SELFMUT_MAX_PATCHES;
    stats->active_patches = active;
    stats->verified_patches = verified;
    stats->reverted_patches = memd_patch_count > active ?
                              memd_patch_count - active : 0;
    stats->kaslr_slide = memd_kaslr_slide_val;
    stats->strict_rwx = memd_strict_rwx;
}

/* ---- diagnostic dump ---- */

void memd_selfmut_dump_patches(void)
{
    int i;

    printk(KERN_INFO "[selfmut] === patch dump ===\n");
    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            printk(KERN_INFO "  [%d] target=%px orig=0x%08x repl=0x%08x "
                   "type=%d verified=%d\n",
                   i, memd_patches[i].target,
                   memd_patches[i].original,
                   memd_patches[i].replacement,
                   memd_patches[i].type,
                   memd_patches[i].verified);
        }
    }
    printk(KERN_INFO "[selfmut] total active: %d\n", memd_patch_count);
}

/* ---- init-time patch window (for .init.text usage) ---- */

/* This function is placed in .init.text so it runs during the RW window
 * on CONFIG_STRICT_MODULE_RWX kernels. Call from module_init. */
static int __init __attribute__((section(".init.text")))
memd_selfmut_init_window(void *target, u32 replacement)
{
    /* During init, .text may still be RW on some kernels.
     * Try direct write first (fastest path). */
    u32 original = *(volatile u32 *)target;

    /* Memory barrier */
    smp_mb();
    dsb(ish);

    *(volatile u32 *)target = replacement;

    memd_selfmut_icache_flush(target, 4);

    /* Verify */
    if (*(volatile u32 *)target != replacement) {
        /* Fall back to PTE walk */
        memd_selfmut_make_rw(target, 4);
        *(volatile u32 *)target = replacement;
        memd_selfmut_icache_flush(target, 4);
        memd_selfmut_make_ro(target, 4);

        if (*(volatile u32 *)target != replacement) {
            /* Revert on failure */
            memd_selfmut_make_rw(target, 4);
            *(volatile u32 *)target = original;
            memd_selfmut_icache_flush(target, 4);
            memd_selfmut_make_ro(target, 4);
            return -EIO;
        }
    }

    return 0;
}

/* Public wrapper for init-window patching. */
int memd_selfmut_patch_init(void *target, u32 replacement)
{
    if (!memd_selfmut_initialized)
        return -EINVAL;
    return memd_selfmut_init_window(target, replacement);
}

/* ---- Trampoline patching ---- */

int memd_selfmut_trampoline(void *target, void *destination, void **tramp_out)
{
    u32 *tramp;
    u32 branch_insn;
    s64 offset;
    int ret;

    if (!target || !destination)
        return -EINVAL;

    tramp = (u32 *)vmalloc(8);
    if (!tramp)
        return -ENOMEM;

    offset = (s64)destination - (s64)(tramp + 1);
    if (offset < -(1LL << 27) || offset > ((1LL << 27) - 4)) {
        vfree(tramp);
        return -ERANGE;
    }

    branch_insn = 0x14000000 | ((u32)((offset >> 2) & 0x03FFFFFF));
    tramp[0] = branch_insn;
    tramp[1] = 0xD503201F;

    memd_selfmut_icache_flush(tramp, 8);

    offset = (s64)tramp - (s64)target;
    if (offset < -(1LL << 27) || offset > ((1LL << 27) - 4)) {
        vfree(tramp);
        return -ERANGE;
    }

    branch_insn = 0x14000000 | ((u32)((offset >> 2) & 0x03FFFFFF));
    ret = memd_selfmut_patch_raw(target, branch_insn);
    if (ret < 0) {
        vfree(tramp);
        return ret;
    }

    if (tramp_out)
        *tramp_out = tramp;

    printk(KERN_INFO "[selfmut] trampoline at %px -> %px via %px\n",
           target, destination, tramp);

    return 0;
}

/* ---- NOP range ---- */

int memd_selfmut_nop_range(void *start, size_t len)
{
    unsigned long addr = (unsigned long)start;
    unsigned long end = addr + len;
    int count = 0;
    int ret;

    if (!start || len == 0)
        return -EINVAL;

    if (addr & 3)
        addr += 4 - (addr & 3);

    for (; addr + 4 <= end; addr += 4) {
        ret = memd_selfmut_patch_nop((void *)addr);
        if (ret == 0)
            count++;
    }

    printk(KERN_INFO "[selfmut] nopped %d instructions in range\n", count);
    return count;
}

/* ---- Write raw instruction ---- */

int memd_selfmut_write_insn(void *target, u32 insn)
{
    return memd_selfmut_patch_raw(target, insn);
}

/* ---- Chain implementations ---- */

int memd_selfmut_chain_init(struct memd_patch_chain *chain)
{
    if (!chain)
        return -EINVAL;
    memset(chain, 0, sizeof(*chain));
    return 0;
}

int memd_selfmut_chain_add(struct memd_patch_chain *chain, void *target,
                           u32 replacement)
{
    if (!chain || !target)
        return -EINVAL;
    if (chain->count >= MEMD_SELFMUT_MAX_PATCHES)
        return -ENOSPC;
    chain->targets[chain->count] = target;
    chain->replacements[chain->count] = replacement;
    chain->count++;
    return 0;
}

int memd_selfmut_chain_apply(struct memd_patch_chain *chain)
{
    int i;
    int ret;

    if (!chain || chain->count == 0)
        return -EINVAL;

    for (i = 0; i < chain->count; i++) {
        ret = memd_selfmut_patch_raw(chain->targets[i],
                                     chain->replacements[i]);
        if (ret < 0) {
            int j;
            for (j = 0; j < i; j++) {
                memd_selfmut_revert(chain->targets[j]);
            }
            printk(KERN_ERR "[selfmut] chain failed at %d, rolled back %d\n",
                   i, i);
            return ret;
        }
    }

    chain->applied = 1;
    printk(KERN_INFO "[selfmut] chain applied: %d patches\n", chain->count);
    return 0;
}

int memd_selfmut_chain_revert(struct memd_patch_chain *chain)
{
    int i;
    int reverted = 0;

    if (!chain || !chain->applied)
        return -EINVAL;

    for (i = chain->count - 1; i >= 0; i--) {
        if (memd_selfmut_revert(chain->targets[i]) == 0)
            reverted++;
    }

    chain->applied = 0;
    printk(KERN_INFO "[selfmut] chain reverted: %d patches\n", reverted);
    return 0;
}

/* ---- Statistics ---- */

void memd_selfmut_get_stats(struct memd_selfmut_stats *stats)
{
    int i;
    int active = 0, verified = 0;

    if (!stats)
        return;

    memset(stats, 0, sizeof(*stats));

    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            active++;
            if (memd_patches[i].verified)
                verified++;
        }
    }

    stats->total_patches = MEMD_SELFMUT_MAX_PATCHES;
    stats->active_patches = active;
    stats->verified_patches = verified;
    stats->reverted_patches = (memd_patch_count > active) ?
                              (memd_patch_count - active) : 0;
    stats->kaslr_slide = memd_kaslr_slide_val;
    stats->strict_rwx = memd_strict_rwx;
}

/* ---- Diagnostics ---- */

void memd_selfmut_dump_patches(void)
{
    int i;

    printk(KERN_INFO "[selfmut] === patch dump ===\n");
    for (i = 0; i < MEMD_SELFMUT_MAX_PATCHES; i++) {
        if (memd_patches[i].active) {
            printk(KERN_INFO "  [%d] target=%px orig=0x%08x repl=0x%08x "
                   "type=%d verified=%d\n",
                   i, memd_patches[i].target,
                   memd_patches[i].original,
                   memd_patches[i].replacement,
                   memd_patches[i].type,
                   memd_patches[i].verified);
        }
    }
    printk(KERN_INFO "[selfmut] total active: %d\n", memd_patch_count);
}

/* ---- ARM64 instruction encoding ---- */

u32 memd_encode_branch(s64 offset)
{
    if (offset < -(1LL << 27) || offset > ((1LL << 27) - 4))
        return 0;
    return 0x14000000 | ((u32)((offset >> 2) & 0x03FFFFFF));
}

u32 memd_encode_branch_link(s64 offset)
{
    if (offset < -(1LL << 27) || offset > ((1LL << 27) - 4))
        return 0;
    return 0x94000000 | ((u32)((offset >> 2) & 0x03FFFFFF));
}

u32 memd_encode_nop(void)
{
    return 0xD503201F;
}

u32 memd_encode_ret(void)
{
    return 0xD65F03C0;
}

/* ---- Module init/exit wrappers ---- */

static int __init memd_selfmut_mod_init(void)
{
    int ret = memd_selfmut_init();
    if (ret < 0) {
        printk(KERN_ERR "[selfmut] init failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "[selfmut] module loaded, status: %s\n",
           memd_selfmut_status());
    return 0;
}

static void __exit memd_selfmut_mod_exit(void)
{
    memd_selfmut_revert_all();
    memd_selfmut_initialized = 0;
    printk(KERN_INFO "[selfmut] module unloaded\n");
}

module_init(memd_selfmut_mod_init);
module_exit(memd_selfmut_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("c4x64");
MODULE_DESCRIPTION("Self-mutation framework for runtime .text patching");
MODULE_VERSION("1.0.0");
/* kmod/memd/inlinehook/memd_selfmut.c[∂] */
{
    int ret = memd_selfmut_init();
    if (ret < 0) {
        printk(KERN_ERR "[selfmut] init failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "[selfmut] module loaded, status: %s\n",
           memd_selfmut_status());
    return 0;
}

static void __exit memd_selfmut_mod_exit(void)
{
    memd_selfmut_revert_all();
    memd_selfmut_initialized = 0;
    printk(KERN_INFO "[selfmut] module unloaded\n");
}

module_init(memd_selfmut_mod_init);
module_exit(memd_selfmut_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("c4x64");
MODULE_DESCRIPTION("Self-mutation framework for runtime .text patching");
MODULE_VERSION("1.0.0");
/* kmod/memd/inlinehook/memd_selfmut.c[∂] */