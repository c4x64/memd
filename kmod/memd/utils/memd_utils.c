#include "memd_utils.h"
#include "memd_kallsyms.h"
#include "memd_learn.h"

#include <asm/sysreg.h>
#include <linux/capability.h>
#include <linux/preempt.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

#include "hijack_arm64.h"
#include "linux/pid.h"

#ifdef CONFIG_CFI_CLANG
#define NO_CFI __nocfi
#else
#define NO_CFI
#endif

/* Floor is 5.10 (single universal image): filp_open is namespace-gated
 * there and up, so always resolve it at runtime. */
static int memd_flip_open(const char* filename, int flags, umode_t mode, struct file** f) {
    static struct file* (*reserve_flip_open)(const char* filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open =
            (struct file * (*)(const char* filename, int flags, umode_t mode)) kallsyms_lookup_name_ex("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
}

static int memd_flip_close(struct file** f, fl_owner_t id) {
    static struct file* (*reserve_flip_close)(struct file** f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file * (*)(struct file * *f, fl_owner_t id)) kallsyms_lookup_name_ex("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
}

bool is_file_exist(const char* filename) {
    struct file* fp;

    if (memd_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            memd_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    //    // int kern_path(const char *name, unsigned int flags, struct path *path)
    //    struct path path;
    //    if (kern_path(filename, LOOKUP_FOLLOW, &path) == 0) {
    //        return true;
    //    }

    return false;
}


pte_t* page_from_virt_user(struct mm_struct* mm, uintptr_t va) {
    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* ptep = NULL;

    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        memd_warn("PGD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        memd_warn("P4D entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
        memd_warn("PUD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    if (pud_leaf(*pud)) {
        memd_debug("Address 0x%lx maps to a PUD-level huge page (leaf), no PTE exists\n", va);
        goto out;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        memd_warn("PMD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    if (pmd_leaf(*pmd)) {
        memd_debug("Address 0x%lx maps to a PMD-level huge page (leaf), no PTE exists\n", va);
        goto out;
    }

    ptep = pte_offset_kernel(pmd, va);
    if (!ptep) {
        memd_warn("Failed to map PTE for address 0x%lx\n", va);
        goto out;
    }
out:
    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */

    return ptep;
}

/* Guarded user page-table walk (universal fail-closed). Every table
 * dereference goes through the extable guard; pgd comes from runtime
 * validation (never bare headers). A wrong pgd, a bad VA, or a
 * concurrent teardown returns 0 — never a fault. */
uintptr_t vaddr_to_phy_addr(struct mm_struct* mm, uintptr_t va) {
    unsigned long pgd_base, v;
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;
    unsigned long pte_v;
    if (!mm) {
        memd_warn("mm_struct is NULL, cannot perform translation\n");
        return 0;
    }
    pgd_base = memd_valid_pgd(mm);
    if (!pgd_base)
        return 0;
    pgdp = (pgd_t *)pgd_base + pgd_index(va);
    if (memd_safe_read64(pgdp, &v))
        return 0;
    if (pgd_none(__pgd(v)) || pgd_bad(__pgd(v)))
        return 0;
    p4dp = (p4d_t *)p4d_offset((pgd_t *)pgd_base, va);
    if (memd_safe_read64(p4dp, &v))
        return 0;
    if (p4d_none(__p4d(v)) || p4d_bad(__p4d(v)))
        return 0;
    pudp = (pud_t *)pud_offset((p4d_t *)p4dp, va);
    if (memd_safe_read64(pudp, &v))
        return 0;
    if (pud_none(__pud(v)) || pud_bad(__pud(v)))
        return 0;
    if (pud_leaf(__pud(v)))
        return 0;
    pmdp = (pmd_t *)pmd_offset((pud_t *)pudp, va);
    if (memd_safe_read64(pmdp, &v))
        return 0;
    if (pmd_none(__pmd(v)) || pmd_bad(__pmd(v)))
        return 0;
    if (pmd_leaf(__pmd(v)))
        return 0;
    ptep = pte_offset_kernel((pmd_t *)pmdp, va);
    if (!ptep)
        return 0;
    if (memd_safe_read64(ptep, &pte_v))
        return 0;
    if (!pte_present(__pte(pte_v)))
        return 0;
    return (pte_pfn(__pte(pte_v)) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
}

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/* Universal resolution: /proc/kallsyms self-parse (memd_kallsyms.c). No
 * kprobe imports of any kind — vendor loaders reject GOT-page relocs
 * against even weak kprobe references, so the kprobe trick can never be
 * in a universal image. kptr_restrict hiding addresses is the fail-soft
 * boundary (callers already degrade to "not found"). */
unsigned long kallsyms_lookup_name_ex(const char* name) {
    return memd_kallsyms(name);
}

/* memd_pfn_ok: pfn_valid without the import. 5.10-baseline headers emit a
 * real pfn_valid call, but some vendor kernels (proven: Samsung 5.15) do
 * not export it. Chain: the kernel's own function via runtime parse
 * (exact semantics) -> max_pfn variable via parse (bound) -> top bound
 * (callers additionally enforce DRAM-range + page-walk validation, so
 * the bound can only over-approximate holes, never grant bad access). */
static int (*memd_pfn_valid_fn)(unsigned long) = NULL;
static unsigned long *memd_max_pfn_ptr;
static bool memd_pfn_probed;

int memd_pfn_ok(unsigned long pfn) {
    if (!memd_pfn_probed) {
        memd_pfn_probed = true;
        memd_pfn_valid_fn =
            (int (*)(unsigned long))memd_kallsyms("pfn_valid");
        memd_max_pfn_ptr =
            (unsigned long *)memd_kallsyms("max_pfn");
    }
    if (memd_pfn_valid_fn)
        return memd_pfn_valid_fn(pfn);
    if (memd_max_pfn_ptr)
        return pfn < READ_ONCE(*memd_max_pfn_ptr);
    return pfn < ((64UL << 30) >> PAGE_SHIFT);
}

struct task_struct* get_target_task(pid_t pid) {
    struct pid* pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return NULL;
    }

    return task;
}

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2) {
#if CONFIG_COMPARE_PT_REGS == 1
    memd_info("==> Comparing pt_regs:\n");

    for (int i = 0; i < 31; ++i) {
        if (regs1->regs[i] != regs2->regs[i]) {
            memd_info("reg[%d] changed from %llx to %llx\n", i, regs1->regs[i], regs2->regs[i]);
        }
    }

    if (regs1->sp != regs2->sp) {
        memd_info("sp changed from %llx to %llx\n", regs1->sp, regs2->sp);
    }

    if (regs1->pc != regs2->pc) {
        memd_info("pc changed from %llx to %llx\n", regs1->pc, regs2->pc);
    }

    if (regs1->pstate != regs2->pstate) {
        memd_info("pstate changed from %llx to %llx\n", regs1->pstate, regs2->pstate);
    }

    if (regs1->sdei_ttbr1 != regs2->sdei_ttbr1) {
        memd_info("sdei_ttbr1 changed from %llx to %llx\n", regs1->sdei_ttbr1, regs2->sdei_ttbr1);
    }

    if (regs1->pmr_save != regs2->pmr_save) {
        memd_info("pmr_save changed from %llx to %llx\n", regs1->pmr_save, regs2->pmr_save);
    }

    if (regs1->stackframe[0] != regs2->stackframe[0] || regs1->stackframe[1] != regs2->stackframe[1]) {
        memd_info("stackframe changed from [%llx, %llx] to [%llx, %llx]\n", regs1->stackframe[0], regs1->stackframe[1],
                 regs2->stackframe[0], regs2->stackframe[1]);
    }
#endif
}

void compare_task_struct(struct task_struct* task1, struct task_struct* task2) {
#if CONFIG_COMPARE_TASK == 1
    memd_info("==> Comparing task_struct:\n");
#ifdef CONFIG_THREAD_INFO_IN_TASK
    if (task1->thread_info.flags != task2->thread_info.flags) {
        memd_info("thread_info.flags changed from %lx to %lx\n", task1->thread_info.flags, task2->thread_info.flags);
    }

    if (task1->thread_info.cpu != task2->thread_info.cpu) {
        memd_info("thread_info.cpu changed from %d to %d\n", task1->thread_info.cpu, task2->thread_info.cpu);
    }
#endif

    if (task1->__state != task2->__state) {
        memd_info("__state changed from %u to %u\n", task1->__state, task2->__state);
    }

    if (task1->stack != task2->stack) {
        memd_info("stack pointer changed from %p to %p\n", task1->stack, task2->stack);
    }

    if (task1->flags != task2->flags) {
        memd_info("flags changed from %u to %u\n", task1->flags, task2->flags);
    }

    if (task1->ptrace != task2->ptrace) {
        memd_info("ptrace changed from %u to %u\n", task1->ptrace, task2->ptrace);
    }

    if (task1->pid != task2->pid) {
        memd_info("pid changed from %d to %d\n", task1->pid, task2->pid);
    }

    if (task1->tgid != task2->tgid) {
        memd_info("tgid changed from %d to %d\n", task1->tgid, task2->tgid);
    }
#endif
}

#define W_PHYS_PFN(x) ((unsigned long)((x) >> PAGE_SHIFT))
#define memd_phys_to_pfn(paddr) W_PHYS_PFN(paddr)

struct page* vaddr_to_page(struct mm_struct* mm, uintptr_t va) {
#if !defined(pfn_to_page)
#error "vaddr_to_page failed: pfn_to_page not found"
#endif
    return pfn_to_page(memd_phys_to_pfn(vaddr_to_phy_addr(mm, va)));
}

/* Kernel-VA translation without struct trust: task/mm layouts also skew
 * across OEMs (proven: active_mm/pgd chain lands outside the image), so
 * read TTBR1_EL1 (swapper pgd phys, a register, no structs) and walk
 * physically, resolving each table VA via the linear map. Every table
 * read is extable-guarded (tables mutate under us). Leaf-aware (kernel
 * text is block-mapped). Read-only; never for kernel-text writes. */
int memd_safe_read64(const void *src, unsigned long *dst)
{
    unsigned long v;
    int err = -EFAULT;
    asm volatile(
        "1: ldr %1, [%2]\n"
        "   mov %w0, #0\n"
        "2:\n"
        "   .pushsection __ex_table, \"a\"\n"
        "   .balign 4\n"
        "   .long (1b - .), (2b - .)\n"
        "   .popsection\n"
        : "+r" (err), "=r" (v) : "r" (src) : "memory");
    if (!err)
        *dst = v;
    return err;
}

int memd_safe_read32(const void *src, unsigned int *dst)
{
    unsigned int v;
    int err = -EFAULT;
    asm volatile(
        "1: ldr %w1, [%2]\n"
        "   mov %w0, #0\n"
        "2:\n"
        "   .pushsection __ex_table, \"a\"\n"
        "   .balign 4\n"
        "   .long (1b - .), (2b - .)\n"
        "   .popsection\n"
        : "+r" (err), "=r" (v) : "r" (src) : "memory");
    if (!err)
        *dst = v;
    return err;
}

/* Guarded u64 store (extable fixup on fault). Used for PTE AP flips and
 * table entries that may be mapped read-only. */
int memd_safe_write64(void *dst, unsigned long v)
{
    int err = -EFAULT;
    asm volatile(
        "1: str %1, [%2]\n"
        "   mov %w0, #0\n"
        "2:\n"
        "   .pushsection __ex_table, \"a\"\n"
        "   .balign 4\n"
        "   .long (1b - .), (2b - .)\n"
        "   .popsection\n"
        : "+r" (err) : "r" (v), "r" (dst) : "memory");
    return err;
}

/* Write a u64 to a possibly read-only kernel page (e.g. sys_call_table
 * under STRICT_KERNEL_RWX): walk TTBR1 to the covering descriptor,
 * flip AP to writable, local TLBI, guarded store, readback verify,
 * exact descriptor restore, TLBI again. Zero new imports, no hypercalls.
 * RKP-active kernels may trap the descriptor write itself (accepted
 * owner risk); plain faults become clean errors, never panics. */
int memd_table_write64(unsigned long entry_va, unsigned long val)
{
    unsigned long ttbr, base, v;
    pgd_t pgd;
    p4d_t p4d;
    pud_t pud;
    pmd_t pmd;
    unsigned long desc_va = 0;
    unsigned long orig_desc = 0;
    unsigned long rw_desc;
    int need_flip = 0;
    int ret = -EFAULT;

    ttbr = read_sysreg(ttbr1_el1);
    base = ttbr & 0x0000FFFFFFFFF000UL;
    if (!base) {
            memd_err("table_write64: stage 0 fail va=%lx\n", entry_va);
        return -EFAULT;
    }
    if (memd_safe_read64(phys_to_virt(base + (unsigned long)pgd_index(entry_va) * 8), &v)) {
            memd_err("table_write64: stage 1 fail va=%lx\n", entry_va);
        return -EFAULT;
    }
    pgd = __pgd(v);
    if (pgd_none(pgd) || pgd_bad(pgd)) {
            memd_err("table_write64: stage 2 fail va=%lx\n", entry_va);
        return -EFAULT;
    }
    {
        p4d_t *p = p4d_offset(&pgd, entry_va);
        if (memd_safe_read64(p, &v))
            {
                memd_err("table_write64: stage 3 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        p4d = __p4d(v);
        if (p4d_none(p4d) || p4d_bad(p4d))
            {
                memd_err("table_write64: stage 4 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
    }
    {
        pud_t *p = pud_offset(&p4d, entry_va);
        if (memd_safe_read64(p, &v))
            {
                memd_err("table_write64: stage 5 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        pud = __pud(v);
        if (pud_none(pud))
            {
                memd_err("table_write64: stage 6 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
    }
    if (!pud_leaf(pud)) {
        if (pud_bad(pud))
            {
                memd_err("table_write64: stage 7 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        pmd_t *p = pmd_offset(&pud, entry_va);
        if (memd_safe_read64(p, &v))
            {
                memd_err("table_write64: stage 8 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        pmd = __pmd(v);
        if (pmd_none(pmd))
            {
                memd_err("table_write64: stage 9 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        if (pmd_bad(pmd) && !pmd_leaf(pmd))
            {
                memd_err("table_write64: stage 10 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        if (!pmd_leaf(pmd)) {
            pte_t *p = pte_offset_kernel(&pmd, entry_va);
            desc_va = (unsigned long)p;
            if (memd_safe_read64(p, &v))
            {
                memd_err("table_write64: stage 11 fail va=%lx\n", entry_va);
                    return -EFAULT;
        }
            orig_desc = v;
        } else {
            desc_va = (unsigned long)pmd_offset(&pud, entry_va);
            orig_desc = v;
        }
    } else {
        desc_va = (unsigned long)pud_offset(&p4d, entry_va);
        orig_desc = v;
    }
    if (!(orig_desc & 1)) {
            memd_err("table_write64: stage 12 fail va=%lx\n", entry_va);
        return -EFAULT;
    }
    /* Descriptor sanity before touching anything: must be a table or
     * block descriptor whose output address is DRAM (not MMIO/device).
     * A mis-walked garbage descriptor fails here instead of corrupting
     * random page tables. AP[1] set means read-only at EL1. */
    {
        unsigned long out = orig_desc & 0x0000FFFFFFFFF000UL;
        unsigned long type = orig_desc & 3UL;
        if (type != 3UL && ((orig_desc & 3UL) != 1UL))
            {
                memd_err("table_write64: stage 13 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
        if (out < 0x40000000UL || out >= (64UL << 30))
            {
                memd_err("table_write64: stage 14 fail va=%lx\n", entry_va);
                return -EFAULT;
        }
    }
    /* AP[1] (bit 7) set means read-only at EL1; clear it for the write.
     * Bit 7 is the RO bit for table, block and page descriptors alike. */
    rw_desc = orig_desc & ~0x80UL;
    need_flip = (rw_desc != orig_desc);
    preempt_disable();
    if (need_flip) {
        /* Break-Before-Make: changing AP on a live descriptor without a
         * break step leaves stale TLB entries (still RO) behind. Break
         * (invalidate), invalidate TLB, then make (RW), invalidate again. */
        if (memd_safe_write64((void *)desc_va, orig_desc & ~1UL)) {
            memd_err("table_write64: break store fail va=%lx\n", entry_va);
            goto out_preempt;
        }
        asm volatile("dsb ish\ntlbi vaae1, %0\ndsb ish\nisb\n" ::"r" (entry_va) : "memory");
        if (memd_safe_write64((void *)desc_va, rw_desc)) {
            memd_err("table_write64: flip store fail va=%lx\n", entry_va);
            goto out_preempt;
        }
        asm volatile("dsb ish\ntlbi vaae1, %0\ndsb ish\nisb\n" ::"r" (entry_va) : "memory");
    }
    /* Entry store with bounded retry (proven transient: first attempt
     * can fault on a stale RO TLB despite BBM+TLBI; immediate retry
     * succeeds. Still fail-closed after 3 — persistent failure is a
     * real problem, not a flake.) */
    {
        int attempt;
        for (attempt = 0; attempt < 3; attempt++) {
            if (!memd_safe_write64((void *)entry_va, val))
                break;
            if (attempt)
                memd_err("table_write64: entry store fail va=%lx (try %d)\n",
                         entry_va, attempt);
            asm volatile("dsb ish\ntlbi vaae1, %0\ndsb ish\nisb\n" ::"r" (entry_va) : "memory");
        }
        if (attempt >= 3) {
            memd_err("table_write64: entry store fail va=%lx\n", entry_va);
            goto restore;
        }
    }
    {
        unsigned long back = 0;
        if (memd_safe_read64((void *)entry_va, &back) || back != val) {
            memd_err("table_write64: readback mismatch va=%lx\n", entry_va);
            goto restore;
        }
    }
    ret = 0;
restore:
    if (need_flip) {
        /* BBM restore: break, invalidate, remake original, invalidate. */
        memd_safe_write64((void *)desc_va, orig_desc & ~1UL);
        asm volatile("dsb ish\ntlbi vaae1, %0\ndsb ish\nisb\n" ::"r" (entry_va) : "memory");
        memd_safe_write64((void *)desc_va, orig_desc);
        asm volatile("dsb ish\ntlbi vaae1, %0\ndsb ish\nisb\n" ::"r" (entry_va) : "memory");
    }
out_preempt:
    preempt_enable();
    return ret;
}

/* Page permissions + phys for a kernel VA without touching content
 * (safe on execute-only mappings): TTBR1 walk, descriptor metadata only.
 * 0 ok (fields filled, present=0 when unmapped), negative err. */
int memd_page_perms(uintptr_t va, uintptr_t *pa_out, unsigned *present_out,
                    unsigned *level_out, unsigned *ap_out, unsigned *xn_out,
                    unsigned long *desc_out)
{
    unsigned long ttbr, base, v;
    pgd_t pgd;
    p4d_t p4d;
    pud_t pud;
    pmd_t pmd;

    *pa_out = 0;
    *present_out = 0;
    *level_out = 3;
    *ap_out = 0;
    *xn_out = 1;
    ttbr = read_sysreg(ttbr1_el1);
    base = ttbr & 0x0000FFFFFFFFF000UL;
    if (!base)
        return -EFAULT;
    if (memd_safe_read64(phys_to_virt(base + (unsigned long)pgd_index(va) * 8), &v))
        return 0;
    pgd = __pgd(v);
    if (desc_out)
        desc_out[0] = v;
    if (pgd_none(pgd) || pgd_bad(pgd))
        return 0;
    {
        p4d_t *p = p4d_offset(&pgd, va);
        if (memd_safe_read64(p, &v))
            return 0;
        p4d = __p4d(v);
        if (p4d_none(p4d) || p4d_bad(p4d))
            return 0;
    }
    {
        pud_t *p = pud_offset(&p4d, va);
        if (memd_safe_read64(p, &v))
            return 0;
        pud = __pud(v);
        if (desc_out)
            desc_out[1] = v;
        if (pud_none(pud))
            return 0;
    }
    *present_out = 1;
    if (pud_leaf(pud)) {
        *level_out = 0;
        *ap_out = (unsigned)((v >> 6) & 3);
        *xn_out = (unsigned)((v >> 53) & 3);
        *pa_out = (pud_pfn(pud) << PAGE_SHIFT) + (va & ((1UL << 30) - 1));
        return 0;
    }
    if (pud_bad(pud)) {
        *present_out = 0;
        return 0;
    }
    {
        pmd_t *p = pmd_offset(&pud, va);
        if (memd_safe_read64(p, &v))
            return 0;
        pmd = __pmd(v);
        if (desc_out)
            desc_out[2] = v;
        if (pmd_none(pmd)) {
            *present_out = 0;
            return 0;
        }
    }
    if (pmd_leaf(pmd)) {
        *level_out = 1;
        *ap_out = (unsigned)((v >> 6) & 3);
        *xn_out = (unsigned)((v >> 53) & 3);
        *pa_out = (pmd_pfn(pmd) << PAGE_SHIFT) + (va & ((1UL << 21) - 1));
        return 0;
    }
    if (pmd_bad(pmd)) {
        *present_out = 0;
        return 0;
    }
    {
        pte_t *p = pte_offset_kernel(&pmd, va);
        pte_t pte;
        if (memd_safe_read64(p, &v))
            return 0;
        pte = __pte(v);
        if (desc_out)
            desc_out[3] = v;
        if (!pte_present(pte)) {
            *present_out = 0;
            return 0;
        }
        *level_out = 2;
        *ap_out = (unsigned)((v >> 6) & 3);
        *xn_out = (unsigned)((v >> 53) & 3);
        *pa_out = (pte_pfn(pte) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
        return 0;
    }
}

static uintptr_t kaddr_to_phy_addr(uintptr_t va)
{
    unsigned long ttbr, base, v;
    pgd_t pgd;
    p4d_t p4d;
    pud_t pud;
    pmd_t pmd;
    pte_t pte;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;

    ttbr = read_sysreg(ttbr1_el1);
    base = ttbr & 0x0000FFFFFFFFF000UL;
    if (!base)
        return 0;
    if (memd_safe_read64(phys_to_virt(base + (unsigned long)pgd_index(va) * 8), &v))
        return 0;
    pgd = __pgd(v);
    if (pgd_none(pgd) || pgd_bad(pgd))
        return 0;
    p4dp = p4d_offset(&pgd, va);
    if (memd_safe_read64(p4dp, &v))
        return 0;
    p4d = __p4d(v);
    if (p4d_none(p4d) || p4d_bad(p4d))
        return 0;
    pudp = pud_offset(&p4d, va);
    if (memd_safe_read64(pudp, &v))
        return 0;
    pud = __pud(v);
    if (pud_none(pud))
        return 0;
    if (pud_leaf(pud))
        return (pud_pfn(pud) << PAGE_SHIFT) + (va & ((1UL << 30) - 1));
    if (pud_bad(pud))
        return 0;
    pmdp = pmd_offset(&pud, va);
    if (memd_safe_read64(pmdp, &v))
        return 0;
    pmd = __pmd(v);
    if (pmd_none(pmd))
        return 0;
    if (pmd_leaf(pmd))
        return (pmd_pfn(pmd) << PAGE_SHIFT) + (va & ((1UL << 21) - 1));
    if (pmd_bad(pmd))
        return 0;
    ptep = pte_offset_kernel(&pmd, va);
    if (memd_safe_read64(ptep, &v))
        return 0;
    pte = __pte(v);
    if (!pte_present(pte))
        return 0;
    return (pte_pfn(pte) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
}

int translate_process_vaddr(pid_t pid, uintptr_t vaddr, uintptr_t* paddr_out) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    uintptr_t paddr;

    /* Canonical-high addresses are kernel VAs on every VA_BITS config:
     * walk swapper directly (pid is irrelevant, no task touched).
     * Priv-gated: kernel memory reads defeat KASLR for any local
     * process, so non-root gets nothing here (user reads unaffected). */
    if ((long)vaddr < 0) {
        if (!memd_capable(CAP_SYS_ADMIN))
            return -EPERM;
        paddr = kaddr_to_phy_addr(vaddr);
        pr_info("[memd] kread: va=%lx -> pa=%lx\n", vaddr, paddr);
        /* Sanity bounds BEFORE pfn_valid: a garbage walk result used as
         * a pfn array index faults unguarded (oops->panic), and a
         * garbage phys in MMIO space can raise Synchronous External
         * Abort (not extable-fixable -> silent reboot). DRAM on all
         * targets lives at/above 0x40000000 (QEMU) or 0x80000000
         * (Samsung); MMIO sits below; nothing real exceeds 64GB.
         * Anything outside is walk garbage: refuse cleanly. */
        if (!paddr || paddr < 0x40000000UL || paddr >= (64UL << 30))
            return -EFAULT;
        *paddr_out = paddr;
        return 0;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        memd_warn("failed to find pid_struct: %d\n", pid);
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_warn("failed to get task: %d\n", pid);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        memd_warn("failed to get mm: %d\n", pid);
        put_task_struct(task);
        return -ESRCH;
    }

    paddr = vaddr_to_phy_addr(mm, vaddr);
    
    mmput(mm);
    put_task_struct(task);

    if (paddr == 0) {
        return -EFAULT;
    }

    *paddr_out = paddr;
    return 0;
}

uintptr_t get_module_base(pid_t pid, char* name, int vm_flag) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct* vma;
    unsigned long addr;
    uintptr_t result;
    struct dentry* dentry;
    size_t name_len, dname_len;

    result = 0;

    name_len = strlen(name);
    if (name_len == 0) {
        memd_err("module name is empty\n");
        return 0;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        memd_err("failed to find pid_struct\n");
        return 0;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_err("failed to get task from pid_struct\n");
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        memd_err("failed to get mm from task\n");
        return 0;
    }
    memd_learn_vma_once();

    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */

    /* find_vma() is stable + exported on 5.10 through 6.12 (list walk
     * below, maple walk above): mm->mmap / vma_iterator would pin the
     * image to one side of 6.1. The name differs by generation
     * (find_vma vs __find_vma): resolve both at runtime. */
    {
        static struct vm_area_struct *(*vma_find)(struct mm_struct *,
                                                  unsigned long) = NULL;
        static bool vma_probed = false;
        if (!vma_probed) {
            vma_probed = true;
            vma_find = (void *)kallsyms_lookup_name_ex("find_vma");
            if (!vma_find)
                vma_find = (void *)kallsyms_lookup_name_ex("__find_vma");
        }
        if (!vma_find) {
            /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */
            mmput(mm);
            return 0;
        }
        for (addr = 0; (vma = vma_find(mm, addr)) != NULL;
             addr = memd_v_end(vma)) {
            if (addr >= memd_v_end(vma))
                break; /* wrapped or stuck: never spin */
        {
            unsigned long _vf = memd_v_file(vma);
            if (!_vf)
                continue;
            if (vm_flag && !(vma->vm_flags & vm_flag)) {
                continue;
            }
            dentry = memd_file_dentry((struct file *)_vf);
            if (!dentry)
                continue;
            dname_len = dentry->d_name.len;
            if (!memcmp(dentry->d_name.name, name, min(name_len, dname_len))) {
                result = memd_v_start(vma);
                goto ret;
            }
        }
    }
    }

ret:
    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */

    mmput(mm);
    return result;
}

int is_pid_alive(pid_t pid) {
    struct pid* pid_struct;
    struct task_struct* task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

/* Single find_process_by_name: get_cmdline via runtime kallsyms
 * (6.1+ kernels), transparent fallback to get_cmdline_ex below. */
int get_cmdline_ex(struct task_struct *task, char *buffer, int buflen);
pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char* prog_name;
    size_t name_len;
    int ret;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("process name is empty\n");
        return -2;
    }

    static int (*my_get_cmdline)(struct task_struct* task, char* buffer, int buflen) = NULL;
    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void*)kallsyms_lookup_name_ex("get_cmdline");
    }
    if (my_get_cmdline == NULL) {
        /* pre-6.1 (or restricted) kernels: read argv the slow way */
        my_get_cmdline = get_cmdline_ex;
    }

    rcu_read_lock();
    for_each_process(task) {
        if (memd_t_mm_null(task)) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
        } else {
            ret = -1;
        }

        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            {
                char tcomm[16] = {0};
                pid_t _p;
                memd_t_comm(task, tcomm, sizeof(tcomm));
                if (strlen(tcomm) == name_len && strncmp(tcomm, name, name_len) == 0) {
                    _p = memd_t_pid(task);
                    rcu_read_unlock();
                    return _p;
                }
            }
        } else {
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            char* space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            char* slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                pid_t _p = memd_t_pid(task);
                rcu_read_unlock();
                return _p;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

int get_cmdline_ex(struct task_struct* task, char* buffer, int buflen) {
    int res = 0;
    unsigned int len;
    struct mm_struct* mm = get_task_mm(task);
    unsigned long arg_start, arg_end, env_start, env_end;
    if (!mm)
        goto out;
    if (!mm->arg_end)
        goto out_mm; /* Shh! No looking before we're done */

    spin_lock(&mm->arg_lock);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    env_start = mm->env_start;
    env_end = mm->env_end;
    spin_unlock(&mm->arg_lock);

    len = arg_end - arg_start;

    if (len > buflen)
        len = buflen;

    res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

    /*
     * If the nul at the end of args has been overwritten, then
     * assume application is using setproctitle(3).
     */
    if (res > 0 && buffer[res - 1] != '\0' && len < buflen) {
        len = strnlen(buffer, res);
        if (len < res) {
            res = len;
        } else {
            len = env_end - env_start;
            if (len > buflen - res)
                len = buflen - res;
            res += access_process_vm(task, env_start, buffer + res, len, FOLL_FORCE);
            res = strnlen(buffer, res);
        }
    }
out_mm:
    mmput(mm);
out:
    return res;
}


static struct list_head* module_previous;
static struct list_head* module_kobj_previous;
static short module_hidden = 0;

void show_module(void) {
    // list_add(&THIS_MODULE->list, module_previous);
    // kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "%s", THIS_MODULE->name);
    // list_add(&THIS_MODULE->mkobj.kobj.entry, module_kobj_previous);
    module_hidden = 0;
}

void hide_module(void) {
#if defined(HIDE_SELF_MODULE)
    if (is_file_exist("/proc/sched_debug")) {
        remove_proc_entry("sched_debug", NULL);
    }

    if (is_file_exist("/proc/uevents_records")) {
        remove_proc_entry("uevents_records", NULL);
    }

#ifdef MODULE
    // module_previous = THIS_MODULE->list.prev;
    // module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
    //
    list_del(&THIS_MODULE->list); // lsmod,/proc/modules
    kobject_del(&THIS_MODULE->mkobj.kobj); // /sys/modules
    list_del(&THIS_MODULE->mkobj.kobj.entry); // kobj struct list_head entry
    module_hidden = 1;
#endif

    // protocol disguise! A lie
    memcpy(THIS_MODULE->name, "nfc\0", 4);
    // remove_proc_entry("protocols", net->proc_net);
#endif
}

int give_root(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
    current->uid = current->gid = 0;
    current->euid = current->egid = 0;
    current->suid = current->sgid = 0;
    current->fsuid = current->fsgid = 0;
#else
    struct cred* newcreds;
    static struct cred* (*my_prepare_creds)(void) = NULL;
    static int (*my_commit_creds)(struct cred*) = NULL;
    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void*)kallsyms_lookup_name_ex("prepare_creds");
        my_commit_creds = (void*)kallsyms_lookup_name_ex("commit_creds");
        if (my_prepare_creds == NULL || my_commit_creds == NULL) {
            return -1;
        }
    }
    newcreds = my_prepare_creds();
    if (newcreds == NULL)
        return -2;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) ||                      \
    LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
#endif
    my_commit_creds(newcreds);
#endif
    return 0;
}

void __iomem* memd_ioremap_prot(uintptr_t phys_addr, size_t size, pgprot_t prot) {
    unsigned long offset, vaddr;
    uintptr_t last_addr;
    struct vm_struct* area;
    int err;

    offset = phys_addr & ~PAGE_MASK;
    /*
     * Page align the mapping address and size, taking account of any
     * offset.
     */
    phys_addr &= PAGE_MASK;
    size = PAGE_ALIGN(size + offset);

    /*
     * Don't allow wraparound, zero size or outside PHYS_MASK.
     */
    last_addr = phys_addr + size - 1;
    if (!size || last_addr < phys_addr || last_addr & ~PHYS_MASK)
        return NULL;

    static int (*my_ioremap_page_range)(unsigned long addr, unsigned long end,
               uintptr_t phys_addr, pgprot_t prot) = NULL;
    static void (*my_free_vm_area)(struct vm_struct *area) = NULL;
    if (my_ioremap_page_range == NULL || my_free_vm_area == NULL) {
        my_ioremap_page_range = (int (*)(unsigned long addr, unsigned long end,
                   uintptr_t phys_addr, pgprot_t prot))kallsyms_lookup_name_ex("ioremap_page_range");
        my_free_vm_area = (void (*)(struct vm_struct *area))kallsyms_lookup_name_ex("free_vm_area");
        if (my_ioremap_page_range == NULL || my_free_vm_area == NULL) {
            memd_err("cannot find ioremap_page_range or free_vm_area\n");
            return NULL;
        }
    }

    /* __get_vm_area_caller (6.6+) first, get_vm_area_caller (5.10+) as
     * fallback: both resolved by name at runtime, one image either way. */
    {
        static struct vm_struct *(*area4)(unsigned long, unsigned long,
                unsigned long, unsigned long, const void *) = NULL;
        static struct vm_struct *(*area3)(unsigned long, unsigned long,
                const void *) = NULL;
        static bool probed = false;
        if (!probed) {
            probed = true;
            area4 = (void *)kallsyms_lookup_name_ex("__get_vm_area_caller");
            area3 = (void *)kallsyms_lookup_name_ex("get_vm_area_caller");
        }
        if (area4)
            area = area4(size, VM_IOREMAP, VMALLOC_START, VMALLOC_END,
                         __builtin_return_address(0));
        else if (area3)
            area = area3(size, VM_IOREMAP, __builtin_return_address(0));
        else {
            memd_err("cannot find vm area allocator\n");
            return NULL;
        }
    }

    if (!area)
        return NULL;
    vaddr = (unsigned long)area->addr;
    area->phys_addr = phys_addr;

    err = my_ioremap_page_range(vaddr, vaddr + size, phys_addr, prot);
    if (err) {
        my_free_vm_area(area);
        return NULL;
    }

    return (void __iomem*)(vaddr + offset);
}

int cfi_bypass(void) {
    int ret = 0;
    unsigned int RET = 0xD65F03C0; // ret指令 (aarch64)
    unsigned int MOV_X0_1 = 0xD2800020; // mov x0, #1 20 00 80 D2

    unsigned long f__cfi_slowpath = kallsyms_lookup_name_ex("__cfi_slowpath");
    if (f__cfi_slowpath) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch __cfi_slowpath successed\n");
        } else {
            memd_info("__cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_slowpath_diag = kallsyms_lookup_name_ex("__cfi_slowpath_diag");
    if (f__cfi_slowpath_diag) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath_diag;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch __cfi_slowpath_diag successed\n");
        } else {
            memd_info("__cfi_slowpath_diag already patched\n");
        }
    }

    unsigned long f_cfi_slowpath = kallsyms_lookup_name_ex("_cfi_slowpath");
    if (f_cfi_slowpath) {
        unsigned int* p = (unsigned int*)f_cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch _cfi_slowpath successed\n");
        } else {
            memd_info("_cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_check_fail = kallsyms_lookup_name_ex("__cfi_check_fail");
    if (f__cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch __cfi_check_fail successed\n");
        } else {
            memd_info("__cfi_check_fail already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail_abort = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail_abort");
    if (f__ubsan_handle_cfi_check_fail_abort) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail_abort;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch __ubsan_handle_cfi_check_fail_abort successed\n");
        } else {
            memd_info("__ubsan_handle_cfi_check_fail_abort already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail");
    if (f__ubsan_handle_cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            memd_err("patch __ubsan_handle_cfi_check_fail successed\n");
        } else {
            memd_info("__ubsan_handle_cfi_check_fail already patched\n");
        }
    }

    unsigned long freport_cfi_failure = kallsyms_lookup_name_ex("report_cfi_failure");
    if (freport_cfi_failure) {
        unsigned int* p = (unsigned int*)freport_cfi_failure;
        if(*p != MOV_X0_1) {
            hook_write_range(p, &MOV_X0_1, INSTRUCTION_SIZE);
            hook_write_range(p + 1, &RET, INSTRUCTION_SIZE);
            ret++;
        } else {
            memd_info("report_cfi_failure already patched\n");
        }
    }

    return ret;
}

/**
 * convert_wmt_to_pgprot - Convert WMT memory type to pgprot_t
 * @wmt_type: WMT memory type constant (WMT_NORMAL, WMT_DEVICE_*, etc.)
 * @prot_out: Output pgprot_t value
 *
 * Return: 0 on success, negative error code on failure
 */
int convert_wmt_to_pgprot(int wmt_type, pgprot_t* prot_out) {
    switch (wmt_type) {
        case WMT_NORMAL:
            *prot_out = __pgprot(PROT_NORMAL);
            return 0;

        case WMT_NORMAL_TAGGED:
#if defined(PROT_NORMAL_TAGGED)
            *prot_out = __pgprot(PROT_NORMAL_TAGGED);
            return 0;
#else
            memd_warn("PROT_NORMAL_TAGGED not defined on this kernel\n");
            return -EINVAL;
#endif

        case WMT_NORMAL_NC:
#if defined(PROT_NORMAL_NC)
            *prot_out = __pgprot(PROT_NORMAL_NC);
            return 0;
#else
            memd_warn("PROT_NORMAL_NC not defined on this kernel\n");
            return -EINVAL;
#endif

        case WMT_NORMAL_WT:
#if defined(PROT_NORMAL_WT)
            *prot_out = __pgprot(PROT_NORMAL_WT);
            return 0;
#else
            memd_warn("PROT_NORMAL_WT not defined on this kernel\n");
            return -EINVAL;
#endif

        case WMT_DEVICE_nGnRnE:
#if defined(PROT_DEVICE_nGnRnE)
            *prot_out = __pgprot(PROT_DEVICE_nGnRnE);
            return 0;
#else
            memd_warn("PROT_DEVICE_nGnRnE not defined on this kernel\n");
            return -EINVAL;
#endif

        case WMT_DEVICE_nGnRE:
#if defined(PROT_DEVICE_nGnRE)
            *prot_out = __pgprot(PROT_DEVICE_nGnRE);
            return 0;
#else
            memd_warn("PROT_DEVICE_nGnRE not defined on this kernel\n");
            return -EINVAL;
#endif

        default:
            memd_warn("invalid prot: %d\n", wmt_type);
            return -EINVAL;
    }
}