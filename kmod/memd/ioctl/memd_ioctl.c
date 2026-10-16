#include "memd_ioctl.h"
#include "memd_uaccess.h"

#include <asm-generic/errno-base.h>
#include <linux/capability.h>
#include <linux/preempt.h>

#include "memd_hide.h"
#include "memd_kallsyms.h"
#include "memd_learn.h"
#include "memd_hwbp.h"
#include "memd_gyro.h"
#include "memd_sigforce.h"
#ifdef MEMD_DISP_TEST
#include "disp_core.h"
#endif
#include "memd_syshook.h"
#include "memd_display.h"

#include "memd_page_walk.h"
#include "memd_sock.h"
#include "memd_utils.h"
#include "memd_region.h"

#include <asm/pgtable-prot.h>
#include <asm/pgtable-types.h>
#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "memd_proc.h"

int do_vaddr_translate(struct socket* sock, void* arg) {
    struct memd_addr_translate_cmd cmd;
    int ret;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    ret = translate_process_vaddr(cmd.pid, cmd.va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_debug_info(struct socket* sock, void* arg) {
    struct memd_debug_info_cmd debug_info_cmd;

    /* Zero first: the struct ends with 4 bytes of tail padding after
     * mm_right that no field assignment touches; copy_to_user below
     * would otherwise leak kernel stack to userspace. */
    memset(&debug_info_cmd, 0, sizeof(debug_info_cmd));
    /* No mmap lock here by construction (not an omission): this is
     * current's OWN mm, pinned for the whole syscall — current cannot
     * exit while executing, and only current itself (sequentially, no
     * concurrency) can change current->mm. virt_to_phys needs no lock
     * (linear map), pgd is fixed at fork, and ASID/mm_right are
     * best-effort diagnostics (a rollover-stale value is reported, never
     * used for translation). A foreign mm would need MM_READ_LOCK. */
    {
        struct mm_struct *dmm = memd_t_mm(current);
        debug_info_cmd.ttbr0_el1 = read_sysreg_s(SYS_TTBR0_EL1);
        debug_info_cmd.task_struct = (u64)current;
        debug_info_cmd.mm_struct = (u64)dmm;
        debug_info_cmd.pgd_addr = dmm ? (u64)memd_m_pgd(dmm) : 0;
        debug_info_cmd.pgd_phys_addr = dmm ? virt_to_phys(memd_m_pgd(dmm)) : 0;
        debug_info_cmd.mm_asid = dmm ? ASID(dmm) : 0;
        debug_info_cmd.mm_right = dmm ?
            (((uint64_t)(ASID(dmm)) << 48 | virt_to_phys(memd_m_pgd(dmm)) | (uint64_t)1) ==
            debug_info_cmd.ttbr0_el1) : 0;
    }

    if (memd_copy_to_user(arg, &debug_info_cmd, sizeof(debug_info_cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_at_s1e0r(struct socket* sock, void* arg) {
    struct memd_at_s1e0r_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        memd_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        memd_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    u64 original_ttbr0 = read_sysreg_s(SYS_TTBR0_EL1);
    u64 new_ttbr0 = (uint64_t)(ASID(mm)) << 48 | virt_to_phys(memd_m_pgd(mm)) | (uint64_t)1;
    /* TTBR0 is per-CPU: pin the CPU across msr/AT/restore, else a
     * migration would corrupt the new CPU's TTBR0. */
    preempt_disable();
    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" ::"r"(new_ttbr0));
    dsb(ish);
    isb();

    asm volatile("at s1e0r, %0" ::"r"(cmd.va));
    isb();
    uintptr_t pa = read_sysreg_s(SYS_PAR_EL1);

    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" ::"r"(original_ttbr0));
    dsb(ish);
    isb();
    preempt_enable();
    mmput(mm);

    /* PAR_EL1 bit 0 is F (fault): translation failed. Phys lives in
     * bits [47:12]; the page offset comes from the VA. */
    if (pa & 1) {
        return -EFAULT;
    }
    cmd.phy_addr = (pa & 0x0000FFFFFFFFF000UL) | (cmd.va & (PAGE_SIZE - 1));
    if (cmd.phy_addr == 0) {
        return -EFAULT;
    }

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_get_page_info(struct socket* sock, void* arg) {
    struct memd_page_info_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        memd_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        memd_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct page* page_struct = vaddr_to_page(mm, cmd.va);
    if (!page_struct) {
        memd_warn("failed to get page for va: %lx\n", cmd.va);
        mmput(mm);
        return -EFAULT;
    }

    uintptr_t phy_addr = page_to_phys(page_struct);
    cmd.page.phy_addr = phy_addr;
    cmd.page.flags = page_struct->flags;
    cmd.page._mapcount = page_struct->_mapcount;
    cmd.page._refcount = page_struct->_refcount;
    {
        bool bad = (cmd.page.phy_addr == 0);
        mmput(mm);
        if (bad)
            return -EFAULT;
    }

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_pte_mapping(struct socket* sock, void* arg) {
#if defined(BUILD_PTE_MAPPING)
    // 这里需要注意 android kenel 6.6.66找不到 pte_mkwrite
    struct memd_sock* ws;
    struct memd_pte_mapping_cmd cmd;
    if (!sock || !sock->sk) {
        return -EINVAL;
    }
    ws = (struct memd_sock*)sock->sk;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.pid <= 0) {
        memd_warn("invalid pid: %d\n", cmd.pid);
        return -EINVAL;
    }

    /* Tracker/session must exist before any PTE is installed: the
     * success path cannot fail after set_pte, so a missing tracker
     * would leak untracked live pages. */
    if (!ws->used_pages) {
        memd_err("used_pages array not initialized\n");
        return -EINVAL;
    }
    if (cmd.hide && !ws->session) {
        memd_err("session not initialized\n");
        return -EINVAL;
    }

    if (cmd.start_addr >= TASK_SIZE_64) {
        memd_warn("invalid start address: 0x%lx\n", cmd.start_addr);
        return -EINVAL;
    }

    if (cmd.num_pages == 0 || cmd.num_pages > (TASK_SIZE_64 - cmd.start_addr) / PAGE_SIZE) {
        memd_warn("invalid number of pages: %zu\n", cmd.num_pages);
        return -EINVAL;
    }

    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;
    struct page* page = NULL;
    struct vm_area_struct* vma;
    int ret = 0;

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        memd_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm;
    uid_t hide_uid;
    int have_uid;
    /* Foreign task layout skews across OEMs (proven, see
     * do_get_process_info): never dereference task->cred directly.
     * Learned offset + extable-guarded read; unknown -> have_uid = 0
     * (hide refused below, never aliased to uid 0). Snapshot
     * before put_task_struct: task may be freed after the put. */
    hide_uid = 0;
    have_uid = 0;
    {
        unsigned long cred_addr;
        unsigned int uid_val;
        if (memd_learned.t_cred >= 0 &&
            !memd_safe_read64((char *)task + memd_learned.t_cred, &cred_addr) && cred_addr &&
            !memd_safe_read32((const void *)(cred_addr + memd_cred_uid_off()), &uid_val)) {
            hide_uid = (uid_t)uid_val;
            have_uid = 1;
        }
    }
    /* Unknown uid must not alias uid 0 (root): fail the hide fast
     * before any PTE is installed. Mapping without hide stays allowed. */
    if (cmd.hide && !have_uid) {
        put_task_struct(task);
        memd_warn("unknown uid for pid %d, refusing hide\n", cmd.pid);
        return -EINVAL;
    }
    mm = get_task_mm(task);
    put_task_struct(task);
    task = NULL;
    if (!mm) {
        memd_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    static int (*my__pmd_alloc)(struct mm_struct* mm, pud_t* pud, unsigned long address) = NULL;
    my__pmd_alloc = (int (*)(struct mm_struct*, pud_t*, unsigned long))kallsyms_lookup_name_ex("__pmd_alloc");
    static int (*my__pte_alloc)(struct mm_struct* mm, pmd_t* pmd) = NULL;
    my__pte_alloc = (int (*)(struct mm_struct*, pmd_t*))kallsyms_lookup_name_ex("__pte_alloc");

    if (my__pmd_alloc == NULL || my__pte_alloc == NULL) {
        memd_err("failed to find __pmd_alloc or __pte_alloc symbols\n");
        ret = -ENOENT;
        goto out_mm;
    }

#define my_pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && my__pte_alloc(mm, pmd))
#define my_pte_alloc_map(mm, pmd, address) (my_pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))

    unsigned long addr = cmd.start_addr;
    size_t i;
    struct page** page_arr = kmalloc_array(cmd.num_pages, sizeof(struct page*), GFP_KERNEL);
    if (!page_arr) {
        memd_err("failed to allocate page array\n");
        ret = -ENOMEM;
        goto out_mm;
    }

    /* Installing PTEs in a live foreign mm without the write lock
     * races reclaim/fork/exit_mmap walks of the same tables. */
    /* Warm the kallsyms table outside the write lock: the first
     * find_vma resolve parses /proc/kallsyms (may sleep); doing that
     * under the held mmap write lock would hold writers across the
     * whole parse. Warmed here, the under-lock resolves below are
     * table-only (no file IO). No VMA walk here (that needs the lock);
     * result discarded. */
    (void)kallsyms_lookup_name_ex("find_vma");
    MM_WRITE_LOCK(mm);

    for (i = 0; i < cmd.num_pages; i++) {
        /* Revalidate under the held write lock: get_task_mm pinned the
         * mm_struct but the target could have munmapped this page in
         * the pin-to-lock window. find_vma is stable here (writers
         * blocked), so a miss means an orphan install: fail closed
         * before allocating any table. End-minus-addr form avoids any
         * addr + PAGE_SIZE wrap question. */
        vma = memd_find_vma(mm, addr);
        if (!vma || memd_v_start(vma) > addr || addr >= memd_v_end(vma) ||
            memd_v_end(vma) - addr < PAGE_SIZE) {
            ret = -EINVAL;
            memd_err("no vma for 0x%lx\n", addr);
            goto rollback;
        }
        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            ret = -EINVAL;
            memd_err("bad pgd for 0x%lx\n", addr);
            goto rollback;
        }

        p4d = p4d_alloc(mm, pgd, addr);
        if (!p4d) {
            ret = -ENOMEM;
            goto rollback;
        }

        pud = pud_alloc(mm, p4d, addr);
        if (!pud) {
            ret = -ENOMEM;
            goto rollback;
        }

        /* A pud block (1GB HugeTLB) has no child pmd table: pmd_offset
         * below would decode the block descriptor as a table base and
         * the pte walk would touch wild memory. Fail closed before
         * descending (same guard as the rollback walk). None must
         * allocate first: a none entry also reads as bad. */
        if (unlikely(pud_none(*pud))) {
            if (my__pmd_alloc(mm, pud, addr)) {
                memd_err("failed to allocate pmd\n");
                ret = -ENOMEM;
                goto rollback;
            }
        } else if (pud_bad(*pud) || pud_huge(*pud)) {
            ret = -EINVAL;
            memd_err("pud huge/bad for 0x%lx\n", addr);
            goto rollback;
        }

        pmd = pmd_offset(pud, addr);
        if (!pmd) {
            memd_err("failed to get pmd\n");
            ret = -ENOMEM;
            goto rollback;
        }

        /* A pmd block (2MB THP/HugeTLB) or a bad entry is not a pte
         * table: pte_offset_map below would decode leaf data as a
         * table base. Fail closed before the pte walk. None is the
         * need-a-table case (handled by my_pte_alloc_map below) and
         * also reads as bad, so only test present entries. */
        if (!pmd_none(*pmd) && (pmd_bad(*pmd) || pmd_huge(*pmd))) {
            ret = -EINVAL;
            memd_err("pmd huge/bad for 0x%lx\n", addr);
            goto rollback;
        }

        pte = my_pte_alloc_map(mm, pmd, addr);
        if (!pte) {
            ret = -ENOMEM;
            memd_err("failed to allocate pte for address 0x%lx\n", addr);
            goto rollback;
        }
        if (!pte_none(*pte)) {
            ret = -EEXIST;
            memd_err("pte already exists for address 0x%lx\n", addr);
            pte_unmap(pte);
            goto rollback;
        }

        page = alloc_page(GFP_USER | __GFP_ZERO);
        if (!page) {
            ret = -ENOMEM;
            memd_err("failed to allocate page %zu\n", i);
            pte_unmap(pte);
            goto rollback;
        }
        page_arr[i] = page;

        pte_t new_pte = mk_pte(page, PAGE_SHARED_EXEC);
        new_pte = pte_mkwrite(pte_mkdirty(pte_mkyoung(new_pte)));
        set_pte(pte, new_pte);
        pte_unmap(pte);

        memd_info("mapped page %zu at address 0x%lx\n", i, addr);
        addr += PAGE_SIZE;
    }

    /* Publish under the write lock, then flush: the PTEs are complete
     * here, so a concurrent fault either blocks on the lock or sees
     * present entries. */
    MM_WRITE_UNLOCK(mm);

    flush_tlb_all();

    mmput(mm);

    for (i = 0; i < cmd.num_pages; ++i) {
        struct page* p = page_arr[i];

        if (!p) {
            memd_err("page %zu is NULL\n", i);
            continue;
        }

        /* One ref stays with the installed PTE, one with the tracker:
         * freeing either side must not pull the page out from under
         * the other. */
        get_page(p);
        arraylist_add(ws->used_pages, p);
    }
    kfree(page_arr);

    if (cmd.hide) {
        memd_add_unsafe_region(ws->session, hide_uid, cmd.start_addr, cmd.num_pages);
    }

    memd_info("successfully mapped page at address 0x%lx for pid %d\n", cmd.start_addr, cmd.pid);
    return 0;

rollback:
    /* Still holding the write lock: zap every PTE installed above so
     * no live entry points at a page we are about to free, then
     * unlock, flush the stale entries, and only then free.
     * Non-allocating walk (p4d/pud/pmd_offset + pte_offset_map) lands
     * on the same pte the install wrote for every 4K page: indices
     * are pure functions of the address and the tables cannot change
     * under the held write lock. Divergence condition: an address
     * covered by a pud/pmd block mapping (1GB/2MB huge) or a bad
     * entry has no pte table at all, so pte_offset_map would decode
     * leaf data as a table base on EITHER walk. The install path now
     * rejects huge/bad before descending, so only pre-install 4K
     * entries are ever visited here; the huge/bad skips below are
     * defense-in-depth for the same condition. */
    {
        size_t j;
        unsigned long a;
        for (j = 0; j < i; j++) {
            a = cmd.start_addr + j * PAGE_SIZE;
            pgd = pgd_offset(mm, a);
            if (pgd_none(*pgd) || pgd_bad(*pgd))
                continue;
            p4d = p4d_offset(pgd, a);
            if (!p4d || p4d_none(*p4d))
                continue;
            pud = pud_offset(p4d, a);
            if (!pud || pud_none(*pud) || pud_bad(*pud) || pud_huge(*pud))
                continue;
            pmd = pmd_offset(pud, a);
            if (!pmd || pmd_none(*pmd) || pmd_bad(*pmd) || pmd_huge(*pmd))
                continue;
            pte = pte_offset_map(pmd, a);
            if (!pte)
                continue;
            if (!pte_none(*pte))
                pte_clear(mm, a, pte);
            pte_unmap(pte);
        }
    }
    MM_WRITE_UNLOCK(mm);
    flush_tlb_all();
    while (i--)
        __free_page(page_arr[i]);
    kfree(page_arr);
out_mm:
    mmput(mm);
    return ret;
#else
    /* Feature compiled out: not a bad argument, the call itself is
     * unsupported on this build. */
    return -ENOSYS;
#endif
}

int do_page_table_walk(struct socket* sock, void* arg) {
    struct memd_page_table_walk_cmd cmd;
    struct page_walk_stats stats;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct task_struct* task = get_target_task(cmd.pid);
    if (!task) {
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    // Traverse page tables and collect statistics
    traverse_page_tables(mm, &stats);

    // Copy statistics to command structure
    cmd.total_pte_count = stats.total_pte_count;
    cmd.present_pte_count = stats.present_pte_count;
    cmd.pmd_huge_count = stats.pmd_huge_count;
    cmd.pud_huge_count = stats.pud_huge_count;

    mmput(mm);
    put_task_struct(task);

    // Copy result back to userspace
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    memd_info("page table walk for pid %d: total_pte=%llu, present_pte=%llu, pmd_huge=%llu, pud_huge=%llu\n",
              cmd.pid, cmd.total_pte_count, cmd.present_pte_count, cmd.pmd_huge_count, cmd.pud_huge_count);

    return 0;
}

// static void (*wake_up_new_task)(struct task_struct *tsk) = NULL;
// if (!wake_up_new_task) {
//     wake_up_new_task = (void (*)(struct task_struct *))kallsyms_lookup_name_ex("wake_up_new_task");
// }
//
// wake_up_new_task(p);
// static __latent_entropy struct task_struct *(*copy_process)(
//             struct pid *pid,
//             int trace,
//             int node,
//             struct kernel_clone_args *args) = NULL;
// if (copy_process == NULL) {
//     copy_process = (typeof(copy_process))kallsyms_lookup_name_ex("copy_process");
// }
//
// if (!copy_process) {
//     ovo_warn("copy_process symbol not found\n");
//     return -ENOENT;
// }
// __latent_entropy struct task_struct *copy_process(
//                     struct pid *pid,
//                     int trace,
//                     int node,
//                     struct kernel_clone_args *args)
int do_copy_process(struct socket* sock, void* arg) {
    int ret = 0;
    struct memd_copy_process_cmd cmd;
    struct pid* pid;
    struct task_struct* task /*, *p*/;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (!cmd.fn || !cmd.child_stack) {
        memd_err("invalid function pointer or child stack\n");
        return -EINVAL;
    }

    /* Stubbed -ENOSYS below: reject nonzero dead fields NOW, so a
     * future enablement cannot silently change their meaning for
     * callers that already pass garbage. Fail closed on pid too. */
    if (cmd.pid <= 0 || cmd.child_stack_size != 0 || cmd.flags != 0 ||
        cmd.arg != NULL || cmd.child_tid != NULL) {
        return -EINVAL;
    }

    pid = find_get_pid(cmd.pid);
    if (!pid) {
        memd_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    if (!task) {
        memd_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    ret = -ENOSYS;
    // cproc源码无了，这里取消
    // ret = create_remote_thread(task, &p, cmd.child_tid, NULL, cmd.flags);
    put_task_struct(task);
    if (ret) {
        memd_err("failed to create remote thread: %d\n", ret);
        goto prepare_fault;
    }

    return 0;

prepare_fault:
    return ret;
}

#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
static inline int memk_valid_phys_addr_range(uintptr_t addr, size_t size) {
    uintptr_t lim = __pa(high_memory);
    if (size > lim)
        return 0;
    return addr <= lim - size;
}
#define IS_VALID_PHYS_ADDR_RANGE(x, y) memk_valid_phys_addr_range(x, y)
#else
#define IS_VALID_PHYS_ADDR_RANGE(x, y) valid_phys_addr_range(x, y)
#endif

int do_read_physical_memory(struct socket* sock, void __user* arg) {
    struct memd_read_physical_memory_cmd cmd;
    struct task_struct *task;
    char *kbuf;
    unsigned long off = 0;
    int ret;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    /* Unbounded size would livelock the chunk loop (and wrap va+off):
     * cap it. Root-only path, but a garbage size must still fail fast. */
    if (!cmd.size || cmd.size > CMD_MAX_BYTES)
        return -EINVAL;
    /* va+off must not wrap: near-ULONG_MAX bases would alias low memory. */
    if (cmd.size - 1 > (unsigned long)-1 - cmd.src_va ||
        cmd.size - 1 > (unsigned long)-1 - cmd.dst_va)
        return -EINVAL;

    /* Phys diagnostic (best-effort walk; 0 when unresolvable, e.g.
     * KPTI user tables — data below does not depend on it). */
    ret = translate_process_vaddr(cmd.pid, cmd.src_va, (uintptr_t*)&cmd.phy_addr);
    if (ret < 0)
        cmd.phy_addr = 0;

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    kbuf = kmalloc(65536, GFP_KERNEL);
    if (!kbuf) {
        put_task_struct(task);
        return -ENOMEM;
    }
    /* Data via kernel cross-process copy (KPTI/lock-safe, universal).
     * No page-table walk or physical-address lookup is required for contents. */
    while (off < cmd.size) {
        unsigned long chunk = cmd.size - off;
        if (chunk > 65536)
            chunk = 65536;
        if (memd_copy_from_task(task, kbuf, cmd.src_va + off, chunk))
            break;
        if (memd_copy_to_user((void *)(cmd.dst_va + off), kbuf, chunk))
            break;
        off += chunk;
    }
    kfree(kbuf);
    put_task_struct(task);
    if (off != cmd.size)
        return -EFAULT;
    return 0;
}

int do_get_module_base(struct socket* sock, void __user* arg) {
    struct memd_get_module_base_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }
    /* User controls all 256 bytes: force NUL so the strlen/match in
     * get_module_base cannot read past the stack struct. */
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    uintptr_t base = get_module_base(cmd.pid, cmd.name, cmd.vm_flag);
    if (base == 0) {
        return -ENAVAIL;
    }

    cmd.base = base;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_find_process(struct socket* sock, void* arg) {
    struct memd_find_proc_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }
    /* Same NUL guarantee as get_module_base (find_process_by_name
     * strlen-matches the name). */
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    cmd.pid = find_process_by_name(cmd.name);
    if (cmd.pid == 0) {
        return -ENAVAIL;
    }

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_write_physical_memory(struct socket* sock, void __user* arg) {
    struct memd_write_physical_memory_cmd cmd;
    struct task_struct *task;
    char *kbuf;
    unsigned long off = 0;
    int ret;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    /* Same cap as the read path (see above): unbounded size livelocks.
     * Validated before the diagnostic write-back so garbage size fails
     * fast without leaking phy_addr. */
    if (!cmd.size || cmd.size > CMD_MAX_BYTES)
        return -EINVAL;
    if (cmd.size - 1 > (unsigned long)-1 - cmd.src_va ||
        cmd.size - 1 > (unsigned long)-1 - cmd.dst_va)
        return -EINVAL;

    /* Phys diagnostic (best-effort; data below does not depend on it). */
    ret = translate_process_vaddr(cmd.pid, cmd.dst_va, (uintptr_t*)&cmd.phy_addr);
    if (ret < 0)
        cmd.phy_addr = 0;

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    kbuf = kmalloc(65536, GFP_KERNEL);
    if (!kbuf) {
        put_task_struct(task);
        return -ENOMEM;
    }
    /* Data via kernel cross-process copy (KPTI/lock-safe, universal). */
    while (off < cmd.size) {
        unsigned long chunk = cmd.size - off;
        if (chunk > 65536)
            chunk = 65536;
        if (memd_copy_from_user(kbuf, (void *)(cmd.src_va + off), chunk))
            break;
        if (memd_copy_to_task(task, cmd.dst_va + off, kbuf, chunk))
            break;
        off += chunk;
    }
    kfree(kbuf);
    put_task_struct(task);
    if (off != cmd.size)
        return -EFAULT;
    return 0;
}

int do_is_process_alive(struct socket* sock, void* arg) {
    struct memd_is_proc_alive_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.alive = is_pid_alive(cmd.pid);

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_hide_process(struct socket* sock, void* arg) {
    struct memd_hide_proc_cmd cmd;
    int ret;
    (void)sock;
    /* Root-only management: any local app could otherwise hide arbitrary
     * pids (confusion/DoS). The overlay runs as root. */
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }
    if (cmd.pid <= 0)
        return -EINVAL;
    /* Pure pid-set design: the target task is never touched (no flag
     * games on foreign structs). Visibility is enforced by the
     * getdents64 filter for non-root readers only. */
    ret = cmd.hide ? memd_hide_add(cmd.pid) : memd_hide_del(cmd.pid);
    if (ret == -ESRCH && !cmd.hide)
        ret = 0; /* unhide of absent pid is success */
    return ret;
}

int do_hide_status(struct socket* sock, void* arg) {
    struct memd_hide_status_cmd cmd;
    int cap;
    unsigned long rc;
    (void)sock;
    cap = memd_capable(CAP_SYS_ADMIN);
    if (!cap)
        return -EPERM;
    cmd.active = memd_hide_active();
    cmd.hidden_count = memd_hide_count();
    rc = memd_copy_to_user(arg, &cmd, sizeof(cmd));
    if (rc) {
        return -EFAULT;
    }
    return 0;
}

int do_hide_install(struct socket* sock, void* arg) {
    struct memd_hide_install_cmd cmd;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }
    /* Userspace gates on CFI status BEFORE calling: on enforcing
     * kernels the indirect table call would trap, so install there is
     * refused by policy (status stays inactive, loud NO-GO). */
    cmd.result = cmd.install ? memd_hide_install() : memd_hide_uninstall();
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_page_perms(struct socket* sock, void* arg) {
    struct memd_page_perms_cmd cmd;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }
    /* Descriptor metadata only: safe on execute-only mappings (no
     * content reads anywhere on this path). desc[] is filled sparsely:
     * the walker writes only the levels it descends, so pre-zero it —
     * unwalked levels report 0 instead of echoing caller input back. */
    memset(cmd.desc, 0, sizeof(cmd.desc));
    ret = memd_page_perms(cmd.va, &cmd.phy_addr, &cmd.present,
                          &cmd.leaf_level, &cmd.ap, &cmd.xn, cmd.desc);
    cmd.idx0 = pgd_index(cmd.va);
    cmd.idx1 = pud_index(cmd.va);
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return ret;
}


int do_disp_status(struct socket* sock, void* arg) {
    struct memd_disp_status_cmd cmd;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    {
        int rc;
        rc = memd_disp_status(&cmd);
        if (rc)
            return rc;
    }
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_disp_install(struct socket* sock, void* arg) {
    struct memd_disp_install_cmd cmd;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    /* Userspace gates on CFI status BEFORE calling (same policy as the
     * hide hook: enforcing kernels are refused, never attempted). */
    ret = memd_disp_install(cmd.backend, cmd.width, cmd.height);
    cmd.rc = ret ? (unsigned int)(-ret) : 0;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_disp_frame(struct socket* sock, void* arg) {
    struct memd_disp_frame_cmd cmd;
    struct memd_disp_op *kops = NULL;
    unsigned int count;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    count = cmd.count;
    /* Never silently truncate: the caller must know every op ran. */
    if (count > MEMD_DISP_MAX_OPS)
        return -EINVAL;
    if (count == 0) {
        cmd.rc = 0;
        if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
            return -EFAULT;
        return 0;
    }
    if (!cmd.ops)
        return -EINVAL;
    kops = kmalloc_array(count, sizeof(*kops), GFP_KERNEL);
    if (!kops)
        return -ENOMEM;
    if (memd_copy_from_user(kops, (void __user *)(uintptr_t)cmd.ops,
                       (size_t)count * sizeof(*kops))) {
        kfree(kops);
        return -EFAULT;
    }
    ret = memd_disp_frame(kops, count);
    kfree(kops);
    cmd.rc = ret ? (unsigned int)(-ret) : 0;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

#ifdef MEMD_DISP_TEST
int do_disp_readback(struct socket* sock, void* arg) {
    struct memd_disp_readback_cmd cmd;
    __u32 w = 0, h = 0;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    ret = memd_core_readback(cmd.dst, cmd.size, &w, &h);
    cmd.rc = ret ? (unsigned int)(-ret) : 0;
    cmd.w = w;
    cmd.h = h;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}
#endif

int do_give_root(struct socket* sock, void* arg) {
    struct memd_give_root_cmd cmd;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    cmd.result = give_root();

    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_read_physical_memory_ioremap(struct socket* sock, void* arg) {
    struct memd_read_physical_memory_ioremap_cmd cmd;
    pgprot_t prot;
    uintptr_t pa;
    void* mapped;
    void* map_base;
    unsigned long ioff;
    int ret;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Validate size
    if (cmd.size == 0 || cmd.size > PAGE_SIZE) {
        return -EINVAL;
    }

    // Validate and convert memory type
    if (cmd.prot < WMT_NORMAL || cmd.prot > WMT_NORMAL_iNC_oWB) {
        return -EINVAL;
    }

    ret = convert_wmt_to_pgprot(cmd.prot, &prot);
    if (ret < 0) {
        return ret;
    }

    // Translate virtual address to physical
    ret = translate_process_vaddr(cmd.pid, cmd.src_va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    // Return physical address to userspace
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    // Map and read physical memory
    pa = cmd.phy_addr;
    if (!pa || !memd_pfn_ok(__phys_to_pfn(pa))) {
        return -EFAULT;
    }

    /* memd_ioremap_prot returns the page-base mapping; add the page
     * offset back so the copy hits the translated bytes, not up to
     * 4095B before them. The request must not cross the page. */
    ioff = pa & ~PAGE_MASK;
    if (ioff + cmd.size > PAGE_SIZE)
        return -EINVAL;
    map_base = memd_ioremap_prot(pa & PAGE_MASK, PAGE_SIZE, prot);
    if (!map_base) {
        memd_err("failed to ioremap physical address 0x%lx\n", pa);
        return -ENOMEM;
    }
    mapped = (void *)((char *)map_base + ioff);

    ret = memd_copy_to_user((void*)cmd.dst_va, mapped, cmd.size);
    iounmap(map_base);

    return ret ? -EFAULT : 0;
}

int do_write_physical_memory_ioremap(struct socket* sock, void* arg) {
    struct memd_write_physical_memory_ioremap_cmd cmd;
    pgprot_t prot;
    uintptr_t pa;
    void* mapped;
    void* map_base;
    unsigned long ioff;
    int ret;

    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Validate size
    if (cmd.size == 0 || cmd.size > PAGE_SIZE) {
        return -EINVAL;
    }

    // Validate and convert memory type
    if (cmd.prot < WMT_NORMAL || cmd.prot > WMT_NORMAL_iNC_oWB) {
        return -EINVAL;
    }

    ret = convert_wmt_to_pgprot(cmd.prot, &prot);
    if (ret < 0) {
        return ret;
    }

    // Translate virtual address to physical
    ret = translate_process_vaddr(cmd.pid, cmd.src_va, &cmd.phy_addr);
    if (ret < 0) {
        return ret;
    }

    // Return physical address to userspace
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    // Map and write physical memory
    pa = cmd.phy_addr;
    if (!pa || !memd_pfn_ok(__phys_to_pfn(pa))) {
        return -EFAULT;
    }

    ioff = pa & ~PAGE_MASK;
    if (ioff + cmd.size > PAGE_SIZE)
        return -EINVAL;
    map_base = memd_ioremap_prot(pa & PAGE_MASK, PAGE_SIZE, prot);
    if (!map_base) {
        memd_err("failed to ioremap physical address 0x%lx\n", pa);
        return -ENOMEM;
    }
    mapped = (void *)((char *)map_base + ioff);

    ret = memd_copy_from_user(mapped, (void*)cmd.dst_va, cmd.size);
    iounmap(map_base);

    return ret ? -EFAULT : 0;
}

int do_list_processes(struct socket* sock, void __user* arg) {
    struct memd_list_processes_cmd cmd;
    struct task_struct* task;
    u8* kernel_bitmap;
    size_t process_count = 0;
    int ret = 0;

    // Copy command from userspace
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Validate bitmap size (must be at least 8192 bytes for PID 0-65535;
    // capped: uncapped kzalloc is a guest-triggered OOM, and size*8 below
    // must not wrap).
    if (cmd.bitmap_size < 8192 || cmd.bitmap_size > (1U << 20)) {
        memd_warn("bitmap size out of range: %zu (need 8192..1M)\n", cmd.bitmap_size);
        return -EINVAL;
    }

    /* Reject NULL bitmap before the kzalloc: saves up to 1M of
     * allocator work and reports EINVAL (bad argument) instead of
     * EFAULT from the later copy. */
    if (!cmd.bitmap) {
        memd_warn("NULL bitmap pointer\n");
        return -EINVAL;
    }

    // Allocate kernel bitmap buffer
    kernel_bitmap = kzalloc(cmd.bitmap_size, GFP_KERNEL);
    if (!kernel_bitmap) {
        memd_err("failed to allocate kernel bitmap\n");
        return -ENOMEM;
    }

    // Iterate through all processes and set corresponding bits
    rcu_read_lock();
    for_each_process(task) {
        pid_t pid = memd_t_pid(task);

        // Check if PID is within bitmap range
        if (pid >= 0 && pid < (cmd.bitmap_size * 8)) {
            size_t byte_index = pid / 8;
            size_t bit_index = pid % 8;

            // Set the bit
            kernel_bitmap[byte_index] |= (1 << bit_index);
            process_count++;
        }
    }
    rcu_read_unlock();

    // Copy bitmap to userspace
    if (memd_copy_to_user(cmd.bitmap, kernel_bitmap, cmd.bitmap_size)) {
        ret = -EFAULT;
        goto out_free;
    }

    // Update process count and copy back to userspace
    cmd.process_count = process_count;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        ret = -EFAULT;
        goto out_free;
    }

    memd_info("listed %zu processes in bitmap\n", process_count);

out_free:
    kfree(kernel_bitmap);
    return ret;
}

int do_get_process_info(struct socket* sock, void __user* arg) {
    struct memd_get_proc_info_cmd cmd;
    struct pid* pid_struct;
    struct task_struct* task;
    char cmdline[256];
    int ret = 0;

    // Copy command from userspace
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    // Find process by PID
    pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        memd_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        memd_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    // Extract basic process information
    cmd.tgid = memd_t_tgid(task);
    /* Foreign task layout skews across OEMs (proven): raw
     * task->cred/real_parent/prio dereferences oops on the wrong offset.
     * Learned offsets + extable-guarded reads instead; unknown -> 0. */
    cmd.uid = 0;
    cmd.ppid = 0;
    cmd.prio = 0;
    {
        unsigned long c = 0;
        unsigned int v = 0;
        if (memd_learned.t_cred >= 0 &&
            !memd_safe_read64((char *)task + memd_learned.t_cred, &c) && c &&
            !memd_safe_read32((const void *)(c + memd_cred_uid_off()), &v))
            cmd.uid = (uid_t)v;
    }
    {
        unsigned long p = 0;
        if (!memd_safe_read64(&task->real_parent, &p) && p) {
            unsigned int pp = 0;
            if (memd_learned.t_pid >= 0) {
                if (!memd_safe_read32((const void *)((char *)p + memd_learned.t_pid), &pp))
                    cmd.ppid = (pid_t)pp;
            } else if (!memd_safe_read32(&((struct task_struct *)p)->pid, &pp)) {
                cmd.ppid = (pid_t)pp;
            }
        }
    }
    {
        int pr = 0;
        /* prio has no learned slot: guarded compiled read only
         * (fault -> 0, never an oops). */
        if (!memd_safe_read32(&task->prio, (unsigned int *)&pr))
            cmd.prio = pr;
    }

    // Attempt to obtain the complete command line.
    cmdline[0] = '\0';

    /* get_cmdline via runtime kallsyms (6.1+), argv fallback below it:
     * one image either way, comm fallback after that. */
    static int (*my_get_cmdline)(struct task_struct* task, char* buffer, int buflen) = NULL;
    static bool cmdline_probed = false;
    if (!cmdline_probed) {
        cmdline_probed = true;
        my_get_cmdline = (void*)kallsyms_lookup_name_ex("get_cmdline");
    }

    if (my_get_cmdline != NULL && !memd_t_mm_null(task)) {
        ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
    } else if (!memd_t_mm_null(task)) {
        struct mm_struct* mm = get_task_mm(task);
        if (mm) {
            unsigned long arg_start, arg_end;
            unsigned long len;

            spin_lock(&mm->arg_lock);
            arg_start = mm->arg_start;
            arg_end = mm->arg_end;
            spin_unlock(&mm->arg_lock);

            /* arg_end <= arg_start means a torn/empty range: the
             * subtraction below would wrap unsigned and fabricate a
             * huge len. Fail to the comm fallback instead. */
            if (arg_end <= arg_start) {
                ret = -1;
            } else {
                len = arg_end - arg_start;
                if (len > sizeof(cmdline) - 1)
                    len = sizeof(cmdline) - 1;

                ret = access_process_vm(task, arg_start, cmdline, (int)len, FOLL_FORCE);
            }
            mmput(mm);
        } else {
            ret = -1;
        }
    } else {
        ret = -1;
    }

    // Fallback to task->comm if cmdline retrieval failed
    if (ret < 0 || cmdline[0] == '\0') {
        memd_t_comm(task, cmd.name, sizeof(cmd.name));
    } else {
        // Extract program name (first part before space)
        char* space = strchr(cmdline, ' ');
        if (space) *space = '\0';

        // Extract filename from path
        char* slash = strrchr(cmdline, '/');
        char* prog_name = slash ? (slash + 1) : cmdline;

        strncpy(cmd.name, prog_name, sizeof(cmd.name) - 1);
    }
    cmd.name[sizeof(cmd.name) - 1] = '\0';

    put_task_struct(task);

    // Copy result back to userspace
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    memd_info("retrieved info for process %d: tgid=%d, name=%s, uid=%d, ppid=%d, prio=%d\n",
              cmd.pid, cmd.tgid, cmd.name, cmd.uid, cmd.ppid, cmd.prio);

    return 0;
}

int do_hwbp_info(struct socket* sock, void __user* arg)
 {
    struct memd_hwbp_info_cmd cmd;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    ret = memd_hwbp_get_info(&cmd);
    if (ret)
        return ret;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_hwbp_set(struct socket* sock, void __user* arg)
 {
    struct memd_hwbp_set_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_hwbp_set(task, &cmd);
    put_task_struct(task);
    if (ret)
        return ret;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_hwbp_remove(struct socket* sock, void __user* arg)
 {
    struct memd_hwbp_remove_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_hwbp_remove(task, cmd.hwbp_id);
    put_task_struct(task);
    return ret;
}

int do_hwbp_list(struct socket* sock, void __user* arg)
 {
    struct memd_hwbp_list_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_hwbp_list(task, &cmd);
    put_task_struct(task);
    if (ret)
        return ret;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_gyro_prepare(struct socket* sock, void __user* arg)
 {
    struct memd_gyro_prepare_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_gyro_prepare_target(task, &cmd);
    put_task_struct(task);
    return ret;
}

int do_touch_init(struct socket* sock, void __user* arg)
 {
    struct memd_touch_init_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_touch_init(task, &cmd);
    put_task_struct(task);
    return ret;
}

int do_touch_inject(struct socket* sock, void __user* arg)
 {
    struct memd_touch_inject_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_touch_inject(task, &cmd);
    put_task_struct(task);
    return ret;
}

int do_gyro_inject(struct socket* sock, void __user* arg)
 {
    struct memd_gyro_inject_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_gyro_inject(task, &cmd);
    put_task_struct(task);
    return ret;
}

int do_sigforce(struct socket* sock, void __user* arg)
 {
    struct memd_sigforce_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    if (cmd.async) {
        ret = memd_sigforce_send_async(task, cmd.sig, cmd.force);
    } else if (cmd.group) {
        ret = memd_sigforce_send_group(task, cmd.sig, cmd.force);
    } else {
        ret = memd_sigforce_send(task, cmd.sig, cmd.force);
    }
    cmd.result = ret;
    put_task_struct(task);
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_gyro_calibrate(struct socket* sock, void __user* arg)
 {
    struct memd_gyro_calibrate_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_gyro_calibrate(task, &cmd);
    put_task_struct(task);
    /* No result field in this struct: a bad action / bad span must fail
     * closed via the return value, never report success with stale data. */
    if (ret)
        return ret;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_touch_calibrate(struct socket* sock, void __user* arg)
 {
    struct memd_touch_calibrate_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    ret = memd_touch_calibrate(task, &cmd);
    put_task_struct(task);
    /* Same contract as gyro_calibrate above: no result field, so the
     * return value is the only status channel — propagate failures. */
    if (ret)
        return ret;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_virtual_input_create(struct socket* sock, void __user* arg)
 {
    struct memd_virtual_input_cmd cmd;
    struct task_struct *task;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    task = get_target_task(cmd.pid);
    if (!task)
        return -ESRCH;
    /* Result-field contract (shared with sigforce/bootstrap/disp rc):
     * the callee records status in cmd.result on every reachable path
     * and this handler always returns 0 after copying back — userspace
     * must check cmd.result, not the ioctl return. Do not convert these
     * handlers to return-ret style. */
    ret = memd_virtual_input_create(task, &cmd);
    put_task_struct(task);
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}

int do_bootstrap(struct socket* sock, void __user* arg)
 {
    struct memd_bootstrap_cmd cmd;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    /* NULL can never be a valid kernel text address: fail fast with
     * the error in result (same convention as below), no call. */
    if (!cmd.filp_open || !cmd.kernel_read || !cmd.filp_close) {
        cmd.result = -EINVAL;
    } else {
        cmd.result = memd_kallsyms_bootstrap((unsigned long)cmd.filp_open,
                                             (unsigned long)cmd.kernel_read,
                                             (unsigned long)cmd.filp_close);
    }
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    return 0;
}
/* kmod/memd/ioctl/memd_ioctl.c[∂] */
