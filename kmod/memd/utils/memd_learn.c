/* Runtime offset learning. See header for the anchor design.
 * Fail-soft per field (loud log, -1 offset); readers fall back to
 * compiled offsets so old behavior is the floor, never worse. */
#include "memd_learn.h"

#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/fs_struct.h>
#include <asm/sysreg.h>

#include "memd_utils.h"
#include "memd_netlayout.h"

static bool memd_learn_initialized = false;
static bool memd_learn_started = false;
static DEFINE_SPINLOCK(memd_learn_lock);

struct memd_learned memd_learned = {
    .t_pid = -1, .t_tgid = -1, .t_comm = -1, .t_mm = -1, .t_cred = -1,
    .m_pgd = -1, .v_start = -1, .v_end = -1, .v_flags = -1,
};

struct memd_learned_ext memd_learned_ext = {
    .t_files = -1, .t_signal = -1, .t_sighand = -1, .t_thread = -1,
    .t_stack = -1, .t_pid_link = -1, .t_real_parent = -1, .t_parent = -1,
    .t_group_leader = -1, .t_nsproxy = -1, .t_fs = -1, .t_io_context = -1,
    .t_cgroups = -1, .t_robust_list = -1, .t_perf_event_ctxp = -1, .t_bts = -1,
    .m_mmap = -1, .m_mmap_cache = -1, .m_map_count = -1, .m_pgtables_bytes = -1,
    .m_hiwater_rss = -1, .m_hiwater_vm = -1, .m_total_vm = -1, .m_locked_vm = -1,
    .m_pinned_vm = -1, .m_data_vm = -1, .m_exec_vm = -1, .m_stack_vm = -1,
    .m_arg_lock = -1, .m_arg_start = -1, .m_arg_end = -1, .m_env_start = -1,
    .m_env_end = -1, .f_fpath = -1, .f_op = -1, .f_private = -1, .f_inode = -1, .f_mapping = -1,
    .f_pos = -1, .f_flags = -1, .f_mode = -1, .f_count = -1,
    .d_name = -1, .d_parent = -1, .d_inode = -1, .d_op = -1,
    .d_sb = -1, .d_lockref = -1, .d_count = -1, .d_flags = -1,
    .i_ino = -1, .i_mode = -1, .i_uid = -1, .i_gid = -1, .i_size = -1,
    .i_blocks = -1, .i_atime = -1, .i_mtime = -1, .i_ctime = -1,
    .i_blkbits = -1, .i_flags = -1, .i_sb = -1, .i_mapping = -1,
    .i_dentry = -1, .i_flock = -1, .i_lock = -1, .i_count = -1,
    .s_id = -1, .s_op = -1, .s_root = -1, .s_dentry = -1,
    .s_files = -1, .s_mounts = -1, .s_instances = -1, .s_list = -1,
    .s_dev = -1, .s_blocksize = -1, .s_blocksize_bits = -1, .s_magic = -1,
    .s_type = -1, .s_flags = -1, .s_time_gran = -1, .s_maxbytes = -1,
    .s_op_flags = -1,
    .t_thread_cpuctx = -1, .t_thread_fpsimd = -1,
    .t_signal_shared_pending = -1, .t_signal_cred_guard = -1,
    .t_sighand_action = -1,
    .t_fs_pwd = -1, .t_fs_root = -1,
    .t_nsproxy_mnt_ns = -1, .t_nsproxy_pid_ns = -1,
    .t_cred_cap_eff = -1, .t_cred_cap_perm = -1, .t_cred_cap_inh = -1,
    .t_cred_uid = -1,
    .t_sighand_verified = -1,
};

#define MEMD_LEARN_SCAN 2048

/* File-scope statics (declared before use). find_vma returns a vma
 * pointer (the old unsigned-long prototype truncated nothing on LP64
 * but lied to the compiler); keep the honest type. */
static struct vm_area_struct *(*memd_fv)(struct mm_struct *, unsigned long) = NULL;
static bool memd_fv_probed = false;

/* Per-generation struct file layout (6.6/6.12 rework file completely).
 * Indices match memd_net_gen(). Verified per-gen by asserts.
 * 5.4 shares the pre-6.6 layout (f_op@40, f_path@16); the android11-5.4
 * matrix job proves it at build time, never at load. */
static const short memd_fop_off[] = { 40, 40, 40, 40, 192, 16 };
static const short memd_fpath_off[] = { 16, 16, 16, 16, 168, 64 };

static int memd_v_file_off = -1;

/* Scan task/mm/file objects for a kernel-pointer target. Exact anchor
 * match required (unique hit wins); anything else leaves -1 so readers
 * fall back to compiled offsets or fail closed, never guess. */

static void memd_learn_task(void)
 {
    struct task_struct *t = current;
    pid_t pid = task_pid_vnr(t);
    pid_t tgid = task_tgid_vnr(t);
    struct mm_struct *mm;
    char comm[TASK_COMM_LEN];
    int off = -1, n_pid, i;
    /* pid/tgid: adjacent u32 pair matching task_pid_vnr/task_tgid_vnr.
     * Unique hit required (first-hit-wins would mis-learn on a
     * coincidental value match elsewhere in task_struct). */
    n_pid = 0;
    for (i = 0; i + 8 <= MEMD_LEARN_SCAN; i += 4) {
        u32 a, b;
        memcpy(&a, (char *)t + i, 4);
        memcpy(&b, (char *)t + i + 4, 4);
        if ((pid_t)a == pid && (pid_t)b == tgid) {
            if (!n_pid)
                off = i;
            n_pid++;
        }
    }
    if (n_pid == 1 && off >= 0) {
        memd_learned.t_pid = off;
        memd_learned.t_tgid = off + 4;
        memd_info("learn: task pid/tgid at +%d\n", off);
    } else {
        memd_err("learn: task pid/tgid ambiguous (%d hits, using compiled)\n",
                 n_pid);
    }
    /* comm: get_task_comm value as a string. */
    get_task_comm(comm, t);
    comm[sizeof(comm) - 1] = '\0';
    {
        size_t cl = strlen(comm);
        int found = -1, n = 0, i;
        if (cl > 0 && cl < sizeof(comm)) {
            memset(comm + cl, 0, sizeof(comm) - cl);
            for (i = 0; i + (int)sizeof(comm) <= MEMD_LEARN_SCAN; i++) {
                if (!memcmp((char *)t + i, comm, sizeof(comm))) {
                    if (!n)
                        found = i;
                    n++;
                }
            }
        }
        if (n == 1) {
            memd_learned.t_comm = found;
            memd_info("learn: task comm at +%d\n", found);
        } else {
            memd_err("learn: task comm ambiguous (%d hits)\n", n);
        }
    }
    /* mm: get_task_mm anchor scanned as a pointer. Never trust the
     * compiled t->mm field on a foreign kernel (its value is garbage
     * there), so always scan. mm/active_mm are adjacent same-value
     * pointers: one hit, or two hits 8 apart, wins. */
    mm = get_task_mm(t);
    if (mm) {
        int o1 = -1, o2 = -1, n = 0, i2;
        for (i2 = 0; i2 + 8 <= MEMD_LEARN_SCAN; i2 += 8) {
            u64 v = 0;
            memcpy(&v, (char *)t + i2, 8);
            if (v == (u64)mm) {
                if (!n)
                    o1 = i2;
                else if (n == 1)
                    o2 = i2;
                n++;
            }
        }
        if (n == 1 || (n == 2 && o2 == o1 + 8 && o2 <= (MEMD_LEARN_SCAN - 8))) {
            memd_learned.t_mm = o1;
            memd_info("learn: task mm at +%d\n", o1);
        } else {
            memd_err("learn: task mm ambiguous (%d)\n", n);
        }
        mmput(mm);
    } else {
        memd_err("learn: no mm on loader task\n");
    }
    /* cred: adjacent equal kernel pointers (real_cred, cred) whose
     * target looks like root cred (usage 1..1000 at +0, uid 0 at +4).

     * Loader is root (su/insmod), so this identifies cred exactly.
     * No tables: fully runtime. */
    {
        int i2, found = -1, n = 0;
        for (i2 = 0; i2 + 16 <= MEMD_LEARN_SCAN; i2 += 8) {
            u64 a = 0, b = 0;
            u32 usage = 0, uid = 0;
            memcpy(&a, (char *)t + i2, 8);
            memcpy(&b, (char *)t + i2 + 8, 8);
            if (a != b || (a & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
            /* read usage (u32@0) + uid (u32@4) via one u64 */
            {
                unsigned long w = 0;
                if (memd_safe_read64((void *)(uintptr_t)a, &w))
                    continue;
                usage = (u32)(w & 0xffffffffU);
                uid = (u32)((w >> 32) & 0xffffffffU);
            }
            if (usage < 1 || usage > 1000 || uid != 0)
                continue;
            if (!n)
                found = i2 + 8; /* cred is second (real_cred first) */
            n++;
        }
        if (n == 1) {
            memd_learned.t_cred = found;
            memd_info("learn: task cred at +%d\n", found);
        } else {
            memd_err("learn: task cred ambiguous (%d)\n", n);
        }
    }
}

static int memd_pgd_shape_ok(u64 phys);

static void memd_learn_pgd(void)
 {
    struct mm_struct *mm;
    u64 ttbr, want;
    mm = get_task_mm(current);
    if (!mm) {
        memd_err("learn: no mm for pgd\n");
        return;
    }
    ttbr = read_sysreg(ttbr0_el1);
    /* TTBR0 match (non-KPTI fast path): strip ASID, keep phys page.
     * mm->pgd is a linear-map VA, so translate it before comparing
     * to the TTBR phys (a raw VA == phys compare never matches).
     * Even on a value match, shape-check before trusting the compiled
     * mm->pgd field (garbage on foreign layouts could alias want). */
    want = ttbr & 0x0000fffffffff000ULL;
    {
        u64 pgd_va = (u64)(uintptr_t)mm->pgd;
        u64 pa = 0;
        int pa_match = 0;
        if ((pgd_va & 0xffff000000000000UL) == 0xffff000000000000UL &&
            virt_addr_valid((void *)(uintptr_t)pgd_va)) {
            pa = (u64)(uintptr_t)virt_to_phys((void *)(uintptr_t)pgd_va);
            pa_match = (pa == want);
        }
        if (pa_match) {
            if (memd_pgd_shape_ok(pa)) {
                memd_learned.m_pgd = (int)((char *)&mm->pgd - (char *)mm);
                memd_info("learn: mm pgd compiled+%d confirmed\n",
                          memd_learned.m_pgd);
                mmput(mm);
                return;
            }
            memd_err("learn: mm pgd compiled match failed shape, scanning\n");
        }
    }
    /* Shape scan (KPTI-proof): TTBR0 (user tables) need not equal
     * mm->pgd, so find the pgd by table shape instead of value.
     * First shape-passing kernel pointer in mm wins (pgd is early).
     * Direct reads are safe (mm slab is mapped); table reads guarded. */
    {
        int i, found = -1, n = 0;
        for (i = 0; i + 8 <= 512; i += 8) {
            unsigned long va = 0, pa = 0;
            if (memd_safe_read64((char *)mm + i, &va))
                continue;
            if ((va & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
            /* virt_to_phys is linear-map only: vmalloc/io addresses
             * would yield a bogus phys, so skip non-linear vas. */
            if (!virt_addr_valid((void *)(uintptr_t)va))
                continue;
            pa = (unsigned long)virt_to_phys((void *)(uintptr_t)va);
            if (!memd_pgd_shape_ok(pa))
                continue;
            if (!n)
                found = i;
            n++;
        }
        if (found >= 0) {
            memd_learned.m_pgd = found;
            memd_info("learn: mm pgd at +%d (shape)\n", found);
        } else {
            memd_err("learn: mm pgd shape ambiguous (%d)\n", n);
        }
    }
    mmput(mm);
}

/* Validate that phys page looks like a pgd (guarded reads only). */
static int memd_pgd_shape_ok(u64 phys)
 {
    int i, zeros = 0, valid = 0;
    void *kv;
    if (phys < 0x40000000UL || phys >= (64UL << 30))
        return 0;
    if (phys & ((1UL << PAGE_SHIFT) - 1))
        return 0;
    kv = (void *)phys_to_virt((phys_addr_t)phys);
    for (i = 0; i < 512; i++) {
        unsigned long d = 0;
        unsigned long out;
        unsigned type;
        if (memd_safe_read64((char *)kv + i * 8, &d))
            return 0;
        if (!d) {
            zeros++;
            continue;
        }
        type = (unsigned)(d & 3UL);
        out = d & 0x0000fffffffff000UL;
        if ((type == 3 || type == 1) && out >= 0x40000000UL &&
            out < (64UL << 30))
            valid++;
    }
    return zeros > 256 && valid > 0 && valid < 32;
}

/* Read one maps line: start, end (hex), perms[0]. Returns 0 ok.
 * perms (nullable out): low bits encode r/w/x/s as VM_READ/VM_WRITE/
 * VM_EXEC/VM_SHARED (stable UAPI constants); 0 when unparseable. The
 * line format is "start-end perms ...": after the end hex, buf[i] is
 * the space and buf[i+1..i+4] are the perms chars. */
static int memd_maps_line(struct file *f, loff_t *pos, unsigned long *start,
                           unsigned long *end, char *base, size_t basecap,
                           unsigned *perms)
 {
    char buf[256];
    ssize_t n;
    int i = 0, j;
    unsigned long s = 0, e = 0;
    n = memd_kernel_read(f, buf, sizeof(buf) - 1, pos);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    /* start-end perms */
    while (buf[i] && (buf[i] < '0' || (buf[i] > '9' && buf[i] < 'a') ||
                       (buf[i] > 'f' && buf[i] != '-')))
        i++;
    while (buf[i] >= '0' && ((buf[i] <= '9') || (buf[i] >= 'a' && buf[i] <= 'f'))) {
        char c = buf[i];
        s = (s << 4) | (unsigned long)(c <= '9' ? c - '0' : c - 'a' + 10);
        i++;
    }
    if (buf[i] != '-')
        return -1;
    i++;
    while (buf[i] >= '0' && ((buf[i] <= '9') || (buf[i] >= 'a' && buf[i] <= 'f'))) {
        char c = buf[i];
        e = (e << 4) | (unsigned long)(c <= '9' ? c - '0' : c - 'a' + 10);
        i++;
    }
    /* advance pos past this line (kernel_read already moved it by n) */
    for (j = 0; j < n && buf[j] != '\n'; j++)
        ;
    if (j >= n)
        return -1;
    *pos = *pos - (loff_t)n + (loff_t)j + 1;
    *start = s;
    *end = e;
    if (!(s && e > s))
        return -1;
    /* perms sit right after the end address ("end<sp>rwxp"): encode the
     * low VM bits; anything unexpected yields 0 (caller treats equal
     * perms as unteachable). Lenient on purpose: the line stays usable
     * for start/end/file even when perms baffle us. */
    if (perms) {
        unsigned p = 0;
        *perms = 0;
        if (buf[i] == ' ' && i + 4 < n &&
            (buf[i + 1] == 'r' || buf[i + 1] == '-') &&
            (buf[i + 2] == 'w' || buf[i + 2] == '-') &&
            (buf[i + 3] == 'x' || buf[i + 3] == '-') &&
            (buf[i + 4] == 's' || buf[i + 4] == 'p')) {
            if (buf[i + 1] == 'r')
                p |= VM_READ;
            if (buf[i + 2] == 'w')
                p |= VM_WRITE;
            if (buf[i + 3] == 'x')
                p |= VM_EXEC;
            if (buf[i + 4] == 's')
                p |= VM_SHARED;
            *perms = p;
        }
    }
    /* basename of pathname (empty for anonymous) */
    if (base && basecap > 1) {
        int k, last = -1;
        base[0] = '\0';
        for (k = 0; k < j; k++) {
            if (buf[k] == '/')
                last = k;
        }
        if (last >= 0) {
            size_t bl = 0;
            k = last + 1;
            while (k < j && buf[k] != ' ' && buf[k] != '\n' &&
                   buf[k] != '\r' && bl + 1 < basecap) {
                base[bl++] = buf[k++];
            }
            base[bl] = '\0';
        }
    }
    return 0;
}

static int memd_find_vma_pair(struct mm_struct *mm, unsigned long addr,
                               int *start_off, int *end_off);

/* Learn vm_flags slot: the one word whose low VM bits match the known
 * maps perms on BOTH confirmed lines. Two lines with differing perms
 * are required (equal perms teach nothing: any shared constant would
 * match). Unique single hit wins; anything else leaves the compiled
 * fallback (fail-soft, loud). Page-aligned addresses (start/end) can
 * only match an all-dash perms pattern, and p1 != p2 rules that out,
 * therefore, learned slots need not be excluded explicitly. */
static void memd_learn_vma_flags(struct mm_struct *mm, unsigned long s1,
                                  unsigned long s2, unsigned p1, unsigned p2)
 {
    static const unsigned long mask = (unsigned long)(VM_READ | VM_WRITE | VM_EXEC | VM_SHARED);
    struct vm_area_struct *v1, *v2;
    int i, found = -1, n = 0;
    if (!mm || !s1 || !s2)
        return;
    if (p1 == p2)
        return;
    if (!memd_fv)
        return;
    MM_READ_LOCK(mm);
    v1 = memd_fv(mm, s1);
    v2 = memd_fv(mm, s2);
    if (!v1 || !v2) {
        MM_READ_UNLOCK(mm);
        return;
    }
    for (i = 0; i + 8 <= 256; i += 8) {
        unsigned long w1 = 0, w2 = 0;
        if (memd_safe_read64((char *)v1 + i, &w1) ||
            memd_safe_read64((char *)v2 + i, &w2))
            continue;
        if ((w1 & mask) == (unsigned long)p1 && (w2 & mask) == (unsigned long)p2) {
            n++;
            found = i;
        }
    }
    MM_READ_UNLOCK(mm);
    if (n == 1) {
        memd_learned.v_flags = found;
        memd_info("learn: vma vm_flags at +%d\n", found);
    } else {
        memd_err("learn: vma vm_flags ambiguous (%d)\n", n);
    }
}

/* Learn vm_file slot: scan vma for a file pointer whose dentry name
 * matches the known maps basename (all reads guarded). */
static int memd_learn_vma_file(struct mm_struct *mm, unsigned long addr,
                               const char *base)
 {
    struct vm_area_struct *vma;
    size_t bl;
    int i, found = -1, n = 0;
    if (!base || !base[0] || !mm)
        return -1;
    bl = strlen(base);
    if (!memd_fv)
        return -1;
    MM_READ_LOCK(mm);
    vma = memd_fv(mm, addr);
    if (!vma) {
        MM_READ_UNLOCK(mm);
        return -1;
    }
    for (i = 0; i + 8 <= 256; i += 8) {
        unsigned long fp = 0, dp = 0, nm = 0, ln = 0;
        char nb[40];
        int k;
        if (memd_safe_read64((char *)vma + i, &fp) || !fp ||
            (fp & 0xffff000000000000UL) != 0xffff000000000000UL)
            continue;
        /* f_path.dentry via running-generation table */
        {
            int fg = memd_net_gen();
            unsigned long fpoff;
            if (fg < 0 || fg >= MEMD_GEN_N) {
                MM_READ_UNLOCK(mm);
                return -1;
            }
            fpoff = (unsigned long)memd_fpath_off[fg];
            if (memd_safe_read64((char *)fp + fpoff + 8, &dp) || !dp ||
                (dp & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
        }
        /* dentry->d_name (qstr at +32, asserted stable): name ptr + len */
        if (memd_safe_read64((char *)dp + 32, &nm) ||
            memd_safe_read64((char *)dp + 32 + 8, &ln))
            continue;
        /* nm must be a kernel string pointer; without this a wrong +32
         * on a foreign layout could match user bytes by coincidence. */
        if (!nm || (nm & 0xffff000000000000UL) != 0xffff000000000000UL)
            continue;
        if (ln != bl || ln >= sizeof(nb))
            continue;
        /* guarded byte compare via u64 reads */
        for (k = 0; k < (int)ln; k += 8) {
            unsigned long w = 0;
            int t;
            if (memd_safe_read64((char *)nm + k, &w))
                break;
            for (t = 0; t < 8 && k + t < (int)ln; t++) {
                nb[k + t] = (char)((w >> (8 * t)) & 0xff);
            }
        }
        if (k < (int)ln)
            continue;
        nb[ln] = '\0';
        if (strcmp(nb, base))
            continue;
        n++;
        found = i;
    }
    MM_READ_UNLOCK(mm);
    if (n == 1) {
        memd_v_file_off = found;
        memd_info("learn: vma vm_file at +%d\n", found);
        return 0;
    }
    /* ambiguous or absent: leave compiled fallback */
    return -1;
}

static void memd_learn_vma(void)
 {
    struct mm_struct *mm;
    struct file *f;
    loff_t pos = 0;
    unsigned long s1 = 0, e1 = 0, s2 = 0, e2 = 0;
    unsigned p1 = 0, p2 = 0;
    char b1[48] = {0}, b2[48] = {0};
    int a = -1, b = -1, c = -1, d = -1, g;
    mm = get_task_mm(current);
    if (!mm) {
        memd_err("learn: no mm for vma\n");
        return;
    }
    if (memd_filp_open("/proc/self/maps", O_RDONLY, 0, &f) != 0) {
        memd_err("learn: no self maps\n");
        mmput(mm);
        return;
    }
    if (IS_ERR(f)) {
        memd_err("learn: no self maps\n");
        mmput(mm);
        return;
    }
    if (memd_maps_line(f, &pos, &s1, &e1, b1, sizeof(b1), &p1)) {
        memd_err("learn: maps parse failed\n");
        memd_filp_close(&f, NULL);
        mmput(mm);
        return;
    }
    /* second line with a pathname (anonymous lines teach nothing) */
    g = 0;
    while (g++ < 8) {
        if (memd_maps_line(f, &pos, &s2, &e2, b2, sizeof(b2), &p2))
            break;
        if (b2[0])
            break;
        s2 = e2 = 0;
        b2[0] = '\0';
        p2 = 0;
    }
    memd_filp_close(&f, NULL);
    if (!memd_find_vma_pair(mm, s1, &a, &b) &&
        s2 && !memd_find_vma_pair(mm, s2, &c, &d) && a == c && b == d &&
        a >= 0) {
        memd_learned.v_start = a;
        memd_learned.v_end = b;
        memd_info("learn: vma start/end at +%d/+%d\n", a, b);
        memd_learn_vma_flags(mm, s1, s2, p1, p2);
    } else {
        memd_err("learn: vma pair unconfirmed\n");
    }
    if (b1[0] && !memd_learn_vma_file(mm, s1, b1))
        memd_info("learn: vma file confirmed on 1 line\n");
    else if (b2[0] && !memd_learn_vma_file(mm, s2, b2))
        memd_info("learn: vma file confirmed on 2 lines\n");
    else
        memd_err("learn: vma file unconfirmed (compiled fallback)\n");
    mmput(mm);
}

/* find_vma by runtime address (dual name), then pair-scan. Holds the
 * mm read lock across lookup+scan so a concurrent munmap cannot free
 * the vma or tear the start/end pair mid-read (fail-soft -1). */
static int memd_find_vma_pair(struct mm_struct *mm, unsigned long addr,
                              int *start_off, int *end_off)
 {
    struct vm_area_struct *vma;
    struct vm_area_struct *(*fv)(struct mm_struct *, unsigned long);
    int i;
    if (!mm || !start_off || !end_off)
        return -1;
    if (!memd_fv_probed) {
        unsigned long r;
        spin_lock(&memd_learn_lock);
        if (!memd_fv_probed) {
            spin_unlock(&memd_learn_lock);
            r = kallsyms_lookup_name_ex("find_vma");
            if (!r)
                r = kallsyms_lookup_name_ex("__find_vma");
            spin_lock(&memd_learn_lock);
            if (!memd_fv_probed) {
                memd_fv = (void *)(uintptr_t)r;
                memd_fv_probed = true;
            }
            spin_unlock(&memd_learn_lock);
        } else {
            spin_unlock(&memd_learn_lock);
        }
    }
    if (!memd_fv)
        return -1;
    fv = memd_fv;
    MM_READ_LOCK(mm);
    vma = fv(mm, addr);
    if (!vma) {
        MM_READ_UNLOCK(mm);
        return -1;
    }
    /* adjacent u64 pair (a, b): a<=addr<b, sane span, page-aligned a */
    for (i = 0; i + 16 <= 512; i += 8) {
        unsigned long x = 0, y = 0;
        /* Guarded: scan can overrun vm_area_struct on foreign layouts;
         * raw memcpy would fault. Skip faulting slots (fail closed). */
        if (memd_safe_read64((char *)vma + i, &x) ||
            memd_safe_read64((char *)vma + i + 8, &y))
            continue;
        if (x <= addr && addr < y && y - x < (1UL << 32) &&
            (x & ((1UL << PAGE_SHIFT) - 1)) == 0) {
            /* confirm uniqueness in this vma */
            int j, hits = 0, jo = -1;
            for (j = 0; j + 16 <= 512; j += 8) {
                unsigned long p = 0, q = 0;
                if (memd_safe_read64((char *)vma + j, &p) ||
                    memd_safe_read64((char *)vma + j + 8, &q))
                    continue;
                if (p == x && q == y) {
                    hits++;
                    jo = j;
                }
            }
            if (hits == 1) {
                *start_off = jo;
                *end_off = jo + 8;
                MM_READ_UNLOCK(mm);
                return 0;
            }
            MM_READ_UNLOCK(mm);
            return -1;
        }
    }
    MM_READ_UNLOCK(mm);
    return -1;
}

int memd_learn(void)
 {
    memd_learn_task();
    memd_learn_pgd();
    return 0;
}

/* Lazy vma learning on first get_module_base (target task context).
 * Claim-once under the learn lock so concurrent callers cannot run the
 * maps parse twice; a loser skips (fail-soft compiled fallback). */
void memd_learn_vma_once(void)
 {
    bool skip = false;
    spin_lock(&memd_learn_lock);
    {
        static bool done = false;
        if (done)
            skip = true;
        else
            done = true;
    }
    spin_unlock(&memd_learn_lock);
    if (skip)
        return;
    memd_learn_vma();
}

pid_t memd_t_pid(struct task_struct *t)
 {
    unsigned int v = 0;
    if (t && memd_learned.t_pid >= 0 &&
        !memd_safe_read32((char *)t + memd_learned.t_pid, &v))
        return (pid_t)v;
    if (!t)
        return 0;
    return t->pid;
}

pid_t memd_t_tgid(struct task_struct *t)
 {
    unsigned int v = 0;
    if (t && memd_learned.t_tgid >= 0 &&
        !memd_safe_read32((char *)t + memd_learned.t_tgid, &v))
        return (pid_t)v;
    if (!t)
        return 0;
    return t->tgid;
}

struct mm_struct *memd_t_mm(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned.t_mm >= 0 &&
        !memd_safe_read64((char *)t + memd_learned.t_mm, &v))
        return (struct mm_struct *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->mm;
}

int memd_t_mm_null(struct task_struct *t)
 {
    return memd_t_mm(t) == NULL;
}

struct cred *memd_t_cred(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned.t_cred >= 0 &&
        !memd_safe_read64((char *)t + memd_learned.t_cred, &v) &&
        (v & 0xffff000000000000UL) == 0xffff000000000000UL)
        return (struct cred *)(uintptr_t)v;
    /* task->cred is const-qualified (RCU); callers must not write
     * through it — all stores go via computed addresses. */
    if (!t)
        return NULL;
    return (struct cred *)t->cred;
}

/* 0 = unknown (fail closed): real sizes are 16K/64K, so 0 is never valid. */
static unsigned long memd_stack_size_learned = 0UL;

unsigned long memd_thread_size(void)
 {
    return memd_stack_size_learned;
}

/* Learn task->stack offset + thread stack size from current.
 * current's sp lies in [base, base+SIZE) with SIZE in {16K (4K pages),
 * 64K (16K pages)} and base SIZE-aligned. thread_info.task sits at
 * base+small offset; scan foff {0..64 step 8} for == current with a
 * unique (size, foff) hit, then scan current's task_struct for == base
 * (unique) to learn t_stack. Exact pointer equality: a false positive
 * would need our own task pointer forged in memory; ambiguity aborts.
 * Runs lazily on first inject (loader/ioctl context, always a user
 * task with a real kernel stack). */
static void memd_learn_task_stack(void)
 {
    struct task_struct *t = current;
    unsigned long sp;
    unsigned long sizes[2] = {16384, 65536};
    int si, foff, i, n, found_foff;
    unsigned long found_size, base, v;
    int off, hits;
    asm volatile("mov %0, sp" : "=r" (sp));
    n = 0;
    found_size = 0;
    found_foff = -1;
    /* If sp is 64K-aligned both masks yield the same base and the same
     * cell counts twice (n == 2): that is genuinely ambiguous between
     * 16K and 64K thread sizes, so keep the abort (fail closed). */
    for (si = 0; si < 2; si++) {
        base = sp & ~(sizes[si] - 1);
        for (foff = 0; foff <= 64; foff += 8) {
            if (memd_safe_read64((void *)(base + (unsigned long)foff), &v))
                continue;
            if (v == (unsigned long)t) {
                n++;
                found_size = sizes[si];
                found_foff = foff;
            }
        }
    }
    if (n != 1) {
        memd_err("learn: task stack base ambiguous (%d)\n", n);
        return;
    }
    base = sp & ~(found_size - 1);
    off = -1;
    hits = 0;
    for (i = 0; i + 8 <= MEMD_LEARN_SCAN; i += 8) {
        if (memd_safe_read64((char *)t + i, &v))
            continue;
        if (v == base) {
            if (!hits)
                off = i;
            hits++;
        }
    }
    if (hits != 1) {
        memd_err("learn: task stack offset ambiguous (%d)\n", hits);
        return;
    }
    memd_learned_ext.t_stack = off;
    memd_stack_size_learned = found_size;
    memd_info("learn: task stack at +%d size %lu (thread_info.task at base+%d)\n",
              off, found_size, found_foff);
}

/* Lazy stack learning on first inject (caller process context).
 * Same claim-once discipline as the vma learner. */
void memd_learn_task_stack_once(void)
 {
    bool skip = false;
    spin_lock(&memd_learn_lock);
    {
        static bool done = false;
        if (done)
            skip = true;
        else
            done = true;
    }
    spin_unlock(&memd_learn_lock);
    if (skip)
        return;
    memd_learn_task_stack();
}

void memd_t_comm(struct task_struct *t, char *buf, size_t cap)
 {
    size_t n = 0;
    unsigned long w0 = 0, w1 = 0;
    char tmp[TASK_COMM_LEN];
    if (t && memd_learned.t_comm >= 0 && cap > 0) {
        n = cap - 1;
        if (n > 15)
            n = 15;
        if (!memd_safe_read64((char *)t + memd_learned.t_comm, &w0) &&
            !memd_safe_read64((char *)t + memd_learned.t_comm + 8, &w1)) {
            memcpy(tmp, &w0, 8);
            memcpy(tmp + 8, &w1, 8);
            memcpy(buf, tmp, n);
            buf[n] = '\0';
            return;
        }
    }
    if (cap > 0) {
        /* get_task_comm requires exactly TASK_COMM_LEN bytes. */
        n = cap - 1;
        get_task_comm(tmp, t);
        if (n >= sizeof(tmp))
            n = sizeof(tmp) - 1;
        memcpy(buf, tmp, n);
        buf[n] = '\0';
    }
}

unsigned long memd_m_pgd(struct mm_struct *mm)
 {
    unsigned long v = 0;
    if (mm && memd_learned.m_pgd >= 0 &&
        !memd_safe_read64((char *)mm + memd_learned.m_pgd, &v))
        return v;
    if (!mm)
        return 0;
    return mm->pgd;
}

unsigned long memd_valid_pgd(struct mm_struct *mm)
 {
    unsigned long va, pa;
    if (!mm)
        return 0;
    va = (unsigned long)memd_m_pgd(mm);
    if ((va & 0xffff000000000000UL) != 0xffff000000000000UL)
        return 0;
    if (!virt_addr_valid((void *)va))
        return 0;
    pa = (unsigned long)virt_to_phys((void *)va);
    if (!memd_pgd_shape_ok(pa))
        return 0;
    return va;
}

/* struct cred layout (stable for years, CI-asserted per generation):
 * usage@0 (atomic_t), uid@4 (kuid_t val), cap_effective low word@56.
 * kernel_cap_struct is definitionally two u32 words, so the high word
 * (caps 32..63) sits at base+4 (60 compiled): no extra learning or
 * per-generation proof needed for the second word. */
#define MEMD_CRED_CAP_EFF 56

static unsigned long memd_task_cred(struct task_struct *t)
 {
    unsigned long c = 0;
    if (memd_learned.t_cred < 0 || !t)
        return 0;
    if (memd_safe_read64((char *)t + memd_learned.t_cred, &c))
        return 0;
    if ((c & 0xffff000000000000UL) != 0xffff000000000000UL)
        return 0;
    return c;
}

int memd_capable(int cap)
 {
    unsigned long c = memd_task_cred(current);
    unsigned long off = MEMD_CRED_CAP_EFF;
    u32 eff = 0;
    unsigned int v = 0;
    if (!c || cap < 0 || cap >= 64)
        return 0;
    /* Prefer the learned offset when the (currently dead-code) cred
     * learner ever fills it; 56 is the CI-asserted compiled fallback.
     * Second word (caps 32..63) is base+4 by kernel_cap_struct
     * definition (two u32s). cap>=64 denied (fail closed). */
    if (memd_learned_ext.t_cred_cap_eff >= 0)
        off = (unsigned long)memd_learned_ext.t_cred_cap_eff;
    if (cap >= 32)
        off += 4;
    if (memd_safe_read32((void *)(c + off), &v))
        return 0;
    eff = v;
    return (eff >> (cap & 31)) & 1;
}

/* Cred uid offset: learned when a value-based learner fills it, else
 * the CI-asserted compiled fallback (4). Centralizes the constant so
 * all uid readers share one treatment (adopted: su_stage/su_unstage in
 * memd_inject.c and both uid fills in memd_ioctl.c use this helper
 * with guarded reads, fail closed; verified end-to-end round 18). */
unsigned long memd_cred_uid_off(void)
 {
    if (memd_learned_ext.t_cred_uid >= 0)
        return (unsigned long)memd_learned_ext.t_cred_uid;
    return 4;
}

unsigned int memd_uid(void)
 {
    unsigned long c = memd_task_cred(current);
    unsigned long off = memd_cred_uid_off();
    unsigned int v = 0;
    if (!c)
        return 999999;
    if (memd_safe_read32((void *)(c + off), &v))
        return 999999;
    return v;
}

/* Shared guarded read of one kernel_cap_struct at a learned base offset.
 * Both words come from guarded slots (second word is base+4 by
 * kernel_cap_struct definition: two u32s); any fault/unknown/NULL
 * yields zero caps (fail closed: deny). Plain C89, no literals. */
static struct memd_learn_cap memd_cred_cap_read(int off,
                                                   struct task_struct *t)
 {
    struct memd_learn_cap cap;
    unsigned long c;
    unsigned int lo = 0, hi = 0;
    cap.cap[0] = 0;
    cap.cap[1] = 0;
    if (off < 0 || !t)
        return cap;
    c = (unsigned long)memd_t_cred(t);
    if (!c)
        return cap;
    if (memd_safe_read32((void *)(c + (unsigned long)off), &lo))
        return cap;
    if (memd_safe_read32((void *)(c + (unsigned long)off + 4), &hi))
        return cap;
    cap.cap[0] = lo;
    cap.cap[1] = hi;
    return cap;
}

struct memd_learn_cap memd_t_cred_cap_eff_fn(struct task_struct *t)
 {
    return memd_cred_cap_read(memd_learned_ext.t_cred_cap_eff, t);
}

struct memd_learn_cap memd_t_cred_cap_perm_fn(struct task_struct *t)
 {
    return memd_cred_cap_read(memd_learned_ext.t_cred_cap_perm, t);
}

struct memd_learn_cap memd_t_cred_cap_inh_fn(struct task_struct *t)
 {
    return memd_cred_cap_read(memd_learned_ext.t_cred_cap_inh, t);
}

/* Guarded cred-uid reader backing the header macro. Offset is the
 * shared helper (learned, else compiled 4); any fault/unknown/NULL
 * yields 999999 (matches memd_uid, never 0-as-root: fail closed). */
kuid_t memd_t_cred_uid_fn(struct task_struct *t)
 {
    kuid_t bad;
    unsigned long c;
    unsigned long off;
    unsigned int v = 0;
    bad.val = 999999;
    if (!t)
        return bad;
    c = (unsigned long)memd_t_cred(t);
    if (!c)
        return bad;
    off = memd_cred_uid_off();
    if (memd_safe_read32((void *)(c + off), &v))
        return bad;
    bad.val = v;
    return bad;
}

unsigned long memd_v_start(struct vm_area_struct *vma)
 {
    unsigned long v = 0;
    if (vma && memd_learned.v_start >= 0 &&
        !memd_safe_read64((char *)vma + memd_learned.v_start, &v))
        return v;
    if (!vma)
        return 0;
    return vma->vm_start;
}

unsigned long memd_v_end(struct vm_area_struct *vma)
 {
    unsigned long v = 0;
    if (vma && memd_learned.v_end >= 0 &&
        !memd_safe_read64((char *)vma + memd_learned.v_end, &v))
        return v;
    if (!vma)
        return 0;
    return vma->vm_end;
}

unsigned long memd_v_flags(struct vm_area_struct *vma)
 {
    unsigned long v = 0;
    if (vma && memd_learned.v_flags >= 0 &&
        !memd_safe_read64((char *)vma + memd_learned.v_flags, &v))
        return v;
    if (!vma)
        return 0;
    return vma->vm_flags;
}

/* Per-generation struct file layout is tabled at file scope (see top);
 * these readers use it. */

/* Per-generation struct file f_path offset (6.6/6.12 rework file).
 * Indices match memd_net_gen(). Verified per-gen by asserts. */
struct file_operations *memd_file_fop(struct file *f)
 {
    int g = memd_net_gen();
    unsigned long v = 0;
    if (g < 0 || g >= MEMD_GEN_N || !f)
        return NULL;
    /* Guarded: f may be a torn/UAF or foreign-layout value (the vma walk
     * holds no mmap_lock by design, and the compiled vm_file fallback is
     * garbage on foreign layouts); a raw load here would oops. */
    if (memd_safe_read64((char *)f + memd_fop_off[g], &v) ||
        (v & 0xffff000000000000UL) != 0xffff000000000000UL)
        return NULL;
    return (struct file_operations *)(uintptr_t)v;
}

struct dentry *memd_file_dentry(struct file *f)
 {
    int g = memd_net_gen();
    unsigned long v = 0;
    if (g < 0 || g >= MEMD_GEN_N || !f)
        return NULL;
    /* struct path = { mnt, dentry }: dentry second. Same guarded
     * treatment as f_op above: raw load of a derived pointer oopses. */
    if (memd_safe_read64((char *)f + memd_fpath_off[g] + 8, &v) ||
        (v & 0xffff000000000000UL) != 0xffff000000000000UL)
        return NULL;
    return (struct dentry *)(uintptr_t)v;
}

unsigned long memd_v_file(struct vm_area_struct *vma)
 {
    unsigned long v = 0;
    if (vma && memd_v_file_off >= 0 &&
        !memd_safe_read64((char *)vma + memd_v_file_off, &v))
        return v;
    if (!vma)
        return 0;
    return (unsigned long)vma->vm_file;
}

/* Guarded learned-slot readers backing the header macros (extable-guarded
 * slot, compiled fallback on fault/unknown, NULL-safe fail closed). Plain
 * functions (not inlines) so the header needs no include reordering. */
struct files_struct *memd_t_files_fn(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned_ext.t_files >= 0 &&
        !memd_safe_read64((char *)t + memd_learned_ext.t_files, &v))
        return (struct files_struct *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->files;
}

struct signal_struct *memd_t_signal_fn(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned_ext.t_signal >= 0 &&
        !memd_safe_read64((char *)t + memd_learned_ext.t_signal, &v))
        return (struct signal_struct *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->signal;
}

struct sighand_struct *memd_t_sighand_fn(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned_ext.t_sighand >= 0 &&
        !memd_safe_read64((char *)t + memd_learned_ext.t_sighand, &v))
        return (struct sighand_struct *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->sighand;
}

struct task_struct *memd_t_real_parent_fn(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned_ext.t_real_parent >= 0 &&
        !memd_safe_read64((char *)t + memd_learned_ext.t_real_parent, &v))
        return (struct task_struct *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->real_parent;
}

void *memd_t_stack_fn(struct task_struct *t)
 {
    unsigned long v = 0;
    if (t && memd_learned_ext.t_stack >= 0 &&
        !memd_safe_read64((char *)t + memd_learned_ext.t_stack, &v))
        return (void *)(uintptr_t)v;
    if (!t)
        return NULL;
    return t->stack;
}

struct vm_area_struct *memd_m_mmap_fn(struct mm_struct *mm)
 {
    unsigned long v = 0;
    if (mm && memd_learned_ext.m_mmap >= 0 &&
        !memd_safe_read64((char *)mm + memd_learned_ext.m_mmap, &v))
        return (struct vm_area_struct *)(uintptr_t)v;
    if (!mm)
        return NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
    return mm->mmap;
#else
    /* 6.1+: vma list removed (maple tree); nothing to fall back to. */
    return NULL;
#endif
}

struct path memd_f_path_fn(struct file *f)
 {
    unsigned long m = 0, d = 0;
    struct path p;
    if (f && memd_learned_ext.f_fpath >= 0 &&
        !memd_safe_read64((char *)f + memd_learned_ext.f_fpath, &m) &&
        !memd_safe_read64((char *)f + memd_learned_ext.f_fpath + 8, &d)) {
        p.mnt = (struct vfsmount *)(uintptr_t)m;
        p.dentry = (struct dentry *)(uintptr_t)d;
        return p;
    }
    if (!f) {
        p.mnt = NULL;
        p.dentry = NULL;
        return p;
    }
    return f->f_path;
}

void *memd_f_private_fn(struct file *f)
 {
    unsigned long v = 0;
    if (f && memd_learned_ext.f_private >= 0 &&
        !memd_safe_read64((char *)f + memd_learned_ext.f_private, &v))
        return (void *)(uintptr_t)v;
    if (!f)
        return NULL;
    return f->private_data;
}

/* Extended offset learning for more universality */
static int memd_scan_for_ptr(const void *base, size_t len, const void *target,
                             int *first_off)
 {
    size_t n = len / 8, i;
    int hits = 0;
    for (i = 0; i < n; i++) {
        unsigned long v = 0;
        /* Guarded: file/dentry/inode scans can overrun the slab object
         * on foreign layouts; memcpy would fault. Fail closed. */
        if (memd_safe_read64((const char *)base + i * 8, &v))
            continue;
        if (v == (u64)target) {
            if (!hits && first_off)
                *first_off = (int)(i * 8);
            hits++;
        }
    }
    return hits;
}

static void memd_learn_task_extended(void)
 {
    struct task_struct *t = current;
    struct files_struct *files = t->files;
    struct signal_struct *signal = t->signal;
    struct sighand_struct *sighand = t->sighand;
    struct task_struct *real_parent = t->real_parent;
    struct nsproxy *nsproxy = t->nsproxy;
    struct fs_struct *fs = t->fs;
    int n, found;

    /* Anchors come from compiled field reads, so they are garbage on
     * foreign layouts. Refuse to learn from a non-kernel anchor value
     * (fail closed) instead of scanning for garbage and locking in a
     * wrong offset. Uniqueness (n == 1) is still required below. */
    if (files && ((u64)files & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, files, &found);
        if (n == 1) {
            memd_learned_ext.t_files = found;
            memd_info("learn: task files at +%d\n", found);
        } else {
            memd_err("learn: task files ambiguous (%d)\n", n);
        }
    } else if (files) {
        memd_err("learn: task files anchor insane, skipping\n");
    }

    if (signal && ((u64)signal & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, signal, &found);
        if (n == 1) {
            memd_learned_ext.t_signal = found;
            memd_info("learn: task signal at +%d\n", found);
        } else {
            memd_err("learn: task signal ambiguous (%d)\n", n);
        }
    } else if (signal) {
        memd_err("learn: task signal anchor insane, skipping\n");
    }

    if (sighand && ((u64)sighand & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, sighand, &found);
        if (n == 1) {
            memd_learned_ext.t_sighand = found;
            memd_info("learn: task sighand at +%d\n", found);
        } else {
            memd_err("learn: task sighand ambiguous (%d)\n", n);
        }
    } else if (sighand) {
        memd_err("learn: task sighand anchor insane, skipping\n");
    }

    if (real_parent &&
        ((u64)real_parent & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, real_parent, &found);
        if (n == 1) {
            memd_learned_ext.t_real_parent = found;
            memd_info("learn: task real_parent at +%d\n", found);
        } else {
            memd_err("learn: task real_parent ambiguous (%d)\n", n);
        }
    } else if (real_parent) {
        memd_err("learn: task real_parent anchor insane, skipping\n");
    }

    if (nsproxy && ((u64)nsproxy & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, nsproxy, &found);
        if (n == 1) {
            memd_learned_ext.t_nsproxy = found;
            memd_info("learn: task nsproxy at +%d\n", found);
        } else {
            memd_err("learn: task nsproxy ambiguous (%d)\n", n);
        }
    } else if (nsproxy) {
        memd_err("learn: task nsproxy anchor insane, skipping\n");
    }

    if (fs && ((u64)fs & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, fs, &found);
        if (n == 1) {
            memd_learned_ext.t_fs = found;
            memd_info("learn: task fs at +%d\n", found);
        } else {
            memd_err("learn: task fs ambiguous (%d)\n", n);
        }
    } else if (fs) {
        memd_err("learn: task fs anchor insane, skipping\n");
    }
}

static void memd_learn_mm_extended(void)
 {
    struct mm_struct *mm = get_task_mm(current);
    if (!mm)
        return;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
    /* vma list anchor: mm->mmap exists pre-6.1 (CI-dumped: present on
     * 5.4/5.10/5.15, gone on 6.1+ maple kernels). Nothing to learn
     * there on newer targets (m_mmap stays -1, fail-soft). */
    {
    struct vm_area_struct *mmap = mm->mmap;
    if (mmap &&
        ((u64)mmap & 0xffff000000000000UL) == 0xffff000000000000UL) {
        int found = -1, n = 0, i;
        for (i = 0; i + 8 <= 512; i += 8) {
            u64 v = 0;
            if (memd_safe_read64((char *)mm + i, &v))
                continue;
            if (v == (u64)mmap) {
                if (!n)
                    found = i;
                n++;
            }
        }
        if (n == 1) {
            memd_learned_ext.m_mmap = found;
            memd_info("learn: mm mmap at +%d\n", found);
        } else {
            memd_err("learn: mm mmap ambiguous (%d)\n", n);
        }
    }
    }
#else
    /* 6.1+: vma list removed; nothing to learn here. */
#endif

    mmput(mm);
}

static void memd_learn_file_extended(void)
 {
    struct file *f;
    struct path path;
    struct dentry *dentry;
    struct vfsmount *mnt;
    struct inode *inode;
    struct super_block *sb;
    int found, n, mnt_off;
    unsigned long tmp;
    if (memd_filp_open("/proc/self/exe", O_RDONLY, 0, &f) != 0)
        return;
    if (IS_ERR(f))
        return;
    path = memd_f_path(f);
    dentry = path.dentry;
    mnt = path.mnt;
    /* f_path is struct path = { mnt, dentry } inline: learn it from the
     * two-pointer adjacency (dentry hit must sit 8 past an mnt hit).
     * The old code scanned for &path (a stack address: never matches,
     * dead) and stored a struct file hit into d_parent (a struct
     * dentry field: cross-struct pollution). Both are removed. */
    if (mnt && dentry &&
        ((u64)mnt & 0xffff000000000000UL) == 0xffff000000000000UL &&
        ((u64)dentry & 0xffff000000000000UL) == 0xffff000000000000UL) {
        n = memd_scan_for_ptr(f, 512, mnt, &mnt_off);
        if (n == 1) {
            n = memd_scan_for_ptr(f, 512, dentry, &found);
            if (n == 1 && found == mnt_off + 8) {
                memd_learned_ext.f_fpath = mnt_off;
                memd_info("learn: file f_path at +%d\n", mnt_off);
            } else {
                memd_err("learn: file f_path unconfirmed (%d)\n", n);
            }
        } else {
            memd_err("learn: file f_path mnt ambiguous (%d)\n", n);
        }
    }
    if (dentry &&
        ((u64)dentry & 0xffff000000000000UL) == 0xffff000000000000UL) {
        inode = NULL;
        tmp = 0;
        if (!memd_safe_read64(&dentry->d_inode, &tmp))
            inode = (struct inode *)(uintptr_t)tmp;
        if (inode &&
            ((u64)inode & 0xffff000000000000UL) == 0xffff000000000000UL) {
            sb = NULL;
            tmp = 0;
            if (!memd_safe_read64(&inode->i_sb, &tmp))
                sb = (struct super_block *)(uintptr_t)tmp;
            n = memd_scan_for_ptr(dentry, 256, inode, &found);
            if (n == 1) {
                memd_learned_ext.d_inode = found;
                memd_info("learn: dentry d_inode at +%d\n", found);
            }
            if (sb &&
                ((u64)sb & 0xffff000000000000UL) == 0xffff000000000000UL) {
                n = memd_scan_for_ptr(dentry, 256, sb, &found);
                if (n == 1) {
                    memd_learned_ext.d_sb = found;
                    memd_info("learn: dentry d_sb at +%d\n", found);
                }
                n = memd_scan_for_ptr(inode, 512, sb, &found);
                if (n == 1) {
                    memd_learned_ext.i_sb = found;
                    memd_info("learn: inode i_sb at +%d\n", found);
                }
            }
        }
    }
    memd_filp_close(&f, NULL);
}

int memd_learn_extended(void)
 {
    memd_learn_task_extended();
    memd_learn_mm_extended();
    memd_learn_file_extended();
    return 0;
}

/* Learn struct file.private_data from an exact anchor: our own anon_inode
 * file, whose private pointer we set at creation. The offset is a
 * per-boot constant, so every bind re-confirms the same value
 * (idempotent — first unique hit wins, later binds are no-ops). A
 * non-unique hit leaves -1 (compiled fallback, loud). Guarded reads:
 * our own freshly-created slab object, current context. */
void memd_learn_file_private(struct file *f, void *known_private)
 {
    int found = -1, n = 0;
    bool skip = false;
    if (!f || !known_private)
        return;
    spin_lock(&memd_learn_lock);
    if (memd_learned_ext.f_private >= 0)
        skip = true;
    spin_unlock(&memd_learn_lock);
    if (skip)
        return;
    n = memd_scan_for_ptr(f, 512, known_private, &found);
    if (n == 1) {
        /* First win sticks: a concurrent bind confirming the same
         * per-boot constant must not rewrite it (publish-once). */
        spin_lock(&memd_learn_lock);
        if (memd_learned_ext.f_private < 0)
            memd_learned_ext.f_private = found;
        spin_unlock(&memd_learn_lock);
        memd_info("learn: file private_data at +%d\n", found);
    } else {
        memd_err("learn: file private_data ambiguous (%d)\n", n);
    }
}

void memd_f_private_set(struct file *f, void *v)
 {
    if (!f)
        return;
    if (memd_learned_ext.f_private >= 0) {
        /* Guarded: a wrong learned slot must fault softly, never
         * corrupt. Falls back to compiled on a guard fault. */
        if (!memd_safe_write64((char *)f + memd_learned_ext.f_private,
                               (unsigned long)v))
            return;
        memd_err("learn: f_private guarded write fault, compiled fallback\n");
    }
    f->private_data = v;
}

/* thread_struct is embedded in task_struct (no pointer to scan for):
 * the old code computed &t->thread with the compiled offset and then
 * scanned task for that value, which is circular (wrong answer on any
 * foreign layout, and zero hits even when headers match, since no
 * word in task points at its own inline thread). Fail closed: leave
 * t_thread at -1. Sub-field learners below are likewise confined to
 * self-consistency checks with range guards. */
static void memd_learn_thread_struct(void)
 {
    return;
}

static void memd_learn_signal_struct(void)
 {
    /* Disabled: embedded sub-objects (sigpending, mutex) have no pointer
     * to scan for, and the anchor (t->signal via compiled offset) plus
     * raw memcpy from an unvalidated pointer could fault on foreign
     * layouts. Fail closed: leave offsets at -1 (readers return NULL). */
    return;
}

static void memd_learn_sighand_struct(void)
 {
    /* Disabled: sighand->action is an embedded array, not a pointer, so
     * an interior-address scan can never match; anchor is a compiled
     * offset read. Fail closed at -1. */
    return;
}

/* struct fs_struct lives in <linux/fs_struct.h> (sched.h only
 * forward-declares it on every matrix DDK — CI-probed). */
static void memd_learn_fs_struct(void)
 {
    /* Disabled: fs->pwd/root are embedded struct paths, not pointers to
     * themselves; same unvalidated-anchor + raw memcpy fault risk as
     * signal. Fail closed at -1. */
    return;
}

static void memd_learn_nsproxy_struct(void)
 {
    /* Disabled: searched for field addresses (&mnt_ns) instead of field
     * targets (mnt_ns), which can never match; anchor likewise compiled.
     * Fail closed at -1. */
    return;
}

static void memd_learn_cred_struct(void)
 {
    /* Disabled: cap/uid fields are embedded values, not pointers, so an
     * interior-address scan can never match. memd_capable/memd_uid use
     * the CI-asserted compiled offsets (56/4) or the learned offset if a
     * future value-based learner fills it. Fail closed at -1. */
    return;
}

static void memd_learn_sighand_verify(void)
 {
    /* No compiled-field trust: t->sighand is garbage on any kernel whose
     * layout differs from the build headers, so comparing against it
     * would drop correct learning exactly on foreign kernels. Sanity
     * only: the learned slot must hold a readable kernel address. */
    struct task_struct *t = current;
    unsigned long v = 0;
    if (memd_learned_ext.t_sighand < 0)
        return;
    if (memd_safe_read64((char *)t + memd_learned_ext.t_sighand, &v) || !v ||
        (v & 0xffff000000000000UL) != 0xffff000000000000UL) {
        memd_err("learn: sighand learned ptr insane, dropping\n");
        memd_learned_ext.t_sighand = -1;
    }
}

static int memd_verify_all_offsets(void)
 {
    /* Anchor-based re-checks only (stable function calls, never compiled
     * field offsets). The old code compared learned reads against
     * t->pid/t->tgid/t->mm/t->cred, which is garbage on any kernel whose
     * layout differs from the build headers — it nuked correct learning
     * exactly on the foreign kernels the universal image targets.
     * All re-check reads are extable-guarded (memd_safe_*): a torn or
     * stale slot fails closed to -1 instead of oopsing. Fields whose
     * learners are permanently parked (-1) never reach a deref: every
     * check below is gated on >= 0, so no permanently-unknown offset is
     * trusted here. */
    struct task_struct *t = current;
    int errors = 0;

    if (memd_learned.t_pid >= 0) {
        unsigned int cur = 0;
        if (memd_safe_read32((char *)t + memd_learned.t_pid, &cur) ||
            (pid_t)cur != task_pid_vnr(t)) {
            memd_err("verify: t_pid offset wrong (%d != %d)\n", (pid_t)cur,
                     task_pid_vnr(t));
            memd_learned.t_pid = -1;
            errors++;
        }
    }

    if (memd_learned.t_tgid >= 0) {
        unsigned int cur = 0;
        if (memd_safe_read32((char *)t + memd_learned.t_tgid, &cur) ||
            (pid_t)cur != task_tgid_vnr(t)) {
            memd_err("verify: t_tgid offset wrong (%d != %d)\n", (pid_t)cur,
                     task_tgid_vnr(t));
            memd_learned.t_tgid = -1;
            errors++;
        }
    }

    if (memd_learned.t_mm >= 0) {
        unsigned long got = 0;
        struct mm_struct *anchor = get_task_mm(t);
        if (anchor) {
            if (memd_safe_read64((char *)t + memd_learned.t_mm, &got) ||
                (struct mm_struct *)(uintptr_t)got != anchor) {
                memd_err("verify: t_mm offset wrong\n");
                memd_learned.t_mm = -1;
                errors++;
            }
            mmput(anchor);
        }
    }

    if (memd_learned.t_cred >= 0) {
        /* Re-run the learning-time anchor: loader runs as root, so the
         * cred must look like root cred (usage sane, uid 0). */
        unsigned long c = 0;
        unsigned long w = 0;
        u32 usage = 0, uid = 0;
        bool ok = false;
        if (!memd_safe_read64((char *)t + memd_learned.t_cred, &c) &&
            (c & 0xffff000000000000UL) == 0xffff000000000000UL &&
            !memd_safe_read64((void *)(uintptr_t)c, &w)) {
            usage = (u32)(w & 0xffffffffU);
            uid = (u32)((w >> 32) & 0xffffffffU);
            ok = (usage >= 1 && usage <= 1000 && uid == 0);
        }
        if (!ok) {
            memd_err("verify: t_cred offset wrong\n");
            memd_learned.t_cred = -1;
            errors++;
        }
    }

    return errors;
}

int memd_learn_comprehensive(void)
 {
    int errors = 0;
    bool skip = false;
    spin_lock(&memd_learn_lock);
    if (memd_learn_initialized || memd_learn_started)
        skip = true;
    else
        memd_learn_started = true;
    spin_unlock(&memd_learn_lock);
    if (skip)
        return 0;

    /* Every learner is fail-soft per field (loud, -1) and never aborts
     * the pass: an early failure must not starve later learners. */
    memd_learn();

    memd_learn_extended();

    memd_learn_thread_struct();
    memd_learn_signal_struct();
    memd_learn_sighand_struct();
    memd_learn_fs_struct();
    memd_learn_nsproxy_struct();
    memd_learn_cred_struct();

    memd_learn_sighand_verify();

    errors = memd_verify_all_offsets();
    if (errors > 0) {
        memd_warn("learn: %d offsets failed verification\n", errors);
    }

    spin_lock(&memd_learn_lock);
    memd_learn_initialized = true;
    spin_unlock(&memd_learn_lock);

    return 0;
}
/* kmod/memd/utils/memd_learn.c[∂] */
