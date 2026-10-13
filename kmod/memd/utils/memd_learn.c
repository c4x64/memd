/* Runtime offset learning. See header for the anchor design.
 * Fail-soft per field (loud log, -1 offset); readers fall back to
 * compiled offsets so old behavior is the floor, never worse. */
#include "memd_learn.h"

#include <linux/cred.h>
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
#include <asm/sysreg.h>

#include "memd_utils.h"
#include "memd_netlayout.h"

static bool memd_learn_initialized = false;
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
    .m_env_end = -1, .f_fpath = -1, .f_op = -1, .f_inode = -1, .f_mapping = -1,
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
};

#define MEMD_LEARN_SCAN 2048

/* File-scope statics (declared before use). */
static unsigned long (*memd_fv)(struct mm_struct *, unsigned long);
static bool memd_fv_probed;

/* Per-generation struct file layout (6.6/6.12 rework file completely).
 * Indices match memd_net_gen(). Verified per-gen by asserts.
 * 5.4 shares the pre-6.6 layout (f_op@40, f_path@16); the android11-5.4
 * matrix job proves it at build time, never at load. */
static const short memd_fop_off[] = { 40, 40, 40, 40, 192, 16 };
static const short memd_fpath_off[] = { 16, 16, 16, 16, 168, 64 };

static int memd_v_file_off = -1;

/* Count 8-byte-aligned u64 matches. */
static int memd_count_u64(const void *base, size_t len, u64 val,
                          int *first_off)
 {
    size_t n = len / 8, i;
    int hits = 0;
    for (i = 0; i < n; i++) {
        u64 v;
        memcpy(&v, (const char *)base + i * 8, 8);
        if (v == val) {
            if (!hits && first_off)
                *first_off = (int)(i * 8);
            hits++;
        }
    }
    return hits;
}

static void memd_learn_task(void)
 {
    struct task_struct *t = current;
    pid_t pid = task_pid_vnr(t);
    pid_t tgid = task_tgid_vnr(t);
    struct mm_struct *mm;
    char comm[TASK_COMM_LEN];
    int off = -1, hits, i;
    /* pid/tgid: adjacent equal u32 pair (loader is single-threaded). */
    for (i = 0; i + 8 <= MEMD_LEARN_SCAN; i += 4) {
        u32 a, b;
        memcpy(&a, (char *)t + i, 4);
        memcpy(&b, (char *)t + i + 4, 4);
        if ((pid_t)a == pid && (pid_t)b == tgid) {
            off = i;
            break;
        }
    }
    if (off >= 0) {
        memd_learned.t_pid = off;
        memd_learned.t_tgid = off + 4;
        memd_info("learn: task pid/tgid at +%d\n", off);
    } else {
        memd_err("learn: task pid/tgid not found (using compiled)\n");
    }
    /* comm: get_task_comm value as a string. */
    get_task_comm(comm, t);
    comm[sizeof(comm) - 1] = '\0';
    {
        size_t cl = strlen(comm);
        int found = -1, n = 0;
        if (cl > 0 && cl < 32) {
            for (i = 0; i + (int)cl + 1 <= MEMD_LEARN_SCAN; i++) {
                if (!memcmp((char *)t + i, comm, cl + 1)) {
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
    /* mm: compiled offset first (fast + self-verifying), then scan.
     * mm/active_mm are adjacent same-value pointers: first hit wins. */
    mm = get_task_mm(t);
    if (mm) {
        int o1 = -1, o2 = -1, n = 0, i2;
        if (t->mm == mm) {
            memd_learned.t_mm = (int)((char *)&t->mm - (char *)t);
            memd_info("learn: task mm compiled+%d confirmed\n",
                      memd_learned.t_mm);
        } else {
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
            if (n == 1 || (n == 2 && o2 == o1 + 8)) {
                memd_learned.t_mm = o1;
                memd_info("learn: task mm at +%d\n", o1);
            } else {
                memd_err("learn: task mm ambiguous (%d)\n", n);
            }
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
    (void)hits;
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
    /* TTBR0 match (non-KPTI fast path): strip ASID, keep phys page. */
    want = ttbr & 0x0000fffffffff000ULL;
    if ((u64)mm->pgd == want) {
        memd_learned.m_pgd = (int)((char *)&mm->pgd - (char *)mm);
        memd_info("learn: mm pgd compiled+%d confirmed\n",
                  memd_learned.m_pgd);
        mmput(mm);
        return;
    }
    /* Shape scan (KPTI-proof): TTBR0 (user tables) need not equal
     * mm->pgd, so find the pgd by table shape instead of value.
     * First shape-passing kernel pointer in mm wins (pgd is early).
     * Direct reads are safe (mm slab is mapped); table reads guarded. */
    {
        int i, found = -1, n = 0;
        for (i = 0; i + 8 <= 512; i += 8) {
            u64 va = 0, pa = 0;
            memcpy(&va, (char *)mm + i, 8);
            if ((va & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
            /* skip obvious non-tables (low values, stack-like?) */
            pa = (unsigned long)virt_to_phys((void *)(uintptr_t)va);
            if (!memd_pgd_shape_ok(pa))
                continue;
            if (!n)
                found = i;
            n++;
        }
        if (found >= 0 && n == 1) {
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
    return zeros > 100 && valid > 0;
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
    n = kernel_read(f, buf, sizeof(buf) - 1, pos);
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
 * so no need to exclude learned slots explicitly. */
static void memd_learn_vma_flags(struct mm_struct *mm, unsigned long s1,
                                  unsigned long s2, unsigned p1, unsigned p2)
 {
    static const unsigned long mask = (unsigned long)(VM_READ | VM_WRITE | VM_EXEC | VM_SHARED);
    struct vm_area_struct *v1, *v2;
    int i, found = -1, n = 0;
    if (!memd_fv || !mm || !s1 || !s2 || p1 == p2)
        return;
    v1 = memd_fv(mm, s1);
    v2 = memd_fv(mm, s2);
    if (!v1 || !v2)
        return;
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
    if (!base || !base[0])
        return -1;
    bl = strlen(base);
    if (!memd_fv)
        return -1;
    vma = memd_fv(mm, addr);
    if (!vma)
        return -1;
    for (i = 0; i + 8 <= 256; i += 8) {
        unsigned long fp = 0, dp = 0, nm = 0, ln = 0;
        char nb[40];
        int g, k;
        if (memd_safe_read64((char *)vma + i, &fp) || !fp ||
            (fp & 0xffff000000000000UL) != 0xffff000000000000UL)
            continue;
        /* f_path.dentry via running-generation table */
        {
            int fg = memd_net_gen();
            unsigned long fpoff;
            if (fg < 0 || fg >= MEMD_GEN_N)
                return -1;
            fpoff = (unsigned long)memd_fpath_off[fg];
            if (memd_safe_read64((char *)fp + fpoff + 8, &dp) || !dp ||
                (dp & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
        }
        /* dentry->d_name (qstr at +32, asserted stable): name ptr + len */
        if (memd_safe_read64((char *)dp + 32, &nm) ||
            memd_safe_read64((char *)dp + 32 + 8, &ln))
            continue;
        if (!nm || ln != bl || ln >= sizeof(nb))
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

/* find_vma by runtime address (dual name), then pair-scan. */
static int memd_find_vma_pair(struct mm_struct *mm, unsigned long addr,
                              int *start_off, int *end_off)
 {
    struct vm_area_struct *vma;
    int i;
    if (!memd_fv_probed) {
        memd_fv_probed = true;
        memd_fv = (void *)kallsyms_lookup_name_ex("find_vma");
        if (!memd_fv)
            memd_fv = (void *)kallsyms_lookup_name_ex("__find_vma");
    }
    if (!memd_fv)
        return -1;
    vma = memd_fv(mm, addr);
    if (!vma)
        return -1;
    /* adjacent u64 pair (a, b): a<=addr<b, sane span, page-aligned a */
    for (i = 0; i + 16 <= 512; i += 8) {
        u64 x, y;
        memcpy(&x, (char *)vma + i, 8);
        memcpy(&y, (char *)vma + i + 8, 8);
        if (x <= addr && addr < y && y - x < (1UL << 32) &&
            (x & ((1UL << PAGE_SHIFT) - 1)) == 0) {
            /* confirm uniqueness in this vma */
            int j, hits = 0, jo = -1;
            for (j = 0; j + 16 <= 512; j += 8) {
                u64 p, q;
                memcpy(&p, (char *)vma + j, 8);
                memcpy(&q, (char *)vma + j + 8, 8);
                if (p == x && q == y) {
                    hits++;
                    jo = j;
                }
            }
            if (hits == 1) {
                *start_off = jo;
                *end_off = jo + 8;
                return 0;
            }
            return -1;
        }
    }
    return -1;
}

int memd_learn(void)
 {
    memd_learn_task();
    memd_learn_pgd();
    return 0;
}

/* Lazy vma learning on first get_module_base (target task context). */
void memd_learn_vma_once(void)
 {
    static bool done = false;
    if (done)
        return;
    done = true;
    memd_learn_vma();
}

pid_t memd_t_pid(struct task_struct *t)
 {
    if (memd_learned.t_pid >= 0)
        return *(pid_t *)((char *)t + memd_learned.t_pid);
    return t->pid;
}

pid_t memd_t_tgid(struct task_struct *t)
 {
    if (memd_learned.t_tgid >= 0)
        return *(pid_t *)((char *)t + memd_learned.t_tgid);
    return t->tgid;
}

struct mm_struct *memd_t_mm(struct task_struct *t)
 {
    if (memd_learned.t_mm >= 0)
        return *(struct mm_struct **)((char *)t + memd_learned.t_mm);
    return t->mm;
}

int memd_t_mm_null(struct task_struct *t)
 {
    return memd_t_mm(t) == NULL;
}

void memd_t_comm(struct task_struct *t, char *buf, size_t cap)
 {
    if (memd_learned.t_comm >= 0 && cap > 0) {
        size_t n = cap - 1;
        if (n > 15)
            n = 15;
        memcpy(buf, (char *)t + memd_learned.t_comm, n);
        buf[n] = '\0';
        return;
    }
    if (cap > 0) {
        /* get_task_comm requires exactly TASK_COMM_LEN bytes. */
        char tmp[TASK_COMM_LEN];
        size_t n = cap - 1;
        get_task_comm(tmp, t);
        if (n > sizeof(tmp))
            n = sizeof(tmp);
        memcpy(buf, tmp, n);
        buf[n] = '\0';
    }
}

unsigned long memd_m_pgd(struct mm_struct *mm)
 {
    if (memd_learned.m_pgd >= 0)
        return *(unsigned long *)((char *)mm + memd_learned.m_pgd);
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
    pa = (unsigned long)virt_to_phys((void *)va);
    if (!memd_pgd_shape_ok(pa))
        return 0;
    return va;
}

/* struct cred layout (stable for years, CI-asserted per generation):
 * usage@0 (atomic_t), uid@4 (kuid_t val), cap_effective low word@56. */
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
    u32 eff = 0;
    unsigned int v = 0;
    if (!c || cap < 0 || cap >= 32)
        return 0;
    if (memd_safe_read32((void *)(c + MEMD_CRED_CAP_EFF), &v))
        return 0;
    eff = v;
    return (eff >> cap) & 1;
}

unsigned int memd_uid(void)
 {
    unsigned long c = memd_task_cred(current);
    unsigned int v = 0;
    if (!c)
        return 999999;
    if (memd_safe_read32((void *)(c + 4), &v))
        return 999999;
    return v;
}

unsigned long memd_v_start(struct vm_area_struct *vma)
 {
    if (memd_learned.v_start >= 0)
        return *(unsigned long *)((char *)vma + memd_learned.v_start);
    return vma->vm_start;
}

unsigned long memd_v_end(struct vm_area_struct *vma)
 {
    if (memd_learned.v_end >= 0)
        return *(unsigned long *)((char *)vma + memd_learned.v_end);
    return vma->vm_end;
}

unsigned long memd_v_flags(struct vm_area_struct *vma)
 {
    if (memd_learned.v_flags >= 0)
        return *(unsigned long *)((char *)vma + memd_learned.v_flags);
    return vma->vm_flags;
}

/* Per-generation struct file layout is tabled at file scope (see top);
 * these readers use it. */

/* Per-generation struct file f_path offset (6.6/6.12 rework file).
 * Indices match memd_net_gen(). Verified per-gen by asserts. */
struct file_operations *memd_file_fop(struct file *f)
 {
    int g = memd_net_gen();
    if (g < 0 || g >= MEMD_GEN_N || !f)
        return NULL;
    return *(struct file_operations **)((char *)f + memd_fop_off[g]);
}

struct dentry *memd_file_dentry(struct file *f)
 {
    int g = memd_net_gen();
    struct dentry *d;
    if (g < 0 || g >= MEMD_GEN_N || !f)
        return NULL;
    /* struct path = { mnt, dentry }: dentry second. */
    d = *(struct dentry **)((char *)f + memd_fpath_off[g] + 8);
    return d;
}

unsigned long memd_v_file(struct vm_area_struct *vma)
 {
    if (memd_v_file_off >= 0)
        return *(unsigned long *)((char *)vma + memd_v_file_off);
    return (unsigned long)vma->vm_file;
}

/* Extended offset learning for more universality */
static int memd_scan_for_ptr(const void *base, size_t len, const void *target,
                             int *first_off)
 {
    size_t n = len / 8, i;
    int hits = 0;
    for (i = 0; i < n; i++) {
        u64 v;
        memcpy(&v, (const char *)base + i * 8, 8);
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
    struct mm_struct *mm = t->mm;
    struct task_struct *real_parent = t->real_parent;
    struct nsproxy *nsproxy = t->nsproxy;
    struct fs_struct *fs = t->fs;
    int i, n, found;

    if (files) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, files, &found);
        if (n == 1) {
            memd_learned_ext.t_files = found;
            memd_info("learn: task files at +%d\n", found);
        } else {
            memd_err("learn: task files ambiguous (%d)\n", n);
        }
    }

    if (signal) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, signal, &found);
        if (n == 1) {
            memd_learned_ext.t_signal = found;
            memd_info("learn: task signal at +%d\n", found);
        } else {
            memd_err("learn: task signal ambiguous (%d)\n", n);
        }
    }

    if (sighand) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, sighand, &found);
        if (n == 1) {
            memd_learned_ext.t_sighand = found;
            memd_info("learn: task sighand at +%d\n", found);
        } else {
            memd_err("learn: task sighand ambiguous (%d)\n", n);
        }
    }

    if (real_parent) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, real_parent, &found);
        if (n == 1) {
            memd_learned_ext.t_real_parent = found;
            memd_info("learn: task real_parent at +%d\n", found);
        } else {
            memd_err("learn: task real_parent ambiguous (%d)\n", n);
        }
    }

    if (nsproxy) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, nsproxy, &found);
        if (n == 1) {
            memd_learned_ext.t_nsproxy = found;
            memd_info("learn: task nsproxy at +%d\n", found);
        } else {
            memd_err("learn: task nsproxy ambiguous (%d)\n", n);
        }
    }

    if (fs) {
        n = memd_scan_for_ptr(t, MEMD_LEARN_SCAN, fs, &found);
        if (n == 1) {
            memd_learned_ext.t_fs = found;
            memd_info("learn: task fs at +%d\n", found);
        } else {
            memd_err("learn: task fs ambiguous (%d)\n", n);
        }
    }
}

static void memd_learn_mm_extended(void)
 {
    struct mm_struct *mm = get_task_mm(current);
    if (!mm)
        return;

    struct vm_area_struct *mmap = mm->mmap;
    if (mmap) {
        int found = -1, n = 0;
        for (int i = 0; i + 8 <= 512; i += 8) {
            u64 v = 0;
            memcpy(&v, (char *)mm + i, 8);
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

    mmput(mm);
}

static void memd_learn_file_extended(void)
 {
    struct file *f;
    struct path path;
    struct dentry *dentry;
    struct inode *inode;
    struct super_block *sb;
    int found, n;

    if (memd_filp_open("/proc/self/exe", O_RDONLY, 0, &f) != 0)
        return;
    if (IS_ERR(f))
        return;

    path = memd_f_path(f);
    dentry = path.dentry;
    if (dentry) {
        inode = dentry->d_inode;
        if (inode) {
            sb = inode->i_sb;

            n = memd_scan_for_ptr(f, 512, &path, &found);
            if (n == 1) {
                memd_learned_ext.f_fpath = found;
                memd_info("learn: file f_path at +%d\n", found);
            }

            n = memd_scan_for_ptr(f, 512, dentry, &found);
            if (n == 1) {
                memd_learned_ext.d_parent = found;
                memd_info("learn: dentry d_parent at +%d\n", found);
            }

            n = memd_scan_for_ptr(dentry, 256, inode, &found);
            if (n == 1) {
                memd_learned_ext.d_inode = found;
                memd_info("learn: dentry d_inode at +%d\n", found);
            }

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
    memd_filp_close(&f, NULL);
}

int memd_learn_extended(void)
 {
    memd_learn_task_extended();
    memd_learn_mm_extended();
    memd_learn_file_extended();
    return 0;
}

static void memd_learn_thread_struct(void)
 {
    struct task_struct *t = current;
    struct thread_struct *thread = &t->thread;
    int found = -1, n = 0;

    for (int i = 0; i + 8 <= MEMD_LEARN_SCAN; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)t + i, 8);
        if (v == (u64)thread) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_thread = found;
        memd_info("learn: task thread at +%d\n", found);
    } else {
        memd_err("learn: task thread ambiguous (%d)\n", n);
    }

    /* Learn thread_struct fields */
    if (found >= 0) {
        struct thread_struct *ts = thread;

        n = memd_scan_for_ptr(thread, 512, &ts->cpu_context, &found);
        if (n == 1) {
            memd_learned_ext.t_thread_cpuctx = found;
            memd_info("learn: thread cpu_context at +%d\n", found);
        }

        n = memd_scan_for_ptr(thread, 512, &ts->fpsimd_state, &found);
        if (n == 1) {
            memd_learned_ext.t_thread_fpsimd = found;
            memd_info("learn: thread fpsimd_state at +%d\n", found);
        }
    }
}

static void memd_learn_signal_struct(void)
 {
    struct task_struct *t = current;
    struct signal_struct *sig = t->signal;
    if (!sig)
        return;

    int found = -1, n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)sig + i, 8);
        if (v == (u64)&sig->shared_pending) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_signal_shared_pending = found;
        memd_info("learn: signal shared_pending at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)sig + i, 8);
        if (v == (u64)&sig->cred_guard_mutex) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_signal_cred_guard = found;
        memd_info("learn: signal cred_guard_mutex at +%d\n", found);
    }
}

static void memd_learn_sighand_struct(void)
 {
    struct task_struct *t = current;
    struct sighand_struct *sh = t->sighand;
    if (!sh)
        return;

    int found = -1, n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)sh + i, 8);
        if (v == (u64)&sh->action) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_sighand_action = found;
        memd_info("learn: sighand action at +%d\n", found);
    }
}

static void memd_learn_fs_struct(void)
 {
    struct task_struct *t = current;
    struct fs_struct *fs = t->fs;
    if (!fs)
        return;

    int found = -1, n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)fs + i, 8);
        if (v == (u64)&fs->pwd) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_fs_pwd = found;
        memd_info("learn: fs pwd at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)fs + i, 8);
        if (v == (u64)&fs->root) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_fs_root = found;
        memd_info("learn: fs root at +%d\n", found);
    }
}

static void memd_learn_nsproxy_struct(void)
 {
    struct task_struct *t = current;
    struct nsproxy *nsp = t->nsproxy;
    if (!nsp)
        return;

    int found = -1, n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)nsp + i, 8);
        if (v == (u64)&nsp->mnt_ns) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_nsproxy_mnt_ns = found;
        memd_info("learn: nsproxy mnt_ns at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)nsp + i, 8);
        if (v == (u64)&nsp->pid_ns_for_children) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_nsproxy_pid_ns = found;
        memd_info("learn: nsproxy pid_ns at +%d\n", found);
    }
}

static void memd_learn_cred_struct(void)
 {
    struct task_struct *t = current;
    struct cred *c = t->cred;
    if (!c)
        return;

    int found = -1, n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)c + i, 8);
        if (v == (u64)&c->cap_effective) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_cred_cap_eff = found;
        memd_info("learn: cred cap_effective at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)c + i, 8);
        if (v == (u64)&c->cap_permitted) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_cred_cap_perm = found;
        memd_info("learn: cred cap_permitted at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)c + i, 8);
        if (v == (u64)&c->cap_inheritable) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_cred_cap_inh = found;
        memd_info("learn: cred cap_inheritable at +%d\n", found);
    }

    found = -1; n = 0;
    for (int i = 0; i + 8 <= 512; i += 8) {
        u64 v = 0;
        memcpy(&v, (char *)c + i, 8);
        if (v == (u64)&c->uid) {
            if (!n)
                found = i;
            n++;
        }
    }
    if (n == 1) {
        memd_learned_ext.t_cred_uid = found;
        memd_info("learn: cred uid at +%d\n", found);
    }
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
     * exactly on the foreign kernels the universal image targets. */
    struct task_struct *t = current;
    int errors = 0;

    if (memd_learned.t_pid >= 0) {
        pid_t *pid_ptr = (void *)((char *)t + memd_learned.t_pid);
        if (*pid_ptr != task_pid_vnr(t)) {
            memd_err("verify: t_pid offset wrong (%d != %d)\n", *pid_ptr, task_pid_vnr(t));
            memd_learned.t_pid = -1;
            errors++;
        }
    }

    if (memd_learned.t_tgid >= 0) {
        pid_t *tgid_ptr = (void *)((char *)t + memd_learned.t_tgid);
        if (*tgid_ptr != task_tgid_vnr(t)) {
            memd_err("verify: t_tgid offset wrong (%d != %d)\n", *tgid_ptr, task_tgid_vnr(t));
            memd_learned.t_tgid = -1;
            errors++;
        }
    }

    if (memd_learned.t_mm >= 0) {
        struct mm_struct **mm_ptr = (void *)((char *)t + memd_learned.t_mm);
        struct mm_struct *anchor = get_task_mm(t);
        if (anchor) {
            if (*mm_ptr != anchor) {
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
    int ret = 0;

    spin_lock(&memd_learn_lock);
    if (memd_learn_initialized) {
        spin_unlock(&memd_learn_lock);
        return 0;
    }
    spin_unlock(&memd_learn_lock);

    ret = memd_learn();
    if (ret)
        return ret;

    memd_learn_extended();

    memd_learn_thread_struct();
    memd_learn_signal_struct();
    memd_learn_sighand_struct();
    memd_learn_fs_struct();
    memd_learn_nsproxy_struct();
    memd_learn_cred_struct();

    memd_learn_sighand_verify();

    int errors = memd_verify_all_offsets();
    if (errors > 0) {
        memd_warn("learn: %d offsets failed verification\n", errors);
    }

    spin_lock(&memd_learn_lock);
    memd_learn_initialized = true;
    spin_unlock(&memd_learn_lock);

    return 0;
}
