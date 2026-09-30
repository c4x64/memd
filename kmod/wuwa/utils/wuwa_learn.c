/* Runtime offset learning. See header for the anchor design.
 * Fail-soft per field (loud log, -1 offset); readers fall back to
 * compiled offsets so old behavior is the floor, never worse. */
#include "wuwa_learn.h"

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
#include <asm/sysreg.h>

#include "wuwa_utils.h"
#include "wuwa_netlayout.h"

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

struct wuwa_learned wuwa_learned = {
    .t_pid = -1, .t_tgid = -1, .t_comm = -1, .t_mm = -1,
    .m_pgd = -1, .v_start = -1, .v_end = -1,
};

#define WUWA_LEARN_SCAN 2048

/* File-scope statics (declared before use). */
static unsigned long (*wuwa_fv)(struct mm_struct *, unsigned long);
static bool wuwa_fv_probed;

/* Per-generation struct file layout (6.6/6.12 rework file completely).
 * Indices match wuwa_net_gen(). Verified per-gen by asserts. */
static const short wuwa_fop_off[] = { 40, 40, 40, 112, 16 };
static const short wuwa_fpath_off[] = { 16, 16, 16, 88, 64 };

static int wuwa_v_file_off = -1;

/* Count 8-byte-aligned u64 matches. */
static int wuwa_count_u64(const void *base, size_t len, u64 val,
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

static void wuwa_learn_task(void)
{
    struct task_struct *t = current;
    pid_t pid = task_pid_vnr(t);
    pid_t tgid = task_tgid_vnr(t);
    struct mm_struct *mm;
    char comm[TASK_COMM_LEN];
    int off = -1, hits, i;
    /* pid/tgid: adjacent equal u32 pair (loader is single-threaded). */
    for (i = 0; i + 8 <= WUWA_LEARN_SCAN; i += 4) {
        u32 a, b;
        memcpy(&a, (char *)t + i, 4);
        memcpy(&b, (char *)t + i + 4, 4);
        if ((pid_t)a == pid && (pid_t)b == tgid) {
            off = i;
            break;
        }
    }
    if (off >= 0) {
        wuwa_learned.t_pid = off;
        wuwa_learned.t_tgid = off + 4;
        wuwa_info("learn: task pid/tgid at +%d\n", off);
    } else {
        wuwa_err("learn: task pid/tgid not found (using compiled)\n");
    }
    /* comm: get_task_comm value as a string. */
    get_task_comm(comm, t);
    comm[sizeof(comm) - 1] = '\0';
    {
        size_t cl = strlen(comm);
        int found = -1, n = 0;
        if (cl > 0 && cl < 32) {
            for (i = 0; i + (int)cl + 1 <= WUWA_LEARN_SCAN; i++) {
                if (!memcmp((char *)t + i, comm, cl + 1)) {
                    if (!n)
                        found = i;
                    n++;
                }
            }
        }
        if (n == 1) {
            wuwa_learned.t_comm = found;
            wuwa_info("learn: task comm at +%d\n", found);
        } else {
            wuwa_err("learn: task comm ambiguous (%d hits)\n", n);
        }
    }
    /* mm: get_task_mm value as a pointer. */
    mm = get_task_mm(t);
    if (mm) {
        if (wuwa_count_u64(t, WUWA_LEARN_SCAN, (u64)mm, &off) == 1) {
            wuwa_learned.t_mm = off;
            wuwa_info("learn: task mm at +%d\n", off);
        } else {
            wuwa_err("learn: task mm ambiguous\n");
        }
        mmput(mm);
    } else {
        wuwa_err("learn: no mm on loader task\n");
    }
    (void)hits;
}

static void wuwa_learn_pgd(void)
{
    struct mm_struct *mm;
    u64 ttbr, mask, want;
    int off = -1;
    mm = get_task_mm(current);
    if (!mm) {
        wuwa_err("learn: no mm for pgd\n");
        return;
    }
    ttbr = read_sysreg(ttbr0_el1);
    mask = ~((1UL << PAGE_SHIFT) - 1);
    want = ttbr & mask;
    /* pgd is early in mm_struct; scan the first page for TTBR0 value. */
    if (wuwa_count_u64(mm, 512, want, &off) == 1) {
        wuwa_learned.m_pgd = off;
        wuwa_info("learn: mm pgd at +%d\n", off);
    } else {
        wuwa_err("learn: mm pgd not unique\n");
    }
    mmput(mm);
}

/* Read one maps line: start, end (hex), perms[0]. Returns 0 ok. */
static int wuwa_maps_line(struct file *f, loff_t *pos, unsigned long *start,
                          unsigned long *end, char *base, size_t basecap)
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

static int wuwa_find_vma_pair(struct mm_struct *mm, unsigned long addr,
                              int *start_off, int *end_off);

/* Learn vm_file slot: scan vma for a file pointer whose dentry name
 * matches the known maps basename (all reads guarded). */
static int wuwa_learn_vma_file(struct mm_struct *mm, unsigned long addr,
                               const char *base)
{
    struct vm_area_struct *vma;
    size_t bl;
    int i, found = -1, n = 0;
    if (!base || !base[0])
        return -1;
    bl = strlen(base);
    if (!wuwa_fv)
        return -1;
    vma = wuwa_fv(mm, addr);
    if (!vma)
        return -1;
    for (i = 0; i + 8 <= 256; i += 8) {
        unsigned long fp = 0, dp = 0, nm = 0, ln = 0;
        char nb[40];
        int g, k;
        if (wuwa_safe_read64((char *)vma + i, &fp) || !fp ||
            (fp & 0xffff000000000000UL) != 0xffff000000000000UL)
            continue;
        /* f_path.dentry via running-generation table */
        {
            int fg = wuwa_net_gen();
            unsigned long fpoff;
            if (fg < 0 || fg >= 5)
                return -1;
            fpoff = (unsigned long)wuwa_fpath_off[fg];
            if (wuwa_safe_read64((char *)fp + fpoff + 8, &dp) || !dp ||
                (dp & 0xffff000000000000UL) != 0xffff000000000000UL)
                continue;
        }
        /* dentry->d_name (qstr at +32, asserted stable): name ptr + len */
        if (wuwa_safe_read64((char *)dp + 32, &nm) ||
            wuwa_safe_read64((char *)dp + 32 + 8, &ln))
            continue;
        if (!nm || ln != bl || ln >= sizeof(nb))
            continue;
        /* guarded byte compare via u64 reads */
        for (k = 0; k < (int)ln; k += 8) {
            unsigned long w = 0;
            int t;
            if (wuwa_safe_read64((char *)nm + k, &w))
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
        wuwa_v_file_off = found;
        wuwa_info("learn: vma vm_file at +%d\n", found);
        return 0;
    }
    /* ambiguous or absent: leave compiled fallback */
    return -1;
}

static void wuwa_learn_vma(void)
{
    struct mm_struct *mm;
    struct file *f;
    loff_t pos = 0;
    unsigned long s1 = 0, e1 = 0, s2 = 0, e2 = 0;
    char b1[48] = {0}, b2[48] = {0};
    int a = -1, b = -1, c = -1, d = -1, g;
    mm = get_task_mm(current);
    if (!mm) {
        wuwa_err("learn: no mm for vma\n");
        return;
    }
    f = filp_open("/proc/self/maps", O_RDONLY, 0);
    if (IS_ERR(f)) {
        wuwa_err("learn: no self maps\n");
        mmput(mm);
        return;
    }
    if (wuwa_maps_line(f, &pos, &s1, &e1, b1, sizeof(b1))) {
        wuwa_err("learn: maps parse failed\n");
        filp_close(f, NULL);
        mmput(mm);
        return;
    }
    /* second line with a pathname (anonymous lines teach nothing) */
    g = 0;
    while (g++ < 8) {
        if (wuwa_maps_line(f, &pos, &s2, &e2, b2, sizeof(b2)))
            break;
        if (b2[0])
            break;
        s2 = e2 = 0;
        b2[0] = '\0';
    }
    filp_close(f, NULL);
    if (!wuwa_find_vma_pair(mm, s1, &a, &b) &&
        s2 && !wuwa_find_vma_pair(mm, s2, &c, &d) && a == c && b == d &&
        a >= 0) {
        wuwa_learned.v_start = a;
        wuwa_learned.v_end = b;
        wuwa_info("learn: vma start/end at +%d/+%d\n", a, b);
    } else {
        wuwa_err("learn: vma pair unconfirmed\n");
    }
    if (b1[0] && !wuwa_learn_vma_file(mm, s1, b1))
        wuwa_info("learn: vma file confirmed on 1 line\n");
    else if (b2[0] && !wuwa_learn_vma_file(mm, s2, b2))
        wuwa_info("learn: vma file confirmed on 2 lines\n");
    else
        wuwa_err("learn: vma file unconfirmed (compiled fallback)\n");
    mmput(mm);
}

/* find_vma by runtime address (dual name), then pair-scan. */
static int wuwa_find_vma_pair(struct mm_struct *mm, unsigned long addr,
                              int *start_off, int *end_off)
{
    struct vm_area_struct *vma;
    int i;
    if (!wuwa_fv_probed) {
        wuwa_fv_probed = true;
        wuwa_fv = (void *)kallsyms_lookup_name_ex("find_vma");
        if (!wuwa_fv)
            wuwa_fv = (void *)kallsyms_lookup_name_ex("__find_vma");
    }
    if (!wuwa_fv)
        return -1;
    vma = wuwa_fv(mm, addr);
    if (!vma)
        return -1;
    /* adjacent u64 pair (a,b): a<=addr<b, sane span, page-aligned a */
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

int wuwa_learn(void)
{
    wuwa_learn_task();
    wuwa_learn_pgd();
    wuwa_learn_vma();
    return 0;
}

pid_t wuwa_t_pid(struct task_struct *t)
{
    if (wuwa_learned.t_pid >= 0)
        return *(pid_t *)((char *)t + wuwa_learned.t_pid);
    return t->pid;
}

pid_t wuwa_t_tgid(struct task_struct *t)
{
    if (wuwa_learned.t_tgid >= 0)
        return *(pid_t *)((char *)t + wuwa_learned.t_tgid);
    return t->tgid;
}

struct mm_struct *wuwa_t_mm(struct task_struct *t)
{
    if (wuwa_learned.t_mm >= 0)
        return *(struct mm_struct **)((char *)t + wuwa_learned.t_mm);
    return t->mm;
}

int wuwa_t_mm_null(struct task_struct *t)
{
    return wuwa_t_mm(t) == NULL;
}

void wuwa_t_comm(struct task_struct *t, char *buf, size_t cap)
{
    if (wuwa_learned.t_comm >= 0 && cap > 0) {
        size_t n = cap - 1;
        if (n > 15)
            n = 15;
        memcpy(buf, (char *)t + wuwa_learned.t_comm, n);
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

unsigned long wuwa_m_pgd(struct mm_struct *mm)
{
    if (wuwa_learned.m_pgd >= 0)
        return *(unsigned long *)((char *)mm + wuwa_learned.m_pgd);
    return mm->pgd;
}

unsigned long wuwa_v_start(struct vm_area_struct *vma)
{
    if (wuwa_learned.v_start >= 0)
        return *(unsigned long *)((char *)vma + wuwa_learned.v_start);
    return vma->vm_start;
}

unsigned long wuwa_v_end(struct vm_area_struct *vma)
{
    if (wuwa_learned.v_end >= 0)
        return *(unsigned long *)((char *)vma + wuwa_learned.v_end);
    return vma->vm_end;
}

/* Per-generation struct file layout is tabled at file scope (see top);
 * these readers use it. */

/* Per-generation struct file f_path offset (6.6/6.12 rework file).
 * Indices match wuwa_net_gen(). Verified per-gen by asserts. */
struct file_operations *wuwa_file_fop(struct file *f)
{
    int g = wuwa_net_gen();
    if (g < 0 || g >= 5 || !f)
        return NULL;
    return *(struct file_operations **)((char *)f + wuwa_fop_off[g]);
}

struct dentry *wuwa_file_dentry(struct file *f)
{
    int g = wuwa_net_gen();
    struct dentry *d;
    if (g < 0 || g >= 5 || !f)
        return NULL;
    /* struct path = { mnt, dentry }: dentry second. */
    d = *(struct dentry **)((char *)f + wuwa_fpath_off[g] + 8);
    return d;
}

unsigned long wuwa_v_file(struct vm_area_struct *vma)
{
    if (wuwa_v_file_off >= 0)
        return *(unsigned long *)((char *)vma + wuwa_v_file_off);
    return (unsigned long)vma->vm_file;
}
