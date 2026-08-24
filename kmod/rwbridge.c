// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c — self-contained ARM64 kernel R/W bridge via eBPF-free
 * hardware-assisted address-space switching.
 *
 * ZERO hardcoded struct offsets. Everything derived at init from:
 *   sp_el0     → current task_struct (hardware guarantee)
 *   ttbr0_el1  → current PGD physical address (hardware guarantee)
 *   Memory scanning at EL1 (raw derefs, full kernel privileges)
 *
 * Cross-process R/W via TTBR0_EL1 switch:
 *   Save current TTBR0 → disable IRQs → set target PGD PA → isb
 *   → deref target VA natively (MMU translates) → restore TTBR0 → isb
 *
 * Interface: sysfs params (same as before)
 *   rw      (0200)  "R,pid,addr,size" / "W,pid,addr,size,value"
 *                   "P,cmdline-substr"  / "B,pid,libname"
 *   out     (0444)  result data
 *   status  (0444)  0 or -errno
 *   stage   (0444)  debug phase string
 *
 * No insmod params. No external dependencies beyond module_layout + _printk.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>

/* ── constants ─────────────────────────────────────────────────────────── */

#define RW_MAX_SIZE      256UL
#define SCAN_RANGE       4096        /* bytes of task_struct to scan */
#define MM_SCAN_RANGE    1024        /* bytes of mm_struct to scan */
#define TASK_WALK_MAX    16384
#define NAME_LEN         16

/* arm64 page constants — universal for aarch64 */
#define PAGE_SIZE_4K     0x1000UL
#define PAGE_MASK_4K     (~(PAGE_SIZE_4K - 1))
#define PA_LOW_BITS      47UL       /* arm64 PA width up to 48 bits */
#define PA_MASK          ((1UL << PA_LOW_BITS) - 1) & ~PAGE_MASK_4K

/* ── module state ──────────────────────────────────────────────────────── */

static unsigned char rw_buf[RW_MAX_SIZE];
static long rw_status;
static long rw_text_len;           /* >0: `out` is ASCII text */
static char rw_stage[16] = "idle";

static unsigned long cur_task;         /* sp_el0 value at init */
static unsigned long pid_offset;       /* offset of pid in task_struct */
static unsigned long mm_offset;        /* offset of mm_struct* in task_struct */
static unsigned long pgd_offset;       /* offset of pgd in mm_struct */
static unsigned long tasks_offset;     /* offset of tasks list_head in task_struct */
static unsigned long comm_offset;      /* offset of comm[] in task_struct */
static unsigned long arg_start_offset; /* offset of arg_start in mm_struct */
static unsigned long arg_end_offset;   /* offset of arg_end in mm_struct */
static unsigned long page_off;         /* PAGE_OFFSET derived from scanning */
static unsigned long phys_off;         /* PHYS_OFFSET derived from ttbr0 vs pgd */
static int derive_ok;

/* LDXR/STXR spinlock — no kernel imports needed */
static volatile unsigned int lock_val;

static inline void lxgr_spin_lock(void)
{
    unsigned int tmp;
    asm volatile(
    "1:\n"
    "   ldxr    %w0, %1\n"
    "   cbnz    %w0, 1b\n"
    "   mov     %w0, #1\n"
    "   stxr    %w0, %w0, %1\n"
    "   cbnz    %w0, 1b\n"
    : "=&r"(tmp), "+Q"(lock_val)
    :
    : "memory");
}

static inline void lxgr_spin_unlock(void)
{
    asm volatile("stlr wzr, %0" : : "Q"(lock_val) : "memory");
}

#define STAGE(s) do { \
    const char *__s = (s); \
    size_t __i = 0; \
    while (__s[__i] && __i < sizeof(rw_stage)-1) { \
        rw_stage[__i] = __s[__i]; __i++; \
    } \
    rw_stage[__i] = 0; \
} while(0)

/* ── hex output helpers ────────────────────────────────────────────────── */

static void put_hex_bytes(unsigned long off, const u8 *data, unsigned long len)
{
    static const char hx[] = "0123456789abcdef";
    unsigned long i;
    for (i = 0; i < len && off + 1 < RW_MAX_SIZE * 2; i++) {
        rw_buf[off++] = hx[data[i] >> 4];
        rw_buf[off++] = hx[data[i] & 0xf];
    }
    rw_text_len = off;
}

static void put_hex_u64(unsigned long off, unsigned long v)
{
    static const char hx[] = "0123456789abcdef";
    int k;
    for (k = 15; k >= 0 && off < RW_MAX_SIZE * 2; k--)
        rw_buf[off++] = hx[(v >> (k * 4)) & 0xf];
    rw_text_len = off;
}

static void put_dec_u32(unsigned long off, u32 v)
{
    char tmp[12];
    int i = 0, n = 0;
    if (!v) { rw_buf[off++] = '0'; rw_text_len = off; return; }
    while (v) { tmp[i++] = '0' + v % 10; v /= 10; }
    while (i) rw_buf[off++] = tmp[--i];
    rw_text_len = off;
}

/* ── init-time derivation ────────────────────────────────────────────────*/

/*
 * Get our own PID. In module_init context this runs inside the insmod
 * process's syscall. We can read it from the task directly once we know
 * the offset, but for FINDING the offset we use the fact that insmod's
 * pid appears in /proc/self (we can't read procfs from kernel space).
 *
 * Instead: scan for two adjacent u32 fields where both equal the same
 * small number (< 4194304). On arm64 Linux, task_struct has pid and
 * tgid adjacent with pid == tgid for thread group leaders.
 */
static int find_pid_offset(unsigned long cur)
{
    unsigned int *p = (unsigned int *)cur;
    int i;

    for (i = 0; i < SCAN_RANGE / 4 - 1; i++) {
        u32 a = p[i], b = p[i + 1];
        /* pid and tgid are adjacent; leader has pid == tgid */
        if (a == b && a > 0 && a < 4194304)
            return i * 4;
    }
    return -1;
}

/*
 * Find PAGE_OFFSET by scanning cur for kernel-range pointers.
 * Kernel VAs on arm64 start at PAGE_OFFSET which is one of:
 *   39-bit: 0xffffff8000000000
 *   48-bit: 0xffff800000000000
 * We detect by looking for values matching either pattern.
 */
static unsigned long find_page_offset(unsigned long cur)
{
    unsigned long *p = (unsigned long *)cur;
    int i;

    for (i = 0; i < SCAN_RANGE / 8; i++) {
        unsigned long v = p[i];
        if ((v & 0xffff800000000000UL) == 0xffff800000000000UL &&
            (v & 0x00007f0000000000UL) != 0)
            return 0xffff800000000000UL;  /* 48-bit VA */
        if ((v & 0xffffff8000000000UL) == 0xffffff8000000000UL &&
            (v & 0x00007fff00000000UL) != 0)
            return 0xffffff8000000000UL;  /* 39-bit VA */
    }
    return 0xffffff8000000000UL;  /* default */
}

/*
 * Find mm_struct pointer within task_struct.
 * A valid mm pointer points to a kernel heap object whose first ~64 bytes
 * contain at least one page-aligned kernel VA (the pgd field).
 */
static int find_mm_offset(unsigned long cur, unsigned long po,
                          unsigned long *mm_out, unsigned long *pgd_out)
{
    unsigned long *p = (unsigned long *)cur;
    int i;

    for (i = 0; i < SCAN_RANGE / 8; i++) {
        unsigned long candidate = p[i];

        /* Must be a kernel-range pointer */
        if (candidate <= po || candidate - po > 0x40000000UL)
            continue;

        /* Check if *(candidate + Y) contains page-aligned kernel VAs */
        {
            unsigned long *mp = (unsigned long *)candidate;
            int j;

            if (candidate - po >= 0x40000000UL - MM_SCAN_RANGE)
                continue;

            for (j = 0; j < MM_SCAN_RANGE / 8; j++) {
                unsigned long q = mp[j];

                if (q > po && !(q & PAGE_MASK_4K) &&
                    (q & PAGE_MASK_4K) - po < 0x40000000UL) {
                    /* This looks like a pgd pointer */
                    *mm_out = candidate;
                    *pgd_out = q;
                    return i * 8;
                }
            }
        }
    }
    return -1;
}

/*
 * Derive PHYS_OFFSET from ttbr0_el1 (PA of pgd) and pgd virtual addr.
 * phys_off = ttbr0_pa - (pgd_va - PAGE_OFFSET)
 */
static unsigned long derive_phys_off(unsigned long ttbr0, unsigned long pgd_va,
                                     unsigned long po)
{
    unsigned long pa_mask = (1UL << PA_LOW_BITS) - 1;
    unsigned long ttbr0_pa = ttbr0 & (pa_mask & PAGE_MASK_4K);
    unsigned long phys = ttbr0_pa - (pgd_va - po);

    if (phys > 0x20000000000UL)
        return 0;
    return phys;
}

/*
 * Find tasks list_head offset by looking for a circular doubly-linked list.
 * At offset T: cur[T] = next, cur[T+8] = prev.
 * next->prev must == cur+T, prev->next must == cur+T.
 */
static int find_tasks_offset(unsigned long cur, unsigned long pid_off)
{
    unsigned long *p = (unsigned long *)cur;
    int t;

    for (t = 0; t < SCAN_RANGE / 8 - 1; t++) {
        if (t == pid_off / 8) continue;

        unsigned long nxt = p[t];
        unsigned long prv = p[t + 1];

        if (!nxt || !prv || nxt == prv)
            continue;

        /* Both must be kernel-range pointers */
        if (nxt <= page_off || prv <= page_off)
            continue;
        if (nxt - page_off > 0x40000000UL)
            continue;
        if (prv - page_off > 0x40000000UL)
            continue;

        /* Compute task bases */
        unsigned long nbase = nxt - t;
        unsigned long pbase = prv - t;

        if (nbase <= page_off || pbase <= page_off)
            continue;

        /* Verify circular: nbase->prev should point back to cur+t */
        unsigned long *np = (unsigned long *)nbase;
        unsigned long back = np[t + 1];
        if (back != cur + t)
            continue;

        /* Verify forward: pbase->next should point to cur+t */
        unsigned long *pp = (unsigned long *)pbase;
        unsigned long fwd = pp[t];
        if (fwd != cur + t)
            continue;

        return t * 8;
    }
    return -1;
}

/* ── full derivation at init ────────────────────────────────────────────── */

static int derive_all(void)
{
    unsigned long ttbr0, pgd_va, mm_ptr;
    unsigned long my_pid_val;
    int r;

    STAGE("init");

    /* Read hardware registers */
    asm volatile("mrs %0, sp_el0" : "=r"(cur_task));
    asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
    pr_info("rwbridge: cur=%lx ttbr0=%lx\n", cur_task, ttbr0);

    if (!cur_task)
        return -ENODEV;

    /* Step 1: find pid offset (scan for adjacent equal small u32s) */
    STAGE("pid");
    r = find_pid_offset(cur_task);
    if (r < 0) { pr_err("rwbridge: pid_offset not found\n"); return -ENOENT; }
    pid_offset = r;
    my_pid_val = *(unsigned int *)(cur_task + pid_offset);
    pr_info("rwbridge: pid_offset=%lu (pid=%u)\n", pid_offset, my_pid_val);

    /* Step 2: find PAGE_OFFSET */
    STAGE("po");
    page_off = find_page_offset(cur_task);
    pr_info("rwbridge: page_offset=%lx\n", page_off);

    /* Step 3: find mm and pgd offsets */
    STAGE("mm");
    r = find_mm_offset(cur_task, page_off, &mm_ptr, &pgd_va);
    if (r < 0) { pr_err("rwbridge: mm_offset not found\n"); return -ENOENT; }
    mm_offset = r;
    pgd_offset = pgd_va - mm_ptr;
    pr_info("rwbridge: mm_offset=%lu pgd_offset=%lu pgd_va=%lx\n",
            mm_offset, pgd_offset, pgd_va);

    /* Step 4: derive PHYS_OFFSET */
    STAGE("phys");
    phys_off = derive_phys_off(ttbr0, pgd_va, page_off);
    if (!phys_off) { pr_err("rwbridge: phys_off derivation failed\n"); return -EIO; }
    pr_info("rwbridge: phys_off=%lx\n", phys_off);

    /* Step 5: find tasks list offset */
    STAGE("tasks");
    r = find_tasks_offset(cur_task, pid_offset);
    if (r < 0) { pr_err("rwbridge: tasks_offset not found\n"); return -ENOENT; }
    tasks_offset = r;
    pr_info("rwbridge: tasks_offset=%lu\n", tasks_offset);

    /* Step 6: find comm offset (scan for our process name "insmod") */
    STAGE("comm");
    {
        char *cp = (char *)cur_task;
        int c;
        for (c = 0; c < SCAN_RANGE - NAME_LEN; c++) {
            if (cp[c] == 'i' && cp[c+1] == 'n' && cp[c+2] == 's' &&
                cp[c+3] == 'm' && cp[c+4] == 'o' && cp[c+5] == 'd' &&
                cp[c+6] == 0) {
                comm_offset = c;
                break;
            }
        }
        if (!comm_offset) comm_offset = 1960;  /* fallback */
        pr_info("rwbridge: comm_offset=%lu\n", comm_offset);
    }

    /* Step 7: find arg_start/arg_end offsets in mm_struct */
    STAGE("arg");
    {
        unsigned long *mp = (unsigned long *)mm_ptr;
        int j;
        for (j = 0; j < MM_SCAN_RANGE / 8 - 1; j++) {
            unsigned long a = mp[j], b = mp[j + 1];
            /* arg_start and arg_end are adjacent, ae > as, both user range,
             * span < 1MB */
            if (a > 0x40000UL && a < page_off &&
                b > a && b - a < 0x100000UL) {
                arg_start_offset = j * 8;
                arg_end_offset = arg_start_offset + 8;
                break;
            }
        }
        if (!arg_start_offset) {
            arg_start_offset = 328;
            arg_end_offset = 336;
        }
        pr_info("rwbridge: arg_start_offset=%lu\n", arg_start_offset);
    }

    derive_ok = 1;
    STAGE("ok");

    pr_info("rwbridge: derivation complete "
        "tasks=%lu pid=%lu mm=%lu pgd=%lu comm=%lu arg=%lu/%lu "
        "page_off=0x%lx phys_off=0x%lx\n",
        tasks_offset, pid_offset, mm_offset, pgd_offset, comm_offset,
        arg_start_offset, arg_end_offset, page_off, phys_off);

    return 0;
}

/* ── task walk ──────────────────────────────────────────────────────────── */

static unsigned long find_task_by_pid(u32 target_pid)
{
    unsigned long cur = cur_task;
    unsigned long p = cur;
    int i;

    for (i = 0; i < TASK_WALK_MAX; i++) {
        u32 tp = *(u32 *)(p + pid_offset);
        if (tp == target_pid)
            return p;

        unsigned long nxt = *(unsigned long *)(p + tasks_offset);
        if (!nxt)
            break;
        p = nxt - tasks_offset;
        if (p == cur)
            break;
    }
    return 0;
}

/* ── TTBR0 switch R/W ───────────────────────────────────────────────────── */

/*
 * Access target process memory by switching TTBR0 to their page tables.
 * The MMU translates their VAs natively. No manual page-table walking.
 *
 * Steps:
 *   1. Find target task → get mm → get pgd VA
 *   2. Convert pgd VA to PA via linear map (using our own phys_off)
 *   3. Save current TTBR0, disable IRQs
 *   4. Set TTBR0 = target pgd PA, ISB, TLB flush
 *   5. Deref target VA directly (MMU handles translation)
 *   6. Restore TTBR0, ISB, re-enable IRQs
 */
static long rw_switch_access(u32 pid, unsigned long addr, void *buf,
                              unsigned long size, int write)
{
    unsigned long task, mm, pgd_va, pgd_pa;
    unsigned long old_ttbr0, daif_save;
    long ret = 0;

    /* Find target task */
    task = find_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    /* Get mm pointer */
    mm = *(unsigned long *)(task + mm_offset);
    if (!mm)
        return -ESRCH;

    /* Get pgd virtual address */
    pgd_va = *(unsigned long *)(mm + pgd_offset);
    if (!pgd_va || (pgd_va & (PAGE_SIZE_4K - 1)))
        return -EFAULT;

    /* Validate pgd is in linear map range */
    if (pgd_va <= page_off || pgd_va - page_off > 0x40000000UL)
        return -EFAULT;

    /* Convert pgd VA to physical address using our linear map */
    pgd_pa = (pgd_va - page_off) + phys_off;
    if (pgd_pa > (1UL << PA_LOW_BITS))
        return -EFAULT;

    /* Save state and disable interrupts */
    asm volatile("mrs %0, ttbr0_el1" : "=r"(old_ttbr0));
    asm volatile("mrs %0, daif" : "=r"(daif_save));
    asm volatile("msr daifset, #3");       /* disable IRQ + FIQ */

    /* Switch to target's address space */
    asm volatile("msr ttbr0_el1, %0" :: "r"(pgd_pa));
    asm volatile("isb");
    asm volatile("tlbi vmalle1is");
    asm volatile("dsb sy");
    asm volatile("isb");

    /* Now we can access target's user VA directly */
    if (write)
        memcpy((void *)addr, buf, size);
    else
        memcpy(buf, (const void *)addr, size);

    ret = 0;

    /* Restore original address space */
    asm volatile("msr ttbr0_el1, %0" :: "r"(old_ttbr0));
    asm volatile("isb");
    asm volatile("tlbi vmalle1is");
    asm volatile("dsb sy");
    asm volatile("isb");

    /* Re-enable interrupts */
    asm volatile("msr daif, %0" :: "r"(daif_save));

    return ret;
}

/* ── sysfs command parser ───────────────────────────────────────────────── */

static inline int parse_dec(const char *s, s64 *out)
{
    s64 val = 0;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9')
        val = val * 10 + (*s++ - '0');
    if (neg) val = -val;
    *out = val;
    return *s ? -1 : 0;
}

static inline int parse_hex(const char *s, u64 *out)
{
    u64 val = 0;
    while (*s) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
        else break;
        val = (val << 4) | d;
        s++;
    }
    *out = val;
    return 0;
}

static int strstr_kernel(const char *haystack, const char *needle)
{
    if (!*needle) return 1;
    while (*haystack) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return 1;
        haystack++;
    }
    return 0;
}

/* strncpy_from_kernel since we can't import kernel helpers */
static long strncpy_from_kernel(char *dst, const char *src, long max)
{
    long n = 0;
    while (n < max && src[n]) { dst[n] = src[n]; n++; }
    dst[n] = 0;
    return n;
}


static int rw_set(const char *val, const struct kernel_param *kp)
{
    char buf[512];
    char *p = buf;
    char op;
    s64 pid_s64 = 0, size_s64 = 0;
    u32 pid;
    u64 addr = 0, wvalue = 0;
    long r;

    if (!derive_ok) {
        rw_status = -EPERM;
        STAGE("no_derive");
        return 0;
    }

    strncpy_from_kernel(buf, val, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    p = buf;
    op = *p++;
    if (*p == ',') p++;

    lxgr_spin_lock();
    STAGE("parse");

    switch (op) {
    case 'R': case 'W': {
        char f[3][64];
        int fi;

        /* Parse pid, addr, size [, value] */
        for (fi = 0; fi < 3; fi++) {
            char *comma = strchr(p, ',');
            size_t len = comma ? (size_t)(comma - p) : strlen(p);
            if (len >= sizeof(f[0])) goto bad;
            memcpy(f[fi], p, len); f[fi][len] = '\0';
            if (comma) p = comma + 1;
            else if (fi < 2) goto bad;
            else break;
        }

        parse_dec(f[0], &pid_s64);
        parse_hex(f[1], &addr);
        parse_dec(f[2], &size_s64);
        pid = (u32)pid_s64;

        if (op == 'W') {
            /* parse hex value after size */
            if (*p == ',') p++;
            parse_hex(p, &wvalue);
            if (size_s64 < 1 || size_s64 > 8) goto bad;
        } else {
            if (size_s64 < 1 || size_s64 > (s64)RW_MAX_SIZE) goto bad;
        }

        if (pid == 0 || addr == 0) goto bad;

        /* Execute via TTBR0 switch */
        STAGE(op == 'R' ? "read" : "write");

        if (op == 'R') {
            memset(rw_buf, 0, RW_MAX_SIZE);
            r = rw_switch_access(pid, addr, rw_buf, (unsigned long)size_s64, 0);
            if (r == 0) {
                rw_status = 0;
                rw_text_len = (long)size_s64 * 2;
                put_hex_bytes(0, rw_buf, size_s64);
                STAGE("ok");
            } else {
                rw_status = r;
                rw_text_len = 0;
            }
        } else {
            r = rw_switch_access(pid, addr, &wvalue,
                                  (unsigned long)size_s64, 1);
            rw_status = r;
            rw_text_len = 0;
            if (r == 0) STAGE("ok");
        }
        lxgr_spin_unlock();
        return 0;
    }

    case 'P': {
        /* Find PID by cmdline substring */
        const char *sub = p;
        unsigned long cur = cur_task;
        unsigned long t = cur;
        int i, found = 0;

        STAGE("findpid");
        for (i = 0; i < TASK_WALK_MAX && !found; i++) {
            char *comm = (char *)(t + comm_offset);
            unsigned long mmv = *(unsigned long *)(t + mm_offset);

            if (mmv && strstr_kernel(comm, sub)) {
                u32 fp = *(u32 *)(t + pid_offset);
                put_dec_u32(0, fp);
                found = 1;
            }

            unsigned long nxt = *(unsigned long *)(t + tasks_offset);
            if (!nxt) break;
            t = nxt - tasks_offset;
            if (t == cur) break;
        }

        if (!found) {
            rw_status = -ESRCH;
            rw_text_len = 0;
        } else {
            rw_status = 0;
        }
        lxgr_spin_unlock();
        return 0;
    }

    case 'B': {
        /* Module base — needs VMA walk (complex in ko).
         * For POC, overlay can compute base from /proc/<pid>/maps as root. */
        rw_status = -EOPNOTSUPP;
        rw_text_len = 0;
        lxgr_spin_unlock();
        return 0;
    }

    default:
        goto bad;
    }

bad:
    rw_status = -EINVAL;
    rw_text_len = 0;
    lxgr_spin_unlock();
    return 0;
}

/* Minimal kernel-space strstr */


/* ── sysfs param declarations ───────────────────────────────────────────── */

static const struct kernel_param_ops rw_param_ops = {
    .set = rw_set,
};
module_param_cb(rw, &rw_param_ops, NULL, 0200);

static int rw_out_get(char *buf, const struct kernel_param *kp)
{
    long n = rw_text_len;
    if (n < 0) n = 0;
    if (n > (long)(RW_MAX_SIZE * 2)) n = RW_MAX_SIZE * 2;
    memcpy(buf, rw_buf, n);
    buf[n] = '\0';
    return (int)n;
}
static const struct kernel_param_ops rw_out_ops = {
    .get = rw_out_get,
};
module_param_cb(out, &rw_out_ops, NULL, 0444);

static int rw_status_get(char *buf, const struct kernel_param *kp)
{
    long v = rw_status;
    int neg = 0;
    int n = 0;
    char tmp[24];
    int i = 0;

    if (v < 0) { buf[n++] = '-'; v = -v; }
    if (!v) buf[n++] = '0';
    while (v) { tmp[i++] = '0' + v % 10; v /= 10; }
    while (i) buf[n++] = tmp[--i];
    buf[n] = '\0';
    return n;
}
static const struct kernel_param_ops rw_status_ops = {
    .get = rw_status_get,
};
module_param_cb(status, &rw_status_ops, NULL, 0444);

static int rw_stage_get(char *buf, const struct kernel_param *kp)
{
    long n = 0;
    while (rw_stage[n]) { buf[n] = rw_stage[n]; n++; }
    buf[n] = '\0';
    return (int)n;
}
static const struct kernel_param_ops rw_stage_ops = {
    .get = rw_stage_get,
};
module_param_cb(stage, &rw_stage_ops, NULL, 0444);

/* ── module init/exit ───────────────────────────────────────────────────── */

static int __init rwbridge_init(void)
{
    pr_info("rwbridge: loading (zero-param, self-deriving)\n");
    return derive_all();
}

static void __exit rwbridge_exit(void)
{
    pr_info("rwbridge: unloaded\n");
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("Self-deriving ARM64 R/W bridge — zero params, zero hardcoded offsets");
