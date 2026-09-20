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
 * No insmod params. No external dependencies beyond module_layout
 * (+ compiler mem* if emitted). Logging is zero-import (in-module ring).
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/uaccess.h> /* copy_from_kernel_nofault only (stable core
                              symbol, 5.8+). uaccess_enable/disable are NOT
                              used — no TTBR0 window exists anymore. */

/* ── zero-import logging ───────────────────────────────────────────────────
 * No printk/_printk import: a kernel exporting neither would refuse the
 * module at load time. All diagnostics go to an in-module ring, readable
 * via the `log` sysfs param; run.sh dumps it to /sdcard/MemoryD/N.log.
 * Logging is explicit composition only (rb_puts/rb_put_hex/rb_put_dec/
 * rb_put_u32 + rb_putc): NO printf-style formatter, NO va_list anywhere.
 * (A __builtin_va_arg-based formatter wedged the guest on first use —
 *  mechanism unknown, hence this rule. Call sites are script-generated
 *  blocks; see commit history.)
 */
#define RB_LOG_MAX 3584
static char rb_logb[RB_LOG_MAX];
static unsigned long rb_loglen;

static void rb_putc(char c)
{
    if (rb_loglen + 1 < RB_LOG_MAX)
        rb_logb[rb_loglen++] = c;
}

static void rb_puts(const char *s)
{
    while (*s)
        rb_putc(*s++);
}

static void rb_put_dec(unsigned long v)
{
    char t[24];
    int i = 0;
    if (!v) { rb_putc('0'); return; }
    while (v) { t[i++] = '0' + v % 10; v /= 10; }
    while (i)
        rb_putc(t[--i]);
}

static void rb_put_u32(unsigned int v)
{
    rb_put_dec(v);
}

static void rb_put_hex(unsigned long v)
{
    static const char hx[] = "0123456789abcdef";
    char t[16];
    int i = 0;
    if (!v) { rb_putc('0'); return; }
    while (v) { t[i++] = hx[v & 0xf]; v >>= 4; }
    while (i)
        rb_putc(t[--i]);
}


/* ── constants ─────────────────────────────────────────────────────────── */

#define RW_MAX_SIZE      256UL
#define SCAN_RANGE       8192        /* bytes of task_struct to scan (mm can
                                       sit past 4K on big android configs) */
/* pid/tgid live around byte 1496 of task_struct on this 5.15 layout
 * (observed (pid,tgid) pair at 1496 across independent tasks; prio
 * triple at 124, exit_signal at 1396, group_leader at 1560, comm at
 * 1960 — coherent custom layout). The pid sweep defaults to a 2KB
 * window covering it. Discovery is one-time per kernel anyway (pin the
 * validated offset via kopts); an explicit S,1.<cap> still overrides
 * for bring-up bisect. */
#define PID_SCAN_WORDS 512
#define MM_SCAN_RANGE    1024        /* bytes of mm_struct to scan */
#define TASK_WALK_MAX    16384
#define NAME_LEN         16

/* arm64 page constants — universal for aarch64 */
#define PAGE_SIZE_4K     0x1000UL
#define PAGE_MASK_4K     (~(PAGE_SIZE_4K - 1))
#define PA_LOW_BITS      47UL       /* arm64 PA width up to 48 bits */
#define PA_MASK          ((1UL << PA_LOW_BITS) - 1) & PAGE_MASK_4K

/* ── module state ──────────────────────────────────────────────────────── */

static unsigned char rw_buf[RW_MAX_SIZE];
static long rw_status;
static long rw_text_len;           /* >0: `out` is ASCII text */
static char rw_stage[16] = "idle";

static unsigned long cur_task;         /* sp_el0 value at init */
static unsigned long pid_offset;       /* offset of pid in task_struct */
static int dbg_scancap;                /* S-step sweep cap (u32 slots, 0=full) */
static int pid_ncands;                /* isolated-pair candidates listed by S1 */
static int pid_cand_off[8];
static unsigned int pid_cand_val[8];
static unsigned long mm_offset;        /* offset of mm_struct* in task_struct */
static unsigned long pgd_offset;       /* offset of pgd in mm_struct */
static unsigned long tasks_offset;     /* offset of tasks list_head in task_struct */
static unsigned long comm_offset;      /* offset of comm[] in task_struct */
static unsigned long arg_start_offset; /* offset of arg_start in mm_struct */
static unsigned long arg_end_offset;   /* offset of arg_end in mm_struct */
static unsigned long page_off;         /* PAGE_OFFSET derived from scanning */
static unsigned long phys_off;         /* PHYS_OFFSET derived from ttbr0 vs pgd */
static int derive_ok;

/* ── runtime kernel data (kopts) ──────────────────────────────────────────
 * Like game offsets: per-kernel layout data is GIVEN to the .ko at runtime
 * (insmod kopts="..." or echo to the param later) instead of being baked
 * per-KMI at compile time. Any key present skips its scan step (values are
 * still sanity-validated); absent keys fall back to self-derivation.
 * Keys: page_offset, phys_offset, va_bits, page_shift,
 *       task_pid_off, task_mm_off, mm_pgd_off, task_tasks_off, task_comm_off,
 *       mm_arg_start_off, mm_arg_end_off
 */
#define K_PAGE_OFF   (1UL << 0)
#define K_PHYS_OFF   (1UL << 1)
#define K_TASK_PID   (1UL << 2)
#define K_TASK_MM    (1UL << 3)
#define K_MM_PGD     (1UL << 4)
#define K_TASK_TASKS (1UL << 5)
#define K_TASK_COMM  (1UL << 6)
#define K_ARG_START  (1UL << 7)
#define K_ARG_END    (1UL << 8)
#define K_STABILITY  (1UL << 9)
#define K_READONLY   (1UL << 10)

static unsigned long kopt_mask;
static unsigned long kopt_va_bits = 48;
static unsigned long kopt_page_shift = 12;
/* Bring-up modes (staged trust):
 * stability=1: init reads registers, logs, and stops — no scans, no walks.
 *   Module sits loaded and idle; proves load + idle safety first.
 * readonly=1:  W ops refused with -EROFS; R ops fully work. Read-only
 *   sessions validate PA translation/offsets before any write is allowed. */
static int kopt_stability;
static int kopt_readonly;
/* Bisect scaffold (TEMPORARY — remove once the R-op panic is located).
 * stub=N skips switch layers cumulatively; each level gets one boot cycle.
 * A panic at level N with clean refusal at N+1 fingers the skipped layer.
 * 0 = full op; 1 = after task find; 2 = after validation, before reg saves;
 * 3 = flip+barriers+restore, no copy (with PAN change);
 * 4 = flip+barriers+restore, no copy (without PAN change).
 * NOTE: derive runs BEFORE all levels (in rw_set), so L1 clean + L0 panic
 * already separates derive-vs-switch. */
static int kopt_stub;
static char kopts_buf[512];
static int kopts_init_done;   /* 0 during insmod arg parsing, 1 after init */

/* Forward declarations (defined beside the sysfs parser below) */
static int kopts_parse_apply(const char *s);
static void kopts_log_state(void);
static unsigned long derive_phys_off(unsigned long ttbr0, unsigned long pgd_va,
                                     unsigned long po);

/* LDXR/STXR spinlock — no kernel imports needed.
 * Bounded trylock, NEVER infinite spin: if a previous holder died holding
 * the word (or two writers collide pathologically), ops refuse with -EBUSY
 * instead of wedging the caller in kernel forever (uninterruptible,
 * unkillable, survives nothing but reboot). A stuck lock is a bug signal,
 * not a waiting room. */
static volatile unsigned int lock_val;

static inline int rb_spin_trylock(void)
{
    unsigned int tmp;
    unsigned int val;
    unsigned int st;
    int i;

    for (i = 0; i < 1000000; i++) {
        asm volatile(
        "   ldxr    %w0, %3\n"
        "   cbnz    %w0, 1f\n"
        "   mov     %w1, #1\n"
        "   stxr    %w2, %w1, %3\n"
        "   b       2f\n"
        "1: mov     %w2, #1\n"
        "2:\n"
        : "=&r"(tmp), "=&r"(val), "=&r"(st), "+Q"(lock_val)
        :
        : "memory");
        if (st == 0)
            return 0;               /* store succeeded: we hold it */
        asm volatile("yield" ::: "memory");
    }
    return -EBUSY;
}

static inline void rb_spin_unlock(void)
{
    asm volatile("stlr wzr, %0" : : "Q"(lock_val) : "memory");
}

static unsigned long rw_strlen(const char *s)
{
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}


/* Forward declarations for self-contained helpers */
static unsigned long rw_strlen(const char *s);
static char *rw_strchr(const char *s, int c);
static void *rw_memcpy(void *dst, const void *src, unsigned long n);

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
    /* Bound is RW_MAX_SIZE (rw_buf size), NOT 2x: callers hex-dump into
     * rw_buf itself (R-case dumps size bytes -> 2x chars), so output
     * must fit the 256B buffer; excess truncates instead of smashing
     * neighboring BSS (lock word, offsets, ring). */
    for (i = 0; i < len && off + 1 < RW_MAX_SIZE; i++) {
        rw_buf[off++] = hx[data[i] >> 4];
        rw_buf[off++] = hx[data[i] & 0xf];
    }
    rw_text_len = off;
}

static void put_dec_u32(unsigned long off, u32 v)
{
    char tmp[12];
    int i = 0;
    if (!v) { rw_buf[off++] = '0'; rw_text_len = off; return; }
    while (v) { tmp[i++] = '0' + v % 10; v /= 10; }
    while (i) rw_buf[off++] = tmp[--i];
    rw_text_len = off;
}

/* ── fault-safe reads (own __ex_table) ─────────────────────────────────────
 * Init scans guess kernel addresses; a wrong guess dereferenced plainly is
 * an oops (panic where panic_on_oops=1). These reads route a fault to a
 * fixup that reports failure instead — a wrong guess is a miss, never a
 * panic. Zero imports: pure section + data; the loader registers module
 * __ex_table like any in-tree user. Keep the deref to the single annotated
 * ldr; keep callers checking _ok before touching _dst (dst stays 0).
 * Numeric local labels use the %= uniquifier (safe under repetition).
 * ENTRY FORMAT IS LOAD-BEARING: arm64 exception_table_entry is TWO s32
 * {insn, fixup}, each relative to its own field address. Emitting .quad
 * (as an earlier revision did) doubles the stride, the kernel misparses
 * every entry, fixups never fire, and faults panic exactly as if the
 * macro were absent. .long pairs only — the gate cannot check this, so
 * read this comment before touching the asm.
 */
#define SAFE_READ64(_dst, _addr, _ok) do { \
    unsigned long __v = 0; int __ok = 0; \
    asm volatile( \
    "   mov %w1, wzr\n" \
    "1%=: ldr %0, [%2]\n" \
    "   mov %w1, #1\n" \
    "2%=:\n" \
    "   .pushsection __ex_table,\"a\"\n" \
    "   .align 2\n" \
    "   .long (1%=b - .)\n" \
    "   .long (3%=f - .)\n" \
    "   .popsection\n" \
    "   b 4%=f\n" \
    "3%=:\n" \
    "4%=:\n" \
    : "=&r"(__v), "=&r"(__ok) : "r"(_addr) : "memory"); \
    (_dst) = __v; (_ok) = __ok; \
} while (0)

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
/* Read one u32 at any alignment via its containing aligned u64. */
static int read_u32_at(unsigned long addr, u32 *out)
{
    unsigned long base = addr & ~7UL;
    unsigned long w = 0;
    int ok = 0;
    SAFE_READ64(w, base, ok);
    if (!ok)
        return -1;
    if (addr & 4)
        w >>= 32;
    *out = (u32)w;
    return 0;
}

static int find_pid_offset(unsigned long cur)
{
    unsigned int *p = (unsigned int *)cur;
    unsigned long aw, bw;
    int aok, bok;
    u32 a, b;
    int i;
    int match_idx[16];
    int nmatch = 0;
    int mi;

    pid_ncands = 0;
    /* Sweep shaped exactly like the proven first-match scanner (returns
     * were observed on-device), but record every equal-pair instead of
     * returning the first: first-match-wins false-positives on stable
     * fields (prio triplet, 460/460). Isolation filtering happens in a
     * bounded post-pass over the recorded matches only. */
    for (i = 0; i < PID_SCAN_WORDS; i++) {
        if (dbg_scancap > 0 && i >= dbg_scancap)
            break;
        aw = 0; bw = 0; aok = 0; bok = 0;
        SAFE_READ64(aw, (unsigned long)&p[i], aok);
        if (!aok)
            continue;
        SAFE_READ64(bw, (unsigned long)&p[i + 1], bok);
        if (!bok)
            continue;
        a = (u32)aw; b = (u32)bw;
        if (a == b && a > 0 && a < 4194304 && nmatch < 16)
            match_idx[nmatch++] = i;
    }
    /* Post-pass: isolated-pair rule. pid/tgid is exactly 2-wide; runs of
     * 3+ (prio/static_prio/normal_prio, all 120) are skipped. Userspace
     * knows its own pid and picks the true slot from the printed list. */
    for (mi = 0; mi < nmatch && pid_ncands < 8; mi++) {
        int j = match_idx[mi];
        u32 v = 0, nb = 0, pf = 0;
        int nbok = 0, pfok = 0;
        if (read_u32_at(cur + j * 4, &v))
            continue;
        if (j + 2 < SCAN_RANGE / 4)
            nbok = !read_u32_at(cur + (j + 2) * 4, &nb);
        if (j > 0)
            pfok = !read_u32_at(cur + (j - 1) * 4, &pf);
        if ((nbok && nb == v) || (pfok && pf == v))
            continue;
        pid_cand_off[pid_ncands] = j * 4;
        pid_cand_val[pid_ncands] = v;
        pid_ncands++;
    }
    if (pid_ncands > 0)
        return pid_cand_off[0];
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
        unsigned long v = 0;
        int vok = 0;
        SAFE_READ64(v, (unsigned long)&p[i], vok);
        if (!vok)
            continue;
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
 * Find mm_struct pointer candidates within task_struct — COLLECT only.
 * Prefilter (cheap, fault-safe): kernel-range candidate holding a
 * page-aligned kernel VA in its first 1KB (pgd-shaped). Deliberately
 * loose: no header skip, no upper-bound cap. False candidates die at the
 * bit-exact proof in derive_all, never here — a too-clever prefilter is
 * how offsets get missed on new layouts. Up to MM_CAND_MAX collected.
 */
#define MM_CAND_MAX 16
static int mm_cand_n;
static unsigned long mm_cand_off[MM_CAND_MAX];
static unsigned long mm_cand_mm[MM_CAND_MAX];
static unsigned long mm_cand_pg[MM_CAND_MAX];

static int find_mm_candidates(unsigned long cur, unsigned long po)
{
    unsigned long *p = (unsigned long *)cur;
    int i;

    mm_cand_n = 0;
    for (i = 0; i < SCAN_RANGE / 8 && mm_cand_n < MM_CAND_MAX; i++) {
        unsigned long candidate = 0;
        int cok = 0;
        int j;

        SAFE_READ64(candidate, (unsigned long)&p[i], cok);
        if (!cok)
            continue;
        if (candidate <= po)
            continue;

        for (j = 0; j < MM_SCAN_RANGE / 8; j++) {
            unsigned long q = 0;
            int qok = 0;
            SAFE_READ64(q, candidate + (unsigned long)j * 8UL, qok);
            if (!qok)
                continue;

            if (q > po && !(q & (PAGE_SIZE_4K - 1))) {
                /* pgd-shaped content; proof decides */
                mm_cand_off[mm_cand_n] = (unsigned long)i * 8UL;
                mm_cand_mm[mm_cand_n] = candidate;
                mm_cand_pg[mm_cand_n] = q;
                mm_cand_n++;
                break;
            }
        }
    }
    return mm_cand_n;
}

/*
 * Bit-exact geometry proof for one (mm, pgd) pair: recompute what ttbr0's
 * PA bits must be from the derived values and demand equality with the
 * measured ttbr0. ~2^-47 false-pass rate. Only a passer may feed the
 * TTBR0 switch.
 */
static int prove_mm(unsigned long pgd_va, unsigned long po,
                    unsigned long ttbr0, unsigned long *phys_out)
{
    unsigned long pa_mask = (1UL << PA_LOW_BITS) - 1;
    unsigned long phys, expect;

    if (pgd_va <= po || (pgd_va & (PAGE_SIZE_4K - 1)))
        return -1;
    phys = derive_phys_off(ttbr0, pgd_va, po);
    if (!phys)
        return -1;
    expect = (pgd_va - po) + phys;
    if ((expect & (pa_mask & PAGE_MASK_4K)) !=
        (ttbr0 & (pa_mask & PAGE_MASK_4K)))
        return -1;
    *phys_out = phys;
    return 0;
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
 * Hardening: candidates must be 16-byte aligned (genuine list_head links
 * always are; garbage rarely is) — checked BEFORE any computed-address
 * deref. nbase/pbase derefs are the highest-fault-risk reads in init, so
 * they only run on candidates passing every cheap test first.
 */
static int find_tasks_offset(unsigned long cur, unsigned long pid_off)
{
    unsigned long *p = (unsigned long *)cur;
    unsigned long nxt, prv, nbase, pbase, back, fwd;
    unsigned long *np, *pp;
    int nok, pok, backok, fwdok;
    int t;

    for (t = 0; t < SCAN_RANGE / 8 - 1; t++) {
        nxt = 0; prv = 0; nok = 0; pok = 0;
        if (t == pid_off / 8) continue;

        SAFE_READ64(nxt, (unsigned long)&p[t], nok);
        if (!nok)
            continue;
        SAFE_READ64(prv, (unsigned long)&p[t + 1], pok);
        if (!pok)
            continue;

        if (!nxt || !prv || nxt == prv)
            continue;

        /* Genuine links are 16-byte aligned; garbage almost never is */
        if ((nxt & 0xFUL) || (prv & 0xFUL))
            continue;

        /* Both must be kernel-range pointers */
        if (nxt <= page_off || prv <= page_off)
            continue;
        if (nxt - page_off > 0x40000000UL)
            continue;
        if (prv - page_off > 0x40000000UL)
            continue;

        /* Compute task bases */
        nbase = nxt - t;
        pbase = prv - t;

        if (nbase <= page_off || pbase <= page_off)
            continue;

        /* Verify circular: nbase->prev should point back to cur+t */
        np = (unsigned long *)nbase;
        pp = (unsigned long *)pbase;
        back = 0; fwd = 0; backok = 0; fwdok = 0;
        SAFE_READ64(back, (unsigned long)&np[t + 1], backok);
        if (!backok || back != cur + t)
            continue;

        /* Verify forward: pbase->next should point to cur+t */
        SAFE_READ64(fwd, (unsigned long)&pp[t], fwdok);
        if (!fwdok || fwd != cur + t)
            continue;

        return t * 8;
    }
    return -1;
}

/* ── full derivation at init ────────────────────────────────────────────── */

/* Cross-step state for the stepped derivation (S op + derive_all share). */
static unsigned long dbg_ttbr0, dbg_mmp, dbg_pgdv;
static unsigned long dbg_done; /* bit n = step n completed ok */

static int st_regs(void)
{
STAGE("init");

    /* Geometry gate: the walker is 4K-hardcoded. A 16K kernel must fail
     * here with a message, never by mis-walking page tables. */
    if (kopt_page_shift != 12) {
                { rb_puts("rwbridge: page_shift="); rb_put_dec((unsigned long)(kopt_page_shift)); rb_puts(" unsupported (4K-only walker)"); rb_putc('\n'); };
        return -ENODEV;
    }

    /* Read hardware registers (into shared state for later steps) */
    asm volatile("mrs %0, sp_el0" : "=r"(cur_task));
    asm volatile("mrs %0, ttbr0_el1" : "=r"(dbg_ttbr0));
        { rb_puts("rwbridge: cur="); rb_put_hex((unsigned long)(cur_task)); rb_puts(" ttbr0="); rb_put_hex((unsigned long)(dbg_ttbr0)); rb_putc('\n'); };

    if (!cur_task)
        return -ENODEV;

    /* Stability mode: observe only — registers + kopts are logged above,
     * no scans, no walks, no writes. The module sits loaded and idle.
     * Ops stay inert (derive_ok remains 0). Proves load + idle safety
     * before any discovery code runs. */
    if (kopt_stability) {
        STAGE("stability-idle");
                { rb_puts("rwbridge: stability mode — idle, no scans ran"); rb_putc('\n'); };
        return 0;
    }

        return 0;
}

static int st_pid(void)
{
    unsigned long my_pid_val = 0;
    int r;

/* Step 1: pid offset (kopts or scan for adjacent equal small u32s) */
    STAGE("pid");
    if (kopt_mask & K_TASK_PID) {
        unsigned long pvw = 0;
        int pvok = 0;
        unsigned int pv = 0;
        SAFE_READ64(pvw, cur_task + pid_offset, pvok);
        pv = pvok ? (unsigned int)pvw : 0;
        if (!pvok || pid_offset >= SCAN_RANGE || pv == 0 || pv >= 4194304) {
                        { rb_puts("rwbridge: kopt task_pid_off="); rb_put_dec((unsigned long)(pid_offset)); rb_puts(" rejected (val="); rb_put_u32((unsigned int)(pv)); rb_puts(")"); rb_putc('\n'); };
            return -EINVAL;
        }
        r = (int)pid_offset;
                { rb_puts("rwbridge: pid_offset="); rb_put_dec((unsigned long)(pid_offset)); rb_puts(" (kopt, pid="); rb_put_u32((unsigned int)(pv)); rb_puts(")"); rb_putc('\n'); };
        my_pid_val = pv;
    } else {
        /* Single-word probe at validated 1496 (V-proven 4x — identical
         * single SAFE_READ64 class). No neighbor reads, no sweep:
         * both wedge this hypervisor intermittently. Miss returns
         * -ENOENT cleanly (sweep stays available only via explicit
         * S,1.<cap> for controlled bisect, never by default). */
        unsigned long pw = 0;
        int pok = 0;
        u32 lo = 0, hi = 0;
        SAFE_READ64(pw, cur_task + 1496, pok);
        if (pok) { lo = (u32)pw; hi = (u32)(pw >> 32); }
        if (pok && lo == hi && lo > 0 && lo < 4194304) {
            pid_offset = 1496;
            pid_ncands = 1;
            pid_cand_off[0] = 1496;
            pid_cand_val[0] = lo;
            r = 1496;
            { rb_puts("rwbridge: pid probe 1496 hit"); rb_putc('\n'); };
        } else if (dbg_scancap > 0) {
            r = find_pid_offset(cur_task);
        } else {
            { rb_puts("rwbridge: pid probe miss (no sweep without cap)"); rb_putc('\n'); };
            return -ENOENT;
        }
        if (r < 0) { { rb_puts("rwbridge: pid_offset not found"); rb_putc('\n'); }; return -ENOENT; }
        pid_offset = r;
    }
    if (!(kopt_mask & K_TASK_PID)) {
        unsigned long myw = 0;
        int myok = 0;
        SAFE_READ64(myw, cur_task + pid_offset, myok);
        my_pid_val = myok ? (unsigned int)myw : 0;
    }
        { rb_puts("rwbridge: pid_offset="); rb_put_dec((unsigned long)(pid_offset)); rb_puts(" (pid="); rb_put_u32((unsigned int)(my_pid_val)); rb_puts(")"); rb_putc('\n'); };
    if (pid_ncands > 0) {
        int ci = 0;
        { rb_puts("rwbridge: pid cands:"); };
        for (ci = 0; ci < pid_ncands; ci++) {
            { rb_puts(" "); rb_put_dec((unsigned long)(pid_cand_off[ci])); rb_puts("="); rb_put_u32((unsigned int)(pid_cand_val[ci])); };
        }
        { rb_putc('\n'); };
    }
    return 0;
}

static int st_po(void)
{
/* Step 2: PAGE_OFFSET (kopts or scan) */
    STAGE("po");
    if (kopt_mask & K_PAGE_OFF)
                { rb_puts("rwbridge: page_offset="); rb_put_hex((unsigned long)(page_off)); rb_puts(" (kopt)"); rb_putc('\n'); }
    else {
        page_off = find_page_offset(cur_task);
                { rb_puts("rwbridge: page_offset="); rb_put_hex((unsigned long)(page_off)); rb_putc('\n'); };
    }

        return 0;
}

static int st_mm(void)
{
    int r = 0;

/* Steps 3+4: mm + pgd + phys, COLLECT then PROVE.
     * Candidates come from the loose scan (or kopts); exactly one thing
     * commits them: the bit-exact dbg_ttbr0 equation inside prove_mm.
     * phys_off is derived per candidate and committed only with it, so a
     * kopts phys value can never pair with a scanned mm (or vice versa). */
    STAGE("mm");
    {
        int i, won = 0;
        unsigned long try_phys = 0;

        if ((kopt_mask & (K_TASK_MM | K_MM_PGD)) == (K_TASK_MM | K_MM_PGD)) {
            int mok = 0, pok = 0;
            SAFE_READ64(dbg_mmp, cur_task + mm_offset, mok);
            if (mok)
                SAFE_READ64(dbg_pgdv, dbg_mmp + pgd_offset, pok);
            if (mok && pok && prove_mm(dbg_pgdv, page_off, dbg_ttbr0,
                                       &try_phys) == 0) {
                /* An explicit phys kopt must agree with hardware truth —
                 * never silently paired with a derivation. */
                if ((kopt_mask & K_PHYS_OFF) && try_phys != phys_off) {
                                        { rb_puts("rwbridge: kopt phys_offset disagrees with hardware"); rb_putc('\n'); };
                    return -EINVAL;
                }
                phys_off = try_phys;
                won = 1;
                                { rb_puts("rwbridge: mm_offset="); rb_put_dec((unsigned long)(mm_offset)); rb_puts(" pgd_offset="); rb_put_dec((unsigned long)(pgd_offset)); rb_puts(" dbg_pgdv="); rb_put_hex((unsigned long)(dbg_pgdv)); rb_puts(" phys_off="); rb_put_hex((unsigned long)(phys_off)); rb_puts(" (kopt, proved)"); rb_putc('\n'); };
            } else {
                                { rb_puts("rwbridge: kopt mm/pgd failed proof"); rb_putc('\n'); };
                return -EINVAL;
            }
        } else {
            find_mm_candidates(cur_task, page_off);
                        { rb_puts("rwbridge: mm candidates="); rb_put_u32((unsigned int)((unsigned int)mm_cand_n)); rb_putc('\n'); };
            for (i = 0; i < mm_cand_n && !won; i++) {
                if (prove_mm(mm_cand_pg[i], page_off, dbg_ttbr0, &try_phys) == 0) {
                    if ((kopt_mask & K_PHYS_OFF) && try_phys != phys_off)
                        continue; /* explicit phys must agree; else next */
                    mm_offset = mm_cand_off[i];
                    dbg_mmp = mm_cand_mm[i];
                    dbg_pgdv = mm_cand_pg[i];
                    pgd_offset = dbg_pgdv - dbg_mmp;
                    phys_off = try_phys;
                    won = 1;
                                        { rb_puts("rwbridge: mm_offset="); rb_put_dec((unsigned long)(mm_offset)); rb_puts(" pgd_offset="); rb_put_dec((unsigned long)(pgd_offset)); rb_puts(" dbg_pgdv="); rb_put_hex((unsigned long)(dbg_pgdv)); rb_puts(" phys_off="); rb_put_hex((unsigned long)(phys_off)); rb_puts(" (proved)"); rb_putc('\n'); };
                }
            }
            if (!won) {
                                { rb_puts("rwbridge: no mm candidate proved (tried "); rb_put_u32((unsigned int)((unsigned int)mm_cand_n)); rb_puts(")"); rb_putc('\n'); };
                return -ENOENT;
            }
        }
        r = 0;
    }
    (void)r;
        return 0;
}

static int st_tasks(void)
{
    int r;

STAGE("tasks");
    if (kopt_mask & K_TASK_TASKS) {
        unsigned long nxt = 0;
        int nok = 0;
        SAFE_READ64(nxt, cur_task + tasks_offset, nok);
        if (!nok || tasks_offset >= SCAN_RANGE || nxt <= page_off ||
            nxt - page_off > 0x40000000UL) {
                        { rb_puts("rwbridge: kopt task_tasks_off="); rb_put_dec((unsigned long)(tasks_offset)); rb_puts(" rejected"); rb_putc('\n'); };
            return -EINVAL;
        }
        r = (int)tasks_offset;
                { rb_puts("rwbridge: tasks_offset="); rb_put_dec((unsigned long)(tasks_offset)); rb_puts(" (kopt)"); rb_putc('\n'); };
    } else {
        r = find_tasks_offset(cur_task, pid_offset);
        if (r < 0) { { rb_puts("rwbridge: tasks_offset not found"); rb_putc('\n'); }; return -ENOENT; }
        tasks_offset = r;
                { rb_puts("rwbridge: tasks_offset="); rb_put_dec((unsigned long)(tasks_offset)); rb_putc('\n'); };
    }
    (void)r;

        return 0;
}

static int st_comm(void)
{
/* Step 6: comm offset (kopts or scan for "insmod") */
    STAGE("comm");
    if (kopt_mask & K_TASK_COMM) {
        if (comm_offset >= SCAN_RANGE) {
                        { rb_puts("rwbridge: kopt task_comm_off="); rb_put_dec((unsigned long)(comm_offset)); rb_puts(" rejected"); rb_putc('\n'); };
            return -EINVAL;
        }
                { rb_puts("rwbridge: comm_offset="); rb_put_dec((unsigned long)(comm_offset)); rb_puts(" (kopt)"); rb_putc('\n'); };
    } else {
        /* Fault-safe byte scan of own task (slab edge may unmap inside the
         * 4K window — a direct cp[c] walk there is an uncovered fault). */
        unsigned long w = 0;
        int wok = 0;
        char cb[8];
        int c, k;
        comm_offset = 0;
        for (c = 0; c < SCAN_RANGE - NAME_LEN; c++) {
            SAFE_READ64(w, cur_task + (unsigned long)(c & ~7), wok);
            if (!wok)
                continue;
            for (k = 0; k < 8; k++)
                cb[k] = (char)((w >> (k * 8)) & 0xFF);
            {
                int o = c & 7;
                if (o + 6 < 8 &&
                    cb[o] == 'i' && cb[o+1] == 'n' && cb[o+2] == 's' &&
                    cb[o+3] == 'm' && cb[o+4] == 'o' && cb[o+5] == 'd' &&
                    cb[o+6] == 0) {
                    comm_offset = c;
                    break;
                }
            }
            if (comm_offset)
                break;
        }
        if (!comm_offset) comm_offset = 1960;  /* fallback */
                { rb_puts("rwbridge: comm_offset="); rb_put_dec((unsigned long)(comm_offset)); rb_putc('\n'); };
    }

        return 0;
}

static int st_arg(void)
{
/* Step 7: arg_start/arg_end offsets in mm_struct (kopts or scan) */
    STAGE("arg");
    if ((kopt_mask & (K_ARG_START | K_ARG_END)) == (K_ARG_START | K_ARG_END)) {
        unsigned long a = 0, b = 0;
        int aok = 0, bok = 0;
        SAFE_READ64(a, dbg_mmp + arg_start_offset, aok);
        SAFE_READ64(b, dbg_mmp + arg_end_offset, bok);
        if (!aok || !bok ||
            !(a > 0x40000UL && a < page_off && b > a && b - a < 0x100000UL)) {
                        { rb_puts("rwbridge: kopt arg offs "); rb_put_dec((unsigned long)(arg_start_offset)); rb_puts("/"); rb_put_dec((unsigned long)(arg_end_offset)); rb_puts(" rejected"); rb_putc('\n'); };
            return -EINVAL;
        }
                { rb_puts("rwbridge: arg_start_offset="); rb_put_dec((unsigned long)(arg_start_offset)); rb_puts(" (kopt)"); rb_putc('\n'); };
    } else {
        unsigned long *mp = (unsigned long *)dbg_mmp;
        int j;
        arg_start_offset = 0;
        for (j = 0; j < MM_SCAN_RANGE / 8 - 1; j++) {
            unsigned long a = 0, b = 0;
            int aok = 0, bok = 0;
            SAFE_READ64(a, (unsigned long)&mp[j], aok);
            if (!aok)
                continue;
            SAFE_READ64(b, (unsigned long)&mp[j + 1], bok);
            if (!bok)
                continue;
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
                { rb_puts("rwbridge: arg_start_offset="); rb_put_dec((unsigned long)(arg_start_offset)); rb_putc('\n'); };
    }

        return 0;
}

static int st_fin(void)
{
derive_ok = 1;
    STAGE("ok");

        { rb_puts("rwbridge: derivation complete tasks="); rb_put_dec((unsigned long)(tasks_offset)); rb_puts(" pid="); rb_put_dec((unsigned long)(pid_offset)); rb_puts(" mm="); rb_put_dec((unsigned long)(mm_offset)); rb_puts(" pgd="); rb_put_dec((unsigned long)(pgd_offset)); rb_puts(" comm="); rb_put_dec((unsigned long)(comm_offset)); rb_puts(" arg="); rb_put_dec((unsigned long)(arg_start_offset)); rb_puts("/"); rb_put_dec((unsigned long)(arg_end_offset)); rb_puts(" page_off=0x"); rb_put_hex((unsigned long)(page_off)); rb_puts(" phys_off=0x"); rb_put_hex((unsigned long)(phys_off)); rb_putc('\n'); };

    return 0;
}

static int (*const st_fns[8])(void) = {
    st_regs, st_pid, st_po, st_mm, st_tasks, st_comm, st_arg, st_fin
};

static int derive_all(void)
{
    int r;
    int i;

    r = st_regs();
    if (r)
        return r;
    dbg_done |= 1UL;
    if (kopt_stability)
        return 0; /* observe-only: scans stay off, exactly as before */
    for (i = 1; i < 8; i++) {
        r = st_fns[i]();
        if (r)
            return r;
        dbg_done |= (1UL << i);
    }
    return 0;
}

/* ── task walk ──────────────────────────────────────────────────────────── */

static unsigned long find_task_by_pid(u32 target_pid)
{
    unsigned long cur = cur_task;
    unsigned long p = cur;
    int i;

    /* Every step is fault-safe: a task can exit mid-walk, leaving p
     * pointing at freed/unmapped memory. A failed read ends the walk
     * (target considered absent), never an oops. */
    for (i = 0; i < TASK_WALK_MAX; i++) {
        unsigned long tpw = 0;
        int tpok = 0;
        unsigned long nxt = 0;
        int nok = 0;
        SAFE_READ64(tpw, p + pid_offset, tpok);
        if (!tpok)
            break;
        if ((u32)tpw == target_pid)
            return p;

        SAFE_READ64(nxt, p + tasks_offset, nok);
        if (!nok || !nxt)
            break;
        p = nxt - tasks_offset;
        if (p == cur)
            break;
    }
    return 0;
}

/* ── linear map R/W — no TTBR0 switch ─────────────────────────────────────
 *
 * Derivation at init gives phys_off (PA base) + page_off (linear map base).
 * For any target user VA: software page walk through TARGET's tables
 * (pgd_va is a kernel VA — readable through our own tables) → resolve PA
 * → PA to kernel VA via linear map → copy_from_kernel_nofault / plain
 * write. No TTBR0 write. No TLBI. No PAN window. No IRQ disable.
 *
 * Constraints: 4K pages only (kopt_page_shift == 12, enforced in
 * derive_all); 48-bit VA (kopt_va_bits == 48). Target exiting mid-op
 * surfaces as SAFE_READ64 failure → -ESRCH, never panic.
 */

/* ARM64 4K/48-bit page table constants (guarded: kernel pgtable headers
 * define the same names — ours are fallbacks with identical values). */
#ifndef PGD_SHIFT
#define PGD_SHIFT   39
#endif
#ifndef PUD_SHIFT
#define PUD_SHIFT   30
#endif
#ifndef PMD_SHIFT
#define PMD_SHIFT   21
#endif
#ifndef PTE_SHIFT
#define PTE_SHIFT   12
#endif

#define PT_INDEX(va, shift)  (((va) >> (shift)) & 0x1FFUL)
#define PA_FROM_PTE(pte)     ((pte) & 0x0000FFFFFFFFF000UL)

/* Validity bits — bit 0 must be set; bit 1 distinguishes table vs block */
#ifndef PTE_VALID
#define PTE_VALID        (1UL << 0)
#endif
#ifndef PTE_TABLE
#define PTE_TABLE        (1UL << 1)   /* set = table descriptor (not block) */
#endif

static inline unsigned long pa_to_kva(unsigned long pa)
{
    /* Linear map: KVA = page_off + (pa - phys_off) */
    return page_off + (pa - phys_off);
}

/*
 * walk_pt — software page walk through target's 4-level page tables.
 *
 * pgd_va: kernel VA of target's PGD (from mm->pgd, already in linear map)
 * user_va: target process VA to resolve
 * pa_out: resolved physical address on success
 *
 * Returns 0 on success, -EFAULT on any bad descriptor or read failure.
 * Every table-level read goes through SAFE_READ64 — a freed/unmapped
 * table entry is a miss, not a panic.
 */
static int walk_pt(unsigned long pgd_va, unsigned long user_va,
                   unsigned long *pa_out)
{
    unsigned long desc, table_kva;
    int ok;

    /* PGD → PUD */
    table_kva = pgd_va + PT_INDEX(user_va, PGD_SHIFT) * 8UL;
    SAFE_READ64(desc, table_kva, ok);
    if (!ok || !(desc & PTE_VALID) || !(desc & PTE_TABLE))
        return -EFAULT;

    /* PUD → PMD */
    table_kva = pa_to_kva(PA_FROM_PTE(desc)) +
                PT_INDEX(user_va, PUD_SHIFT) * 8UL;
    SAFE_READ64(desc, table_kva, ok);
    if (!ok || !(desc & PTE_VALID))
        return -EFAULT;

    /* 1GB block at PUD level */
    if (!(desc & PTE_TABLE)) {
        *pa_out = (PA_FROM_PTE(desc) & ~((1UL << PUD_SHIFT) - 1)) |
                  (user_va & ((1UL << PUD_SHIFT) - 1));
        return 0;
    }

    /* PMD → PTE */
    table_kva = pa_to_kva(PA_FROM_PTE(desc)) +
                PT_INDEX(user_va, PMD_SHIFT) * 8UL;
    SAFE_READ64(desc, table_kva, ok);
    if (!ok || !(desc & PTE_VALID))
        return -EFAULT;

    /* 2MB block at PMD level */
    if (!(desc & PTE_TABLE)) {
        *pa_out = (PA_FROM_PTE(desc) & ~((1UL << PMD_SHIFT) - 1)) |
                  (user_va & ((1UL << PMD_SHIFT) - 1));
        return 0;
    }

    /* PTE → PA */
    table_kva = pa_to_kva(PA_FROM_PTE(desc)) +
                PT_INDEX(user_va, PTE_SHIFT) * 8UL;
    SAFE_READ64(desc, table_kva, ok);
    if (!ok || !(desc & PTE_VALID))
        return -EFAULT;

    *pa_out = PA_FROM_PTE(desc) | (user_va & ((1UL << PTE_SHIFT) - 1));
    return 0;
}

/*
 * linear_read_range — read up to RW_MAX_SIZE bytes from a target VA range.
 *
 * Handles the common case where the request crosses a page boundary:
 * walks each page separately, copies the slice that falls within it.
 * copy_from_kernel_nofault on the linear-map KVA — if the PA resolves
 * but the KVA is somehow unmapped, it returns -EFAULT instead of panicking.
 */
static long linear_read_range(unsigned long pgd_va, unsigned long addr,
                               void *dst, unsigned long size)
{
    unsigned long done = 0;

    while (done < size) {
        unsigned long va    = addr + done;
        unsigned long pa    = 0;
        unsigned long kva, slice, page_rem;
        int           r;

        r = walk_pt(pgd_va, va, &pa);
        if (r)
            return r;

        kva      = pa_to_kva(pa);
        page_rem = PAGE_SIZE_4K - (pa & (PAGE_SIZE_4K - 1));
        slice    = size - done;
        if (slice > page_rem)
            slice = page_rem;

        r = copy_from_kernel_nofault((u8 *)dst + done, (void *)kva, slice);
        if (r)
            return r;

        done += slice;
    }
    return 0;
}

/*
 * linear_write_range — write bytes into target process memory.
 *
 * Same page-by-page walk as linear_read_range.
 * Plain memcpy to linear-map KVA — cache coherency is the caller's
 * problem if they're writing executable pages (not our use case here).
 * Returns -EROFS immediately if readonly mode is active.
 */
static long linear_write_range(unsigned long pgd_va, unsigned long addr,
                                const void *src, unsigned long size)
{
    unsigned long done = 0;

    if (kopt_readonly)
        return -EROFS;

    while (done < size) {
        unsigned long va    = addr + done;
        unsigned long pa    = 0;
        unsigned long kva, slice, page_rem;
        int           r;

        r = walk_pt(pgd_va, va, &pa);
        if (r)
            return r;

        kva      = pa_to_kva(pa);
        page_rem = PAGE_SIZE_4K - (pa & (PAGE_SIZE_4K - 1));
        slice    = size - done;
        if (slice > page_rem)
            slice = page_rem;

        rw_memcpy((void *)kva, (const u8 *)src + done, slice);
        done += slice;
    }
    return 0;
}

/* ── explicit-offset (stateless) translation ─────────────────────────────
 * Same machinery as the linear-map path, but every layout input arrives
 * per-op as arguments (userspace offset table) instead of cached globals.
 * Writes NOTHING but a stack temp, rw_buf/status/stage/ring (V-class) —
 * no pin globals, no sweeps, no derive. Rationale: cached-pin writes
 * intermittently seize this hypervisor while V/F-class ops stay clean,
 * so the R/W path takes its map per-op. Universality unchanged: the .ko
 * still carries zero layout data; all of it arrives at runtime. */
static inline unsigned long pa_to_kva_ex(unsigned long po, unsigned long ph,
                                          unsigned long pa)
{
    return po + (pa - ph);
}

static int walk_pt_ex(unsigned long root_va, unsigned long user_va,
                       unsigned long *pa_out, unsigned long po, unsigned long ph)
{
    /* Level-agnostic walker: 48-bit VA roots at L0 (shifts 39/30/21/12),
     * 39-bit VA roots at L1 (shifts 30/21/12) — mm->pgd points at the
     * root table in both cases. Selected by page_off (the canonical
     * 48/39-bit bases); anything else is rejected, never mis-walked.
     * (The legacy 4-level-only walk_pt shares this file but is unused
     * by the explicit path.) */
    static const int sh4[] = { 39, 30, 21, 12 };
    static const int sh3[] = { 30, 21, 12 };
    const int *sh;
    int nlv, li;
    unsigned long table_kva = root_va;
    unsigned long desc = 0;
    int ok = 0;

    if (po == 0xffff8000000000UL) { sh = sh4; nlv = 4; }
    else if (po == 0xffffff8000000000UL) { sh = sh3; nlv = 3; }
    else return -EINVAL;

    for (li = 0; li < nlv; li++) {
        unsigned long ent = table_kva + PT_INDEX(user_va, sh[li]) * 8UL;
        SAFE_READ64(desc, ent, ok);
        if (!ok || !(desc & PTE_VALID))
            return -EFAULT;
        if (li == nlv - 1)
            break;
        if (!(desc & PTE_TABLE)) {
            /* Block descriptor: covers 2^sh[li] bytes. */
            *pa_out = (PA_FROM_PTE(desc) & ~((1UL << sh[li]) - 1)) |
                      (user_va & ((1UL << sh[li]) - 1));
            return 0;
        }
        table_kva = pa_to_kva_ex(po, ph, PA_FROM_PTE(desc));
    }
    *pa_out = PA_FROM_PTE(desc) | (user_va & ((1UL << PTE_SHIFT) - 1));
    return 0;
}

static unsigned long find_task_ex(unsigned long start, u32 target_pid,
                                  unsigned long pid_off, unsigned long tasks_off)
{
    unsigned long p = start;
    int i;

    for (i = 0; i < TASK_WALK_MAX; i++) {
        unsigned long tpw = 0;
        int tpok = 0;
        unsigned long nxt = 0;
        int nok = 0;
        SAFE_READ64(tpw, p + pid_off, tpok);
        if (!tpok)
            break;
        if ((u32)tpw == target_pid)
            return p;

        SAFE_READ64(nxt, p + tasks_off, nok);
        if (!nok || !nxt)
            break;
        p = nxt - tasks_off;
        if (p == start)
            break;
    }
    return 0;
}

/* Stateless translate + move: task→mm→pgd→walk each page. write=0 reads
 * via copy_from_kernel_nofault, write=1 writes via plain memcpy (caller
 * enforces the readonly gate). Returns 0 or negative errno. */
static long ex_access(u32 pid, unsigned long addr, void *buf,
                      unsigned long size, int write,
                      unsigned long pid_off, unsigned long tasks_off,
                      unsigned long mm_off, unsigned long pgd_off,
                      unsigned long po, unsigned long ph)
{
    unsigned long task, mm, pgd_va;
    unsigned long done = 0;
    int mok = 0, pok = 0;

    task = find_task_ex(cur_task, pid, pid_off, tasks_off);
    if (!task)
        return -ESRCH;
    SAFE_READ64(mm, task + mm_off, mok);
    if (!mok || !mm)
        return -ESRCH;
    SAFE_READ64(pgd_va, mm + pgd_off, pok);
    if (!pok || !pgd_va || (pgd_va & (PAGE_SIZE_4K - 1)))
        return -EFAULT;
    /* pgd must sit inside the linear map (sanity window 1TB — the old
     * 1GB window wrongly rejected real pgds, e.g. +0x65d29000 here). */
    if (pgd_va <= po || pgd_va - po > 0x10000000000UL)
        return -EFAULT;

    while (done < size) {
        unsigned long va = addr + done;
        unsigned long pa = 0;
        unsigned long kva, slice, page_rem;
        int r;

        r = walk_pt_ex(pgd_va, va, &pa, po, ph);
        if (r)
            return r;
        kva = pa_to_kva_ex(po, ph, pa);
        page_rem = PAGE_SIZE_4K - (pa & (PAGE_SIZE_4K - 1));
        slice = size - done;
        if (slice > page_rem)
            slice = page_rem;
        if (write)
            rw_memcpy((void *)kva, (const u8 *)buf + done, slice);
        else {
            r = copy_from_kernel_nofault((u8 *)buf + done, (void *)kva, slice);
            if (r)
                return r;
        }
        done += slice;
    }
    return 0;
}

/*
 * rw_switch_access — entry point, linear-map variant.
 *
 * Caller contract unchanged: same signature, same error codes.
 * Internal: no register saves, no IRQ disable, no PAN toggle.
 * The "switch" in the name is vestigial — kept for call-site compatibility.
 */
static long rw_switch_access(u32 pid, unsigned long addr, void *buf,
                              unsigned long size, int write)
{
    unsigned long task, mm, pgd_va;

    /* Stub gate — conviction levels still work for bisect if needed */
    task = find_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    if (kopt_stub >= 1)
        return -EIO;

    {
        int mok = 0;
        SAFE_READ64(mm, task + mm_offset, mok);
        if (!mok || !mm)
            return -ESRCH;
    }

    {
        int pok = 0;
        SAFE_READ64(pgd_va, mm + pgd_offset, pok);
        if (!pok || !pgd_va || (pgd_va & (PAGE_SIZE_4K - 1)))
            return -EFAULT;
    }

    if (pgd_va <= page_off || pgd_va - page_off > 0x40000000UL)
        return -EFAULT;

    if (kopt_stub >= 2)
        return -EIO;

    /* Linear map path — no TTBR0 write from here down */
    if (write)
        return linear_write_range(pgd_va, addr, buf, size);
    else
        return linear_read_range(pgd_va, addr, buf, size);
}

/* ── sysfs command parser ───────────────────────────────────────────────── */

/* NOTE on linkage AND sections: the 9 kernel-called entry points below
 * (init, exit, rw/kopts/out/status/stage/log handlers) are deliberately
 * NON-static (GCC omits BTI landing pads on static functions), and init /
 * exit deliberately carry NO __init / __exit attributes. Reason: at least
 * one vendor loader in the wild forms the module with initsize=0 (init
 * sections dropped, init never runs, yet state=Live) — with init in core
 * .text the entry always survives formation. Costs a few KB never freed;
 * irrelevant for a debug bridge. */

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

/* ── kopts: runtime kernel data ────────────────────────────────────────────
 * Format: "key=val,key=val,..."  (val dec or 0x-hex)
 * Accepted any time (insmod arg or later write); each valid key updates the
 * globals immediately. Invalid keys/values are ignored (never fatal).
 * Key matching is manual (no libc, no memcmp import).
 */
static int kopts_key_eq(const char *key, unsigned long klen, const char *e)
{
    unsigned long i = 0;
    while (e[i]) {
        if (i >= klen || key[i] != e[i]) return 0;
        i++;
    }
    return klen == i;
}

static int kopts_set_one(const char *key, unsigned long klen, u64 val)
{
    if (kopts_key_eq(key, klen, "page_offset")) {
        if ((val & 0xffff000000000000UL) != 0xffff000000000000UL) return -1;
        page_off = val; kopt_mask |= K_PAGE_OFF; return 0;
    }
    if (kopts_key_eq(key, klen, "phys_offset")) {
        if (val == 0 || val > 0x20000000000UL) return -1;
        phys_off = val; kopt_mask |= K_PHYS_OFF; return 0;
    }
    if (kopts_key_eq(key, klen, "va_bits")) {
        if (val != 39 && val != 48) return -1;
        kopt_va_bits = val; return 0;
    }
    if (kopts_key_eq(key, klen, "page_shift")) {
        if (val != 12 && val != 14 && val != 16) return -1;
        kopt_page_shift = val; return 0;
    }
    if (kopts_key_eq(key, klen, "task_pid_off")) {
        if (val >= SCAN_RANGE) return -1;
        pid_offset = val; kopt_mask |= K_TASK_PID; return 0;
    }
    if (kopts_key_eq(key, klen, "task_mm_off")) {
        if (val >= SCAN_RANGE) return -1;
        mm_offset = val; kopt_mask |= K_TASK_MM; return 0;
    }
    if (kopts_key_eq(key, klen, "mm_pgd_off")) {
        if (val >= SCAN_RANGE) return -1;
        pgd_offset = val; kopt_mask |= K_MM_PGD; return 0;
    }
    if (kopts_key_eq(key, klen, "task_tasks_off")) {
        if (val >= SCAN_RANGE) return -1;
        tasks_offset = val; kopt_mask |= K_TASK_TASKS; return 0;
    }
    if (kopts_key_eq(key, klen, "task_comm_off")) {
        if (val >= SCAN_RANGE) return -1;
        comm_offset = val; kopt_mask |= K_TASK_COMM; return 0;
    }
    if (kopts_key_eq(key, klen, "mm_arg_start_off")) {
        if (val >= SCAN_RANGE) return -1;
        arg_start_offset = val; kopt_mask |= K_ARG_START; return 0;
    }
    if (kopts_key_eq(key, klen, "mm_arg_end_off")) {
        if (val >= SCAN_RANGE) return -1;
        arg_end_offset = val; kopt_mask |= K_ARG_END; return 0;
    }
    if (kopts_key_eq(key, klen, "stability")) {
        kopt_stability = (val != 0);
        kopt_mask |= K_STABILITY;
        return 0;
    }
    if (kopts_key_eq(key, klen, "readonly")) {
        kopt_readonly = (val != 0);
        kopt_mask |= K_READONLY;
        return 0;
    }
    if (kopts_key_eq(key, klen, "stub")) {
        if (val > 4)
            return -1;
        kopt_stub = (int)val;
        return 0;
    }
    return -1;
}

static int kopts_parse_apply(const char *s)
{
    int applied = 0;
    while (s && *s) {
        const char *eq;
        const char *comma;
        unsigned long klen;
        u64 val = 0;
        while (*s == ',' || *s == ' ' || *s == '\t' || *s == '\n') s++;
        if (!*s) break;
        eq = rw_strchr(s, '=');
        if (!eq) break;
        klen = (unsigned long)(eq - s);
        if (klen == 0 || klen >= 32) break;
        s = eq + 1;
        /* dec-or-hex: 0x-prefix means hex, else decimal (parse_hex alone
         * would misread e.g. va_bits=48 as 0x48). Stops at first foreign
         * char (comma/space/NUL). */
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            s += 2;
            while (*s) {
                int d;
                if (*s >= '0' && *s <= '9') d = *s - '0';
                else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
                else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
                else break;
                val = (val << 4) | (u64)d;
                s++;
            }
        } else {
            while (*s >= '0' && *s <= '9') {
                val = val * 10 + (u64)(*s - '0');
                s++;
            }
        }
        if (kopts_set_one(eq - klen, klen, val) == 0) applied++;
        comma = rw_strchr(s, ',');
        if (!comma) break;
        s = comma + 1;
    }
    return applied;
}

static void kopts_log_state(void)
{
        { rb_puts("rwbridge: kopts mask="); rb_put_hex((unsigned long)(kopt_mask)); rb_puts(" va_bits="); rb_put_dec((unsigned long)(kopt_va_bits)); rb_puts(" page_shift="); rb_put_dec((unsigned long)(kopt_page_shift)); rb_puts(" stab="); rb_put_u32((unsigned int)((unsigned int)kopt_stability)); rb_puts(" ro="); rb_put_u32((unsigned int)((unsigned int)kopt_readonly)); rb_putc('\n'); };
}

/* strncpy_from_kernel since we can't import kernel helpers */
static long strncpy_from_kernel(char *dst, const char *src, long max)
{
    long n = 0;
    while (n < max && src[n]) { dst[n] = src[n]; n++; }
    dst[n] = 0;
    return n;
}



/* Self-contained implementations — no kernel symbol imports needed */

static char *rw_strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return NULL;
}

static void *rw_memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

/* Use these instead of kernel strlen/strchr/memcpy */
#define strlen rw_strlen
#define strchr rw_strchr

/* ── write-path safety gates ───────────────────────────────────────────────
 * 1. IN-APP-VA: the target must lie fully inside user address space
 *    ([1, page_off)). Uses derived PAGE_OFFSET when available, else the
 *    static arm64 user-range bound. Rejects NULL, wrap, kernel spill.
 * 2. PTR-PROTECTED-SYS: kernel/system addresses are write-protected —
 *    touching them can crash the whole device. App VAs are NOT protected
 *    in this sense: each process's user memory is hardware-isolated, so a
 *    write there can at worst crash that app, never the system.
 */
static int in_app_va(unsigned long addr, unsigned long size)
{
    unsigned long lim = page_off ? page_off : 0x8000000000UL;
    if (!addr || !size)
        return 0;
    if (addr + size < addr)
        return 0;                       /* wraparound */
    if (addr >= lim)
        return 0;
    if (addr + size > lim)
        return 0;                       /* straddles user/kernel line */
    return 1;
}

static int ptr_protected_sys(unsigned long addr, unsigned long size)
{
    unsigned long lim = page_off ? page_off : 0x8000000000UL;
    if (!addr || !size)
        return 1;
    if (addr + size < addr)
        return 1;
    if (addr >= lim)
        return 1;                       /* kernel space: system-protected */
    if (addr + size > lim)
        return 1;                       /* straddles the line */
    return 0;                           /* app VA: isolated, cannot crash system */
}


int rw_set(const char *val, const struct kernel_param *kp)
{
    char buf[512];
    char *p = buf;
    char op;
    s64 pid_s64 = 0, size_s64 = 0;
    u32 pid;
    u64 addr = 0, wvalue = 0;
    u64 exv = 0;
    long r;

    /* Fresh current-task every op: each sysfs write runs in a DIFFERENT
     * writer process, so a cur_task captured by an earlier op (or an
     * earlier S step) points at a possibly-dead task. One mrs keeps every
     * path (derive, find, S steps) anchored to the living caller. Layout
     * offsets are process-independent and stay cached. */
    asm volatile("mrs %0, sp_el0" : "=r"(cur_task));

    if (!derive_ok && val[0] != 'F' && val[0] != 'T' && val[0] != 'S' && val[0] != 'V' && val[0] != 'E' && val[0] != 'Y') {
        /* Lazy first-use derivation: some loaders drop init sections
         * (the initcall pointer lives in one, so init never runs, yet
         * state=Live with pristine data). Deriving here makes operation
         * independent of init execution; module_init stays as the eager
         * fast-path where loaders are sane. Idempotent: a second caller
         * while one derives just recomputes the same values.
         * 'F' (fault probe) bypasses derive: it tests the fixup armor
         * itself and must run even when derive is broken/unknown.
         * 'V' (verify-u32) also bypasses: single guarded read, no walk.
         * 'E'/'Y' (explicit-offset R/W) bypass: stateless, map arrives
         * per-op as arguments, no cached pins touched. */
        derive_all();
    }
    if (!derive_ok && val[0] != 'F' && val[0] != 'T' && val[0] != 'S' && val[0] != 'V' && val[0] != 'E' && val[0] != 'Y') {
        rw_status = -EPERM;
        STAGE("no_derive");
        return 0;
    }

    strncpy_from_kernel(buf, val, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    p = buf;
    op = *p++;
    if (*p == ',') p++;

    if (rb_spin_trylock()) {
        rw_status = -EBUSY;
        STAGE("busy");
        return 0;
    }
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
            rw_memcpy(f[fi], p, len); f[fi][len] = '\0';
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

        /* Read-only session gate: W refused before any other handling.
         * Reads validate PA translation/offsets first; writes come later. */
        if (op == 'W' && kopt_readonly) {
            rw_status = -EROFS;
            rw_text_len = 0;
            STAGE("readonly");
            rb_spin_unlock();
            return 0;
        }

        /* Gate 1 — IN-APP-VA: target must sit inside user address space. */
        if (!in_app_va(addr, (unsigned long)size_s64)) {
            rw_status = -EFAULT;
            rw_text_len = 0;
            STAGE("not_app_va");
            rb_spin_unlock();
            return 0;
        }

        /* Gate 2 — PTR-PROTECTED-SYS: writes never touch system addrs.
         * (Reads keep gate 1 only; app-VA reads are always system-safe.) */
        if (op == 'W' && ptr_protected_sys(addr, (unsigned long)size_s64)) {
            rw_status = -EPERM;
            rw_text_len = 0;
            STAGE("protected_sys");
            rb_spin_unlock();
            return 0;
        }

        /* Execute via TTBR0 switch */
        STAGE(op == 'R' ? "read" : "write");

        if (op == 'R') {
            memset(rw_buf, 0, RW_MAX_SIZE);
            r = rw_switch_access(pid, addr, rw_buf, (unsigned long)size_s64, 0);
            if (r == 0) {
                rw_status = 0;
                rw_text_len = (long)size_s64 * 2;
                if (rw_text_len > (long)RW_MAX_SIZE - 1)
                    rw_text_len = (long)RW_MAX_SIZE - 1;
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
        rb_spin_unlock();
        return 0;
    }

    case 'E': case 'Y': {
        /* Explicit-offset R/W — stateless, V-class. Format:
         *   E,<pid>,<addr>,<size>,<pid_off>,<tasks_off>,<mm_off>,
         *     <pgd_off>,<page_off>,<phys_off>
         *   Y,<same 9 fields>,<value-hex>
         * pid/size dec; addr, offsets, value hex. NOTE: offsets are HEX
         * (5d8 = 1496). Output goes through a stack temp because
         * put_hex_bytes cannot dump rw_buf into itself (overlap).
         * (Same overlap bug exists latent in the R-case; untouched.) */
        char f[9][64];
        int fi;
        unsigned long ex_pid_off = 0, ex_tasks_off = 0, ex_mm_off = 0,
                      ex_pgd_off = 0;
        unsigned long ex_po = 0, ex_ph = 0;
        u8 ex_tmp[128];

        for (fi = 0; fi < 9; fi++) {
            char *comma = strchr(p, ',');
            size_t len = comma ? (size_t)(comma - p) : strlen(p);
            if (len >= sizeof(f[0])) goto bad;
            rw_memcpy(f[fi], p, len); f[fi][len] = '\0';
            if (comma) p = comma + 1;
            else if (fi < 8) goto bad;
            else break;
        }

        parse_dec(f[0], &pid_s64);
        parse_hex(f[1], &addr);
        parse_dec(f[2], &size_s64);
        pid = (u32)pid_s64;
        parse_hex(f[3], &exv); ex_pid_off = (unsigned long)exv;
        parse_hex(f[4], &exv); ex_tasks_off = (unsigned long)exv;
        parse_hex(f[5], &exv); ex_mm_off = (unsigned long)exv;
        parse_hex(f[6], &exv); ex_pgd_off = (unsigned long)exv;
        parse_hex(f[7], &exv); ex_po = (unsigned long)exv;
        parse_hex(f[8], &exv); ex_ph = (unsigned long)exv;

        if (op == 'Y') {
            if (*p == ',') p++;
            parse_hex(p, &wvalue);
            if (size_s64 < 1 || size_s64 > 8) goto bad;
        } else {
            if (size_s64 < 1 || size_s64 > 128) goto bad;
        }

        if (pid == 0 || addr == 0) goto bad;
        if (ex_pid_off >= SCAN_RANGE || ex_tasks_off >= SCAN_RANGE ||
            ex_mm_off >= SCAN_RANGE || ex_pgd_off >= SCAN_RANGE) goto bad;
        if (ex_po == 0 || ex_ph == 0) goto bad;

        if (op == 'Y' && kopt_readonly) {
            rw_status = -EROFS;
            rw_text_len = 0;
            STAGE("readonly");
            rb_spin_unlock();
            return 0;
        }

        /* App-VA gate against the explicit page_off (mirrors in_app_va;
         * Y additionally mirrors the W-side system guard: user range
         * writes are hardware-isolated per process). */
        if (addr >= ex_po || addr + (unsigned long)size_s64 < addr ||
            addr + (unsigned long)size_s64 > ex_po) {
            rw_status = -EFAULT;
            rw_text_len = 0;
            STAGE("not_app_va");
            rb_spin_unlock();
            return 0;
        }

        STAGE(op == 'E' ? "eread" : "ewrite");

        if (op == 'E') {
            memset(ex_tmp, 0, sizeof(ex_tmp));
            r = ex_access(pid, addr, ex_tmp, (unsigned long)size_s64, 0,
                          ex_pid_off, ex_tasks_off, ex_mm_off, ex_pgd_off,
                          ex_po, ex_ph);
            if (r == 0) {
                rw_status = 0;
                rw_text_len = (long)size_s64 * 2;
                if (rw_text_len > (long)RW_MAX_SIZE - 1)
                    rw_text_len = (long)RW_MAX_SIZE - 1;
                put_hex_bytes(0, ex_tmp, size_s64);
                STAGE("ok");
            } else {
                rw_status = r;
                rw_text_len = 0;
            }
        } else {
            r = ex_access(pid, addr, &wvalue, (unsigned long)size_s64, 1,
                          ex_pid_off, ex_tasks_off, ex_mm_off, ex_pgd_off,
                          ex_po, ex_ph);
            rw_status = r;
            rw_text_len = 0;
            if (r == 0) STAGE("ok");
        }
        rb_spin_unlock();
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
            /* Snapshot comm locally first: the task may exit mid-walk, so
             * never run strstr directly on remote bytes. */
            unsigned long cw[2] = { 0, 0 };
            int cwok = 0;
            unsigned long mmv = 0;
            int mok = 0;
            char *comm;
            SAFE_READ64(cw[0], t + comm_offset, cwok);
            if (cwok)
                SAFE_READ64(cw[1], t + comm_offset + 8, cwok);
            if (!cwok)
                break;
            comm = (char *)cw;
            comm[15] = '\0'; /* bound strstr even on garbage reads */
            SAFE_READ64(mmv, t + mm_offset, mok);
            if (!mok)
                break;

            if (mmv && strstr_kernel(comm, sub)) {
                unsigned long fpw = 0;
                int fpok = 0;
                SAFE_READ64(fpw, t + pid_offset, fpok);
                if (!fpok)
                    break;
                put_dec_u32(0, (u32)fpw);
                found = 1;
            }

            {
                unsigned long nxt = 0;
                int nok = 0;
                SAFE_READ64(nxt, t + tasks_offset, nok);
                if (!nok || !nxt) break;
                t = nxt - tasks_offset;
                if (t == cur) break;
            }
        }

        if (!found) {
            rw_status = -ESRCH;
            rw_text_len = 0;
        } else {
            rw_status = 0;
        }
        rb_spin_unlock();
        return 0;
    }

    case 'B': {
        /* Module base — needs VMA walk (complex in ko).
         * Any root caller can compute base from /proc/<pid>/maps. */
        rw_status = -EOPNOTSUPP;
        rw_text_len = 0;
        rb_spin_unlock();
        return 0;
    }

    case 'F': {
        /* Controlled-fault probe: does one SAFE_READ64 at the given (hex)
         * kernel address and reports. Answers whether __ex_table fixups
         * fire on this loader: ok=1/fault-clean vs panic. The address is
         * SUPPOSED to fault (use an unmapped high VA); a clean report
         * proves the armor works, a panic proves fixups are dead here. */
        u64 faddr = 0;
        unsigned long fv = 0xAAAAAAAAAAAAAAAAUL;
        int fok = 0;
        parse_hex(p, &faddr);
        SAFE_READ64(fv, (unsigned long)faddr, fok);
        if (fok) {
            rw_status = 1;
            put_hex_bytes(0, (const u8 *)&fv, 8);
        } else {
            rw_status = 0;
            rw_text_len = 0;
        }
        rb_spin_unlock();
        return 0;
    }

    case 'T': {
        /* Bare TTBR0-read probe: mrs ttbr0_el1 and nothing else. Under a
         * hypervisor that traps TTBR0 guest reads (HCR_EL2.TVM), THIS
         * instruction is where derive and the old switch died — a wedge
         * here with no other code running convicts the trap, not our
         * logic. Reports low 32 bits of ttbr0 in status on success. */
        unsigned long ttv = 0;
        asm volatile("mrs %0, ttbr0_el1" : "=r"(ttv));
        rw_status = (long)(ttv & 0xFFFFFFFFUL);
        rw_text_len = 0;
        STAGE("ttbr0-ok");
        rb_spin_unlock();
        return 0;
    }

    case 'V': {
        /* Verify-u32: V,<byteoff>,<hexval> reads one u32 at cur_task+off
         * and compares with val. Single ex-table-guarded read pair —
         * F-class safety, no sweep, no walk. Used to validate candidate
         * offsets (pid at 1496, comm probes) synchronously inside the
         * live writer: status 0 = match, -EIO = mismatch, -EFAULT =
         * unreadable. Reports the observed u32 in `out` always. */
        u64 voff = 0, vval = 0;
        unsigned long vw = 0;
        int vok = 0;
        char *comma2;
        parse_hex(p, &voff);
        comma2 = strchr(p, ',');
        if (comma2)
            parse_hex(comma2 + 1, &vval);
        if (voff >= SCAN_RANGE) {
            rw_status = -EINVAL;
            rw_text_len = 0;
            rb_spin_unlock();
            return 0;
        }
        SAFE_READ64(vw, cur_task + (unsigned long)voff, vok);
        if (vok) {
            u32 seen = (u32)vw;
            put_hex_bytes(0, (const u8 *)&seen, 4);
            rw_status = (seen == (u32)vval) ? 0 : -EIO;
        } else {
            rw_status = -EFAULT;
            rw_text_len = 0;
        }
        rb_spin_unlock();
        return 0;
    }

    case 'N': {
        /* No-op bisect: lock + one ring line + unlock. No reads, no
         * global writes. If even this seizes, the rw-write path itself
         * is fragile on this target; if clean, the trigger is in reads
         * or pin writes (see G). */
        { rb_puts("rwbridge: nop"); rb_putc('\n'); };
        rw_status = 0;
        rw_text_len = 0;
        rb_spin_unlock();
        return 0;
    }

    case 'G': {
        /* Write-only bisect: records pid_offset=1496 + mask + cands with
         * ZERO reads. Convicts or clears the pin-write hypothesis that
         * K and the S,1 probe share (both seized; V/F/S,0/T never write
         * these globals and never seize). */
        pid_offset = 1496;
        kopt_mask |= K_TASK_PID;
        pid_ncands = 1;
        pid_cand_off[0] = 1496;
        pid_cand_val[0] = 0;
        { rb_puts("rwbridge: G wrote pin (no reads)"); rb_putc('\n'); };
        rw_status = 0;
        rw_text_len = 0;
        rb_spin_unlock();
        return 0;
    }

    case 'K': {        /* Pin pid offset: K,<byteoff> records pid_offset + K_TASK_PID
         * from the proven-safe `rw` channel (kopts/insmod-arg channels
         * are retired — both wedge the loader/writer on this
         * hypervisor). Pure assignment + one guarded validation read;
         * S,1 afterwards takes the pinned single-read branch, never a
         * sweep. status 0 = pinned (validation read ok),
         * -EFAULT = unreadable at that off, -EINVAL = out of range. */
        u64 koff = 0;
        unsigned long kw = 0;
        int kok = 0;
        parse_hex(p, &koff);
        if (koff >= SCAN_RANGE) {
            rw_status = -EINVAL;
            rw_text_len = 0;
            rb_spin_unlock();
            return 0;
        }
        SAFE_READ64(kw, cur_task + (unsigned long)koff, kok);
        if (!kok) {
            rw_status = -EFAULT;
            rw_text_len = 0;
            rb_spin_unlock();
            return 0;
        }
        pid_offset = (unsigned long)koff;
        kopt_mask |= K_TASK_PID;
        { rb_puts("rwbridge: pid pinned off="); rb_put_dec((unsigned long)(koff)); rb_puts(" (K op)"); rb_putc('\n'); };
        rw_status = 0;
        rw_text_len = 0;
        rb_spin_unlock();
        return 0;
    }

    case 'S': {
        /* Single derive step: S,<0..7> runs exactly one step
         * (regs/pid/po/mm/tasks/comm/arg/fin). Steps must run in order
         * (lower bits of dbg_done all set); step 0 always allowed.
         * Reports the step's return code in status; stage names the step.
         * Stability mode refuses steps >0 (observe-only contract).
         * A wedge inside exactly one step convicts it. */
        u64 sn = 0;
        int n;
        parse_hex(p, &sn);
        n = (int)sn;
        /* Optional sweep cap for wedge-bisect: "S,1.64" caps step 1's
         * sweep at 64 u32 slots (wall-time the echo per cap to find a
         * poison word). No dot = full range (dbg_scancap=0). */
        {
            const char *dot = buf;
            dbg_scancap = 0;
            while (*dot && *dot != '.')
                dot++;
            if (*dot == '.') {
                int cap = 0;
                dot++;
                while (*dot >= '0' && *dot <= '9') {
                    cap = cap * 10 + (*dot - '0');
                    dot++;
                }
                if (cap > 0 && cap < SCAN_RANGE / 4)
                    dbg_scancap = cap;
            }
        }
        if (sn > 7 || (sn == 0 && p[0] != '0')) {
            rw_status = -EINVAL;
            rw_text_len = 0;
            STAGE("bad-step");
            rb_spin_unlock();
            return 0;
        }
        if (n > 0 && (dbg_done & ((1UL << n) - 1)) != ((1UL << n) - 1)) {
            rw_status = -EAGAIN;
            rw_text_len = 0;
            STAGE("need-prev");
            rb_spin_unlock();
            return 0;
        }
        if (n > 0 && kopt_stability) {
            rw_status = -EPERM;
            rw_text_len = 0;
            STAGE("stability");
            rb_spin_unlock();
            return 0;
        }
        {
            int rc = st_fns[n]();
            if (rc == 0)
                dbg_done |= (1UL << n);
            rw_status = rc;
            rw_text_len = 0;
        }
        rb_spin_unlock();
        return 0;
    }

    default:
        goto bad;
    }

bad:
    rw_status = -EINVAL;
    rw_text_len = 0;
    rb_spin_unlock();
    return 0;
}

/* Minimal kernel-space strstr */


/* ── sysfs param declarations ───────────────────────────────────────────── */

/* kopts: runtime kernel data (see above). Writable live; insmod-time values
 * are parsed before init, so derive_all() already honors them. */
int kopts_param_set(const char *val, const struct kernel_param *kp)
{
    /* ALWAYS -EPERM (load-time AND runtime). Reason: READING val in
     * .set wedges the loader on this hypervisor (two pinned loads
     * stuck in Loading with 53 refs; the EPERM-only build returned
     * instantly). The val pointer at load-time is not safely
     * dereferenceable here, and sysfs writes wedge intermittently —
     * so this channel is retired entirely. Pin offsets via the K op
     * on the `rw` channel (proven-safe bounded path) instead. */
    (void)val; (void)kp;
    return -EPERM;
}

int kopts_param_get(char *buf, const struct kernel_param *kp)
{
    unsigned long n = 0;
    while (kopts_buf[n] && n < sizeof(kopts_buf) - 1) {
        buf[n] = kopts_buf[n];
        n++;
    }
    buf[n] = '\0';
    return (int)n;
}

static const struct kernel_param_ops kopts_param_ops = {
    .set = kopts_param_set,
    .get = kopts_param_get,
};
module_param_cb(kopts, &kopts_param_ops, NULL, 0600);
MODULE_PARM_DESC(kopts, "runtime kernel data: key=val,... (see source)");

static const struct kernel_param_ops rw_param_ops = {
    .set = rw_set,
};
module_param_cb(rw, &rw_param_ops, NULL, 0200);

int rw_out_get(char *buf, const struct kernel_param *kp)
{
    long n = rw_text_len;
    if (n < 0) n = 0;
    if (n > (long)(RW_MAX_SIZE * 2)) n = RW_MAX_SIZE * 2;
    rw_memcpy(buf, rw_buf, n);
    buf[n] = '\0';
    return (int)n;
}
static const struct kernel_param_ops rw_out_ops = {
    .get = rw_out_get,
};
module_param_cb(out, &rw_out_ops, NULL, 0444);

int rw_status_get(char *buf, const struct kernel_param *kp)
{
    long v = rw_status;
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

int rw_stage_get(char *buf, const struct kernel_param *kp)
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

/* `log`: the full in-module ring (see zero-import logging above). This is
 * the primary diagnostic channel — run.sh saves it to /sdcard/MemoryD/. */
int rw_log_get(char *buf, const struct kernel_param *kp)
{
    unsigned long n = rb_loglen;
    if (n > RB_LOG_MAX)
        n = RB_LOG_MAX;
    rw_memcpy(buf, rb_logb, n);
    buf[n] = '\0';
    return (int)n;
}
static const struct kernel_param_ops rw_log_ops = {
    .get = rw_log_get,
};
module_param_cb(log, &rw_log_ops, NULL, 0444);
MODULE_PARM_DESC(log, "in-module diagnostic ring (zero-import logging)");

/* ── module init/exit ───────────────────────────────────────────────────── */
int rwbridge_init(void)
{
    /* NOTE: no utsname()/current derefs here — those bake in struct layouts.
     * The loader (run.sh) already prints uname -r from userspace.
     * NOTE 2: NO derive_all() here — derivation is lazy on first op
     * (see rw_set). Eager derive at init wedges load on hypervisors
     * where sweeps hit non-faulting poison (module sticks in Loading
     * with piled-up refs, killing param I/O until reboot). Kopts pins
     * are already recorded by .set before init; S-steps validate them
     * safely on first use (single reads, no sweeps when pinned). */
        { rb_puts("rwbridge: loading (universal single-build, kopts runtime)"); rb_putc('\n'); };
    kopts_log_state();
        { rb_puts("rwbridge: init ok (lazy derive)"); rb_putc('\n'); };
    kopts_init_done = 1;
    return 0;
}

void rwbridge_exit(void)
{
        { rb_puts("rwbridge: unloaded"); rb_putc('\n'); };
    kopts_init_done = 0;
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("c4x64");
MODULE_DESCRIPTION("Self-deriving ARM64 R/W bridge — zero params, zero hardcoded offsets");
