#include "wuwa_syshook.h"
#include "wuwa_hide.h"
#include "wuwa_utils.h"

#include <asm/barrier.h>
#include <asm/extable.h>
#include <asm/sysreg.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifndef __NR_getdents64
#define __NR_getdents64 61 /* arm64 stable ABI */
#endif

/* Local dirent layout (stable userspace ABI, no header roulette). */
struct wuwa_dirent64 {
    u64 d_ino;
    s64 d_off;
    u16 d_reclen;
    u8 d_type;
    char d_name[];
};

/* Max single getdents64 result we filter; larger reads pass through
 * unfiltered (documented; /proc readers use small counts). */
#define WUWA_DENTS_CAP (131072u)

typedef asmlinkage long (*getdents64_fn)(unsigned int fd,
                                         void __user *dirent,
                                         unsigned int count);

static getdents64_fn orig_getdents64;
#define SYSHOOK_MAX_TABLES 2
static unsigned long *hook_tables[SYSHOOK_MAX_TABLES];
static getdents64_fn hook_origs[SYSHOOK_MAX_TABLES];
static int hook_ntables;
static int hook_active;
static DEFINE_SPINLOCK(syshook_lock);

/* ---- hidden-set aware filter (runs in syscall context) ---- */
static bool name_is_hidden_pid(const char *name, unsigned int maxlen)
{
    unsigned long v = 0;
    unsigned int i = 0;

    if (maxlen == 0)
        return false;
    while (i < maxlen && name[i]) {
        if (name[i] < '0' || name[i] > '9')
            return false;
        v = v * 10 + (unsigned int)(name[i] - '0');
        if (v > 0x7fffffffUL)
            return false;
        i++;
    }
    if (i == 0 || i >= maxlen)
        return false;
    return wuwa_hide_contains((pid_t)v);
}

asmlinkage long wuwa_getdents64(unsigned int fd,
                                struct wuwa_dirent64 __user *dirent,
                                unsigned int count)
{
    getdents64_fn orig;
    long ret;
    char *kbuf;
    long bpos, kept;
    bool module_held = false;

    orig = READ_ONCE(orig_getdents64);
    if (!orig)
        return -ENOSYS;
    ret = orig(fd, dirent, count);
    if (ret <= 0)
        return ret;
    /* Root sees everything (debugging); everyone else gets filtered. */
    if (uid_eq(current_euid(), GLOBAL_ROOT_UID))
        return ret;
    if (!try_module_get(THIS_MODULE))
        return ret; /* teardown race: passthrough, never crash */
    module_held = true;
    if ((unsigned long)ret > WUWA_DENTS_CAP)
        goto out_put;
    kbuf = kmalloc((size_t)ret, GFP_KERNEL);
    if (!kbuf)
        goto out_put;
    if (copy_from_user(kbuf, dirent, (size_t)ret)) {
        kfree(kbuf);
        ret = -EFAULT;
        goto out_put_nofree;
    }
    bpos = 0;
    kept = ret;
    while (bpos < kept) {
        u16 reclen;
        unsigned int namelen;
        if (kept - bpos < 19)
            break;
        reclen = (u16)((u8)kbuf[bpos + 16] | ((u16)(u8)kbuf[bpos + 17] << 8));
        if (reclen < 19 || bpos + reclen > kept)
            break; /* corrupt record: stop filtering, keep rest as-is */
        namelen = reclen - 19;
        if (namelen > 0 && namelen < 256 &&
            name_is_hidden_pid(kbuf + bpos + 19, namelen)) {
            if (kept > bpos + reclen)
                memmove(kbuf + bpos, kbuf + bpos + reclen,
                        (size_t)(kept - (bpos + reclen)));
            kept -= reclen;
            continue;
        }
        bpos += reclen;
    }
    if (copy_to_user(dirent, kbuf, (size_t)kept))
        kept = -EFAULT;
    kfree(kbuf);
    ret = kept;
out_put_nofree:
    (void)0;
out_put:
    if (module_held)
        module_put(THIS_MODULE);
    return ret;
}

/* ---- table discovery: pointer-run signature + prologue validation ---- */
#define SCAN_MIN_RUN 400
#define SCAN_SAMPLE_EVERY 16
#define SCAN_SAMPLE_NEED 20
#define SCAN_SAMPLE_TOTAL 24
#define SCAN_DISTINCT_NEED 200

/* Duplicate-value census over a run: syscall tables share one ni_syscall
 * stub across dozens of entries; kallsyms/data runs do not repeat.
 * Returns the highest repeat count seen (sampling every 8th). */
static int run_maxdup(unsigned long base, unsigned long len)
{
    unsigned long vals[64];
    int n = 0, i, j, best = 0;
    unsigned long v;
    long k;
    for (k = 0; k + 8 <= (long)len && n < 64; k += 64) {
        if (wuwa_safe_read64((void *)(base + (unsigned long)k), &v))
            return -1;
        vals[n++] = v;
    }
    for (i = 0; i < n; i++) {
        int c = 0;
        for (j = 0; j < n; j++) {
            if (vals[j] == vals[i])
                c++;
        }
        if (c > best)
            best = c;
    }
    return best;
}

#define SCAN_DUP_NEED 8 /* ni-stub repeats across sampled slots */

/* Run statistics from entry VALUES only (never target contents:
 * kernel text is execute-only on hardened kernels, so prologue checks
 * are impossible there). Distinct + unsorted + duplicates identify
 * syscall tables: ni_syscall stub repeats, kallsyms is sorted. */
static int run_stats(unsigned long base, unsigned long *distinct_out,
                     unsigned long *ascents_out)
{
    unsigned long v, prev = 0;
    unsigned long distinct = 0, ascents = 0;
    int sampled = 0, i = 0;
    for (i = 0; i < SCAN_MIN_RUN; i += SCAN_SAMPLE_EVERY) {
        if (sampled >= SCAN_SAMPLE_TOTAL)
            break;
        if (wuwa_safe_read64((void *)(base + (unsigned long)i * 8), &v))
            return -1;
        if (sampled > 0 && v >= prev)
            ascents++;
        if (v != prev) {
            distinct++;
            prev = v;
        }
        sampled++;
    }
    if (sampled < SCAN_SAMPLE_TOTAL)
        return -1;
    *distinct_out = distinct;
    *ascents_out = ascents;
    return 0;
}

/* Locate sys_call_table without symbols: VBAR gives a kernel-text anchor;
 * tables are long runs of in-window function pointers with valid
 * prologues. Up to SYSHOOK_MAX_TABLES candidates (main + compat: hooking
 * both also covers 32-bit readers); sorted runs (kallsyms) rejected.
 * Returns candidate count, 0 = NO-GO. */
static int find_syscall_tables(unsigned long *out, int cap)
{
    unsigned long vbar, lo, hi, a, run = 0;
    unsigned long best_run = 0, best_at = 0, near = 0;
    int found = 0;
    unsigned long v;

    if (cap <= 0)
        return 0;
    vbar = read_sysreg(vbar_el1);
    if (vbar < (1UL << 40))
        return 0; /* sanity: kernel text lives high */
    lo = (vbar & ~((1UL << 21) - 1)) - (1UL << 21);
    hi = vbar + (128UL << 20);
    for (a = lo; a + 8 <= hi; a += 8) {
        if (wuwa_safe_read64((void *)a, &v)) {
            if (run > best_run) {
                best_run = run;
                best_at = a - run * 8;
            }
            if (run >= 100)
                near++;
            run = 0;
            continue;
        }
        if (v >= lo && v <= hi && (v & 7) == 0) {
            run++;
            if (run == 100) {
                /* Near-miss diagnostics: stats only, no target reads. */
                unsigned long dd = 0, aa = 0;
                int s2 = run_stats(a - 99 * 8, &dd, &aa);
                pr_info("[wuwa] near100 @%lx rc=%d dist=%lu asc=%lu\n",
                        a - 99 * 8, s2, dd, aa);
            }
            if (run == SCAN_MIN_RUN) {
                unsigned long base = a - (SCAN_MIN_RUN - 1) * 8;
                unsigned long dist = 0, asc = 0;
                int dup = -1;
                int rc;
                /* sys_call_table is 4K-aligned (entry.S access);
                 * unaligned 400+ runs are logged, never accepted. */
                if (base & 4095) {
                    pr_info("[wuwa] unaligned 400+ run @%lx skipped\n", base);
                    continue;
                }
                rc = run_stats(base, &dist, &asc);
                if (rc == 0)
                    dup = run_maxdup(base,
                                     (unsigned long)SCAN_MIN_RUN * 8);
                pr_info("[wuwa] run400 @%lx rc=%d dist=%lu asc=%lu dup=%d\n",
                        base, rc, dist, asc, dup);
                /* Accept: aligned 400+ in-window run, unsorted,
                 * mostly distinct, ni-stub duplicates present.
                 * No target reads anywhere (XOM-safe). */
                if (rc == 0 && dist >= SCAN_DISTINCT_NEED &&
                    asc < SCAN_SAMPLE_TOTAL - 2 && dup >= SCAN_DUP_NEED) {
                    if (found < cap)
                        out[found] = base;
                    found++;
                } else if (rc < 0) {
                    run = 0;
                }
                /* keep scanning to prove uniqueness bound */
            }
            continue;
        }
        if (run > best_run) {
            best_run = run;
            best_at = a - run * 8;
        }
        if (run >= 100)
            near++;
        run = 0;
    }
    pr_info("[wuwa] table scan: vbar=%lx ttbr1=%lx win=[%lx,%lx] best_run=%lu at %lx near100=%lu found=%d\n",
            vbar, (unsigned long)read_sysreg(ttbr1_el1), lo, hi, best_run, best_at, near, found);
    return found;
}

int wuwa_hide_install(void)
{
    unsigned long found[SYSHOOK_MAX_TABLES];
    int n, i, installed = 0;
    unsigned long flags;
    unsigned long vbar, lo, hi;

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&syshook_lock, flags);

    /* Scan without the lock (seconds worst case, fault-safe probes). */
    n = find_syscall_tables(found, SYSHOOK_MAX_TABLES);
    if (n <= 0 || n > SYSHOOK_MAX_TABLES)
        return -ESRCH;

    /* In-window check for pre-write sanity (same anchor math as scan). */
    vbar = read_sysreg(vbar_el1);
    lo = (vbar & ~((1UL << 21) - 1)) - (1UL << 21);
    hi = vbar + (128UL << 20);

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned long *table = (unsigned long *)found[i];
        unsigned long orig;
        if (wuwa_safe_read64(&table[__NR_getdents64], &orig))
            continue;
        /* Pre-write sanity is structural only (in-window, aligned):
         * target contents are execute-only on hardened kernels and
         * must never be read. The functional ls test is the proof. */
        if (orig < lo || orig > hi || (orig & 7))
            continue;
        hook_tables[installed] = table;
        hook_origs[installed] = (getdents64_fn)orig;
        /* Table pages are read-only at runtime: flip AP via the
         * table writer (guarded, verified, restored below). */
        if (wuwa_table_write64((unsigned long)&table[__NR_getdents64],
                               (unsigned long)wuwa_getdents64))
            continue;
        installed++;
    }
    smp_wmb();
    /* Verify every write; roll back all on any mismatch. */
    for (i = 0; i < installed; i++) {
        unsigned long back = 0;
        if (wuwa_safe_read64(&hook_tables[i][__NR_getdents64], &back) ||
            back != (unsigned long)wuwa_getdents64) {
            int j;
            for (j = 0; j < installed; j++)
                wuwa_table_write64((unsigned long)&hook_tables[j][__NR_getdents64],
                                   (unsigned long)hook_origs[j]);
            for (j = 0; j < installed; j++) {
                hook_tables[j] = NULL;
                hook_origs[j] = NULL;
            }
            hook_ntables = 0;
            spin_unlock_irqrestore(&syshook_lock, flags);
            return -EIO;
        }
    }
    if (!installed) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return -EINVAL;
    }
    orig_getdents64 = hook_origs[0];
    hook_ntables = installed;
    hook_active = 1;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return 0;
}

int wuwa_hide_uninstall(void)
{
    unsigned long flags;
    int i, bad = 0;

    spin_lock_irqsave(&syshook_lock, flags);
    if (!hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    for (i = 0; i < hook_ntables; i++)
        wuwa_table_write64((unsigned long)&hook_tables[i][__NR_getdents64],
                           (unsigned long)hook_origs[i]);
    smp_wmb();
    for (i = 0; i < hook_ntables; i++) {
        unsigned long back = 0;
        if (wuwa_safe_read64(&hook_tables[i][__NR_getdents64], &back) ||
            back != (unsigned long)hook_origs[i])
            bad = 1;
        hook_tables[i] = NULL;
        hook_origs[i] = NULL;
    }
    orig_getdents64 = NULL;
    hook_ntables = 0;
    hook_active = 0;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return bad ? -EIO : 0;
}

int wuwa_hide_active(void)
{
    int a;
    unsigned long flags;

    spin_lock_irqsave(&syshook_lock, flags);
    a = hook_active;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return a;
}
