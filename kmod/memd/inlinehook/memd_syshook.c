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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>

/* One filldir actor for every kernel: int (pre-6.1) vs bool (6.1+) only
 * differ in type, not ABI — 0/continue and 1/stop share the same w0
 * values, and the wrapped kernel actor only ever returns 0/1. */
typedef int hide_filldir_ret_t;
#define HIDE_FILLDIR_OK 0
#define HIDE_FILLDIR_FULL 1
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/atomic.h>
#include <linux/rculist.h>

/* filp_open/filp_close resolved at runtime via kallsyms (memd_utils.c).
 * No VFS namespace import needed — avoids loader rejection on some kernels. */

/* VFS readdir hook for /proc pid hiding.
 *
 * Why not sys_call_table: on obscured OEM kernels the table is not
 * discoverable by content (no 400+ plain run anywhere; text is unreadable,
 * so targets cannot be validated; KASLR relocates it anew at every boot). The
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

#define MAX_HOOKED_OPS 8

struct hooked_fops {
    const struct file_operations *ops;
    iterate_shared_fn orig_iterate;
    const char *path;
    struct rcu_head rcu;
};

static struct hooked_fops hooked_fops[MAX_HOOKED_OPS];
static int hooked_fops_count = 0;
static DEFINE_SPINLOCK(syshook_lock);
static atomic_t hook_active = ATOMIC_INIT(0);

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

/* Dispatch: one replacement serves up to MAX_HOOKED_OPS tables; find
 * the original for this file's ops. Lock-free (install/uninstall mutate
 * under syshook_lock while readers run): a stale hit after uninstall
 * merely calls the kernel's own iterate directly (one unfiltered
 * listing, never a crash); rmmod is fenced by try_module_get below. */
static iterate_shared_fn memd_orig_for_ops(const struct file_operations *ops)
 {
    int n, i;
    if (!ops)
        return NULL;
    n = READ_ONCE(hooked_fops_count);
    if (n > MAX_HOOKED_OPS)
        n = MAX_HOOKED_OPS;
    for (i = 0; i < n; i++) {
        if (READ_ONCE(hooked_fops[i].ops) == ops)
            return READ_ONCE(hooked_fops[i].orig_iterate);
    }
    return NULL;
}

static bool should_hide_pid(pid_t pid, struct pid_namespace *ns)
 {
    return memd_hide_contains_ns(pid, ns);
}

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
    return should_hide_pid((pid_t)v, &init_pid_ns);
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
        return HIDE_FILLDIR_OK;
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

    orig = memd_orig_for_ops(memd_file_fop(filp));
    if (!orig)
        return -ENOSYS;

    if (memd_capable(CAP_SYS_ADMIN))
        return orig(filp, ctx);
    if (!try_module_get(THIS_MODULE))
        return orig(filp, ctx);
    held = true;
    hc.base = *ctx;
    hc.base.actor = (filldir_t)(void *)hide_filldir;
    hc.orig = ctx;
    ret = orig(filp, &hc.base);
    ctx->pos = hc.base.pos;
    if (held)
        module_put(THIS_MODULE);
    return ret;
}

static int hook_proc_dir(const char *path)
 {
    struct file *f;
    const struct file_operations *ops;
    iterate_shared_fn orig;
    int i;

    if (hooked_fops_count >= MAX_HOOKED_OPS)
        return -ENOSPC;

    if (memd_filp_open(path, O_RDONLY | O_DIRECTORY, 0, &f) != 0)
        return -ENOSPC;
    if (IS_ERR(f))
        return PTR_ERR(f);

    ops = memd_file_fop(f);
    memd_filp_close(&f, NULL);
    if (!ops || !memd_iter_get(ops)) {
        memd_err("hide install: no f_op/iterate for %s\n", path);
        return -ENOSYS;
    }
    orig = (iterate_shared_fn)memd_iter_get(ops);
    memd_err("hide install: %s f_op=%px iterate=%px\n", path, ops, orig);

    for (i = 0; i < hooked_fops_count; i++) {
        if (hooked_fops[i].ops == ops)
            return 0;
    }

    hooked_fops[hooked_fops_count].ops = ops;
    hooked_fops[hooked_fops_count].orig_iterate = orig;
    hooked_fops[hooked_fops_count].path = path;
    hooked_fops_count++;

    return 0;
}

static int install_hooks_on_fops(const struct file_operations *ops, iterate_shared_fn new_iter)
 {
    int wr;

    wr = memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                            (unsigned long)new_iter);
    if (wr) {
        memd_err("hide install: table write failed\n");
        return -EIO;
    }

    iterate_shared_fn back = (iterate_shared_fn)memd_iter_get(ops);
    if (!back || back != new_iter) {
        memd_err("hide install: readback mismatch\n");
        memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                           (unsigned long)hooked_fops[0].orig_iterate);
        return -EIO;
    }

    return 0;
}

static int uninstall_hooks_from_fops(const struct file_operations *ops, iterate_shared_fn orig_iter)
 {
    int wr;

    wr = memd_table_write64((unsigned long)ops + (unsigned long)memd_iter_off(),
                            (unsigned long)orig_iter);
    if (wr) {
        memd_err("hide uninstall: table write failed\n");
        return -EIO;
    }

    iterate_shared_fn back = (iterate_shared_fn)memd_iter_get(ops);
    if (!back || back != orig_iter) {
        memd_err("hide uninstall: readback mismatch\n");
        return -EIO;
    }

    return 0;
}

int memd_hide_install(void)
 {
    unsigned long flags;
    int ret = 0;
    int i;

    spin_lock_irqsave(&syshook_lock, flags);
    if (atomic_read(&hook_active)) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&syshook_lock, flags);

    const char *proc_dirs[] = {
        "/proc",
        "/proc/self/task",
        "/proc/self/fd",
        "/proc/self/fdinfo",
        "/proc/self/ns",
        NULL
    };

    for (i = 0; proc_dirs[i]; i++) {
        ret = hook_proc_dir(proc_dirs[i]);
        if (ret && ret != -ENOSYS) {
            memd_err("hide install: failed to hook %s: %d\n", proc_dirs[i], ret);
            goto fail;
        }
    }

    for (i = 0; i < hooked_fops_count; i++) {
        ret = install_hooks_on_fops(hooked_fops[i].ops, memd_iterate_shared);
        if (ret) {
            memd_err("hide install: failed to install hook on %s: %d\n", hooked_fops[i].path, ret);
            goto fail;
        }
    }

    spin_lock_irqsave(&syshook_lock, flags);
    atomic_set(&hook_active, 1);
    spin_unlock_irqrestore(&syshook_lock, flags);

    memd_info("hide: installed hooks on %d proc directories\n", hooked_fops_count);
    return 0;

fail:
    for (i = 0; i < hooked_fops_count; i++) {
        uninstall_hooks_from_fops(hooked_fops[i].ops, hooked_fops[i].orig_iterate);
    }
    hooked_fops_count = 0;
    return ret;
}

int memd_hide_uninstall(void)
 {
    unsigned long flags;
    int ret = 0;
    int i;

    spin_lock_irqsave(&syshook_lock, flags);
    if (!atomic_read(&hook_active)) {
        spin_unlock_irqrestore(&syshook_lock, flags);
        return 0;
    }
    atomic_set(&hook_active, 0);
    spin_unlock_irqrestore(&syshook_lock, flags);

    for (i = 0; i < hooked_fops_count; i++) {
        ret = uninstall_hooks_from_fops(hooked_fops[i].ops, hooked_fops[i].orig_iterate);
        if (ret) {
            memd_err("hide uninstall: failed to uninstall hook on %s: %d\n", hooked_fops[i].path, ret);
        }
    }

    hooked_fops_count = 0;

    memd_info("hide: uninstalled hooks from %d proc directories\n", i);
    return ret;
}

int memd_hide_active(void)
 {
    return atomic_read(&hook_active);
}
/* kmod/memd/inlinehook/memd_syshook.c[∂] */
