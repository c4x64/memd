// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - probe module writing its own log file.
 *
 * Validation module for the build/load chain. printk is unreliable on this
 * tuned firmware, /proc can be masked by mount namespaces, so the most direct
 * observable is module code writing a file into the root filesystem via
 * filp_open + vfs_write. On a successful init with the right kernel, the file
 * /data/local/tmp/lxgr_probe.log exists with the running UTS release inside.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

static const char lxgr_logpath[] = "/data/local/tmp/lxgr_probe.log";
static int fail_init = 0;
module_param(fail_init, int, 0444);

static int __init lxgr_probe_init(void)
{
    char buf[160];
    struct file *f;
    unsigned int n;

    if (fail_init)
        return -EINVAL;

    n = snprintf(buf, sizeof(buf),
                 "INIT_OK kernel=%s %s %s\n",
                 init_uts_ns.name.release,
                 init_uts_ns.name.version,
                 init_uts_ns.name.machine);

    f = filp_open(lxgr_logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f)) {
        return PTR_ERR(f);
    }
    kernel_write(f, buf, n, &f->f_pos);
    filp_close(f, NULL);

    return 0;
}

static void __exit lxgr_probe_exit(void)
{
}

module_init(lxgr_probe_init);
module_exit(lxgr_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("lxgr probe module");