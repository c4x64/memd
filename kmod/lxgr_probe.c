// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - probe module exposing a /proc node.
 *
 * Validates the full build/load chain on the target device and provides a
 * deterministic, readable log path (/proc/lxgr_probe) rather than relying on
 * printk, which may be suppressed on quieted firmware. Creating a proc entry
 * is exactly the mechanism the real silent cross-process memory backend will
 * use to expose a read interface, so this doubles as a skeleton.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

static char lxgr_msg[256];

static ssize_t lxgr_proc_read(struct file *file, char __user *buf,
                              size_t len, loff_t *off)
{
    return simple_read_from_buffer(buf, len, off, lxgr_msg,
                                   strlen(lxgr_msg));
}

static const struct proc_ops lxgr_proc_ops = {
    .proc_read = lxgr_proc_read,
};

static struct proc_dir_entry *lxgr_proc_entry;

static int __init lxgr_probe_init(void)
{
    snprintf(lxgr_msg, sizeof(lxgr_msg),
             "lxgr_probe: INIT OK kernel=%s %s %s\n",
             init_uts_ns.name.release,
             init_uts_ns.name.version,
             init_uts_ns.name.machine);

    lxgr_proc_entry = proc_create("lxgr_probe", 0444, NULL, &lxgr_proc_ops);
    if (!lxgr_proc_entry) {
        printk(KERN_ERR "lxgr_probe: failed to create /proc/lxgr_probe\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit lxgr_probe_exit(void)
{
    if (lxgr_proc_entry)
        proc_remove(lxgr_proc_entry);
}

module_init(lxgr_probe_init);
module_exit(lxgr_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("lxgr probe module");