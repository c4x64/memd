// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - minimal probe module.
 *
 * Bare-minimum validation module: imports only printk + module_layout so the
 * synthesized Module.symvers (CRCs from the device kernel's own modules) fully
 * covers it. On load it emits a KERN_INFO line that must appear in dmesg,
 * proving module_init runs when the __versions CRCs match the device kernel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init lxgr_probe_init(void)
{
    return -EINVAL;
}

static void __exit lxgr_probe_exit(void)
{
}

module_init(lxgr_probe_init);
module_exit(lxgr_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("lxgr probe module");