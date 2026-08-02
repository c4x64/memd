// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c — minimal loadable kernel module.
 *
 * Goal: prove the full toolchain works on the target device before adding the
 * silent cross-process memory backend. On load it registers with the kernel,
 * prints the running kernel version (UTS_RELEASE) and its own computed
 * vermagic through the ring buffer (dmesg). If the vermagic matches the
 * target kernel, the module loads and we see the print.
 *
 * Kept deliberately trivial: it imports ONLY the symbols the module ABI needs
 * (module printing / init/exit boilerplate), no kallsyms resolution yet, so we
 * can first validate that a module built in GitHub Actions can be insmod'd on
 * the device at all.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/init.h>

static int __init lxgr_probe_init(void)
{
    printk(KERN_INFO "lxgr_probe: init ok, kernel=%s %s %s\n",
        init_uts_ns.name.release,
        init_uts_ns.name.version,
        init_uts_ns.name.machine);
    return 0;
}

static void __exit lxgr_probe_exit(void)
{
    printk(KERN_INFO "lxgr_probe: exit ok\n");
}

module_init(lxgr_probe_init);
module_exit(lxgr_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("lxgr probe module");