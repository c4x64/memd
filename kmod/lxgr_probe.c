// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - probe module exposing module parameters.
 *
 * Validation module for the build/load chain. printk is unreliable on this
 * tuned firmware and /proc entries can be masked by mount namespaces, so this
 * exposes a `msg` module parameter written at init and readable through the
 * guaranteed visible /sys/module/lxgr_probe/parameters/msg node. Reading that
 * confirms the module's init ran on the target kernel.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/string.h>

static char lxgr_status_buf[256] = "loading";
static char *lxgr_status = lxgr_status_buf;
module_param(lxgr_status, charp, 0444);

static int __init lxgr_probe_init(void)
{
    snprintf(lxgr_status_buf, sizeof(lxgr_status_buf),
             "INIT OK kernel=%s %s %s",
             init_uts_ns.name.release,
             init_uts_ns.name.version,
             init_uts_ns.name.machine);
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