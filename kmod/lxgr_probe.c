// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - probe module with guaranteed-on-load code path.
 *
 * module_init is skipped on this device kernel (verified: init returning
 * -EINVAL still loads rc=0 / live). This probe runs code via the module param
 * SET callback: insmod trig=1 forces the kernel to call our ops->set during
 * argument parsing, independent of do_init_module. Only uses param_ops_int
 * (CRC-matched) plus printk/module_layout. No kernel param helpers imported,
 * so the CRC surface stays minimal.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int lxgr_trig;

static int lxgr_set(const char *val, const struct kernel_param *kp)
{
    printk(KERN_INFO "lxgr_probe: PARAM_SET_RAN\n");
    lxgr_trig = 1;
    return 0;
}

static int lxgr_get(char *buf, const struct kernel_param *kp)
{
    buf[0] = '1';
    buf[1] = '\0';
    return 1;
}

static const struct kernel_param_ops lxgr_trig_ops = {
    .set = lxgr_set,
    .get = lxgr_get,
};

module_param_cb(trig, &lxgr_trig_ops, &lxgr_trig, 0644);

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