// SPDX-License-Identifier: GPL-2.0
/*
 * lxgr_probe.c - probe module using runtime kallsyms resolution.
 *
 * kallsyms_lookup_name is NOT exported on Linux >= 5.7, so we can't import it
 * or even statically call it. Instead the insmod command passes the symbol's
 * address (obtained from /proc/kallsyms as root) via the `klook_addr` int param.
 * init calls through that address to resolve filp_open/kernel_write on the fly
 * and write a log file, proving both the load chain and the runtime-resolution
 * path the real silent module will use.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

static unsigned long klook_addr = 0;
module_param(klook_addr, ulong, 0444);

static void *(*k_s)(const char *name);

static struct file *(*filp_open_s)(const char *, int, umode_t);
static ssize_t (*kernel_write_s)(struct file *, const void *, size_t,
                                 loff_t *);
static int (*filp_close_s)(struct file *, void *);

static int fail_init = 0;
module_param(fail_init, int, 0444);

static int __init lxgr_probe_init(void)
{
    char buf[256];
    struct file *f;
    unsigned int n;
    loff_t pos = 0;

    if (fail_init)
        return -EINVAL;

    k_s = (void *)klook_addr;
    if (!k_s)
        return -ENXIO;

    filp_open_s = (void *)k_s("filp_open");
    kernel_write_s = (void *)k_s("kernel_write");
    filp_close_s = (void *)k_s("filp_close");
    if (!filp_open_s || !kernel_write_s || !filp_close_s)
        return -ENOENT;

    n = snprintf(buf, sizeof(buf),
                 "INIT_OK kernel=%s %s %s klook=%lu\n",
                 init_uts_ns.name.release,
                 init_uts_ns.name.version,
                 init_uts_ns.name.machine,
                 klook_addr);

    f = filp_open_s("/data/local/tmp/lxgr_probe.log",
                    O_WRONLY | O_CREAT | O_TRUNC, (umode_t)0600);
    if (IS_ERR(f))
        return PTR_ERR(f);
    kernel_write_s(f, buf, n, &pos);
    filp_close_s(f, NULL);

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