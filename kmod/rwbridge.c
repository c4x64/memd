// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for GKI Android kernels.
 *
 * Philosophy: expect nothing from the kernel. module_init may or may not run
 * (on the target it is skipped), exported symbols are unreliable, ioctls and
 * char devices cannot be assumed to exist. Therefore:
 *   - The ONLY entry points that are guaranteed are the module parameter
 *     set/get callbacks, driven through /sys/module/rwbridge/parameters/*.
 *   - The ONLY symbols imported at link time are module_layout + _printk.
 *   - Every kernel helper (find_task_by_vpid, get_task_mm, access_remote_vm)
 *     is resolved at runtime from kallsyms_lookup_name, whose ADDRESS is
 *     passed in as a module parameter (it is not exported on >= 5.7).
 *
 * Interface (sysfs params):
 *   rw       - write: "R,pid,addr,size[,atomic]"  read from a process VA
 *                    "W,pid,addr,size,value[,atomic]" write to a process VA
 *   out      - read: last result as hex string
 *   status   - read: last status code (0 ok, <0 errno)
 *
 * ARM64 only. No hardcoded addresses. No unexported symbol imports.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>

/* ---- runtime-resolved kernel helpers (via kallsyms_lookup_name) ---- */
static unsigned long ksym_addr;
module_param(ksym_addr, ulong, 0444);

typedef void *(*klookup_t)(const char *name);

typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *task);
typedef long (*access_remote_vm_t)(struct mm_struct *mm, unsigned long addr,
                                   void *buf, size_t len, unsigned int flags);
typedef void (*mmput_t)(struct mm_struct *mm);

static find_task_by_vpid_t p_find_task_by_vpid;
static get_task_mm_t p_get_task_mm;
static access_remote_vm_t p_access_remote_vm;
static mmput_t p_mmput;

#define FOLL_WRITE 0x01

/* ---- scratch state ---- */
static char rw_out[64] = "idle";
static long rw_status = 0;

/* ---- tiny hex parser (self-contained, no kstrto* dependency) ---- */
static unsigned long parse_hex(const char *s)
{
    unsigned long v = 0;
    char c;
    int i;

    if (*s == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (i = 0; i < 16 && s[i]; i++) {
        c = s[i];
        if (c >= '0' && c <= '9')
            v = (v << 4) | (c - '0');
        else if (c >= 'a' && c <= 'f')
            v = (v << 4) | (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v = (v << 4) | (c - 'A' + 10);
        else
            break;
    }
    return v;
}

static long parse_long(const char *s)
{
    int neg = 0;
    long v = 0;

    if (*s == '-') {
        neg = 1;
        s++;
    }
    while (*s && *s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return neg ? -v : v;
}

static int count_fields(const char *s, int n)
{
    int c = 1;
    while (*s) {
        if (*s == ',' && c < n)
            c++;
        s++;
    }
    return c;
}

/* ---- resolve all runtime symbols on first use ---- */
static int rw_resolve(void)
{
    klookup_t kl;

    if (p_access_remote_vm && p_find_task_by_vpid && p_get_task_mm)
        return 0;
    if (!ksym_addr)
        return -ENXIO;

    kl = (klookup_t)ksym_addr;
    p_find_task_by_vpid = (find_task_by_vpid_t)kl("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kl("get_task_mm");
    p_access_remote_vm = (access_remote_vm_t)kl("access_remote_vm");
    p_mmput = (mmput_t)kl("mmput");
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_access_remote_vm ||
        !p_mmput)
        return -ENOENT;
    return 0;
}

/* ---- core read/write on a process virtual address ---- */
static long rw_read_vm(int pid, unsigned long addr, unsigned long size,
                       unsigned long *value)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long tmp = 0;
    long ret;
    int rc;

    rc = rw_resolve();
    if (rc)
        return rc;

    task = p_find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;
    mm = p_get_task_mm(task);
    if (!mm)
        return -EACCES;

    ret = p_access_remote_vm(mm, addr, &tmp, size, 0);
    p_mmput(mm);
    if (ret != (long)size)
        return -EFAULT;

    *value = tmp;
    return 0;
}

static long rw_write_vm(int pid, unsigned long addr, unsigned long size,
                        unsigned long value)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long tmp = value;
    long ret;
    int rc;

    rc = rw_resolve();
    if (rc)
        return rc;

    task = p_find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;
    mm = p_get_task_mm(task);
    if (!mm)
        return -EACCES;

    ret = p_access_remote_vm(mm, addr, &tmp, size, FOLL_WRITE);
    p_mmput(mm);
    if (ret != (long)size)
        return -EFAULT;

    return 0;
}

/* ---- param set: the guaranteed entry point ---- */
static int rw_set(const char *val, const struct kernel_param *kp)
{
    const char *p = val;
    int pid;
    unsigned long addr, value;
    unsigned long size = 4;
    char op;
    long r = -EINVAL;
    unsigned long readout = 0;

    /* skip leading spaces */
    while (*p == ' ')
        p++;

    if (count_fields(p, 6) < 2)
        goto done;

    op = *p++;
    if (*p == ',')
        p++;

    pid = (int)parse_long(p);
    while (*p && *p != ',')
        p++;
    if (*p == ',')
        p++;
    addr = parse_hex(p);
    while (*p && *p != ',')
        p++;
    if (*p == ',')
        p++;
    size = parse_long(p);
    while (*p && *p != ',')
        p++;
    if (*p == ',')
        p++;
    value = parse_hex(p);

    if (op != 'R' && op != 'W')
        goto done;

    if (op == 'R')
        r = rw_read_vm(pid, addr, size, &readout);
    else
        r = rw_write_vm(pid, addr, size, value);

    if (r == 0 && op == 'R') {
        /* self-contained hex formatter */
        int i;
        char tmp[17];
        unsigned long v = readout;
        static const char hx[] = "0123456789abcdef";
        for (i = 15; i >= 0; i--) {
            tmp[i] = hx[v & 0xf];
            v >>= 4;
        }
        tmp[16] = 0;
        memcpy(rw_out, tmp, 17);
        rw_status = 0;
    } else if (r == 0) {
        memcpy(rw_out, "ok", 3);
        rw_status = 0;
    } else {
        rw_status = r;
        rw_out[0] = 'e';
        rw_out[1] = 'r';
        rw_out[2] = 'r';
        rw_out[3] = 0;
    }

done:
    return 0; /* never fail the param write; status goes to /status */
}

static const struct kernel_param_ops rw_param_ops = {
    .set = rw_set,
};

module_param_cb(rw, &rw_param_ops, NULL, 0200);

/* ---- param get: read back result ---- */
static int rw_out_get(char *buf, const struct kernel_param *kp)
{
    int n = (int)strlen(rw_out);
    memcpy(buf, rw_out, n);
    buf[n] = '\0';
    return n;
}

static const struct kernel_param_ops rw_out_ops = {
    .get = rw_out_get,
};

module_param_cb(out, &rw_out_ops, NULL, 0444);

/* ---- status param ---- */
static int rw_status_get(char *buf, const struct kernel_param *kp)
{
    int n = 0;
    long v = rw_status;
    char tmp[24];
    int i = 22;
    int neg = 0;

    if (v < 0) {
        neg = 1;
        v = -v;
    }
    tmp[23] = 0;
    do {
        tmp[i--] = '0' + (v % 10);
        v /= 10;
    } while (v && i > 0);
    if (neg)
        tmp[i--] = '-';
    i++;
    n = 24 - i;
    memcpy(buf, tmp + i, n);
    buf[n] = 0;
    return n;
}

static const struct kernel_param_ops rw_status_ops = {
    .get = rw_status_get,
};

module_param_cb(status, &rw_status_ops, NULL, 0444);

static int __init rwbridge_init(void)
{
    return 0;
}

static void __exit rwbridge_exit(void)
{
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("self-contained memory R/W bridge (no kernel feature deps)");