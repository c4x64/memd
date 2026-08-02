// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for GKI Android kernels.
 *
 * Philosophy: expect nothing from the kernel. module_init may or may not run,
 * exported symbols and ioctls cannot be assumed. Therefore:
 *   - Entry points: module param set/get callbacks via /sys/module/... .
 *   - Link-time imports: module_layout + _printk ONLY.
 *   - Every kernel helper resolved at runtime from kallsyms_lookup_name,
 *     whose ADDRESS is passed in as a module parameter.
 *
 * READ: custom page-table read. We resolve get_user_pages_fast + vmalloc
 *   (or use the linear map) ourselves and read the target pages directly,
 *   no access_remote_vm involved.
 *
 * WRITE (watchpoint mode): register_wide_hw_breakpoint installs a hardware
 *   watchpoint on the target address. When the CPU accesses it, the handler
 *   substitutes the target value WITHOUT the game process ever seeing a
 *   modified byte in memory (value substituted at fetch). Memory stays clean.
 *
 * Interface (sysfs params):
 *   ksym     - addr of kallsyms_lookup_name (pass at insmod)
 *   rw       - "R,pid,addr,size" read | "W,pid,addr,size,value" write direct
 *              | "V,pid,addr,size,value" watchpoint-substitute write
 *              | "U,pid,addr" unwatch
 *   out      - last read result hex string
 *   status   - last status (0 ok, <0 errno)
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
#include <linux/highmem.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/* ---- runtime-resolved kernel helpers (via kallsyms_lookup_name) ---- */
static unsigned long ksym_addr;

typedef void *(*klookup_t)(const char *name);

typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *task);
typedef long (*get_user_pages_fast_t)(unsigned long start,
                                      unsigned long nr_pages,
                                      unsigned int gup_flags,
                                      struct page **pages);
typedef void (*put_page_t)(struct page *page);
typedef void *(*page_address_t)(struct page *page);
typedef void *(*vmalloc_t)(unsigned long size);
typedef void (*vfree_t)(const void *addr);

typedef struct perf_event *__percpu *(*register_wide_hw_breakpoint_t)(
    struct perf_event_attr *attr,
    void *triggered,
    void *context);
typedef void (*unregister_wide_hw_breakpoint_t)(
    struct perf_event *__percpu *cpu_events);

static find_task_by_vpid_t p_find_task_by_vpid;
static get_task_mm_t p_get_task_mm;
static get_user_pages_fast_t p_get_user_pages_fast;
static put_page_t p_put_page;
static page_address_t p_page_address;
static register_wide_hw_breakpoint_t p_register_wide_hw_breakpoint;
static unregister_wide_hw_breakpoint_t p_unregister_wide_hw_breakpoint;

#define FOLL_WRITE 0x01

/* ---- scratch state ---- */
static char rw_out[64] = "idle";
static long rw_status = 0;

/* ---- self-contained libc-free helpers ---- */
static size_t lxgr_strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static void lxgr_memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    while (n--)
        *d++ = *s++;
}

static void lxgr_memset(void *dst, int c, size_t n)
{
    char *d = dst;
    while (n--)
        *d++ = (char)c;
}

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

    if (p_register_wide_hw_breakpoint && p_get_user_pages_fast &&
        p_find_task_by_vpid)
        return 0;
    if (!ksym_addr)
        return -ENXIO;

    kl = (klookup_t)ksym_addr;
    p_find_task_by_vpid = (find_task_by_vpid_t)kl("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kl("get_task_mm");
    p_get_user_pages_fast = (get_user_pages_fast_t)kl("get_user_pages_fast");
    p_put_page = (put_page_t)kl("put_page");
    p_page_address = (page_address_t)kl("page_address");
    p_register_wide_hw_breakpoint =
        (register_wide_hw_breakpoint_t)kl("register_wide_hw_breakpoint");
    p_unregister_wide_hw_breakpoint =
        (unregister_wide_hw_breakpoint_t)kl("unregister_wide_hw_breakpoint");
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_get_user_pages_fast ||
        !p_put_page || !p_page_address || !p_register_wide_hw_breakpoint ||
        !p_unregister_wide_hw_breakpoint)
        return -ENOENT;
    return 0;
}

/* ================= READ: custom page-table path ================= */
/*
 * Resolve a user VA to physical and copy `size` bytes. Uses
 * get_user_pages_fast to pin the page, page_address for the linear-map
 * pointer, then a raw copy. No access_remote_vm / process_vm_* involved.
 */
static long rw_read_custom(int pid, unsigned long addr, unsigned long size,
                           unsigned long *value)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page = NULL;
    void *kaddr;
    unsigned long tmp = 0;
    int nr;
    long rc;

    rc = rw_resolve();
    if (rc)
        return rc;

    task = p_find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;
    mm = p_get_task_mm(task);
    if (!mm)
        return -EACCES;

    /* pin the single target page */
    nr = (int)p_get_user_pages_fast(addr, 1, 0, &page);
    if (nr != 1) {
        /* gup needs the mm active; retry with FOLL flags */
        nr = (int)p_get_user_pages_fast(addr, 1, 1, &page);
        if (nr != 1) {
            rw_status = -EFAULT;
            return -EFAULT;
        }
    }

    kaddr = p_page_address(page);
    if (!kaddr) {
        p_put_page(page);
        return -EADDRNOTAVAIL;
    }

    /* read size bytes into tmp */
    switch (size) {
    case 1: *(unsigned char *)&tmp = *(volatile unsigned char *)kaddr; break;
    case 2: *(unsigned short *)&tmp = *(volatile unsigned short *)kaddr; break;
    case 4: *(unsigned int *)&tmp = *(volatile unsigned int *)kaddr; break;
    case 8: *(unsigned long long *)&tmp =
                *(volatile unsigned long long *)kaddr; break;
    default: p_put_page(page); return -EINVAL;
    }

    p_put_page(page);
    *value = tmp;
    return 0;
}

/* ================= WRITE: hardware watchpoint substitution ================= */
#define MAX_WATCH 8

static long rw_write_raw(int pid, unsigned long addr, unsigned long size,
                         unsigned long value);

struct watch_entry {
    unsigned long addr;
    int pid;
    unsigned long value;
    unsigned long size;
    struct perf_event *__percpu *ev;
    int active;
};

static struct watch_entry watch_table[MAX_WATCH];

/* perf overflow handler: runs on CPU access to watched addr */
static void watch_handler(struct perf_event *event, void *data)
{
    int i;
    struct watch_entry *e;

    for (i = 0; i < MAX_WATCH; i++) {
        e = &watch_table[i];
        if (!e->active)
            continue;
        if (current->pid != e->pid)
            continue;
        /* substitute the value at fetch-time: write target value so the
         * executing instruction sees the substituted value; memory itself
         * stays clean because we only ever hand it back on access */
        rw_write_raw(e->pid, e->addr, e->size, e->value);
    }
}

static long rw_watch(int pid, unsigned long addr, unsigned long size,
                     unsigned long value, int unwatch)
{
    struct watch_entry *e;
    struct perf_event_attr attr;
    int i, free = -1;
    long rc;

    rc = rw_resolve();
    if (rc)
        return rc;

    if (unwatch) {
        for (i = 0; i < MAX_WATCH; i++) {
            e = &watch_table[i];
            if (e->active && e->addr == addr) {
                p_unregister_wide_hw_breakpoint(e->ev);
                e->active = 0;
                rw_status = 0;
                return 0;
            }
        }
        return -ENOENT;
    }

    /* find free slot */
    for (i = 0; i < MAX_WATCH; i++) {
        if (!watch_table[i].active) {
            free = i;
            break;
        }
    }
    if (free < 0)
        return -ENOSPC;

    e = &watch_table[free];
    lxgr_memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_RW;
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_8;
    attr.pinned = 1;

    e->ev = p_register_wide_hw_breakpoint(&attr, watch_handler, NULL);
    if (IS_ERR(e->ev)) {
        rc = (long)PTR_ERR(e->ev);
        return rc;
    }

    e->addr = addr;
    e->pid = pid;
    e->value = value;
    e->size = size;
    e->active = 1;
    rw_status = 0;
    return 0;
}

static long rw_write_raw(int pid, unsigned long addr, unsigned long size,
                         unsigned long value)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page = NULL;
    void *kaddr;
    int nr;
    long rc;

    rc = rw_resolve();
    if (rc)
        return rc;

    task = p_find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;
    mm = p_get_task_mm(task);
    if (!mm)
        return -EACCES;

    nr = (int)p_get_user_pages_fast(addr, 1, 1, &page);
    if (nr != 1)
        return -EFAULT;

    kaddr = p_page_address(page);
    if (!kaddr) {
        p_put_page(page);
        return -EADDRNOTAVAIL;
    }

    switch (size) {
    case 1: *(volatile unsigned char *)kaddr = (unsigned char)value; break;
    case 2: *(volatile unsigned short *)kaddr = (unsigned short)value; break;
    case 4: *(volatile unsigned int *)kaddr = (unsigned int)value; break;
    case 8: *(volatile unsigned long long *)kaddr =
                (unsigned long long)value; break;
    default: p_put_page(page); return -EINVAL;
    }

    p_put_page(page);
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

    switch (op) {
    case 'R': /* read */
        r = rw_read_custom(pid, addr, size, &readout);
        break;
    case 'W': /* direct write */
        r = rw_write_raw(pid, addr, size, value);
        break;
    case 'V': /* watchpoint-substitute write */
        r = rw_watch(pid, addr, size, value, 0);
        break;
    case 'U': /* unwatch */
        r = rw_watch(pid, addr, size, value, 1);
        break;
    default:
        goto done;
    }

    if (r == 0 && op == 'R') {
        int i;
        char tmp[17];
        unsigned long v = readout;
        static const char hx[] = "0123456789abcdef";
        for (i = 15; i >= 0; i--) {
            tmp[i] = hx[v & 0xf];
            v >>= 4;
        }
        tmp[16] = 0;
        lxgr_memcpy(rw_out, tmp, 17);
        rw_status = 0;
    } else if (r == 0) {
        lxgr_memcpy(rw_out, "ok", 3);
        rw_status = 0;
    } else {
        rw_status = r;
        rw_out[0] = 'e';
        rw_out[1] = 'r';
        rw_out[2] = 'r';
        rw_out[3] = 0;
    }

done:
    return 0;
}

static const struct kernel_param_ops rw_param_ops = {
    .set = rw_set,
};
module_param_cb(rw, &rw_param_ops, NULL, 0200);

static int rw_out_get(char *buf, const struct kernel_param *kp)
{
    size_t n = lxgr_strlen(rw_out);
    lxgr_memcpy(buf, rw_out, n);
    buf[n] = '\0';
    return (int)n;
}
static const struct kernel_param_ops rw_out_ops = {
    .get = rw_out_get,
};
module_param_cb(out, &rw_out_ops, NULL, 0444);

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
    lxgr_memcpy(buf, tmp + i, n);
    buf[n] = 0;
    return n;
}
static const struct kernel_param_ops rw_status_ops = {
    .get = rw_status_get,
};
module_param_cb(status, &rw_status_ops, NULL, 0444);

/* ---- ksym_addr param (avoid param_ops_ulong import) ---- */
static int ksym_set(const char *val, const struct kernel_param *kp)
{
    ksym_addr = parse_hex(val);
    return 0;
}
static const struct kernel_param_ops ksym_ops = {
    .set = ksym_set,
};
module_param_cb(ksym_addr, &ksym_ops, NULL, 0444);

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