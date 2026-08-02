// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - memory R/W / substitution bridge for ARM64 Android kernels.
 *
 * Everything runs in kernel mode (module param set callback). No kernel
 * symbol is linked: all kernel functions are resolved FRESH from
 * /proc/kallsyms by the loader on every insmod (kernel is KASLR re-based
 * after reboot, stale addresses = panic). Nothing is hardcoded.
 *
 * Operations (sysfs param `rw`, comma separated):
 *   R,pid,addr,size                  read user VA, result in `out`
 *   W,pid,addr,size,value            direct write (modifies memory)
 *   V,pid,addr,size,value            arm hardware-watchpoint substitution:
 *                                    on access, write `value`, then restore
 *                                    the original bytes. Memory appears
 *                                    unmodified; executing code sees value.
 *   U,pid,addr                       disarm watchpoint
 *   H,pid,addr,size,value,period_ms,dir   fixed-Hz hook: every period_ms
 *                                    re-write (dir=W) or read (dir=R) so the
 *                                    value stays pinned. dir is 'R' or 'W'.
 *
 * Diagnosis params: out, status (errno), stage (last step without printk).
 *
 * ARM64 only. Link-time imports: module_layout ONLY.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/workqueue.h>

/* ================= self-contained libc-free helpers ================= */

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

static unsigned long parse_dec(const char *s)
{
	unsigned long v = 0;
	while (*s && *s >= '0' && *s <= '9') {
		v = v * 10 + (*s - '0');
		s++;
	}
	return v;
}

/* ============ runtime-resolved kernel functions (fresh kallsyms) ====== */

typedef struct task_struct *(*find_task_by_vpid_fn)(pid_t nr);
typedef struct mm_struct *(*get_task_mm_fn)(struct task_struct *task);
typedef void (*mmput_fn)(struct mm_struct *mm);
typedef long (*access_remote_vm_fn)(struct mm_struct *mm,
				    unsigned long addr, void *buf, size_t len,
				    unsigned int flags);
typedef struct perf_event *__percpu *(*reg_wide_fn)(
	struct perf_event_attr *attr,
	void (*triggered)(struct perf_event *, struct perf_sample_data *,
			  struct pt_regs *),
	void *context);
typedef void (*unreg_wide_fn)(struct perf_event *__percpu *cpu_events);
typedef bool (*schedule_delayed_work_fn)(struct delayed_work *dwork,
					 unsigned long delay);
typedef bool (*cancel_delayed_work_sync_fn)(struct delayed_work *dwork);

static unsigned long g_find_task_by_vpid;
static unsigned long g_get_task_mm;
static unsigned long g_mmput;
static unsigned long g_access_remote_vm;
static unsigned long g_reg_wide;
static unsigned long g_unreg_wide;
static unsigned long g_sched_dwork;
static unsigned long g_cancel_dwork;

#define FOLL_WRITE 0x01

#define SFN(t, p, s) ((t)(p))

static int lxgr_ptrs_ok(void)
{
	return g_find_task_by_vpid && g_get_task_mm &&
	       g_mmput && g_access_remote_vm;
}

/* ================= direct READ / WRITE ================================ */

static long rw_read_custom(int pid, unsigned long addr, unsigned long size,
			   unsigned long *value)
{
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long tmp = 0;
	long rc;

	if (!lxgr_ptrs_ok())
		return -EINVAL;

	task = SFN(find_task_by_vpid_fn, g_find_task_by_vpid, pid);
	if (!task)
		return -ESRCH;
	mm = SFN(get_task_mm_fn, g_get_task_mm, task);
	if (!mm)
		return -EACCES;

	rc = SFN(access_remote_vm_fn, g_access_remote_vm)(mm, addr, &tmp, size,
							  0);
	SFN(mmput_fn, g_mmput)(mm);
	if (rc != (long)size)
		return -EFAULT;

	*value = tmp;
	return 0;
}

static long rw_write_direct(int pid, unsigned long addr, unsigned long size,
			    unsigned long value)
{
	struct task_struct *task;
	struct mm_struct *mm;
	long rc;

	if (!lxgr_ptrs_ok())
		return -EINVAL;

	task = SFN(find_task_by_vpid_fn, g_find_task_by_vpid, pid);
	if (!task)
		return -ESRCH;
	mm = SFN(get_task_mm_fn, g_get_task_mm, task);
	if (!mm)
		return -EACCES;

	rc = SFN(access_remote_vm_fn, g_access_remote_vm)(mm, addr, &value,
							  size, FOLL_WRITE);
	SFN(mmput_fn, g_mmput)(mm);
	if (rc != (long)size)
		return -EFAULT;
	return 0;
}

/* ================= watchpoint substitution engine ===================== */

#define MAX_WATCH 8
#define SUBST_RESTORE_MS 5

struct watch_entry {
	unsigned long addr;
	int pid;
	unsigned long size;
	unsigned long value;
	unsigned long orig;
	int active;
	struct perf_event *__percpu *ev;
	struct delayed_work subst_work;
	struct delayed_work restore_work;
};

static struct watch_entry watch_table[MAX_WATCH];

static void watch_restore_work_fn(struct work_struct *work)
{
	struct watch_entry *e;

	e = container_of(work, struct watch_entry, restore_work.work);
	if (!e->active)
		return;
	/* put the original bytes back; memory looks untouched again */
	(void)rw_write_direct(e->pid, e->addr, e->size, e->orig);
}

static void watch_subst_work_fn(struct work_struct *work)
{
	struct watch_entry *e;
	unsigned long orig = 0;

	e = container_of(work, struct watch_entry, subst_work.work);
	if (!e->active)
		return;

	/* snapshot original, write substitute, then schedule a restore */
	if (rw_read_custom(e->pid, e->addr, e->size, &orig) != 0)
		return;
	if (rw_write_direct(e->pid, e->addr, e->size, e->value) != 0)
		return;
	e->orig = orig;

	SFN(schedule_delayed_work_fn, g_sched_dwork)(
		&e->restore_work, msecs_to_jiffies(SUBST_RESTORE_MS));
}

/* perf overflow handler: runs in atomic/debug context, only defers work */
static void watch_handler(struct perf_event *event,
			  struct perf_sample_data *data,
			  struct pt_regs *regs)
{
	int i;
	struct watch_entry *e;

	(void)event;
	(void)data;
	(void)regs;

	for (i = 0; i < MAX_WATCH; i++) {
		e = &watch_table[i];
		if (!e->active)
			continue;
		if (current->pid != e->pid)
			continue;
		SFN(schedule_delayed_work_fn, g_sched_dwork)(
			&e->subst_work, 0);
		break;
	}
}

static long rw_watch(int pid, unsigned long addr, unsigned long size,
		     unsigned long value, int unwatch)
{
	struct perf_event_attr attr;
	struct watch_entry *e;
	int i, free = -1;
	long rc;

	if (unwatch) {
		for (i = 0; i < MAX_WATCH; i++) {
			e = &watch_table[i];
			if (e->active && e->addr == addr && e->pid == pid) {
				e->active = 0;
				SFN(cancel_delayed_work_sync_fn, g_cancel_dwork)(
					&e->subst_work);
				SFN(cancel_delayed_work_sync_fn, g_cancel_dwork)(
					&e->restore_work);
				if (e->ev) {
					SFN(unreg_wide_fn, g_unreg_wide)(e->ev);
					e->ev = NULL;
				}
				return 0;
			}
		}
		return -ENOENT;
	}

	if (!lxgr_ptrs_ok() || !g_reg_wide || !g_unreg_wide ||
	    !g_sched_dwork || !g_cancel_dwork)
		return -EINVAL;

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

	e->ev = SFN(reg_wide_fn, g_reg_wide)(&attr, watch_handler, NULL);
	if (IS_ERR(e->ev)) {
		rc = (long)PTR_ERR(e->ev);
		e->ev = NULL;
		return rc;
	}

	e->addr = addr;
	e->pid = pid;
	e->size = size;
	e->value = value;
	e->active = 1;
	INIT_DELAYED_WORK(&e->subst_work, watch_subst_work_fn);
	INIT_DELAYED_WORK(&e->restore_work, watch_restore_work_fn);
	return 0;
}

/* ================= fixed-Hz hook ====================================== */

#define MAX_HOOKS 4

struct hook_entry {
	int pid;
	unsigned long addr;
	unsigned long size;
	unsigned long value;
	unsigned long period_ms;
	int dir; /* 'R' or 'W' */
	int active;
	unsigned long ticks;
	struct delayed_work work;
};

static struct hook_entry hook_table[MAX_HOOKS];

static void hook_work_fn(struct work_struct *work)
{
	struct hook_entry *h;
	unsigned long tmp = 0;

	h = container_of(work, struct hook_entry, work.work);
	if (!h->active)
		return;

	if (h->dir == 'W')
		(void)rw_write_direct(h->pid, h->addr, h->size, h->value);
	else
		(void)rw_read_custom(h->pid, h->addr, h->size, &tmp);

	h->ticks++;
	SFN(schedule_delayed_work_fn, g_sched_dwork)(
		&h->work, msecs_to_jiffies(h->period_ms));
}

static long rw_hook(int pid, unsigned long addr, unsigned long size,
		    unsigned long value, unsigned long period_ms,
		    unsigned long dir, int stop)
{
	struct hook_entry *h;
	int i, free = -1;

	if (stop) {
		for (i = 0; i < MAX_HOOKS; i++) {
			h = &hook_table[i];
			if (h->active && h->pid == pid && h->addr == addr) {
				h->active = 0;
				SFN(cancel_delayed_work_sync_fn, g_cancel_dwork)(
					&h->work);
				return 0;
			}
		}
		return -ENOENT;
	}

	if (!lxgr_ptrs_ok() || !g_sched_dwork || !g_cancel_dwork)
		return -EINVAL;
	if (period_ms == 0)
		period_ms = 100;
	if (period_ms > 60000)
		period_ms = 60000;
	if (dir != 'R' && dir != 'W')
		return -EINVAL;

	for (i = 0; i < MAX_HOOKS; i++) {
		if (!hook_table[i].active) {
			free = i;
			break;
		}
	}
	if (free < 0)
		return -ENOSPC;

	h = &hook_table[free];
	h->pid = pid;
	h->addr = addr;
	h->size = size;
	h->value = value;
	h->period_ms = period_ms;
	h->dir = (int)dir;
	h->ticks = 0;
	h->active = 1;
	INIT_DELAYED_WORK(&h->work, hook_work_fn);
	SFN(schedule_delayed_work_fn, g_sched_dwork)(
		&h->work, msecs_to_jiffies(period_ms));
	return 0;
}

/* ================= param set: guaranteed entry point ================== */

static char rw_out[64] = "idle";
static long rw_status = 0;
static char rw_stage[16] = "idle";

#define STAGE(s) lxgr_memcpy(rw_stage, (s), sizeof(s) - 1), \
		rw_stage[sizeof(s) - 1] = 0

static int rw_set(const char *val, const struct kernel_param *kp)
{
	const char *p = val;
	int pid;
	unsigned long addr, size, value;
	unsigned long period = 0, dir = 0;
	char op;
	long r;
	unsigned long readout = 0;

	while (*p == ' ')
		p++;
	if (!*p) {
		rw_status = -EINVAL;
		return 0;
	}

	op = *p++;
	if (*p == ',')
		p++;
	else {
		rw_status = -EINVAL;
		return 0;
	}
	STAGE("parse");

	pid = (int)parse_dec(p);
	while (*p && *p != ',')
		p++;
	if (*p == ',')
		p++;
	else {
		rw_status = -EINVAL;
		return 0;
	}

	addr = parse_hex(p);
	while (*p && *p != ',')
		p++;
	if (*p == ',')
		p++;
	else {
		rw_status = -EINVAL;
		return 0;
	}

	size = parse_dec(p);
	while (*p && *p != ',')
		p++;
	if (*p == ',') {
		p++;
		value = parse_hex(p);
	} else {
		value = 0;
	}

	/* optional extra fields for H op: period_ms, dir */
	if (op == 'H') {
		while (*p && *p != ',')
			p++;
		if (*p == ',') {
			p++;
			period = parse_dec(p);
		}
		while (*p && *p != ',')
			p++;
		if (*p == ',')
			dir = *++p;
	}

	/* ---- strict validation: nothing here may ever crash ---- */
	if (!(op == 'R' || op == 'W' || op == 'V' || op == 'U' || op == 'H'))
		goto bad;
	if (pid <= 0 || pid > 0x7fffffff)
		goto bad;
	if (addr == 0 || addr >= 0x0000800000000000UL)
		goto bad;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		goto bad;
	if (addr + size < addr) /* wraparound */
		goto bad;
	goto ok;
bad:
	rw_status = -EINVAL;
	return 0;
ok:
	switch (op) {
	case 'R':
		STAGE("read");
		r = rw_read_custom(pid, addr, size, &readout);
		break;
	case 'W':
		STAGE("write");
		r = rw_write_direct(pid, addr, size, value);
		break;
	case 'V':
		STAGE("watch");
		r = rw_watch(pid, addr, size, value, 0);
		break;
	case 'U':
		STAGE("unwatch");
		r = rw_watch(pid, addr, size, value, 1);
		break;
	case 'H':
		STAGE("hook");
		r = rw_hook(pid, addr, size, value, period, dir, 0);
		break;
	default:
		r = -EINVAL;
		break;
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

static int rw_stage_get(char *buf, const struct kernel_param *kp)
{
	size_t n = lxgr_strlen(rw_stage);
	lxgr_memcpy(buf, rw_stage, n);
	buf[n] = '\0';
	return (int)n;
}
static const struct kernel_param_ops rw_stage_ops = {
	.get = rw_stage_get,
};
module_param_cb(stage, &rw_stage_ops, NULL, 0444);

/* ---- function-pointer params (custom ops, avoid param_ops_* imports) -- */

static int set_hex_ul(const char *val, unsigned long *store)
{
	*store = parse_hex(val);
	return 0;
}

#define DEF_HEX_PARAM(name, var)                                        \
	static int name##_set(const char *val, const struct kernel_param *kp) \
	{                                                               \
		return set_hex_ul(val, &var);                            \
	}                                                               \
	static const struct kernel_param_ops name##_ops = {             \
		.set = name##_set,                                      \
	};                                                              \
	module_param_cb(name, &name##_ops, NULL, 0444)

DEF_HEX_PARAM(find_task_by_vpid, g_find_task_by_vpid);
DEF_HEX_PARAM(get_task_mm, g_get_task_mm);
DEF_HEX_PARAM(mmput, g_mmput);
DEF_HEX_PARAM(access_remote_vm, g_access_remote_vm);
DEF_HEX_PARAM(register_wide_hw_breakpoint, g_reg_wide);
DEF_HEX_PARAM(unregister_wide_hw_breakpoint, g_unreg_wide);
DEF_HEX_PARAM(schedule_delayed_work, g_sched_dwork);
DEF_HEX_PARAM(cancel_delayed_work_sync, g_cancel_dwork);

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
MODULE_DESCRIPTION("R/W + watchpoint substitution + fixed-Hz hook bridge");
