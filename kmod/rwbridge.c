// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - memory R/W / substitution bridge for ARM64 Android kernels.
 *
 * Everything runs in kernel mode. No kernel symbol is linked: all kernel
 * functions are resolved FRESH from /proc/kallsyms by the loader on every
 * insmod (kernel is KASLR re-based after reboot, stale addresses = panic).
 * Nothing is hardcoded. Link-time imports: module_layout ONLY.
 *
 * A single worker kthread (created lazily on first V/H) does all periodic
 * work in process context: watchpoint substitute+restore and fixed-Hz
 * hooks. The atomic perf handler only flags fired watchpoints.
 *
 * Operations (sysfs param `rw`, comma separated):
 *   R,pid,addr,size                  read user VA, result in `out`
 *   W,pid,addr,size,value            direct write (modifies memory)
 *   V,pid,addr,size,value            arm watchpoint substitution:
 *                                    on access, write value, restore orig
 *                                    after SUBST_RESTORE_MS. Memory appears
 *                                    untouched; executing code sees value.
 *   U,pid,addr[,size]                disarm watchpoint (size optional)
 *   H,pid,addr,size,value,period_ms,dir  fixed-Hz hook: every period_ms
 *                                    re-write (dir=W) or re-read (dir=R).
 *   X,pid,addr                       stop a hook
 *
 * Diagnosis params: out, status (errno), stage (last step without printk).
 *
 * ARM64 only. BTI required (-mbranch-protection=standard).
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kthread.h>
#include <linux/delay.h>

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
typedef struct task_struct *(*kthread_create_fn)(int (*threadfn)(void *),
						 void *data, int node,
						 const char *namefmt, ...);
typedef int (*wake_up_process_fn)(struct task_struct *tsk);
typedef int (*kthread_should_stop_fn)(void);
typedef int (*kthread_stop_fn)(struct task_struct *tsk);
typedef void (*msleep_fn)(unsigned int msecs);

static unsigned long g_find_task_by_vpid;
static unsigned long g_get_task_mm;
static unsigned long g_mmput;
static unsigned long g_access_remote_vm;
static unsigned long g_reg_wide;
static unsigned long g_unreg_wide;
static unsigned long g_kthread_create;
static unsigned long g_wake_up_process;
static unsigned long g_kthread_should_stop;
static unsigned long g_kthread_stop;
static unsigned long g_msleep;

#define FOLL_WRITE 0x01

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

	task = ((find_task_by_vpid_fn)g_find_task_by_vpid)(pid);
	if (!task)
		return -ESRCH;
	mm = ((get_task_mm_fn)g_get_task_mm)(task);
	if (!mm)
		return -EACCES;

	rc = ((access_remote_vm_fn)g_access_remote_vm)(mm, addr, &tmp, size, 0);
	((mmput_fn)g_mmput)(mm);
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

	task = ((find_task_by_vpid_fn)g_find_task_by_vpid)(pid);
	if (!task)
		return -ESRCH;
	mm = ((get_task_mm_fn)g_get_task_mm)(task);
	if (!mm)
		return -EACCES;

	rc = ((access_remote_vm_fn)g_access_remote_vm)(mm, addr, &value, size,
						       FOLL_WRITE);
	((mmput_fn)g_mmput)(mm);
	if (rc != (long)size)
		return -EFAULT;
	return 0;
}

/* ================= watchpoint substitution engine ===================== */

#define MAX_WATCH 8
#define MAX_HOOKS 4
#define WORKER_TICK_MS 5
#define SUBST_RESTORE_MS 15

struct watch_entry {
	unsigned long addr;
	int pid;
	unsigned long size;
	unsigned long value;
	unsigned long orig;
	int active;
	int reserved;		/* slot reserved mid-arm; worker skips */
	int fired;		/* set by atomic handler */
	int substituted;	/* currently substituted, restore pending */
	int restore_in;		/* ticks until restore */
	struct perf_event *__percpu *ev;
};

static struct watch_entry watch_table[MAX_WATCH];

struct hook_entry {
	int pid;
	unsigned long addr;
	unsigned long size;
	unsigned long value;
	unsigned long period_ms;
	int dir; /* 'R' or 'W' */
	int active;
	unsigned long next_tick; /* ticks until next run */
};

static struct hook_entry hook_table[MAX_HOOKS];

static struct task_struct *g_worker;
static int g_exiting;

/* Self-contained spinlock: inline LL/SC asm only, so no kernel symbol or
 * libgcc outline-atomic helper (__aarch64_cas4_sync etc.) is imported.
 * ldaxr/stlxr/stlr are ARMv8.0 base instructions.
 */
static int g_lock;

static int lxgr_cas(int *ptr, int old, int new)
{
	int val;
	unsigned long status;

	asm volatile(
		"1:	ldaxr	%w0, [%2]\n"
		"	cmp	%w0, %w3\n"
		"	b.ne	2f\n"
		"	stlxr	%w1, %w4, [%2]\n"
		"	cbnz	%w1, 1b\n"
		"2:"
		: "=&r" (val), "=&r" (status)
		: "r" (ptr), "r" (old), "r" (new)
		: "cc", "memory");
	return val;
}

static void lxgr_lock(void)
{
	while (lxgr_cas(&g_lock, 0, 1) != 0)
		cpu_relax();
}

static void lxgr_unlock(void)
{
	asm volatile("stlr	wzr, [%0]" : : "r" (&g_lock) : "memory");
}

/* atomic perf overflow handler: only flags the matching watchpoint */
static void watch_handler(struct perf_event *event,
			  struct perf_sample_data *data,
			  struct pt_regs *regs)
{
	int i;
	struct watch_entry *e;
	unsigned long addr;

	(void)data;
	(void)regs;

	if (!event)
		return;
	addr = event->attr.bp_addr;

	for (i = 0; i < MAX_WATCH; i++) {
		e = &watch_table[i];
		if (!READ_ONCE(e->active))
			continue;
		if (READ_ONCE(e->addr) != addr)
			continue;
		/* match process via tgid (threads of same proc share it) */
		if (current->tgid != READ_ONCE(e->pid))
			continue;
		WRITE_ONCE(e->fired, 1);
		break;
	}
}

static void worker_tick(void)
{
	int i;
	struct hook_entry *h;
	unsigned long tmp = 0;

	if (READ_ONCE(g_exiting))
		return;

	/* process fired watchpoints */
	for (i = 0; i < MAX_WATCH; i++) {
		struct watch_entry *e = &watch_table[i];
		int pid, fired, substituted;
		unsigned long addr, size, value, orig, restore_in;

		/* snapshot the whole entry under the lock so we never do I/O
		 * with a torn view (arm/unwatch can rewrite fields) */
		lxgr_lock();
		if (!READ_ONCE(e->active)) {
			lxgr_unlock();
			continue;
		}
		pid = e->pid;
		addr = e->addr;
		size = e->size;
		value = e->value;
		orig = e->orig;
		substituted = e->substituted;
		fired = READ_ONCE(e->fired);
		restore_in = e->restore_in;
		lxgr_unlock();

		if (substituted) {
			/* count down the restore window */
			if (restore_in > 0) {
				restore_in--;
				lxgr_lock();
				if (READ_ONCE(e->active) &&
				    e->pid == pid && e->addr == addr)
					e->restore_in = restore_in;
				lxgr_unlock();
				continue;
			}
			/* window elapsed: put orig back first */
			(void)rw_write_direct(pid, addr, size, orig);
			/* if a hit landed while substituted, immediately
			 * re-substitute so executors keep seeing value */
			if (fired) {
				WRITE_ONCE(e->fired, 0);
				if (rw_write_direct(pid, addr, size,
						    value) == 0) {
					lxgr_lock();
					if (READ_ONCE(e->active) &&
					    e->pid == pid && e->addr == addr) {
						e->substituted = 1;
						e->restore_in =
							SUBST_RESTORE_MS /
							WORKER_TICK_MS;
					}
					lxgr_unlock();
				} else {
					lxgr_lock();
					if (READ_ONCE(e->active) &&
					    e->pid == pid && e->addr == addr)
						e->substituted = 0;
					lxgr_unlock();
				}
			} else {
				lxgr_lock();
				if (READ_ONCE(e->active) &&
				    e->pid == pid && e->addr == addr)
					e->substituted = 0;
				lxgr_unlock();
			}
		} else if (fired) {
			WRITE_ONCE(e->fired, 0);
			if (rw_read_custom(pid, addr, size, &orig) == 0 &&
			    rw_write_direct(pid, addr, size, value) == 0) {
				lxgr_lock();
				if (READ_ONCE(e->active) &&
				    e->pid == pid && e->addr == addr) {
					e->orig = orig;
					e->substituted = 1;
					e->restore_in = SUBST_RESTORE_MS /
							WORKER_TICK_MS;
				}
				lxgr_unlock();
			}
		}
	}

	/* fixed-Hz hooks */
	for (i = 0; i < MAX_HOOKS; i++) {
		int pid, dir;
		unsigned long addr, size, value, period;

		lxgr_lock();
		h = &hook_table[i];
		if (!READ_ONCE(h->active)) {
			lxgr_unlock();
			continue;
		}
		pid = h->pid;
		addr = h->addr;
		size = h->size;
		value = h->value;
		period = h->period_ms;
		dir = h->dir;
		lxgr_unlock();

		if (READ_ONCE(h->next_tick) > 0) {
			WRITE_ONCE(h->next_tick, h->next_tick - 1);
			continue;
		}
		if (dir == 'W')
			(void)rw_write_direct(pid, addr, size, value);
		else
			(void)rw_read_custom(pid, addr, size, &tmp);
		WRITE_ONCE(h->next_tick, period / WORKER_TICK_MS);
	}
}

static int lxgr_worker_fn(void *data)
{
	(void)data;
	while (!((kthread_should_stop_fn)g_kthread_should_stop)()) {
		worker_tick();
		((msleep_fn)g_msleep)(WORKER_TICK_MS);
	}
	return 0;
}

static int lxgr_ensure_worker(void)
{
	struct task_struct *t;

	if (!g_kthread_create || !g_wake_up_process ||
	    !g_kthread_should_stop || !g_kthread_stop || !g_msleep)
		return -EINVAL;

	lxgr_lock();
	if (READ_ONCE(g_exiting)) {
		lxgr_unlock();
		return -ESHUTDOWN;
	}
	if (g_worker) {
		lxgr_unlock();
		return 0;
	}
	lxgr_unlock();

	t = ((kthread_create_fn)g_kthread_create)(lxgr_worker_fn, NULL,
						  -1, "lxgrw");
	if (IS_ERR(t))
		return (long)PTR_ERR(t);

	/* assign BEFORE wake so teardown never sees a running worker with
	 * g_worker == NULL and skips kthread_stop */
	lxgr_lock();
	if (READ_ONCE(g_exiting)) {
		lxgr_unlock();
		((kthread_stop_fn)g_kthread_stop)(t);
		return -ESHUTDOWN;
	}
	if (g_worker) {		/* lost the creation race */
		lxgr_unlock();
		((kthread_stop_fn)g_kthread_stop)(t);
		return 0;
	}
	g_worker = t;
	lxgr_unlock();

	((wake_up_process_fn)g_wake_up_process)(t);
	return 0;
}

static long rw_watch(int pid, unsigned long addr, unsigned long size,
		     unsigned long value, int unwatch)
{
	struct perf_event_attr attr;
	struct watch_entry *e = NULL;
	int i, free = -1;
	long rc;
	struct perf_event *__percpu *ev;

	if (unwatch) {
		int upid;
		unsigned long uaddr, usize, uorig;
		int need_restore = 0;

		if (READ_ONCE(g_exiting))
			return -ESHUTDOWN;
		if (!g_unreg_wide)
			return -EINVAL;
		lxgr_lock();
		for (i = 0; i < MAX_WATCH; i++) {
			e = &watch_table[i];
			if (READ_ONCE(e->active) && e->addr == addr &&
			    e->pid == pid) {
				/* snapshot any live substitution so the target
				 * memory goes back to orig after we detach */
				upid = e->pid;
				uaddr = e->addr;
				usize = e->size;
				uorig = e->orig;
				need_restore = e->substituted;
				WRITE_ONCE(e->active, 0);
				WRITE_ONCE(e->reserved, 0);
				WRITE_ONCE(e->fired, 0);
				WRITE_ONCE(e->substituted, 0);
				ev = e->ev;
				WRITE_ONCE(e->ev, NULL);
				lxgr_unlock();
				if (ev)
					((unreg_wide_fn)g_unreg_wide)(ev);
				if (need_restore)
					(void)rw_write_direct(upid, uaddr,
							      usize, uorig);
				return 0;
			}
		}
		lxgr_unlock();
		return -ENOENT;
	}

	if (!lxgr_ptrs_ok() || !g_reg_wide || !g_unreg_wide)
		return -EINVAL;
	if (READ_ONCE(g_exiting))
		return -ESHUTDOWN;
	rc = lxgr_ensure_worker();
	if (rc)
		return rc;

	lxgr_lock();
	/* reject duplicate pid+addr: two armed events would each restore
	 * their own stale orig and corrupt the memory (check reserved too,
	 * since an in-flight arm already owns the slot) */
	for (i = 0; i < MAX_WATCH; i++) {
		e = &watch_table[i];
		if ((READ_ONCE(e->active) || READ_ONCE(e->reserved)) &&
		    e->addr == addr && e->pid == pid) {
			lxgr_unlock();
			return -EEXIST;
		}
	}
	for (i = 0; i < MAX_WATCH; i++) {
		if (!READ_ONCE(watch_table[i].active) &&
		    !READ_ONCE(watch_table[i].reserved)) {
			free = i;
			break;
		}
	}
	if (free < 0) {
		lxgr_unlock();
		return -ENOSPC;
	}

	e = &watch_table[free];
	lxgr_memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_type = HW_BREAKPOINT_RW;
	attr.bp_addr = addr;
	switch (size) {
	case 1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
	case 2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
	case 4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
	case 8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
	default: lxgr_unlock(); return -EINVAL;
	}
	attr.pinned = 1;

	/* reserve + fill BEFORE arming so handler/worker never see garbage;
	 * worker skips reserved entries (active still 0) */
	e->addr = addr;
	e->pid = pid;
	e->size = size;
	e->value = value;
	e->orig = 0;
	WRITE_ONCE(e->fired, 0);
	WRITE_ONCE(e->substituted, 0);
	e->restore_in = 0;
	WRITE_ONCE(e->reserved, 1);
	lxgr_unlock();

	ev = ((reg_wide_fn)g_reg_wide)(&attr, watch_handler, NULL);
	if (IS_ERR(ev)) {
		rc = (long)PTR_ERR(ev);
		lxgr_lock();
		WRITE_ONCE(e->reserved, 0);
		lxgr_unlock();
		return rc;
	}

	lxgr_lock();
	WRITE_ONCE(e->ev, ev);
	WRITE_ONCE(e->reserved, 0);
	WRITE_ONCE(e->active, 1);
	lxgr_unlock();
	return 0;
}

/* ================= fixed-Hz hook ====================================== */

static long rw_hook(int pid, unsigned long addr, unsigned long size,
		    unsigned long value, unsigned long period_ms,
		    unsigned long dir, int stop)
{
	struct hook_entry *h;
	int i, free = -1;
	long rc;

	if (stop) {
		if (READ_ONCE(g_exiting))
			return -ESHUTDOWN;
		lxgr_lock();
		for (i = 0; i < MAX_HOOKS; i++) {
			h = &hook_table[i];
			if (h->active && h->pid == pid && h->addr == addr) {
				WRITE_ONCE(h->active, 0);
				lxgr_unlock();
				return 0;
			}
		}
		lxgr_unlock();
		return -ENOENT;
	}

	if (!lxgr_ptrs_ok())
		return -EINVAL;
	if (READ_ONCE(g_exiting))
		return -ESHUTDOWN;
	if (period_ms == 0)
		period_ms = 100;
	if (period_ms > 60000)
		period_ms = 60000;
	if (dir != 'R' && dir != 'W')
		return -EINVAL;
	rc = lxgr_ensure_worker();
	if (rc)
		return rc;

	lxgr_lock();
	for (i = 0; i < MAX_HOOKS; i++) {
		if (!READ_ONCE(hook_table[i].active)) {
			free = i;
			break;
		}
	}
	if (free < 0) {
		lxgr_unlock();
		return -ENOSPC;
	}

	h = &hook_table[free];
	h->pid = pid;
	h->addr = addr;
	h->size = size;
	h->value = value;
	h->period_ms = period_ms;
	h->dir = (int)dir;
	h->next_tick = 0;
	WRITE_ONCE(h->active, 1);
	lxgr_unlock();
	return 0;
}

static void rw_teardown(void)
{
	int i;
	struct watch_entry *e;
	struct task_struct *worker;
	struct perf_event *__percpu *evs[MAX_WATCH];

	WRITE_ONCE(g_exiting, 1);

	/* stop the worker FIRST: kthread_stop joins it, so after this returns
	 * no code can be touching watch_table/hook_table (worker_tick bails on
	 * g_exiting and kthread_stop wakes it out of msleep). Read g_worker
	 * under the lock so we cannot miss a worker whose g_worker store (in
	 * lxgr_ensure_worker) is still in flight. */
	lxgr_lock();
	worker = g_worker;
	g_worker = NULL;
	lxgr_unlock();
	if (worker && g_kthread_stop)
		((kthread_stop_fn)g_kthread_stop)(worker);

	/* restore any live substitutions so target memory returns to orig */
	for (i = 0; i < MAX_WATCH; i++) {
		e = &watch_table[i];
		if (READ_ONCE(e->active) && e->substituted && e->ev)
			(void)rw_write_direct(e->pid, e->addr, e->size,
					      e->orig);
	}

	lxgr_lock();
	for (i = 0; i < MAX_WATCH; i++) {
		e = &watch_table[i];
		evs[i] = e->ev;
		WRITE_ONCE(e->active, 0);
		WRITE_ONCE(e->reserved, 0);
		WRITE_ONCE(e->fired, 0);
		WRITE_ONCE(e->substituted, 0);
		WRITE_ONCE(e->ev, NULL);
	}
	for (i = 0; i < MAX_HOOKS; i++)
		WRITE_ONCE(hook_table[i].active, 0);
	lxgr_unlock();

	/* unregister perf events outside the lock (may sleep) */
	if (g_unreg_wide) {
		for (i = 0; i < MAX_WATCH; i++)
			if (evs[i])
				((unreg_wide_fn)g_unreg_wide)(evs[i]);
	}
}

/* ================= param set: guaranteed entry point ================== */

static char rw_out[64] = "idle";
static long rw_status = 0;
static char rw_stage[16] = "idle";

#define STAGE(s) lxgr_memcpy(rw_stage, (s), sizeof(s) - 1), \
		rw_stage[sizeof(s) - 1] = 0

/* split next comma field from p into buf; returns field length or -1 */
static int next_field(const char **pp, char *buf, int bufsz)
{
	const char *p = *pp;
	int n = 0;

	while (*p == ' ')
		p++;
	while (*p && *p != ',' && n < bufsz - 1)
		buf[n++] = *p++;
	buf[n] = 0;
	if (*p == ',')
		p++;
	*pp = p;
	return n;
}

static int rw_set(const char *val, const struct kernel_param *kp)
{
	const char *p = val;
	char f[24];
	char op;
	int pid;
	unsigned long addr, size, value, period, dir;
	long r;
	unsigned long readout = 0;

	while (*p == ' ')
		p++;
	if (!*p)
		goto bad;
	op = *p++;
	if (*p == ',')
		p++;
	else
		goto bad;
	STAGE("parse");

	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	pid = (int)parse_dec(f);
	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	addr = parse_hex(f);

	size = 0;
	value = 0;
	period = 0;
	dir = 0;

	if (op != 'U' && op != 'X') {
		if (next_field(&p, f, sizeof(f)) <= 0)
			goto bad;
		size = parse_dec(f);
	}
	if (op == 'W' || op == 'V' || op == 'H') {
		if (next_field(&p, f, sizeof(f)) <= 0)
			goto bad;
		value = parse_hex(f);
	}
	if (op == 'H') {
		if (next_field(&p, f, sizeof(f)) <= 0)
			goto bad;
		period = parse_dec(f);
		if (next_field(&p, f, sizeof(f)) <= 0)
			goto bad;
		dir = f[0];
	}

	/* ---- strict validation: nothing here may ever crash ---- */
	if (!(op == 'R' || op == 'W' || op == 'V' || op == 'U' ||
	      op == 'H' || op == 'X'))
		goto bad;
	if (pid <= 0 || pid > 0x7fffffff)
		goto bad;
	if (addr == 0 || addr >= 0x0000800000000000UL)
		goto bad;
	if (op != 'U' && op != 'X' &&
	    size != 1 && size != 2 && size != 4 && size != 8)
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
	case 'X':
		STAGE("unhook");
		r = rw_hook(pid, addr, size, value, 0, 0, 1);
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
DEF_HEX_PARAM(kthread_create_on_node, g_kthread_create);
DEF_HEX_PARAM(wake_up_process, g_wake_up_process);
DEF_HEX_PARAM(kthread_should_stop, g_kthread_should_stop);
DEF_HEX_PARAM(kthread_stop, g_kthread_stop);
DEF_HEX_PARAM(msleep, g_msleep);

static int __init rwbridge_init(void)
{
	return 0;
}

static void __exit rwbridge_exit(void)
{
	rw_teardown();
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("R/W + watchpoint substitution + fixed-Hz hook bridge");
