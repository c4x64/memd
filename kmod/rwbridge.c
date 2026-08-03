// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - silent memory R/W bridge for ARM64 Android kernels.
 *
 * Minimal design: only READ and WRITE of a target process's user memory via
 * access_remote_vm(). No watchpoints, no perf, no hooks, no kthread. The four
 * kernel functions used (access_remote_vm, find_task_by_vpid, get_task_mm,
 * mmput) are all EXPORT_SYMBOL_GPL fundamentals the kernel itself needs and
 * cannot ship without, so no vendor kernel can remove them.
 *
 * Nothing is linked from the kernel: the four addresses are resolved FRESH
 * from /proc/kallsyms by the loader on every insmod (the kernel is KASLR
 * re-based after reboot, stale addresses = panic). Link-time imports:
 * module_layout ONLY.
 *
 * Operations (sysfs param `rw`, comma separated):
 *   R,pid,addr,size    read user VA, result (16 hex digits) in `out`
 *   W,pid,addr,size,value  write value to user VA (modifies memory)
 *
 * Diagnosis params: out (last read value), status (errno), stage (step).
 *
 * ARM64 only. BTI required (-mbranch-protection=standard).
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/err.h>
#include <linux/time64.h>

/*
 * Serialize every command. The module is a single-slot sysfs interface; two
 * concurrent users (e.g. a stale overlay + the live one) would otherwise
 * interleave rw_buf/rw_status writes and return torn reads. The overlay also
 * serializes, but the module must not rely on that to stay correct.
 *
 * LAYOUT-INDEPENDENCE: this module never dereferences task_struct /
 * thread_info fields and never reads current->pid / comm / preempt_count.
 * Struct offsets (e.g. TSK_TI_PREEMPT, task->flags) differ between kernels and
 * are NOT fixed here — the vendor kernel compiles with CONFIG_ARM64_SW_TTBR0_PAN
 * (preempt_count lives at offset 16, not 8), so any such access would read
 * garbage (it previously read the ttbr0 page-table base as "preempt_count",
 * making the atomic-guard fire on every op and block all reads with -EAGAIN).
 * The only entry point is the sysfs `rw` set callback, which always runs in
 * process context with preemption enabled, so access_remote_vm() (which may
 * sleep) is always legal here. The process-lifetime safety net is the
 * mm == NULL check after get_task_mm(), which is layout-independent.
 */
static DEFINE_MUTEX(rw_mtx);

/* ================= self-contained libc-free helpers ================= */

#define RW_MAX_SIZE 256    /* max bytes per R op (out exposes 2*size hex chars) */

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

/* ================= file logging ======================================= */

#define RW_LOG_PATH "/data/local/tmp/rwbridge.log"

static struct file *rw_log_file;

static void rw_log_open(void)
{
	if (rw_log_file || !g_filp_open || !g_kernel_write)
		return;
	rw_log_file = ((filp_open_fn)g_filp_open)(RW_LOG_PATH,
						   O_WRONLY | O_CREAT | O_APPEND,
						   0644);
	if (IS_ERR(rw_log_file))
		rw_log_file = NULL;
}

static int fmt_hex(char *d, unsigned long v)
{
	char t[16];
	int n = 0, i;

	do {
		t[n++] = "0123456789abcdef"[v & 0xf];
		v >>= 4;
	} while (v);
	for (i = 0; i < n; i++)
		d[i] = t[n - 1 - i];
	return n;
}

static int fmt_dec(char *d, long v)
{
	char t[16];
	int n = 0, i, neg = 0;

	if (v < 0) {
		neg = 1;
		v = -v;
	}
	do {
		t[n++] = '0' + (v % 10);
		v /= 10;
	} while (v);
	if (neg)
		t[n++] = '-';
	for (i = 0; i < n; i++)
		d[i] = t[n - 1 - i];
	return n;
}

/* Append one op record: "<epoch>.<ms> <op> <pid> 0x<addr> <size> => <status>\n".
 * status -1 marks the entry of an op that is about to run (lets us see the
 * last op that entered but never returned if the kernel dies mid-read). */
static void rw_log(const char *op, int pid, unsigned long addr,
		   unsigned long size, long status)
{
	char line[96];
	char *p = line;
	int n = 0;
	struct timespec64 ts;
	unsigned long ms;

	if (!g_kernel_write || !g_ktime_get_real_ts64)
		return;
	((ktime_get_real_ts64_fn)g_ktime_get_real_ts64)(&ts);
	n += fmt_dec(p + n, (long)ts.tv_sec);
	p[n++] = '.';
	ms = (unsigned long)ts.tv_nsec / 1000000UL;
	if (ms < 10)
		p[n++] = '0';
	if (ms < 100)
		p[n++] = '0';
	n += fmt_dec(p + n, (long)ms);
	p[n++] = ' ';
	p[n++] = op[0];
	p[n++] = ' ';
	n += fmt_dec(p + n, pid);
	p[n++] = ' ';
	p[n++] = '0';
	p[n++] = 'x';
	n += fmt_hex(p + n, addr);
	p[n++] = ' ';
	n += fmt_dec(p + n, (long)size);
	p[n++] = ' ';
	p[n++] = '=';
	p[n++] = '>';
	p[n++] = ' ';
	n += fmt_dec(p + n, status);
	p[n++] = '\n';

	rw_log_open();
	if (!rw_log_file)
		return;
	{
		loff_t pos = 0;
		((kernel_write_fn)g_kernel_write)(rw_log_file, line, n, &pos);
	}
}

/* ============ runtime-resolved kernel functions (fresh kallsyms) ====== */
typedef struct task_struct *(*find_task_by_vpid_fn)(pid_t nr);
typedef struct mm_struct *(*get_task_mm_fn)(struct task_struct *task);
typedef void (*mmput_fn)(struct mm_struct *mm);
typedef long (*access_remote_vm_fn)(struct mm_struct *mm,
				    unsigned long addr, void *buf, size_t len,
				    unsigned int flags);

/* Logging to a file (/data/local/tmp/rwbridge.log) so the op trace survives
 * a kernel panic/reboot and does not flood dmesg. Same kallsyms-resolve
 * scheme as the core 4; if any of these is missing the module simply skips
 * logging and keeps working. */
typedef struct file *(*filp_open_fn)(const char *path, int flags, umode_t mode);
typedef ssize_t (*kernel_write_fn)(struct file *file, const void *buf,
				   size_t count, loff_t *pos);
typedef int (*filp_close_fn)(struct file *file, void *owner);
typedef void (*ktime_get_real_ts64_fn)(struct timespec64 *ts);

static unsigned long g_find_task_by_vpid;
static unsigned long g_get_task_mm;
static unsigned long g_mmput;
static unsigned long g_access_remote_vm;
static unsigned long g_filp_open;
static unsigned long g_kernel_write;
static unsigned long g_filp_close;
static unsigned long g_ktime_get_real_ts64;

#define FOLL_WRITE 0x01

static int lxgr_ptrs_ok(void)
{
	return g_find_task_by_vpid && g_get_task_mm &&
	       g_mmput && g_access_remote_vm;
}

/* ================= READ ============================================== */

static long rw_read_custom(int pid, unsigned long addr, unsigned long size,
			   void *buf)
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
		return -ESRCH;    /* dying task / kernel thread: no user mm */

	rc = ((access_remote_vm_fn)g_access_remote_vm)(mm, addr, buf, size, 0);
	((mmput_fn)g_mmput)(mm);
	if (rc != (long)size)
		return -EFAULT;

	return 0;
}

/* ================= WRITE ============================================= */

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
		return -ESRCH;    /* dying task / kernel thread: no user mm */

	rc = ((access_remote_vm_fn)g_access_remote_vm)(mm, addr, &value, size,
						       FOLL_WRITE);
	((mmput_fn)g_mmput)(mm);
	if (rc != (long)size)
		return -EFAULT;
	return 0;
}

/* ================= param set: guaranteed entry point ================== */

static unsigned char rw_buf[RW_MAX_SIZE];
static long rw_last_size = 0;    /* bytes produced by the last R op */
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
	unsigned long addr, size, value;
	long r;

	(void)kp;
	mutex_lock(&rw_mtx);
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

	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	size = parse_dec(f);
	if (op == 'W') {
		if (next_field(&p, f, sizeof(f)) <= 0)
			goto bad;
		value = parse_hex(f);
	}

	/* ---- strict validation: nothing here may ever crash ---- */
	if (!(op == 'R' || op == 'W'))
		goto bad;
	if (pid <= 0 || pid > 0x7fffffff)
		goto bad;
	if (addr == 0 || addr >= 0x0000800000000000UL)
		goto bad;
	if (size < 1 || size > RW_MAX_SIZE)
		goto bad;
	if (op == 'W' && size != 1 && size != 2 && size != 4 && size != 8)
		goto bad;              /* writes stay single small values */
	if (addr + size < addr) /* wraparound */
		goto bad;
	goto ok;
bad:
	rw_status = -EINVAL;
	rw_last_size = 0;
	mutex_unlock(&rw_mtx);
	return 0;
ok:
	rw_log(op == 'R' ? "R" : "W", pid, addr, size, -1);
	switch (op) {
	case 'R':
		STAGE("read");
		r = rw_read_custom(pid, addr, size, rw_buf);
		break;
	case 'W':
		STAGE("write");
		r = rw_write_direct(pid, addr, size, value);
		break;
	default:
		r = -EINVAL;
		break;
	}
	rw_log(op == 'R' ? "R" : "W", pid, addr, size, r);

	if (r == 0 && op == 'R') {
		rw_last_size = (long)size;
		rw_status = 0;
	} else if (r == 0) {
		rw_last_size = 0;
		rw_status = 0;
	} else {
		rw_status = r;
		rw_last_size = 0;
	}
	mutex_unlock(&rw_mtx);
	return 0;
}

static const struct kernel_param_ops rw_param_ops = {
	.set = rw_set,
};
module_param_cb(rw, &rw_param_ops, NULL, 0200);

static int rw_out_get(char *buf, const struct kernel_param *kp)
{
	int i, n = 0;
	long s;
	static const char hx[] = "0123456789abcdef";

	(void)kp;
	mutex_lock(&rw_mtx);
	s = rw_last_size;
	if (s <= 0) {
		buf[0] = '\0';
		mutex_unlock(&rw_mtx);
		return 0;
	}
	if (s > RW_MAX_SIZE)
		s = RW_MAX_SIZE;
	for (i = 0; i < s; i++) {
		buf[n++] = hx[(rw_buf[i] >> 4) & 0xf];
		buf[n++] = hx[rw_buf[i] & 0xf];
	}
	buf[n] = '\0';
	mutex_unlock(&rw_mtx);
	return n;
}
static const struct kernel_param_ops rw_out_ops = {
	.get = rw_out_get,
};
module_param_cb(out, &rw_out_ops, NULL, 0444);

static int rw_status_get(char *buf, const struct kernel_param *kp)
{
	long v = rw_status;
	char tmp[24];
	int i = 23;
	int neg = 0;

	if (v < 0) {
		neg = 1;
		v = -v;
	}
	tmp[23] = 0;
	do {
		tmp[--i] = '0' + (v % 10);
		v /= 10;
	} while (v && i > 0);
	if (neg)
		tmp[--i] = '-';
	neg = 24 - i;
	lxgr_memcpy(buf, tmp + i, neg);
	buf[neg] = 0;
	return neg;
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
		(void)kp;                                               \
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
DEF_HEX_PARAM(filp_open, g_filp_open);
DEF_HEX_PARAM(kernel_write, g_kernel_write);
DEF_HEX_PARAM(filp_close, g_filp_close);
DEF_HEX_PARAM(ktime_get_real_ts64, g_ktime_get_real_ts64);

static int __init rwbridge_init(void)
{
	rw_log_open();
	rw_log("L", 0, 0, 0, 0);
	return 0;
}

static void __exit rwbridge_exit(void)
{
	if (rw_log_file && g_filp_close)
		((filp_close_fn)g_filp_close)(rw_log_file, NULL);
	rw_log_file = NULL;
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("Silent R/W bridge via access_remote_vm");
