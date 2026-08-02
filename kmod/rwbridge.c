// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for ARM64 Android kernels.
 *
 * Philosophy: expect nothing from the kernel. No exported kernel symbol is
 * ever called, no ioctl, no proc/fs hook. Everything is driven through
 * module-param sysfs entries, and every piece of kernel memory we touch is
 * read/written through our OWN exception-table fault handlers so that a bad
 * address returns an error instead of a kernel oops/panic.
 *
 * READ / WRITE (direct): manual page-table walk. We start from init_task
 * (address passed as a param), walk the process list until pid matches,
 * read the task's mm->pgd, walk pgd/pud/pmd/pte ourselves, translate the
 * user VA to a physical address, then access it through the linear map.
 * No access_remote_vm / get_user_pages / process_vm_* involved.
 *
 * The layout constants (init_task, task_struct offsets, mm_struct offsets,
 * linear-map base, VA bits) are passed as module params because this is a
 * vendor kernel whose config is unknown. Wrong offsets fail cleanly via the
 * fault handlers - they never panic.
 *
 * Interface (sysfs params):
 *   init_task  - address of init_task (from /proc/kallsyms)
 *   page_offset- linear-map base (0xffff800000000000 for 48-bit VA,
 *                0xffffffc000000000 for 39-bit VA)
 *   memstart   - PHYS_OFFSET / memstart_addr (0 if RAM starts at phys 0)
 *   va_bits    - number of VA bits (48 or 39)
 *   off_pid    - task_struct offset of pid
 *   off_tasks  - task_struct offset of tasks (list_head)
 *   off_mm     - task_struct offset of mm
 *   off_pgd    - mm_struct offset of pgd
 *   rw         - "R,pid,addr,size" read | "W,pid,addr,size,value" write
 *              | "V,..." watchpoint (not yet, returns -EOPNOTSUPP)
 *   out        - last read result as hex string
 *   status     - last status (0 ok, <0 errno)
 *
 * ARM64 only. Build: ccflags-y += -mbranch-protection=standard (BTI),
 * -fno-stack-protector -fno-builtin.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/version.h>

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

/* ================= crash handlers: fault-safe kernel memory =================
 * Every access to kernel memory goes through these. If the address faults,
 * the CPU exception table (the __ex_table section we emit below) redirects
 * execution to the fixup label, which sets rc=1 - we return an error to
 * userspace instead of oopsing the kernel.
 */

static long lxgr_probe_read(void *dst, const void *src, size_t n)
{
	long rc = 0;
	char *d = dst;
	const char *s = src;
	unsigned long rem = n;
	char tmp;

	if (!n)
		return 0;
	asm volatile(
		"	mov %0, #0\n"
		"1:	ldrb %w3, [%1], #1\n"
		"	strb %w3, [%2], #1\n"
		"	subs %4, %4, #1\n"
		"	b.ne	1b\n"
		"	b	3f\n"
		"2:	mov %0, #1\n"
		"3:\n"
		".pushsection __ex_table,\"a\"\n"
		"	.align 3\n"
		"	.long (1b - .), (2b - .)\n"
		".popsection\n"
		: "=&r"(rc), "+r"(s), "+r"(d), "=&r"(tmp), "+r"(rem)
		:
		: "memory");
	return rc ? -EFAULT : 0;
}

static long lxgr_probe_write(void *dst, const void *src, size_t n)
{
	long rc = 0;
	char *d = dst;
	const char *s = src;
	unsigned long rem = n;
	char tmp;

	if (!n)
		return 0;
	asm volatile(
		"	mov %0, #0\n"
		"1:	ldrb %w3, [%1], #1\n"
		"	strb %w3, [%2], #1\n"
		"	subs %4, %4, #1\n"
		"	b.ne	1b\n"
		"	b	3f\n"
		"2:	mov %0, #1\n"
		"3:\n"
		".pushsection __ex_table,\"a\"\n"
		"	.align 3\n"
		"	.long (1b - .), (2b - .)\n"
		".popsection\n"
		: "=&r"(rc), "+r"(s), "+r"(d), "=&r"(tmp), "+r"(rem)
		:
		: "memory");
	return rc ? -EFAULT : 0;
}

static long lxgr_read_u32(unsigned long addr, unsigned int *v)
{
	return lxgr_probe_read(v, (const void *)addr, 4);
}

static long lxgr_read_u64(unsigned long addr, unsigned long *v)
{
	return lxgr_probe_read(v, (const void *)addr, 8);
}

/* ================= layout params (vendor kernel, must be provided) ===== */

static unsigned long g_init_task;
static unsigned long g_page_offset;
static unsigned long g_memstart;
static unsigned int g_va_bits = 48;
static unsigned long g_off_pid;
static unsigned long g_off_tasks;
static unsigned long g_off_mm;
static unsigned long g_off_pgd;

static int lxgr_config_ok(void)
{
	return g_init_task && g_page_offset && g_off_tasks &&
	       g_off_mm && g_off_pgd &&
	       (g_va_bits == 48 || g_va_bits == 39);
}

/* ================= process lookup via manual task-list walk =========== */

static char rw_out[64] = "idle";
static long rw_status = 0;
static char rw_stage[16] = "idle";

#define STAGE(s) lxgr_memcpy(rw_stage, (s), sizeof(s) - 1), \
		rw_stage[sizeof(s) - 1] = 0

static long lxgr_find_mm(int pid, unsigned long *mm)
{
	unsigned long cur, next, task;
	unsigned long limit = 0x10000;
	unsigned int pidv;

	if (!lxgr_config_ok())
		return -EINVAL;

	STAGE("tasks");
	/* init_task.tasks is a list_head at g_init_task + g_off_tasks */
	cur = g_init_task + g_off_tasks;
	if (lxgr_read_u64(cur, &next))
		return -EFAULT;

	while (next != cur && limit--) {
		task = next - g_off_tasks; /* container_of(list_head) */

		if (lxgr_read_u32(task + g_off_pid, &pidv))
			return -EFAULT;
		if (pidv == (unsigned int)pid) {
			STAGE("mm");
			if (lxgr_read_u64(task + g_off_mm, mm))
				return -EFAULT;
			if (!*mm)
				return -ESRCH;
			return 0;
		}
		if (lxgr_read_u64(task + g_off_tasks, &next))
			return -EFAULT;
	}
	return -ESRCH;
}

/* ================= manual page-table walk ============================== */

#define LXGR_PHYS_MASK 0x0000fffffffff000UL

/* translate a user VA to a physical address using the given pgd */
static long lxgr_virt_to_phys(unsigned long pgd_base, unsigned long addr,
			      unsigned long *phys)
{
	unsigned long cur = pgd_base;
	unsigned long pte;
	int levels, i;

	if (addr >= 0x0000800000000000UL)
		return -EINVAL;

	levels = (int)((g_va_bits - 12) / 9); /* 48 -> 4, 39 -> 3 */
	if (levels < 2 || levels > 4)
		return -EINVAL;

	for (i = 0; i < levels; i++) {
		unsigned long shift = 12 + 9UL * (levels - 1 - i);
		unsigned long idx = (addr >> shift) & 0x1ff;

		if (lxgr_read_u64(cur + idx * 8, &pte))
			return -EFAULT;
		if (!(pte & 0x1)) /* not present */
			return -ENOENT;
		if (i == levels - 1) { /* leaf (PTE/page) */
			*phys = (pte & LXGR_PHYS_MASK) | (addr & 0xfff);
			return 0;
		}
		if ((pte & 0x3) == 0x1) { /* block mapping (section/huge) */
			*phys = (pte & LXGR_PHYS_MASK) |
				(addr & ((1UL << shift) - 1));
			return 0;
		}
		cur = pte & LXGR_PHYS_MASK; /* next-level table */
	}
	return -EFAULT;
}

/* physical -> linear-map virtual */
static unsigned long lxgr_phys_to_virt(unsigned long phys)
{
	return phys + (g_page_offset - g_memstart);
}

/* ================= READ =============================================== */

static long rw_read_custom(int pid, unsigned long addr, unsigned long size,
			   unsigned long *value)
{
	unsigned long mm, pgd, phys, kva;
	unsigned long tmp = 0;
	long rc;

	rc = lxgr_find_mm(pid, &mm);
	if (rc)
		return rc;
	if (lxgr_read_u64(mm + g_off_pgd, &pgd))
		return -EFAULT;
	if (!pgd)
		return -EFAULT;

	STAGE("walk");
	rc = lxgr_virt_to_phys(pgd, addr, &phys);
	if (rc)
		return rc;

	kva = lxgr_phys_to_virt(phys);
	STAGE("copy");
	rc = lxgr_probe_read(&tmp, (const void *)kva, size);
	if (rc)
		return rc;

	STAGE("done");
	*value = tmp;
	return 0;
}

/* ================= WRITE ============================================== */

static long rw_write_direct(int pid, unsigned long addr, unsigned long size,
			    unsigned long value)
{
	unsigned long mm, pgd, phys, kva;
	long rc;

	rc = lxgr_find_mm(pid, &mm);
	if (rc)
		return rc;
	if (lxgr_read_u64(mm + g_off_pgd, &pgd))
		return -EFAULT;
	if (!pgd)
		return -EFAULT;

	STAGE("walk");
	rc = lxgr_virt_to_phys(pgd, addr, &phys);
	if (rc)
		return rc;

	kva = lxgr_phys_to_virt(phys);
	STAGE("copy");
	rc = lxgr_probe_write((void *)kva, &value, size);
	if (rc)
		return rc;
	STAGE("done");
	return 0;
}

/* watchpoint write: requires direct DBG register programming on ARM64.
 * Not implemented yet - fail cleanly instead of importing perf symbols. */
static long rw_watch(int pid, unsigned long addr, unsigned long size,
		     unsigned long value, int unwatch)
{
	(void)pid;
	(void)addr;
	(void)size;
	(void)value;
	(void)unwatch;
	return -EOPNOTSUPP;
}

/* ================= param set: the guaranteed entry point ============== */

static int rw_set(const char *val, const struct kernel_param *kp)
{
	const char *p = val;
	int pid;
	unsigned long addr, size, value;
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

	/* ---- strict validation: nothing here may ever crash ---- */
	if (!(op == 'R' || op == 'W' || op == 'V' || op == 'U')) {
		rw_status = -EINVAL;
		return 0;
	}
	if (pid <= 0 || pid > 0x7fffffff) {
		rw_status = -EINVAL;
		return 0;
	}
	if (addr == 0 || addr >= 0x0000800000000000UL) {
		rw_status = -EINVAL;
		return 0;
	}
	if (size != 1 && size != 2 && size != 4 && size != 8) {
		rw_status = -EINVAL;
		return 0;
	}
	if (addr + size < addr) { /* wraparound */
		rw_status = -EINVAL;
		return 0;
	}

	switch (op) {
	case 'R':
		r = rw_read_custom(pid, addr, size, &readout);
		break;
	case 'W':
		r = rw_write_direct(pid, addr, size, value);
		break;
	case 'V':
		r = rw_watch(pid, addr, size, value, 0);
		break;
	case 'U':
		r = rw_watch(pid, addr, size, value, 1);
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

/* ---- layout params (all via custom ops to avoid param_ops_* imports) -- */

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

static int va_bits_set(const char *val, const struct kernel_param *kp)
{
	g_va_bits = (unsigned int)parse_dec(val);
	return 0;
}
static const struct kernel_param_ops va_bits_ops = {
	.set = va_bits_set,
};
module_param_cb(va_bits, &va_bits_ops, NULL, 0444);

DEF_HEX_PARAM(init_task, g_init_task);
DEF_HEX_PARAM(page_offset, g_page_offset);
DEF_HEX_PARAM(memstart, g_memstart);
DEF_HEX_PARAM(off_pid, g_off_pid);
DEF_HEX_PARAM(off_tasks, g_off_tasks);
DEF_HEX_PARAM(off_mm, g_off_mm);
DEF_HEX_PARAM(off_pgd, g_off_pgd);

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
MODULE_DESCRIPTION("self-contained memory R/W bridge (no exported symbols)");
