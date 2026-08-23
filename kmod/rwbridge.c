// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for ARM64 Android kernels.
 *
 * HARD RULE: the kernel's only job is to LOAD this module (.ko via insmod).
 * Nothing else comes from the kernel. No kallsyms, no find_task_by_vpid /
 * get_task_mm / mmput / access_remote_vm, no filp_open / kernel_write, no
 * current->* / preempt_count() / thread_info derefs, no page-walk helpers.
 *
 * Everything is done inside the module:
 *   - defaults are the hardcoded layout constants for the verified kernel:
 *     target: 5.15.137-v5.21.770-optimizations-5.21.771.4051 (BlueStacks)
 *     vendor struct offsets (from the vendor asm-offsets / kheaders):
 *       task_struct.tasks=1232  task_struct.pid=1496  task_struct.mm=1312
 *       task_struct.comm=1960   mm_struct.pgd=64      THREAD_SIZE=0x4000
 *   - every layout value is also a module PARAM (lxgr_off_* / lxgr_pgd_shift
 *     / lxgr_page_offset / lxgr_user_va_top) so one .ko adapts to other
 *     kernels without a rebuild, and with `derive=1` the module derives the
 *     core layout itself from sp_el0 + ttbr0_el1 and VERIFIES it by reading
 *     back its own argv through the derived page tables. If neither works,
 *     insmod fails and the loader falls back to an on-device compile.
 *
 * 1) Find the process: arm64 current == sp_el0 (CONFIG_THREAD_INFO_IN_TASK,
 *    asm/current.h). Walk task_struct.tasks (circular list) and compare
 *    ->pid. Get ->mm (NULL = kernel thread / dying: bail).
 * 2) Translate user VA -> PA: walk the page table anchored at mm->pgd with a
 *    generic per-level walker. 39-bit / 4K pages / 3 levels: shifts PGD=30 /
 *    PMD=21 / PTE=12, 9-bit indices, descriptor bits[1:0]: 01=block,
 *    11=table, 00=invalid. 48-bit / 4 levels handled via lxgr_pgd_shift=39.
 * 3) Access the physical page through the linear map (it maps ALL RAM,
 *    user pages included) so no TTBR0 switch is needed and the access is
 *    cache-coherent (normal memory, same type as the user mapping):
 *        phys_to_virt(pa) = (pa - PHYS_OFFSET) | PAGE_OFFSET
 *    PAGE_OFFSET = 0xffffff8000000000 (39-bit VA, from arch/arm64/memory.h).
 *    PHYS_OFFSET is derived at runtime, no kallsyms: current->mm->pgd is the
 *    VIRTUAL address of our own top table and TTBR0_EL1 is its PHYSICAL
 *    address (ASID/CnP masked off), so
 *        PHYS_OFFSET = ttbr0 - (pgd_va - PAGE_OFFSET).
 *
 * The linear map derefs are plain cached memory accesses, exactly what the
 * kernel itself does for every page-table walk / swap / bzero, so KASAN
 * (CONFIG_KASAN_HW_TAGS) has no special effect on them.
 *
 * Operations (sysfs param `rw`, comma separated, same interface as before):
 *   R,pid,addr,size        read user VA, result hex (byte0 first) in `out`
 *   W,pid,addr,size,value  write value to user VA (writes native LE bytes)
 *   P,<cmdline-substr>     find pid by argv substring (in-kernel; `out`=dec)
 *   B,<pid>,<lib>          load base of file-backed lib mapping (`out`=hex)
 * Plus `status` (errno of last op), `out` (hex), `stage` (debug) params.
 *
 * Link-time imports: module_layout, _printk. Only.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>

/* ============ layout constants ========================================
 * Defaults = the verified BlueStacks vendor layout. Every value is a module
 * PARAM ISO the same binary adapts to other kernels:
 *   - a loader may pass explicit offsets (from kallsyms scanning or a cached
 *     per-kernel config) via insmod params;
 *   - with `derive=1` the module derives task/mm/geometry for itself at init
 *     from `current` (sp_el0), anchored on ttbr0_el1 vs the pgd VA and on
 *     `lxgr_pid_anchor` (the loading process pid), then VERIFIES the whole
 *     walk by reading back its own argv through the derived page tables;
 *   - if neither matches, insmod fails and the loader falls back to an
 *     on-device compile against that kernel's headers.
 *
 * The pgtable geometry (pgd_shift, PAGE_OFFSET, user VA top) is likewise a
 * param so a 48-bit / 4-level kernel needs no code change. */

#define LXGR_DEF_TASKS      1232UL
#define LXGR_DEF_PID        1496UL
#define LXGR_DEF_MM         1312UL
#define LXGR_DEF_COMM       1960UL
#define LXGR_DEF_MM_PGD     64UL

#define LXGR_DEF_MM_MMAP          0x000UL
#define LXGR_DEF_MM_ARGSTART      0x148UL
#define LXGR_DEF_MM_ARGEND        0x150UL

#define LXGR_DEF_VMA_START  0x00UL
#define LXGR_DEF_VMA_NEXT   0x10UL
#define LXGR_DEF_VMA_PGOFF  0x98UL
#define LXGR_DEF_VMA_FILE   0xa0UL

#define LXGR_DEF_FILE_PATH      0x10UL
#define LXGR_DEF_PATH_DENTRY    0x08UL
#define LXGR_DEF_DENTRY_NAME    0x20UL
#define LXGR_DEF_QSTR_NAME      0x08UL
#define LXGR_DEF_QSTR_LEN       0x04UL

#define LXGR_DEF_PAGE_OFFSET 0xffffff8000000000ULL   /* 39-bit VA */
#define LXGR_DEF_USER_VA_TOP 0x8000000000ULL
#define LXGR_DEF_PGD_SHIFT   30UL    /* 30 -> 39-bit/3L; 39 -> 48-bit/4L */

static unsigned long lxgr_off_tasks       = LXGR_DEF_TASKS;
static unsigned long lxgr_off_pid         = LXGR_DEF_PID;
static unsigned long lxgr_off_mm          = LXGR_DEF_MM;
static unsigned long lxgr_off_comm        = LXGR_DEF_COMM;
static unsigned long lxgr_off_mm_pgd      = LXGR_DEF_MM_PGD;
static unsigned long lxgr_off_mm_mmap     = LXGR_DEF_MM_MMAP;
static unsigned long lxgr_off_mm_argstart = LXGR_DEF_MM_ARGSTART;
static unsigned long lxgr_off_mm_argend   = LXGR_DEF_MM_ARGEND;
static unsigned long lxgr_off_vma_start   = LXGR_DEF_VMA_START;
static unsigned long lxgr_off_vma_next    = LXGR_DEF_VMA_NEXT;
static unsigned long lxgr_off_vma_pgoff   = LXGR_DEF_VMA_PGOFF;
static unsigned long lxgr_off_vma_file    = LXGR_DEF_VMA_FILE;
static unsigned long lxgr_off_file_path   = LXGR_DEF_FILE_PATH;
static unsigned long lxgr_off_path_dentry = LXGR_DEF_PATH_DENTRY;
static unsigned long lxgr_off_dentry_name = LXGR_DEF_DENTRY_NAME;
static unsigned long lxgr_off_qstr_name   = LXGR_DEF_QSTR_NAME;
static unsigned long lxgr_off_qstr_len    = LXGR_DEF_QSTR_LEN;

static unsigned long lxgr_page_offset = LXGR_DEF_PAGE_OFFSET;
static unsigned long lxgr_user_va_top = LXGR_DEF_USER_VA_TOP;
static unsigned long lxgr_pgd_shift   = LXGR_DEF_PGD_SHIFT;

/* Run-time derivation knobs (loader-supplied, `derive=1` to enable). */
static unsigned long lxgr_derive = 0;  /* try header-free self-derived layout */
static unsigned long lxgr_pid_anchor = 0;  /* pid of the LOADING process      */
/* derive-scan translate-attempt budget (termination guarantee). Default
 * suits native CPUs; drop it (e.g. 50000) on emulators. */
static unsigned long lxgr_scan_budget = 4000000UL;
/* set by loader alongside lxgr_ram_limit: proves the linear-window bound
 * reflects REAL DRAM (from /proc/iomem), not a guess. Redrive refuses
 * without it — an oversized window faults instead of failing. */
static unsigned long lxgr_have_ram = 0;
/* Linear-window bound (bytes). Default 4 GiB; widened at runtime by
 * lxgr_derive_ram_limit(), or pinned by the loader via the param below. */
static unsigned long lxgr_ram_limit = 0x100000000UL;

/* Helper accessors honoring the derived layout. */
static inline unsigned long OF_TASKS(void)       { return lxgr_off_tasks; }
static inline unsigned long OF_PID(void)         { return lxgr_off_pid; }
static inline unsigned long OF_MM(void)          { return lxgr_off_mm; }
static inline unsigned long OF_COMM(void)        { return lxgr_off_comm; }
static inline unsigned long OF_MM_PGD(void)      { return lxgr_off_mm_pgd; }
static inline unsigned long OF_MM_MMAP(void)     { return lxgr_off_mm_mmap; }
static inline unsigned long OF_MM_ARGSTART(void) { return lxgr_off_mm_argstart; }
static inline unsigned long OF_MM_ARGEND(void)   { return lxgr_off_mm_argend; }
static inline unsigned long OF_VMA_START(void)   { return lxgr_off_vma_start; }
static inline unsigned long OF_VMA_NEXT(void)    { return lxgr_off_vma_next; }
static inline unsigned long OF_VMA_PGOFF(void)   { return lxgr_off_vma_pgoff; }
static inline unsigned long OF_VMA_FILE(void)    { return lxgr_off_vma_file; }
static inline unsigned long OF_FILE_PATH(void)   { return lxgr_off_file_path; }
static inline unsigned long OF_PATH_DENTRY(void) { return lxgr_off_path_dentry; }
static inline unsigned long OF_DENTRY_NAME(void) { return lxgr_off_dentry_name; }
static inline unsigned long OF_QSTR_NAME(void)   { return lxgr_off_qstr_name; }
static inline unsigned long OF_QSTR_LEN(void)    { return lxgr_off_qstr_len; }
static inline unsigned long PGD_SHIFT(void)      { return lxgr_pgd_shift; }
static inline unsigned long PAGE_OFF(void)       { return lxgr_page_offset; }
static inline unsigned long USER_VA_TOP(void)    { return lxgr_user_va_top; }

/* ── param plumbing WITHOUT importing param_ops_* ─────────────────────────
 * module_param(n, ulong/int/bool, ...) references the kernel's exported
 * param_ops_ulong/int/bool — extra link-time imports (and MODVERSIONS CRCs)
 * we refuse to need: the vendor symvers carries only module_layout/_printk/
 * memset/vabits_actual. So all numeric params share ONE custom ops pair with
 * hand-rolled parsers (decimal or 0x-hex for ulongs; int accepts -/+; bool
 * accepts 1/0/y/n). Same insmod/sysfs behaviour as the standard macros. */
static int lxgr_p_set(const char *val, const struct kernel_param *kp)
{
	unsigned long v = 0;
	int neg = 0;

	if (!val || !*val)
		return -EINVAL;
	if (*val == '-') { neg = 1; val++; }
	else if (*val == '+') val++;

	if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
		val += 2;
		if (!*val)
			return -EINVAL;
		for (; *val; val++) {
			int d;
			if (*val >= '0' && *val <= '9') d = *val - '0';
			else if (*val >= 'a' && *val <= 'f') d = *val - 'a' + 10;
			else if (*val >= 'A' && *val <= 'F') d = *val - 'A' + 10;
			else return -EINVAL;
			if (v > (ULONG_MAX >> 4))
				return -ERANGE;
			v = (v << 4) | (unsigned long)d;
		}
	} else {
		for (; *val; val++) {
			if (*val < '0' || *val > '9')
				return -EINVAL;
			if (v > (ULONG_MAX - 9) / 10)
				return -ERANGE;
			v = v * 10 + (unsigned long)(*val - '0');
		}
	}
	if (neg)
		v = 0UL - v;
	*(unsigned long *)kp->arg = v;
	return 0;
}

static int lxgr_p_get(char *buf, const struct kernel_param *kp)
{
	unsigned long v = *(unsigned long *)kp->arg;
	char tmp[24];
	int i = 0, n = 0;

	if ((long)v < 0) {
		buf[n++] = '-';
		v = 0UL - v;
	}
	do {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	} while (v);
	while (i)
		buf[n++] = tmp[--i];
	buf[n] = '\0';
	return n;
}

static const struct kernel_param_ops lxgr_param_ops = {
	.set = lxgr_p_set,
	.get = lxgr_p_get,
};

#define LXGR_PARAM_ULONG(name) \
	module_param_cb(name, &lxgr_param_ops, &name, 0644)

module_param_cb(lxgr_derive, &lxgr_param_ops, &lxgr_derive, 0644);
LXGR_PARAM_ULONG(lxgr_off_tasks);
LXGR_PARAM_ULONG(lxgr_off_pid);
LXGR_PARAM_ULONG(lxgr_off_mm);
LXGR_PARAM_ULONG(lxgr_off_comm);
LXGR_PARAM_ULONG(lxgr_off_mm_pgd);
LXGR_PARAM_ULONG(lxgr_off_mm_mmap);
LXGR_PARAM_ULONG(lxgr_off_mm_argstart);
LXGR_PARAM_ULONG(lxgr_off_mm_argend);
LXGR_PARAM_ULONG(lxgr_off_vma_start);
LXGR_PARAM_ULONG(lxgr_off_vma_next);
LXGR_PARAM_ULONG(lxgr_off_vma_pgoff);
LXGR_PARAM_ULONG(lxgr_off_vma_file);
LXGR_PARAM_ULONG(lxgr_off_file_path);
LXGR_PARAM_ULONG(lxgr_off_path_dentry);
LXGR_PARAM_ULONG(lxgr_off_dentry_name);
LXGR_PARAM_ULONG(lxgr_off_qstr_name);
LXGR_PARAM_ULONG(lxgr_off_qstr_len);
LXGR_PARAM_ULONG(lxgr_page_offset);
LXGR_PARAM_ULONG(lxgr_user_va_top);
LXGR_PARAM_ULONG(lxgr_pgd_shift);
LXGR_PARAM_ULONG(lxgr_ram_limit);   /* bytes; 0 keeps the derived/default */
LXGR_PARAM_ULONG(lxgr_scan_budget);
LXGR_PARAM_ULONG(lxgr_have_ram);
LXGR_PARAM_ULONG(lxgr_pid_anchor);

/* Universal (kernel-model independent) page-table constants: 4K pages, 9-bit
 * indices, ARM64 descriptor type bits. These never change across kernels. */
#define LXGR_PAGE_SIZE   0x1000UL
#define LXGR_IDX_MASK    0x1ffUL
#define LXGR_DESC_MASK   0x3UL
#define LXGR_DESC_BLOCK  0x1UL
#define LXGR_DESC_TABLE  0x3UL
#define LXGR_PA_MASK     0x0000fffffffff000ULL   /* table ptr / 4K page PA */
#define LXGR_PTE_SHIFT_FIXED  12UL               /* 4K page, always last level */

/* On this guest the whole of physical RAM sits in a single contiguous window
 * [phys_off, phys_off + RAM_LIMIT) (MemTotal ~4 GiB). The linear map maps only
 * that window: a page-table entry whose address bits resolve to a PA outside
 * it is not real RAM — typically a descriptor salvaged out of a page table page
 * that the live game freed/reused mid-walk. Dereferencing such an address via
 * the linear map lands in the unmapped hole above the linear map and faults at
 * EL1 (a panic). So we never build a linear address from an out-of-window PA.
 * The bound is deliberately generous so genuine pages are never rejected,
 * yet never trusts a PA whose linear VA could sit past real RAM (fault).
 * RUNTIME-DERIVED: lxgr_derive_ram_limit() widens this from observed PAs;
 * the lxgr_ram_limit param can force it for exotic memory maps. */

#define RW_MAX_SIZE      256UL

/* Serialize all state: the overlay serializes too, but a stray reader must
 * not tear rw_buf/rw_status. Self-contained LDXR/STXR spinlock so the module
 * imports NOTHING from the kernel for synchronization (only module_layout
 * and _printk at link time). Never sleeps, safe in the param set/get path.
 * No IRQ handler ever takes this lock, so no IRQ-disable needed. */
static unsigned long lxgr_lock;

static inline void lxgr_spin_lock(void)
{
	unsigned long r, v;

	asm volatile(
		"	mov	%0, #1\n"
		"1:	ldaxr	%1, [%2]\n"
		"	cbnz	%1, 1b\n"
		"	stxr	%w1, %0, [%2]\n"
		"	cbnz	%w1, 1b\n"
		: "=&r"(r), "=&r"(v)
		: "r"(&lxgr_lock)
		: "memory");
}

static inline void lxgr_spin_unlock(void)
{
	asm volatile("stlrb wzr, [%0]"
		     :: "r"(&lxgr_lock) : "memory");
}

/* Derived once on first op. */
static unsigned long lxgr_phys_off;
static int lxgr_phys_off_ready;

static unsigned char rw_buf[RW_MAX_SIZE];
static long rw_last_size;                 /* bytes produced by last R op */
static long rw_status;
static char rw_stage[16] = "idle";

#define STAGE(s) lxgr_memcpy(rw_stage, (s), sizeof(s) - 1), \
		rw_stage[sizeof(s) - 1] = 0
static long rw_text_len;                  /* >0: `out` is raw ASCII text */

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

static int lxgr_memcmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = a, *y = b;
	while (n--) {
		if (*x != *y)
			return *x - *y;
		x++;
		y++;
	}
	return 0;
}

/* Text-formatters for the P/B ops: results land in rw_buf as ASCII and
 * rw_out_get() returns them verbatim (never hex-encoded). */
static void lxgr_put_dec(unsigned long v)
{
	char tmp[24];
	int k = 23, i = 0;

	tmp[k] = 0;
	do {
		tmp[--k] = '0' + (v % 10);
		v /= 10;
	} while (v && k > 0);
	while (k < 23)
		rw_buf[i++] = (unsigned char)tmp[k++];
	rw_text_len = i;
}

static void lxgr_put_hex_at(int off, unsigned long v)
{
	static const char hx[] = "0123456789abcdef";
	char tmp[17];
	int k, n = 0;

	for (k = 15; k >= 0; k--)
		tmp[n++] = (unsigned char)hx[(v >> (k * 4)) & 0xf];
	/* strip leading zeros (keep at least one digit) */
	{
		int s = 0;
		while (s < n - 1 && tmp[s] == '0')
			s++;
		for (k = s; k < n && (unsigned)off < RW_MAX_SIZE; k++)
			rw_buf[off++] = (unsigned char)tmp[k];
	}
	rw_text_len = off;
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

/* ================= current / linear map ============================== */

static unsigned long lxgr_current(void)
{
	unsigned long cur;

	asm volatile("mrs %0, sp_el0" : "=r"(cur));
	return cur;
}

static unsigned long lxgr_current_pid(void)
{
	return *(unsigned long *)(lxgr_current() + OF_PID());
}

static inline unsigned long lxgr_phys_to_virt(unsigned long pa)
{
	return (pa - lxgr_phys_off) | PAGE_OFF();
}

/* Build the linear-map address only when pa is inside the real RAM window.
 * Returns 0 for an out-of-window / bogus PA so callers can bail out safely
 * instead of faulting the kernel. `pa - lxgr_phys_off` unsigned-wraps to a huge
 * value when pa < phys_off, so the single >= test catches both under- and
 * overruns. */
static inline unsigned long lxgr_safe_virt(unsigned long pa)
{
	unsigned long off = pa - lxgr_phys_off;
	if (off >= lxgr_ram_limit)
		return 0;
	return off | PAGE_OFF();
}

/* Derive PHYS_OFFSET from our own pgd: VA (mm->pgd) vs PA (TTBR0_EL1).
 * Must be called from the process context that owns mm (the sysfs writer). */
static long lxgr_derive_phys_off(void)
{
	unsigned long cur, mm, pgd_va, ttbr0;

	if (lxgr_phys_off_ready)
		return 0;

	cur = lxgr_current();
	mm = *(unsigned long *)(cur + OF_MM());
	if (!mm)
		return -EIO;
	pgd_va = *(unsigned long *)(mm + OF_MM_PGD());
	if (!pgd_va || (pgd_va & (LXGR_PAGE_SIZE - 1)) ||
	    pgd_va < PAGE_OFF())
		return -EIO;

	asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
	ttbr0 &= LXGR_PA_MASK;               /* drop ASID/CnP bits */
	if (!ttbr0)
		return -EIO;

	lxgr_phys_off = ttbr0 - (pgd_va - PAGE_OFF());
	/* phys_off (memstart) may be ~0 on low-RAM kernels or several GiB on
	 * high-RAM ones; only the top bound rejects garbage pgd candidates. */
	if (lxgr_phys_off > 0x20000000000ULL)
		return -EIO;
	lxgr_phys_off_ready = 1;
	pr_info("rwbridge: linear map ready, PHYS_OFFSET=0x%lx\n",
		lxgr_phys_off);
	return 0;
}

static void lxgr_init_shifts(void);
static long lxgr_translate(unsigned long pgd_va, unsigned long va,
			   unsigned long *pa_out);
long lxgr_redrive(void);
static void lxgr_derive_ram_limit(void);

/* ================= header-free layout derivation =====================
 * With `derive=1` the module figures out task_struct / mm_struct / page-
 * table geometry on its own, so the SAME .ko runs on any arm64 kernel with
 * zero per-kernel compile. The loader only has to supply lxgr_pid_anchor
 * (its own pid). Everything is verified end-to-end:
 *   1. the task_struct base = sp_el0 (CONFIG_THREAD_INFO_IN_TASK);
 *   2. OF_TASKS is the doubly-linked circular list that links current back
 *      to itself (checked on both next and prev sides, plus a bounded full
 *      walk that must wrap exactly to current);
 *   3. OF_PID is the field that equals lxgr_pid_anchor (when given);
 *   4. OF_MM points at a linear-map slab object whose pgd candidate, when
 *      converted to PA via the ttbr0<->PAGE_OFF relation, yields a phys_off
 *      in a sane window AND successfully translates our own argv (the final
 *      smoke test: the whole walk + geometry must actually work).
 * The B,/P, discovery VMA/dentry offsets are NOT derived here: they stay
 * param-configured (loader supplies via compile/kallsyms); if wrong those
 * ops fail cleanly with -EIO rather than guess.
 * Any candidate that fails the linear-window/type gates is REJECTED before
 * it is ever dereferenced, so garbage offsets can never fault (panic). */

/* Geometry-independent user-space ceiling: the larger VA top of both
 * candidate geometries (48-bit). Used for pre-filtering mm-field garbage
 * before any geometry is committed. */
#define LXGR_USER_TOP_MAX 0x0001000000000000ULL

/* Printable-ASCII check at a translated PA: argv strings are text. */
static int lxgr_probe_bytes(unsigned long pa)
{
	unsigned char b[8];
	unsigned long lin;
	int i;

	lin = lxgr_safe_virt(pa);
	if (!lin)
		return 0;
	lxgr_memcpy(b, (const void *)lin, sizeof(b));
	for (i = 0; i < (int)sizeof(b); i++)
		if (b[i] < 0x20 || b[i] > 0x7e)
			return 0;
	return 1;
}

/* Only VAs in [PAGE_OFF, PAGE_OFF + RAM_LIMIT) are guaranteed mapped real
 * RAM (the same window safe_virt() uses). Reading anything else as a
 * "kernel VA" risks an EL1 fault, so every heuristic deref is gated on
 * this predicate first. cur's own task_struct always passes, and the whole
 * task list / slab heap lives inside this window. */
static inline int lxgr_kva_ok(unsigned long va)
{
	if (va < PAGE_OFF())
		return 0;
	return (va - PAGE_OFF()) < lxgr_ram_limit;
}

static unsigned long lxgr_krd(unsigned long va)
{
	if (!lxgr_kva_ok(va))
		return 0;
	return *(unsigned long *)va;
}

/* geometry candidates to try: 39-bit (3 levels) and 48-bit (4 levels). */
static const struct lxgr_geom {
	unsigned long page_off;
	unsigned long user_top;
	unsigned long pgd_shift;
} lxgr_geoms[] = {
	{ 0xffffff8000000000ULL, 0x8000000000ULL,      30UL },
	{ 0xffff800000000000ULL, 0x1000000000000ULL,   39UL },
};

/* (old probe_arg folded into derive_geom_mm: pairs pre-filtered, one midpoint probe) */

/* Apply geometry candidates against every (mm,pgd) pair from cur, running
 * the argv readback test. On success commits mm/pgd/phys_off/argstart/argend
 * and returns 0; on total failure restores nothing (the caller/memset work),
 * geometry is simply left set to the LAST tried candidate — the operator must
 * treat a non-zero return as "do not trust this layout". */
/* mm_struct fingerprint (offset-free): a real mm window contains
 *  - at least one page-aligned linear-map pointer (->pgd)
 *  - a tight cluster of >=3 user VAs (arg_start/arg_end/env_start/
 *    env_end/start_brk/start_stack all live within a few MB of each
 *    other near the stack top) — garbage memory almost never does.
 * Lead with this BEFORE any page-table work: only fingerprint-passing
 * candidates reach the translate stage. */
#define LXGR_MM_WIN_QWORDS 256          /* 2048-byte scan window */
#define LXGR_CLUSTER_SPAN   0x800000UL  /* 8 MB */
#define LXGR_USR_MIN        0x40000UL

static long lxgr_derive_geom_mm(unsigned long cur, unsigned long ttbr0)
{
	unsigned long mm, o, budget = lxgr_scan_budget;
	int g;
	unsigned long n_mm = 0, n_fp = 0;

	for (o = 0; o < 4096; o += 8) {
		unsigned long win[LXGR_MM_WIN_QWORDS];
		unsigned long usr[32];
		int n_usr = 0, i;
		int pgd_seen = 0;

		cond_resched();
		mm = lxgr_krd(cur + o);
		if (!lxgr_kva_ok(mm))
			continue;
		n_mm++;

		/* gated bulk read of the candidate window */
		for (i = 0; i < LXGR_MM_WIN_QWORDS; i++) {
			if (!lxgr_kva_ok(mm + i * 8))
				break;
			win[i] = lxgr_krd(mm + i * 8);
		}
		if (i < LXGR_MM_WIN_QWORDS)
			continue;

		for (i = 0; i < LXGR_MM_WIN_QWORDS; i++) {
			unsigned long v = win[i];

			if (v && !(v & (LXGR_PAGE_SIZE - 1)) &&
			    lxgr_kva_ok(v))
				pgd_seen = 1;
			if (v >= LXGR_USR_MIN && v < LXGR_USER_TOP_MAX &&
			    n_usr < 32)
				usr[n_usr++] = v;
		}
		if (!pgd_seen || n_usr < 3)
			continue;

		/* tight-cluster test on the user-VA set */
		{
			int a, b, best = 0;

			for (a = 0; a < n_usr; a++) {
				int c = 0;

				for (b = 0; b < n_usr; b++)
					if (usr[b] >= usr[a] &&
					    usr[b] - usr[a] <=
					        LXGR_CLUSTER_SPAN)
						c++;
				if (c > best)
					best = c;
			}
			if (best < 3)
				continue;
		}
		n_fp++;

		/* ---- verified-real mm: locate arg pair + prove geometry -- */
		for (i = 0;
		     i + 1 < LXGR_MM_WIN_QWORDS && budget > 0;
		     i++, budget--) {
			unsigned long as = win[i], ae = win[i + 1];
			unsigned long pgo;

			if ((ae - as) < 8 || (ae - as) > 0x100000 ||
			    as < LXGR_USR_MIN || as >= LXGR_USER_TOP_MAX ||
			    ae > LXGR_USER_TOP_MAX)
				continue;

			for (pgo = 0;
			     pgo < LXGR_MM_WIN_QWORDS && budget > 0;
			     pgo++, budget--) {
				unsigned long pgd = win[pgo];

				if (!pgd || (pgd & (LXGR_PAGE_SIZE - 1)) ||
				    !lxgr_kva_ok(pgd))
					continue;

				for (g = 0; g < 2 && budget > 0;
				     g++, budget--) {
					unsigned long po, pa;

					lxgr_page_offset =
						lxgr_geoms[g].page_off;
					lxgr_user_va_top =
						lxgr_geoms[g].user_top;
					lxgr_pgd_shift =
						lxgr_geoms[g].pgd_shift;
					lxgr_init_shifts();

					po = ttbr0 -
					     (pgd - lxgr_page_offset);
					/* memstart can never exceed the
					 * MEASURED DRAM span; this also
					 * instantly kills cross-geometry
					 * candidates (a 48-bit PAGE_OFFSET
					 * assumption on a 39-bit kernel
					 * yields astronomical po). */
					if (po > lxgr_ram_limit)
						continue;

					lxgr_phys_off = po;
					lxgr_phys_off_ready = 1;

					STAGE("drv:mm");
					if (lxgr_translate(
					      pgd, as + (ae - as) / 2,
					      &pa) == 0 &&
					    lxgr_probe_bytes(pa)) {
						lxgr_off_mm = o;
						lxgr_off_mm_pgd = pgo * 8;
						lxgr_off_mm_argstart = i * 8;
						lxgr_off_mm_argend = i * 8+8;
						pr_info("rwbridge: derived "
							"mm=%lu pgd=%lu "
							"arg=%lu/%lu\n",
							o, pgo * 8, i * 8,
							i * 8 + 8);
						STAGE("drv:ram");
						lxgr_derive_ram_limit();
						return 0;
					}
					lxgr_phys_off_ready = 0;
				}
			}
		}
	}
	pr_warn("rwbridge: scan end budget=%lu mm=%lu fp=%lu\n",
		budget, n_mm, n_fp);
	return -ENOENT;
}

/* Full derivation. Returns 0 on success (everything committed + phys_off
 * ready), -ENOENT if any gate fails and we should not trust the layout. */
static long lxgr_derive_layout(void)
{
	unsigned long cur = lxgr_current();
	unsigned long ttbr0, t, p;
	int found = 0;

	asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
	ttbr0 &= LXGR_PA_MASK;
	if (!ttbr0)
		return -ENOENT;

	/* ---- OF_TASKS: circular doubly-linked list anchored at cur ---- */
	for (t = 0; t < 4096; t += 8) {
		cond_resched();   /* voluntary-preempt kernels need the hint */
		unsigned long nxt = lxgr_krd(cur + t);        /* ->next      */
		unsigned long prv = lxgr_krd(cur + t + 8);    /* ->prev      */
		unsigned long nbase, pbase, node;
		int cnt;

		if (!nxt || !prv)
			continue;
		if (!lxgr_kva_ok(nxt) || !lxgr_kva_ok(prv))
			continue;
		nbase = nxt - t;                 /* next task_struct base */
		pbase = prv - t;                 /* prev task_struct base */
		if (!lxgr_kva_ok(nbase) || !lxgr_kva_ok(pbase) ||
		    !lxgr_kva_ok(nbase + t + 8) || !lxgr_kva_ok(pbase + t))
			continue;
		if (lxgr_krd(nbase + t + 8) != cur + t)    /* next->prev == cur */
			continue;
		if (lxgr_krd(pbase + t) != cur + t)        /* prev->next == cur */
			continue;

		/* bounded full walk must wrap exactly back to cur */
		node = cur;
		cnt = 0;
		for (;;) {
			if ((++cnt & 255) == 0)
				cond_resched();
			unsigned long nx = lxgr_krd(node + t);
			unsigned long nb;
			if (!nx || !lxgr_kva_ok(nx))
				break;
			nb = nx - t;
			if (!lxgr_kva_ok(nb))
				break;
			node = nb;
			if (++cnt > 16384)
				break;
			if (node == cur)
				break;
		}
		if (node == cur && cnt >= 2) {
			lxgr_off_tasks = t;
			found = 1;
			break;
		}
	}
	if (!found)
		return -ENOENT;

	/* ---- OF_PID: anchor pid if supplied ----
	 * For a thread-group leader pid == tgid, so the anchor value matches TWO
	 * adjacent 4-byte fields: that pattern is actually the strongest sig -
	 * take the first of the pair. A lone single match (leader only stored) is
	 * accepted too; any other ambiguity keeps the param default. */
	if (lxgr_pid_anchor) {
		int first = -1, second = -1;
		for (p = 0; p < 4096; p += 4) {
			unsigned int v = *(unsigned int *)(cur + p);
			if (v == (unsigned int)lxgr_pid_anchor) {
				if (first < 0)
					first = (int)p;
				else if (second < 0)
					second = (int)p;
				else
					break;      /* 3+ matches: garbage */
			}
		}
		if (first >= 0 &&
		    (second < 0 || (unsigned long)second == (unsigned long)(first + 4))) {
			lxgr_off_pid = (unsigned long)first;
			pr_info("rwbridge: derived pid offset = %lu\n",
				lxgr_off_pid);
		} else if (first >= 0) {
			pr_warn("rwbridge: pid anchor %lu ambiguous (%d,%d): "
				"keeping default %lu\n", lxgr_pid_anchor,
				first, second, OF_PID());
		}
	}

	/* ---- OF_MM + pgd + phys_off + geometry (argv-verified) ---- */
	return lxgr_derive_geom_mm(cur, ttbr0);
}

/* Widen the linear-window bound from OBSERVED physical addresses once the
 * map is proven. Probes a handful of guaranteed-translatable VAs (our own
 * kernel objects + our argv page through our own tables) and takes 2x the
 * highest offset seen, clamped to [4 GiB, 1 TiB]. This is a heuristic floor:
 * pages above it are rejected by safe_virt() (fail-closed) rather than
 * trusted. A loader may pin lxgr_ram_limit explicitly instead. */
static void lxgr_derive_ram_limit(void)
{
	unsigned long cur = lxgr_current();
	unsigned long probes[4];
	unsigned long best = 0;
	int i;

	probes[0] = cur;                       /* task_struct            */
	probes[1] = cur + lxgr_off_comm;       /* ->comm bytes           */
	probes[2] = cur + lxgr_off_pid;
	/* our argv page through our own tables: user RAM can sit high */
	{
		unsigned long mm = *(unsigned long *)(cur + OF_MM());
		if (mm) {
			unsigned long pgd = *(unsigned long *)(mm + OF_MM_PGD());
			unsigned long as = *(unsigned long *)(mm + OF_MM_ARGSTART());
			unsigned long pa;

			if (pgd && as && as < USER_VA_TOP() &&
			    lxgr_translate(pgd, as, &pa) == 0 &&
			    pa >= lxgr_phys_off)
				probes[3] = pa - lxgr_phys_off;
			else
				probes[3] = 0;
		} else
			probes[3] = 0;
	}

	best = 0;
	for (i = 0; i < 3; i++) {
		unsigned long va = probes[i];
		unsigned long off;
		if (!va || !lxgr_kva_ok(va))
			continue;
		off = va - PAGE_OFF();
		if (off > best)
			best = off;
	}
	if (probes[3] > best)
		best = probes[3];

	if (best > lxgr_ram_limit / 2 && best <= (1UL << 40))
		lxgr_ram_limit = best * 2;

	pr_info("rwbridge: ram_limit=0x%lx\n", lxgr_ram_limit);
}

/* Self-bootstrapping derive entry point. Fixes the ordering trap where the
 * kva_ok() gate ran against the DEFAULT geometry during the scan: on a
 * 48-bit-VA kernel every real linear-map address failed the 39-bit default
 * PAGE_OFFSET test and derive silently found nothing. Here each geometry
 * candidate is committed FIRST, sanity-gated on current itself being a valid
 * kernel VA under it, and only then handed to the existing scanner. State is
 * reset between candidates so a partial fit never leaks into the next try. */
static long lxgr_bootstrap(void)
{
	unsigned long cur, ttbr0;
	int g;
	static const struct {
		unsigned long page_off, user_top, pgd_shift;
	} geoms[] = {
		{ 0xffffff8000000000ULL, 0x0000008000000000ULL, 30UL }, /* 39-bit */
		{ 0xffff800000000000ULL, 0x0001000000000000ULL, 39UL }, /* 48-bit */
	};

	STAGE("drv:tasks");
	pr_info("rwbridge: [drv] tasks scan enter\n");
	cur = lxgr_current();
	asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
	ttbr0 &= LXGR_PA_MASK;
	if (!ttbr0)
		return -ENOENT;

	STAGE("drv:pid");
	pr_info("rwbridge: [drv] pid anchor=%lu enter\n", lxgr_pid_anchor);
	/* no anchor supplied? the WRITER is a fine one: its own argv is what
	 * the readback verifies against (sysfs D-op context). */
	if (!lxgr_pid_anchor)
		lxgr_pid_anchor = lxgr_current_pid();

	/* loader override wins outright */
	if (lxgr_page_offset && lxgr_user_va_top && lxgr_pgd_shift)
		return lxgr_derive_layout();

	for (g = 0; g < 2; g++) {
		long r;

		lxgr_page_offset  = geoms[g].page_off;
		lxgr_user_va_top  = geoms[g].user_top;
		lxgr_pgd_shift    = geoms[g].pgd_shift;
		lxgr_init_shifts();

		/* candidate geometry must at least place `current` in its own
		 * linear window before any field of it is touched */
		if (!lxgr_kva_ok(cur))
			continue;

		r = lxgr_derive_layout();
		if (r == 0) {
			pr_info("rwbridge: bootstrap ok geom=%d PAGE_OFF=0x%lx "
				"PGD_SHIFT=%lu PHYS_OFFSET=0x%lx\n",
				g, lxgr_page_offset, lxgr_pgd_shift,
				lxgr_phys_off);
			STAGE("drv:ram");
			pr_info("rwbridge: [drv] ram-limit widen\n");
			lxgr_derive_ram_limit();
			return 0;
		}
		/* scrub derived state before the next candidate */
		lxgr_phys_off       = 0;
		lxgr_phys_off_ready = 0;
	}
	return -ENOENT;
}

/* Redrive derivation from ANY process context (sysfs writer). Kept out of
 * module_init on purpose: init runs under module_mutex, so any wedge there
 * takes down every introspection tool with it. The sysfs D op calls this in
 * the writer's own context where /proc/<pid>/stack, sysrq-t etc all stay
 * alive if something ever blocks again. */
long lxgr_redrive(void)
{
	unsigned long sv_pg, sv_top, sv_s0, sv_po, sv_rl;
	int sv_rdy;
	long r;

	sv_pg  = lxgr_page_offset;
	sv_top = lxgr_user_va_top;
	sv_s0  = lxgr_pgd_shift;
	sv_po  = lxgr_phys_off;
	sv_rdy = lxgr_phys_off_ready;
	sv_rl  = lxgr_ram_limit;

	r = lxgr_bootstrap();
	if (r) {
		pr_warn("rwbridge: derive failed (%ld): restoring param "
			"defaults\n", r);
		lxgr_page_offset   = sv_pg;
		lxgr_user_va_top   = sv_top;
		lxgr_pgd_shift     = sv_s0;
		lxgr_phys_off      = sv_po;
		lxgr_phys_off_ready= sv_rdy;
		lxgr_ram_limit     = sv_rl ? : 0x100000000UL;
	}
	lxgr_init_shifts();
	return r;
}

/* ================= task list walk ==================================== */

/* Walk task_struct.tasks from `current` (always alive - we run in it) until
 * we wrap back to it. Bounded by a hard counter so a concurrently-mutating
 * list can never loop forever. Returns the target's ->mm in *mm_out.
 * `current` itself is a candidate too (self read/write), so it is examined
 * before advancing; wrap-back stops the loop. */
static long lxgr_find_task(unsigned long want, unsigned long *mm_out)
{
	unsigned long cur = lxgr_current();
	unsigned long p = cur;
	unsigned long nxt, pid;
	int i;

	pid = *(unsigned long *)(p + OF_PID());
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;               /* layout sanity: current->pid sane */

	for (i = 0; i < 16384; i++) {
		pid = *(unsigned long *)(p + OF_PID());
		if ((unsigned int)pid == (unsigned int)want) {
			*mm_out = *(unsigned long *)(p + OF_MM());
			return 0;
		}
		nxt = *(unsigned long *)(p + OF_TASKS());
		if (!nxt)
			return -ESRCH;
		p = nxt - OF_TASKS();  /* next node -> task_struct */
		if (p == cur)
			break;               /* wrapped whole list */
	}
	return -ESRCH;
}

/* ================= page table walk =================================== */

/* Per-level index shift, top (PGD/PUD) down to PTE. Built at init from the
 * PGD_SHIFT param: 39-bit VA -> {39,30,21,12} (4 levels), 39-bit PGD_30 ->
 * {30,21,12} (3 levels). Leaf PTE level is always the last one. */
static unsigned long lxgr_shifts[4];
static int lxgr_levels = 3;

static void lxgr_init_shifts(void)
{
	int l = 0;
	unsigned long s = PGD_SHIFT();

	/* Per-level index shifts step down by 9 bits per level (ARM64 4K pages,
	 * 9-bit indices, 8-byte descriptors). The top level's shift is the
	 * geometry: PGD_SHIFT()=30 -> 39-bit VA / 3 levels {30,21,12};
	 * PGD_SHIFT()=39 -> 48-bit VA / 4 levels {39,30,21,12}. The PTE level
	 * is always shift 12 (page size), regardless of VA size; drive the loop
	 * from that fixed terminal level, NOT from a separately-configurable
	 * PTE_SHIFT (which derived geometry could set to a wrong value). */
	while (s > LXGR_PTE_SHIFT_FIXED && l < 4) {
		lxgr_shifts[l++] = s;
		s -= 9;
	}
	lxgr_shifts[l++] = LXGR_PTE_SHIFT_FIXED;
	lxgr_levels = l;
}

/* Translate user VA to physical PA through mm->pgd (a linear-map VA of the
 * top-level table). Generic multi-level walk: at each non-leaf level a
 * descriptor may be a BLOCK (01: a contiguous physical span of this level's
 * granularity) or a TABLE (11: pointer to the next level). The leaf (PTE)
 * level must be a TABLE to yield a 4K page. out-of-user-range and out-of-RAM
 * descriptors are rejected up front so no bogus linear address is ever
 * dereferenced (a stale page-table page freed by the live game mid-walk
 * would otherwise fault at EL1 -> panic). */
static long lxgr_translate(unsigned long pgd_va, unsigned long va,
			   unsigned long *pa_out)
{
	unsigned long e, t, lin, tab = pgd_va;
	unsigned long idx;
	int l;

	if (va >= USER_VA_TOP())
		return -EINVAL;

	for (l = 0; l < lxgr_levels; l++) {
		unsigned long shift = lxgr_shifts[l];
		unsigned long toff;

		/* HARD GATE (self-contained, caller-independent): the table we
		 * are about to read slots from must itself be inside the linear
		 * window INCLUDING this level's slot extent — a top-of-RAM table
		 * page plus idx*8 must never cross past real RAM. This holds even
		 * when a caller hands us an unvalidated pgd_va. */
		if (!lxgr_kva_ok(tab))
			return -EFAULT;
		toff = tab - PAGE_OFF();
		idx = (va >> shift) & LXGR_IDX_MASK;
		if (toff + idx * 8 + 8 > lxgr_ram_limit)
			return -EFAULT;

		e = *(volatile unsigned long *)(tab + idx * 8);
		t = e & LXGR_DESC_MASK;
		if (l == lxgr_levels - 1) {
			/* leaf: only a PAGE descriptor (0b11) is valid */
			if (t != LXGR_DESC_TABLE)
				return -EFAULT;
			if (!lxgr_safe_virt(e & LXGR_PA_MASK))
				return -EFAULT;
			*pa_out = (e & LXGR_PA_MASK) + (va & (LXGR_PAGE_SIZE - 1));
			return 0;
		}
		if (t == LXGR_DESC_BLOCK) {
			/* block descriptor: continuous physical span of this level */
			unsigned long span = 1UL << shift;   /* e.g. 1GB / 2MB */
			unsigned long base = e & ~(span - 1) & LXGR_PA_MASK;

			if (!lxgr_safe_virt(base))
				return -EFAULT;
			*pa_out = base + (va & (span - 1));
			return 0;
		}
		if (t != LXGR_DESC_TABLE)
			return -EFAULT;
		/* next-level table page must live in real RAM */
		lin = lxgr_safe_virt(e & LXGR_PA_MASK);
		if (!lin)
			return -EFAULT;
		tab = lin;
	}
	return -EFAULT;
}


static long rw_read_custom(unsigned long pid, unsigned long addr,
			   unsigned long size)
{
	unsigned long mm, pgd, done = 0;

	if (lxgr_find_task(pid, &mm) || !mm)
		return -ESRCH;
	pgd = *(unsigned long *)(mm + OF_MM_PGD());
	if (!pgd)
		return -EFAULT;

	while (done < size) {
		unsigned long pa, chunk, lin;
		long r = lxgr_translate(pgd, addr + done, &pa);

		if (r)
			return r;
		/* final data page: block (1GB/2MB) and page paths both land here;
		 * a non-RAM final PA (device/huge or stale) would fault EL1. */
		if (!lxgr_safe_virt(pa))
			return -EFAULT;
		chunk = LXGR_PAGE_SIZE - (pa & (LXGR_PAGE_SIZE - 1));
		if (chunk > size - done)
			chunk = size - done;
		lin = lxgr_phys_to_virt(pa);
		lxgr_memcpy(rw_buf + done, (const void *)lin, chunk);
		done += chunk;
	}
	return 0;
}

/* ================= WRITE ============================================= */

static long rw_write_direct(unsigned long pid, unsigned long addr,
			    unsigned long size, unsigned long value)
{
	unsigned long mm, pgd, done = 0;
	unsigned char *src = (unsigned char *)&value;

	if (lxgr_find_task(pid, &mm) || !mm)
		return -ESRCH;
	pgd = *(unsigned long *)(mm + OF_MM_PGD());
	if (!pgd)
		return -EFAULT;

	while (done < size) {
		unsigned long pa, chunk, lin;
		long r = lxgr_translate(pgd, addr + done, &pa);

		if (r)
			return r;
		if (!lxgr_safe_virt(pa))
			return -EFAULT;
		chunk = LXGR_PAGE_SIZE - (pa & (LXGR_PAGE_SIZE - 1));
		if (chunk > size - done)
			chunk = size - done;
		lin = lxgr_phys_to_virt(pa);
		lxgr_memcpy((void *)lin, src + done, chunk);
		done += chunk;
	}
	return 0;
}

/* ================= discovery ops (P/B) ============================== */

/* Like lxgr_find_task but also hands back the found task_struct VA. */
static long lxgr_find_task_va(unsigned long want, unsigned long *task_out,
			      unsigned long *mm_out)
{
	unsigned long cur = lxgr_current();
	unsigned long p = cur, nxt, pid;
	int i;

	pid = *(unsigned long *)(p + OF_PID());
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;

	for (i = 0; i < 16384; i++) {
		pid = *(unsigned long *)(p + OF_PID());
		if ((unsigned int)pid == (unsigned int)want) {
			if (task_out)
				*task_out = p;
			if (mm_out)
				*mm_out = *(unsigned long *)(p + OF_MM());
			return 0;
		}
		nxt = *(unsigned long *)(p + OF_TASKS());
		if (!nxt)
			return -ESRCH;
		p = nxt - OF_TASKS();
		if (p == cur)
			break;
	}
	return -ESRCH;
}

/* Does task's argv (mm->arg_start..arg_end) contain substring `sub`? The argv
 * region is user memory, read through the target's own page tables; a partial
 * read (task mid-exec / unmapped page) is treated as non-matching, never as a
 * fault. Case-sensitive. */
static long lxgr_task_cmdline_has(unsigned long task, const char *sub)
{
	unsigned long mm, pgd, as, ae, cap, done = 0, i;
	unsigned long sublen = lxgr_strlen(sub);
	unsigned char cmd[4096];

	if (sublen == 0 || sublen >= sizeof(cmd))
		return 0;
	mm = *(unsigned long *)(task + OF_MM());
	if (!mm)
		return 0;                 /* kernel thread: no user cmdline */
	pgd = *(unsigned long *)(mm + OF_MM_PGD());
	if (!pgd)
		return 0;
	as = *(unsigned long *)(mm + OF_MM_ARGSTART());
	ae = *(unsigned long *)(mm + OF_MM_ARGEND());
	if (!as || !ae || ae <= as)
		return 0;
	cap = ae - as;
	if (cap > sizeof(cmd) - 1)
		cap = sizeof(cmd) - 1;

	while (done < cap) {
		unsigned long pa, chunk, lin;
		long r = lxgr_translate(pgd, as + done, &pa);

		if (r)
			break;             /* partial read: use what we have */
		if (!lxgr_safe_virt(pa))
			break;
		chunk = LXGR_PAGE_SIZE - (pa & (LXGR_PAGE_SIZE - 1));
		if (chunk > cap - done)
			chunk = cap - done;
		lin = lxgr_phys_to_virt(pa);
		lxgr_memcpy(cmd + done, (const void *)lin, chunk);
		done += chunk;
	}
	cmd[done] = 0;

	for (i = 0; i + sublen <= done; i++)
		if (cmd[i] == sub[0] && !lxgr_memcmp(cmd + i, sub, sublen))
			return 1;
	return 0;
}

/* P,<substr>: find the first task whose argv contains substr; pid is written
 * by the caller via lxgr_put_dec. The task list is walked in-kernel so no
 * /proc/<pid>/cmdline syscall is ever made (invisible to userspace). */
static long lxgr_find_pid_cmdline(const char *sub)
{
	unsigned long cur = lxgr_current();
	unsigned long p = cur, nxt, pid;
	int i;

	pid = *(unsigned long *)(p + OF_PID());
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;

	for (i = 0; i < 16384; i++) {
		pid = *(unsigned long *)(p + OF_PID());
		if ((unsigned int)pid >= 1 &&
		    lxgr_task_cmdline_has(p, sub))
			return (long)(unsigned int)pid;
		nxt = *(unsigned long *)(p + OF_TASKS());
		if (!nxt)
			return -ESRCH;
		p = nxt - OF_TASKS();
		if (p == cur)
			break;
	}
	return -ESRCH;
}

/* Read a short NUL-terminated string from a linear-map (kernel) VA. */
static long lxgr_kstr(unsigned long va, unsigned long max, char *out)
{
	unsigned long off;

	if (va < PAGE_OFF())
		return -EFAULT;
	off = va - PAGE_OFF();
	if (off >= lxgr_ram_limit || off + max > lxgr_ram_limit)
		return -EFAULT;
	lxgr_memcpy(out, (const void *)va, max);
	out[max] = 0;
	return 0;
}

/* B,<pid>,<lib>: walk the target's VMA list (mm->mmap / vma->vm_next), find the
 * file-backed mapping whose dentry basename matches `lib`, and return
 * EVERY pgoff==0 vm_start (each is a full ELF base of that lib) as a
 * comma-separated hex list via rw_buf/rw_text_len. A lib is sometimes mapped
 * more than once as a complete image (e.g. an inert/on-disk copy plus the live
 * runtime copy); returning all of them lets the caller pick the one it needs.
 * Fully in-kernel: the file name comes from the live struct file/dentry, never
 * from /proc. */
static long lxgr_module_base(unsigned long pid, const char *lib)
{
	unsigned long task, mm, mmap_va, vma, nxt;
	unsigned long liblen = lxgr_strlen(lib);
	int i, wrote = 0;

	if (liblen == 0 || liblen > 63)
		return -EINVAL;
	if (lxgr_find_task_va(pid, &task, &mm) || !mm)
		return -ESRCH;
	mmap_va = *(unsigned long *)(mm + OF_MM_MMAP());
	if (!mmap_va || mmap_va < PAGE_OFF())
		return -ESRCH;

	for (vma = mmap_va, i = 0; i < 16384; i++) {
		unsigned long start, file, pgoff, dentry, dn, hl;
		unsigned long len;
		char nm[96];

		if (vma < PAGE_OFF())
			break;
		start = *(unsigned long *)(vma + OF_VMA_START());
		if (start == 0 || start >= USER_VA_TOP())
			break;             /* stale list / not a user vma */
		file = *(unsigned long *)(vma + OF_VMA_FILE());
		pgoff = *(unsigned long *)(vma + OF_VMA_PGOFF());
		if (file >= PAGE_OFF() && pgoff == 0) {
			dentry = *(unsigned long *)(file + OF_FILE_PATH() +
						    OF_PATH_DENTRY());
			if (dentry >= PAGE_OFF()) {
				hl = *(unsigned long *)(dentry + OF_DENTRY_NAME());
				dn = *(unsigned long *)(dentry + OF_DENTRY_NAME() +
							OF_QSTR_NAME());
				len = hl >> 32;   /* qstr.hash_len: len in high half */
				if (len > 63)
					len = 63;
				if (dn >= PAGE_OFF() &&
				    lxgr_kstr(dn, len + 1, nm) == 0 &&
				    len == liblen &&
				    !lxgr_memcmp(nm, lib, liblen)) {
					/* full (pgoff==0) base of this lib. */
					if (wrote && (unsigned long)rw_text_len < RW_MAX_SIZE - 20)
						rw_buf[rw_text_len++] = ',';
					lxgr_put_hex_at(rw_text_len, start);
					wrote++;
				}
			}
		}
		nxt = *(unsigned long *)(vma + OF_VMA_NEXT());
		if (!nxt || nxt == mmap_va || nxt < PAGE_OFF())
			break;
		vma = nxt;
	}
	if (!wrote)
		return -ESRCH;
	return 0;
}

/* ================= param set: guaranteed entry point ================= */


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
	char name[96];
	char op;
	unsigned long pid, addr, size, value;
	long r = 0;

	(void)kp;
	lxgr_spin_lock();
	rw_text_len = 0;
	STAGE("parse");
	while (*p == ' ')
		p++;
	if (!*p)
		goto bad;
	op = *p++;
	if (*p == ',')
		p++;
	else
		goto bad;

	/* ---- discovery ops: P,<cmdline-substr> -> pid; B,<pid>,<lib> -> base ---- */
	if (op == 'P' || op == 'B') {
		unsigned long bpid = 0;
		int n = 0;

		if (op == 'B') {
			if (next_field(&p, f, sizeof(f)) <= 0)
				goto bad;
			bpid = parse_dec(f);
			if (bpid <= 0 || bpid > 0x7fffffff)
				goto bad;
		}
		while (*p && *p != ',' && n < (int)sizeof(name) - 1)
			name[n++] = *p++;
		name[n] = 0;
		while (n > 0 && (name[n - 1] == '\n' || name[n - 1] == '\r' ||
				 name[n - 1] == ' '))
			name[--n] = 0;
		if (n <= 0)
			goto bad;
		STAGE("derive");
		r = lxgr_derive_phys_off();
		if (r)
			goto finish;
		if (op == 'P') {
			STAGE("pid");
			r = lxgr_find_pid_cmdline(name);
			if (r > 0) {
				lxgr_put_dec((unsigned long)r);
				r = 0;
			} else if (r == 0) {
				r = -ESRCH;
			}
		} else {
			STAGE("base");
			/* list of pgoff==0 bases written to rw_buf by lxgr_module_base */
			r = lxgr_module_base(bpid, name);
		}
		goto finish;
	}

	/* ---- D: derive redrive (debuggable context — no module_mutex) ----
	 * "D" or "D,<anchor-pid>". Runs lxgr_redrive() in THIS writer's
	 * process context; anchor defaults to the writer's own pid so the
	 * argv-readback verification has something real to bite on. */
	if (op == 'D') {
		long anchor = 0;

		if (!lxgr_have_ram) {
			rw_status = -EPERM;
			STAGE("drv:noram");
			lxgr_spin_unlock();
			return 0;
		}

		if (next_field(&p, f, sizeof(f)) > 0)
			anchor = parse_dec(f);
		if (!anchor)
			anchor = (long)lxgr_current_pid();
		lxgr_pid_anchor = (unsigned long)anchor;
		STAGE("drv:go");
		/* RELEASE the op lock across the scan: redrive touches only
		 * derive state, and cond_resched() inside a held LDXR/STXR
		 * lock lets a spinner steal the vCPU -> livelock. */
		lxgr_spin_unlock();
		r = lxgr_redrive();
		lxgr_spin_lock();
		rw_status = r;
		rw_last_size = 0;
		rw_text_len = 0;
		if (r == 0)
			STAGE("drv:ok");
		lxgr_spin_unlock();
		return 0;
	}

	/* ---- R/W ops (unchanged layout) ---- */
	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	pid = parse_dec(f);
	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	addr = parse_hex(f);
	if (next_field(&p, f, sizeof(f)) <= 0)
		goto bad;
	size = parse_dec(f);

	value = 0;
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
	if (addr == 0 || addr >= USER_VA_TOP())
		goto bad;
	if (size < 1 || size > RW_MAX_SIZE)
		goto bad;
	if (op == 'W' && size != 1 && size != 2 && size != 4 && size != 8)
		goto bad;              /* writes stay single small values */
	if (addr + size < addr)      /* wraparound */
		goto bad;
	goto ok;
bad:
	rw_status = -EINVAL;
	rw_last_size = 0;
	rw_text_len = 0;
	lxgr_spin_unlock();
	return 0;
ok:
	STAGE("derive");
	r = lxgr_derive_phys_off();
	if (r)
		goto fail;

	switch (op) {
	case 'R':
		STAGE("read");
		r = rw_read_custom(pid, addr, size);
		break;
	case 'W':
		STAGE("write");
		r = rw_write_direct(pid, addr, size, value);
		break;
	}
finish:
fail:
	if (r == 0) {
		rw_status = 0;
		if (op == 'R')
			rw_last_size = (long)size;
		else
			rw_last_size = 0;
		STAGE("ok");
	} else {
		rw_status = r;
		rw_last_size = 0;
		rw_text_len = 0;
	}
	lxgr_spin_unlock();
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
	lxgr_spin_lock();
	/* P/B outputs are raw ASCII (decimal pid / hex base), never hex bytes. */
	if (rw_text_len > 0) {
		long t = rw_text_len;

		if (t > (long)(RW_MAX_SIZE - 1))
			t = (long)(RW_MAX_SIZE - 1);
		lxgr_memcpy(buf, rw_buf, (size_t)t);
		buf[t] = '\0';
		rw_text_len = 0;
		lxgr_spin_unlock();
		return (int)t;
	}
	s = rw_last_size;
	if (s <= 0) {
		buf[0] = '\0';
		lxgr_spin_unlock();
		return 0;
	}
	if (s > (long)RW_MAX_SIZE)
		s = (long)RW_MAX_SIZE;
	for (i = 0; i < s; i++) {
		buf[n++] = hx[(rw_buf[i] >> 4) & 0xf];
		buf[n++] = hx[rw_buf[i] & 0xf];
	}
	buf[n] = '\0';
	lxgr_spin_unlock();
	return n;
}
static const struct kernel_param_ops rw_out_ops = {
	.get = rw_out_get,
};
module_param_cb(out, &rw_out_ops, NULL, 0444);

static int rw_status_get(char *buf, const struct kernel_param *kp)
{
	char tmp[24];
	long v;
	int i = 23;
	int neg = 0;

	(void)kp;
	lxgr_spin_lock();
	v = rw_status;
	lxgr_spin_unlock();

	tmp[23] = 0;
	if (v < 0) {
		neg = 1;
		v = -v;
	}
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
	size_t n;

	(void)kp;
	/* LOCKLESS on purpose: diagnostics must stay readable while a D-op
	 * redrive holds the main spinlock. Worst case is a torn label. */
	n = lxgr_strlen(rw_stage);
	lxgr_memcpy(buf, rw_stage, n);
	buf[n] = '\0';
	return (int)n;
}
static const struct kernel_param_ops rw_stage_ops = {
	.get = rw_stage_get,
};
module_param_cb(stage, &rw_stage_ops, NULL, 0444);

static int __init rwbridge_init(void)
{
	long r = 0;

	/* Build the generic level table from the geometry params up front. */
	lxgr_init_shifts();

	if (lxgr_derive)
		r = lxgr_redrive();

	pr_info("rwbridge: self-contained module loaded "
		"(offsets tasks=%lu pid=%lu mm=%lu comm=%lu pgd=%lu "
		"arg=%lu/%lu; geometry pgd_shift=%lu levels=%d pa_off=0x%lx "
		"phys=0x%lx derive=%lu)\n",
		OF_TASKS(), OF_PID(), OF_MM(), OF_COMM(), OF_MM_PGD(),
		OF_MM_ARGSTART(), OF_MM_ARGEND(),
		PGD_SHIFT(), lxgr_levels, lxgr_page_offset, lxgr_phys_off,
		lxgr_derive);
	return 0;
}

static void __exit rwbridge_exit(void)
{
}

module_init(rwbridge_init);
module_exit(rwbridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxgr");
MODULE_DESCRIPTION("Self-contained R/W bridge (task walk + page walk + "
		   "linear map; kernel only loads the module)");
