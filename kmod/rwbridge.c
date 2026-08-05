// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for ARM64 Android kernels.
 *
 * HARD RULE: the kernel's only job is to LOAD this module (.ko via insmod).
 * Nothing else comes from the kernel. No kallsyms, no find_task_by_vpid /
 * get_task_mm / mmput / access_remote_vm, no filp_open / kernel_write, no
 * current->* / preempt_count() / thread_info derefs, no page-walk helpers.
 *
 * Everything is done inside the module with hardcoded layout constants for
 * this exact kernel build:
 *   target: 5.15.137-v5.21.770-optimizations-5.21.771.4051 (BlueStacks)
 *   vendor struct offsets (from the vendor asm-offsets / kheaders):
 *     task_struct.tasks=1232  task_struct.pid=1496  task_struct.mm=1312
 *     task_struct.comm=1960   mm_struct.pgd=64      THREAD_SIZE=0x4000
 *
 * 1) Find the process: arm64 current == sp_el0 (CONFIG_THREAD_INFO_IN_TASK,
 *    asm/current.h). Walk task_struct.tasks (circular list) and compare
 *    ->pid. Get ->mm (NULL = kernel thread / dying: bail).
 * 2) Translate user VA -> PA: walk the 4-level page table anchored at
 *    mm->pgd. This kernel: CONFIG_ARM64_VA_BITS=39, 4K pages,
 *    CONFIG_PGTABLE_LEVELS=3 -> shifts PGD=30 / PMD=21 / PTE=12, 9-bit
 *    indices, descriptor bits[1:0]: 01=block, 11=table, 00=invalid.
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
 * Plus `status` (errno of last op), `out` (hex), `stage` (debug) params.
 *
 * Link-time imports: module_layout, _printk. Only.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>

/* ============ vendor layout constants (see header comment) ============ */

#define LXGR_OFF_TASKS   1232UL
#define LXGR_OFF_PID     1496UL
#define LXGR_OFF_MM      1312UL
#define LXGR_OFF_COMM    1960UL
#define LXGR_OFF_MM_PGD  64UL

/* struct mm_struct / vm_area_struct / file / dentry layout, verified live
 * on the vendor kernel via the linear-map probes (see commit history). */
#define LXGR_OFF_MM_MMAP     0x000UL  /* struct mm_struct.mmap      */
#define LXGR_OFF_MM_ARGSTART 0x148UL  /* struct mm_struct.arg_start */
#define LXGR_OFF_MM_ARGEND   0x150UL  /* struct mm_struct.arg_end   */

#define LXGR_OFF_VMA_START  0x00UL  /* struct vm_area_struct.vm_start */
#define LXGR_OFF_VMA_NEXT   0x10UL  /* struct vm_area_struct.vm_next  */
#define LXGR_OFF_VMA_PGOFF  0x98UL  /* struct vm_area_struct.vm_pgoff */
#define LXGR_OFF_VMA_FILE   0xa0UL  /* struct vm_area_struct.vm_file  */

#define LXGR_OFF_FILE_PATH      0x10UL  /* struct file.f_path          */
#define LXGR_OFF_PATH_DENTRY    0x08UL  /* struct path.dentry (offset within f_path) */
#define LXGR_OFF_DENTRY_NAME    0x20UL  /* struct dentry.d_name (qstr) */
#define LXGR_OFF_QSTR_NAME      0x08UL  /* struct qstr.name           */
#define LXGR_OFF_QSTR_LEN       0x04UL  /* struct qstr.len (u32)      */

#define LXGR_PAGE_OFFSET 0xffffff8000000000ULL   /* 39-bit VA */
#define LXGR_USER_VA_TOP 0x8000000000ULL
#define LXGR_PAGE_SIZE   0x1000ULL

#define LXGR_PGD_SHIFT   30UL
#define LXGR_PMD_SHIFT   21UL
#define LXGR_PTE_SHIFT   12UL
#define LXGR_IDX_MASK    0x1ffUL
#define LXGR_DESC_MASK   0x3UL
#define LXGR_DESC_BLOCK  0x1UL
#define LXGR_DESC_TABLE  0x3UL
#define LXGR_PA_MASK     0x0000fffffffff000ULL   /* table ptr / 4K page PA */
#define LXGR_PMD_BLOCK   0x0000ffffffe00000ULL   /* 2MB block PA           */
#define LXGR_PGD_BLOCK   0x0000ffffc0000000ULL   /* 1GB block PA           */

/* On this guest the whole of physical RAM sits in a single contiguous window
 * [phys_off, phys_off + RAM_LIMIT) (MemTotal ~4 GiB). The linear map maps only
 * that window: a page-table entry whose address bits resolve to a PA outside
 * it is not real RAM — typically a descriptor salvaged out of a page table page
 * that the live game freed/reused mid-walk. Dereferencing such an address via
 * the linear map lands in the unmapped hole above the linear map and faults at
 * EL1 (a panic). So we never build a linear address from an out-of-window PA.
 * The bound is deliberately the full 4 GiB extent so genuine low-memory pages
 * are never rejected (any PA beyond it cannot be RAM on this box). */
#define LXGR_RAM_LIMIT   0x100000000UL

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

static void lxgr_put_hex(unsigned long v)
{
	static const char hx[] = "0123456789abcdef";
	int i = 0, k, lead;

	for (k = 15; k >= 0; k--)
		rw_buf[i++] = (unsigned char)hx[(v >> (k * 4)) & 0xf];
	lead = 0;
	while (lead < i - 1 && rw_buf[lead] == '0')
		lead++;
	if (lead) {
		for (k = lead; k < i; k++)
			rw_buf[k - lead] = rw_buf[k];
		i -= lead;
	}
	rw_text_len = i;
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

static inline unsigned long lxgr_phys_to_virt(unsigned long pa)
{
	return (pa - lxgr_phys_off) | LXGR_PAGE_OFFSET;
}

/* Build the linear-map address only when pa is inside the real RAM window.
 * Returns 0 for an out-of-window / bogus PA so callers can bail out safely
 * instead of faulting the kernel. `pa - lxgr_phys_off` unsigned-wraps to a huge
 * value when pa < phys_off, so the single >= test catches both under- and
 * overruns. */
static inline unsigned long lxgr_safe_virt(unsigned long pa)
{
	unsigned long off = pa - lxgr_phys_off;
	if (off >= LXGR_RAM_LIMIT)
		return 0;
	return off | LXGR_PAGE_OFFSET;
}

/* Derive PHYS_OFFSET from our own pgd: VA (mm->pgd) vs PA (TTBR0_EL1).
 * Must be called from the process context that owns mm (the sysfs writer). */
static long lxgr_derive_phys_off(void)
{
	unsigned long cur, mm, pgd_va, ttbr0;

	if (lxgr_phys_off_ready)
		return 0;

	cur = lxgr_current();
	mm = *(unsigned long *)(cur + LXGR_OFF_MM);
	if (!mm)
		return -EIO;
	pgd_va = *(unsigned long *)(mm + LXGR_OFF_MM_PGD);
	if (!pgd_va || (pgd_va & (LXGR_PAGE_SIZE - 1)) ||
	    pgd_va < LXGR_PAGE_OFFSET)
		return -EIO;

	asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
	ttbr0 &= LXGR_PA_MASK;               /* drop ASID/CnP bits */
	if (!ttbr0)
		return -EIO;

	lxgr_phys_off = ttbr0 - (pgd_va - LXGR_PAGE_OFFSET);
	if (lxgr_phys_off < 0x10000000ULL || lxgr_phys_off > 0x20000000000ULL)
		return -EIO;
	lxgr_phys_off_ready = 1;
	pr_info("rwbridge: linear map ready, PHYS_OFFSET=0x%lx\n",
		lxgr_phys_off);
	return 0;
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

	pid = *(unsigned long *)(p + LXGR_OFF_PID);
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;               /* layout sanity: current->pid sane */

	for (i = 0; i < 1048576; i++) {
		pid = *(unsigned long *)(p + LXGR_OFF_PID);
		if ((unsigned int)pid == (unsigned int)want) {
			*mm_out = *(unsigned long *)(p + LXGR_OFF_MM);
			return 0;
		}
		nxt = *(unsigned long *)(p + LXGR_OFF_TASKS);
		if (!nxt)
			return -ESRCH;
		p = nxt - LXGR_OFF_TASKS;  /* next node -> task_struct */
		if (p == cur)
			break;               /* wrapped whole list */
	}
	return -ESRCH;
}

/* ================= page table walk =================================== */

/* Translate user VA to physical PA through mm->pgd (a linear-map VA of the
 * top-level table). Handles 1GB/2MB blocks and 4K pages, per-level. */
static long lxgr_translate(unsigned long pgd_va, unsigned long va,
			   unsigned long *pa_out)
{
	unsigned long e, t;
	unsigned long idx;

	if (va >= LXGR_USER_VA_TOP)
		return -EINVAL;

	/* level 0 (PGD, bits 38:30) */
	idx = (va >> LXGR_PGD_SHIFT) & LXGR_IDX_MASK;
	e = *(volatile unsigned long *)(pgd_va + idx * 8);
	t = e & LXGR_DESC_MASK;
	if (t == LXGR_DESC_BLOCK) {
		*pa_out = (e & LXGR_PGD_BLOCK) + (va & 0x3fffffffUL);
		return 0;
	}
	if (t != LXGR_DESC_TABLE)
		return -EFAULT;

	/* level 1 (PMD, bits 29:21): the referenced page-table page must live in
	 * RAM. A stale/foreign descriptor (e.g. salvaged from a table the live
	 * game freed mid-walk) yields a PA outside the RAM window; dereferencing
	 * its linear address faults at EL1 (panic), so reject it up front. */
	idx = (va >> LXGR_PMD_SHIFT) & LXGR_IDX_MASK;
	{
		unsigned long lin = lxgr_safe_virt(e & LXGR_PA_MASK);
		if (!lin)
			return -EFAULT;
		e = *(volatile unsigned long *)(lin + idx * 8);
	}
	t = e & LXGR_DESC_MASK;
	if (t == LXGR_DESC_BLOCK) {
		*pa_out = (e & LXGR_PMD_BLOCK) + (va & 0x1fffffUL);
		return 0;
	}
	if (t != LXGR_DESC_TABLE)
		return -EFAULT;

	/* level 2 (PTE, bits 20:12): same safety guard on the table page, then a
	 * final guard on the data page PA before exposing it to caller. */
	idx = (va >> LXGR_PTE_SHIFT) & LXGR_IDX_MASK;
	{
		unsigned long lin = lxgr_safe_virt(e & LXGR_PA_MASK);
		if (!lin)
			return -EFAULT;
		e = *(volatile unsigned long *)(lin + idx * 8);
	}
	t = e & LXGR_DESC_MASK;
	if (t != LXGR_DESC_TABLE)        /* valid page descriptor = 0b11 */
		return -EFAULT;
	if (!lxgr_safe_virt(e & LXGR_PA_MASK))
		return -EFAULT;

	*pa_out = (e & LXGR_PA_MASK) + (va & 0xfffUL);
	return 0;
}

/* ================= READ ============================================== */

static long rw_read_custom(unsigned long pid, unsigned long addr,
			   unsigned long size)
{
	unsigned long mm, pgd, done = 0;

	if (lxgr_find_task(pid, &mm) || !mm)
		return -ESRCH;
	pgd = *(unsigned long *)(mm + LXGR_OFF_MM_PGD);
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
	pgd = *(unsigned long *)(mm + LXGR_OFF_MM_PGD);
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

	pid = *(unsigned long *)(p + LXGR_OFF_PID);
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;

	for (i = 0; i < 1048576; i++) {
		pid = *(unsigned long *)(p + LXGR_OFF_PID);
		if ((unsigned int)pid == (unsigned int)want) {
			if (task_out)
				*task_out = p;
			if (mm_out)
				*mm_out = *(unsigned long *)(p + LXGR_OFF_MM);
			return 0;
		}
		nxt = *(unsigned long *)(p + LXGR_OFF_TASKS);
		if (!nxt)
			return -ESRCH;
		p = nxt - LXGR_OFF_TASKS;
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
	mm = *(unsigned long *)(task + LXGR_OFF_MM);
	if (!mm)
		return 0;                 /* kernel thread: no user cmdline */
	pgd = *(unsigned long *)(mm + LXGR_OFF_MM_PGD);
	if (!pgd)
		return 0;
	as = *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART);
	ae = *(unsigned long *)(mm + LXGR_OFF_MM_ARGEND);
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

	pid = *(unsigned long *)(p + LXGR_OFF_PID);
	if ((pid & 0xffffffffUL) > 0x7fffffffUL)
		return -EIO;

	for (i = 0; i < 1048576; i++) {
		pid = *(unsigned long *)(p + LXGR_OFF_PID);
		if ((unsigned int)pid >= 1 &&
		    lxgr_task_cmdline_has(p, sub))
			return (long)(unsigned int)pid;
		nxt = *(unsigned long *)(p + LXGR_OFF_TASKS);
		if (!nxt)
			return -ESRCH;
		p = nxt - LXGR_OFF_TASKS;
		if (p == cur)
			break;
	}
	return -ESRCH;
}

/* Read a short NUL-terminated string from a linear-map (kernel) VA. */
static long lxgr_kstr(unsigned long va, unsigned long max, char *out)
{
	unsigned long off;

	if (va < LXGR_PAGE_OFFSET)
		return -EFAULT;
	off = va - LXGR_PAGE_OFFSET;
	if (off >= LXGR_RAM_LIMIT || off + max > LXGR_RAM_LIMIT)
		return -EFAULT;
	lxgr_memcpy(out, (const void *)va, max);
	out[max] = 0;
	return 0;
}

/* B,<pid>,<lib>: walk the target's VMA list (mm->mmap / vma->vm_next), find
 * the file-backed mapping whose dentry basename matches `lib`, and return the
 * lowest vm_start (its ELF base) via lxgr_put_hex. Fully in-kernel: the file
 * name comes from the live struct file/dentry, never from /proc. */
static long lxgr_module_base(unsigned long pid, const char *lib)
{
	unsigned long task, mm, mmap_va, vma, nxt;
	unsigned long liblen = lxgr_strlen(lib);
	unsigned long best = 0;
	int i;

	if (liblen == 0 || liblen > 63)
		return -EINVAL;
	if (lxgr_find_task_va(pid, &task, &mm) || !mm)
		return -ESRCH;
	mmap_va = *(unsigned long *)(mm + LXGR_OFF_MM_MMAP);
	if (!mmap_va || mmap_va < LXGR_PAGE_OFFSET)
		return -ESRCH;

	for (vma = mmap_va, i = 0; i < 1048576; i++) {
		unsigned long start, file, pgoff, dentry, dn, hl;
		unsigned long len;
		char nm[96];

		if (vma < LXGR_PAGE_OFFSET)
			break;
		start = *(unsigned long *)(vma + LXGR_OFF_VMA_START);
		if (start == 0 || start >= LXGR_USER_VA_TOP)
			break;             /* stale list / not a user vma */
		file = *(unsigned long *)(vma + LXGR_OFF_VMA_FILE);
		pgoff = *(unsigned long *)(vma + LXGR_OFF_VMA_PGOFF);
		if (file >= LXGR_PAGE_OFFSET) {
			dentry = *(unsigned long *)(file + LXGR_OFF_FILE_PATH +
						    LXGR_OFF_PATH_DENTRY);
			if (dentry >= LXGR_PAGE_OFFSET) {
				hl = *(unsigned long *)(dentry + LXGR_OFF_DENTRY_NAME);
				dn = *(unsigned long *)(dentry + LXGR_OFF_DENTRY_NAME +
							LXGR_OFF_QSTR_NAME);
				len = hl >> 32;   /* qstr.hash_len: len in high half */
				if (len > 63)
					len = 63;
				if (dn >= LXGR_PAGE_OFFSET &&
				    lxgr_kstr(dn, len + 1, nm) == 0 &&
				    len == liblen &&
				    !lxgr_memcmp(nm, lib, liblen)) {
					/* lib found: prefer the offset-0 mapping,
					 * else the lowest vma of this lib. */
					if (pgoff == 0)
						return (long)start;
					if (!best || start < best)
						best = start;
				}
			}
		}
		nxt = *(unsigned long *)(vma + LXGR_OFF_VMA_NEXT);
		if (!nxt || nxt == mmap_va || nxt < LXGR_PAGE_OFFSET)
			break;
		vma = nxt;
	}
	return best ? (long)best : -ESRCH;
}

/* ================= param set: guaranteed entry point ================= */

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
			r = lxgr_module_base(bpid, name);
			if (r > 0) {
				lxgr_put_hex((unsigned long)r);
				r = 0;
			} else if (r == 0) {
				r = -ESRCH;
			}
		}
		goto finish;
	}

	/* ---- debug: D,0,0,0 -> current mm arg/env region head (TEMPORARY) ---- */
	if (op == 'D') {
		unsigned long cur, mm, v[8];
		int i;

		STAGE("debug");
		cur = lxgr_current();
		mm = *(unsigned long *)(cur + LXGR_OFF_MM);
		v[0] = mm;
		v[1] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART) : 0;
		v[2] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGEND) : 0;
		v[3] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART + 0x18) : 0; /* env_start */
		v[4] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART + 0x20) : 0; /* env_end   */
		v[5] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART - 0x28) : 0; /* start_stack */
		v[6] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART - 0x20) : 0; /* brk */
		v[7] = mm ? *(unsigned long *)(mm + LXGR_OFF_MM_MMAP) : 0;
		for (i = 0; i < 8; i++)
			lxgr_memcpy(rw_buf + i * 8, &v[i], 8);
		size = 8 * 8;
		r = 0;
		goto finish;
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
	if (addr == 0 || addr >= LXGR_USER_VA_TOP)
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
		if (op == 'R' || op == 'D')
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
	lxgr_spin_lock();
	n = lxgr_strlen(rw_stage);
	lxgr_memcpy(buf, rw_stage, n);
	lxgr_spin_unlock();
	buf[n] = '\0';
	return (int)n;
}
static const struct kernel_param_ops rw_stage_ops = {
	.get = rw_stage_get,
};
module_param_cb(stage, &rw_stage_ops, NULL, 0444);

static int __init rwbridge_init(void)
{
	pr_info("rwbridge: self-contained module loaded (offsets "
		"tasks=%lu pid=%lu mm=%lu comm=%lu pgd=%lu)\n",
		LXGR_OFF_TASKS, LXGR_OFF_PID, LXGR_OFF_MM, LXGR_OFF_COMM,
		LXGR_OFF_MM_PGD);
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
