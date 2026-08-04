// SPDX-License-Identifier: GPL-2.0
/*
 * rwbridge.c - self-contained memory R/W bridge for ARM64 Android kernels.
 *
 * HARD RULE: the kernel's only job is to LOAD this module (.ko via insmod).
 * Nothing else comes from the kernel. No kallsyms, no find_task_by_vpid /
 * get_task_mm / mmput / access_remote_vm, no filp_open / kernel_write, no
 * current->* / preempt_count() / thread_info derefs, no page-walk helpers.
 *
 * Layout constants are taken from THIS kernel's own headers at build time:
 * offsetof(struct task_struct,*), offsetof(struct mm_struct,pgd), PAGE_OFFSET
 * and TASK_SIZE (from asm/memory.h), and the pgtable shifts (from
 * asm/pgtable-hwdef.h). Since struct offsets/VA_BITS are NOT part of the GKI
 * stable-KMI and vary per major, the user compiles this module against the
 * exact kernel it will be loaded on — no offsets file, no CI generation.
 * arm64 4K pages, 3 or 4 levels (39/48-bit VA) are handled generically. A
 * .ko only insmods on a kernel with a matching vermagic, so run.sh just picks
 * the bundled rwbridge-*.ko that matches (CRC check refuses the rest).
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
 *   P,<cmdline-substr>     find first task whose argv contains substr -> pid
 *                          (decimal, in `out`; replaces the /proc/<pid>/cmdline
 *                          scan — the task list + page tables are walked in
 *                          the kernel, nothing touches /proc)
 *   B,pid,<libname>        resolve the offset-0 mapping of the named shared
 *                          object via the target's vma list + file dentry
 *                          name -> base (hex, in `out`; replaces the
 *                          /proc/<pid>/maps parser)
 * Plus `status` (errno of last op), `out` (hex bytes / ASCII pid/base),
 * `stage` (debug) params.
 *
 * Link-time imports: module_layout, _printk. Only.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/stddef.h>
#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>
#include <asm/page.h>

/* Per-kernel layout is taken from THIS kernel's own headers at build time:
 * the user compiles this module against the exact kernel it will be loaded
 * on, so offsetof() / PAGE_OFFSET / TASK_SIZE / pgtable shifts are correct
 * for that kernel. No offsets file, no CI-generated constants. Offsets are
 * NOT part of the GKI stable-KMI and vermagic encodes the full release, so a
 * .ko only ever loads on the kernel it was built for. */
#define LXGR_OFF_TASKS   offsetof(struct task_struct, tasks)
#define LXGR_OFF_PID     offsetof(struct task_struct, pid)
#define LXGR_OFF_MM      offsetof(struct task_struct, mm)
#define LXGR_OFF_COMM    offsetof(struct task_struct, comm)
#define LXGR_OFF_MM_PGD  offsetof(struct mm_struct, pgd)

/* PID + module-base discovery (operations P / B) traverse the target's own
 * mm/vma/file/dentry, so their field offsets come from header offsetof() too. */
#define LXGR_OFF_MM_ARGSTART offsetof(struct mm_struct, arg_start)
#define LXGR_OFF_MM_ARGEND   offsetof(struct mm_struct, arg_end)
#define LXGR_OFF_MM_MMAP     offsetof(struct mm_struct, mmap)

#define LXGR_OFF_VMA_START  offsetof(struct vm_area_struct, vm_start)
#define LXGR_OFF_VMA_PGOFF  offsetof(struct vm_area_struct, vm_pgoff)
#define LXGR_OFF_VMA_FILE   offsetof(struct vm_area_struct, vm_file)
#define LXGR_OFF_VMA_NEXT   offsetof(struct vm_area_struct, vm_next)

#define LXGR_OFF_FILE_PATH    offsetof(struct file, f_path)
#define LXGR_OFF_PATH_DENTRY  offsetof(struct path, dentry)
#define LXGR_OFF_DENTRY_NAME  offsetof(struct dentry, d_name)
#define LXGR_OFF_QSTR_NAME    offsetof(struct qstr, name)
#define LXGR_OFF_QSTR_LEN     offsetof(struct qstr, len)

#define LXGR_PAGE_SIZE   (1UL << PAGE_SHIFT)

/* arm64 VA geometry from this kernel's headers (4K pages, 39/48-bit VA). */
#define LXGR_PAGE_OFFSET ((unsigned long)PAGE_OFFSET)
#define LXGR_USER_VA_TOP ((unsigned long)TASK_SIZE)

#define LXGR_IDX_MASK    0x1ffUL
#define LXGR_DESC_MASK   0x3UL
#define LXGR_DESC_BLOCK  0x1UL
#define LXGR_DESC_TABLE  0x3UL
#define LXGR_PA_MASK     0x0000fffffffff000ULL   /* table ptr / 4K page PA */
#define LXGR_PMD_BLOCK   0x0000ffffffe00000ULL   /* 2MB block PA           */
#define LXGR_PGD_BLOCK   0x0000ffffc0000000ULL   /* 1GB block PA           */

/* Page-table levels: 3 (39-bit VA) or 4 (48-bit VA), from the kernel config. */
#if defined(CONFIG_PGTABLE_LEVELS) && CONFIG_PGTABLE_LEVELS == 4
#define LXGR_PGT_LEVELS 4
static const unsigned long lxgr_lvl_shift[LXGR_PGT_LEVELS] = {
	PGDIR_SHIFT, PUD_SHIFT, PMD_SHIFT, PAGE_SHIFT
};
static const unsigned long lxgr_lvl_block[LXGR_PGT_LEVELS] = {
	LXGR_PGD_BLOCK, LXGR_PGD_BLOCK, LXGR_PMD_BLOCK, 0UL
};
#else
#define LXGR_PGT_LEVELS 3
static const unsigned long lxgr_lvl_shift[LXGR_PGT_LEVELS] = {
	PGDIR_SHIFT, PMD_SHIFT, PAGE_SHIFT
};
static const unsigned long lxgr_lvl_block[LXGR_PGT_LEVELS] = {
	LXGR_PGD_BLOCK, LXGR_PMD_BLOCK, 0UL
};
#endif

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

/* A kernel object (task/vma/file/dentry/qstr string) lives in the
 * linearly-mapped RAM window above PAGE_OFFSET. Guard every foreign kernel
 * pointer with this before dereferencing, so a stale/reused address can
 * never fault EL1. */
static inline int lxgr_kern_ptr(unsigned long p)
{
	return (p - LXGR_PAGE_OFFSET) < LXGR_RAM_LIMIT;
}

/* Reads chunk through the bulk path; 1024 bytes keeps the hex `out` payload
 * (2 chars/byte = 2048 chars) safely under the one PAGE_SIZE buffer that the
 * kernel's param-framework hands to rw_out_get, while cutting the sysfs op
 * count ~4x versus 256-byte chunks (less per-op noise for the read path). */
#define RW_MAX_SIZE      1024UL

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
static long rw_text_len;                  /* >0: `out` is raw ASCII text     */
static long rw_status;
static char rw_stage[16] = "idle";

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

/* substring test (libc strstr is a link-time import, so self-contained). */
static int lxgr_strstr(const char *hay, const char *needle)
{
	size_t hl = lxgr_strlen(hay), nl = lxgr_strlen(needle);
	size_t i, j;

	if (!nl || nl > hl)
		return 0;
	for (i = 0; i + nl <= hl; i++) {
		for (j = 0; j < nl; j++)
			if (hay[i + j] != needle[j])
				break;
		if (j == nl)
			return 1;
	}
	return 0;
}

/* exact name match against a (name,len) qstr pair. */
static int lxgr_name_eq(const unsigned char *name, unsigned long len,
			const char *want)
{
	size_t wl = lxgr_strlen(want);
	unsigned long k;

	if (len != wl)
		return 0;
	for (k = 0; k < len; k++)
		if (name[k] != (unsigned char)want[k])
			return 0;
	return 1;
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

static long lxgr_translate(unsigned long pgd_va, unsigned long va,
			   unsigned long *pa_out);

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

/* Read up to cap bytes of a task's argv string (its cmdline) into out, as a
 * single NUL-terminated C string. Uses the same safe translate/linear-map path
 * as rw_read_custom, so an unmapped/racing arg page just ends the read. */
static long lxgr_read_cmdline(unsigned long mm, char *out, unsigned long cap)
{
	unsigned long arg_start, arg_end, pgd, done = 0;

	if (!lxgr_kern_ptr(mm))
		return 0;
	arg_start = *(unsigned long *)(mm + LXGR_OFF_MM_ARGSTART);
	arg_end   = *(unsigned long *)(mm + LXGR_OFF_MM_ARGEND);
	if (!arg_start || arg_end <= arg_start)
		return 0;
	if (arg_end - arg_start > cap)
		arg_end = arg_start + cap;
	pgd = *(unsigned long *)(mm + LXGR_OFF_MM_PGD);
	if (!pgd)
		return 0;

	while (arg_start + done < arg_end) {
		unsigned long pa, chunk, lin, k;
		long r = lxgr_translate(pgd, arg_start + done, &pa);

		if (r)
			break;
		if (!lxgr_safe_virt(pa))
			break;
		chunk = LXGR_PAGE_SIZE - (pa & (LXGR_PAGE_SIZE - 1));
		if (chunk > arg_end - (arg_start + done))
			chunk = arg_end - (arg_start + done);
		lin = lxgr_phys_to_virt(pa);
		for (k = 0; k < chunk; k++) {
			char c = *(char *)(lin + k);
			out[done + k] = c;
			if (c == 0) {
				out[done + k] = 0;
				return (long)(done + k);
			}
		}
		done += chunk;
	}
	out[done] = 0;
	return (long)done;
}

/* Find a task whose cmdline contains `sub` (like the old /proc/<pid>/cmdline
 * scan). Walks the task list exactly like lxgr_find_task — same anchored,
 * bounded, self-contained traversal; the cmdline is read through the page
 * tables, never through /proc. Returns the target pid. */
static long lxgr_find_task_by_name(const char *sub, unsigned long *pid_out)
{
	unsigned long cur = lxgr_current();
	unsigned long p = cur, nxt, mm;
	char cmd[192];
	int i;

	for (i = 0; i < 1048576; i++) {
		mm = *(unsigned long *)(p + LXGR_OFF_MM);
		if (mm && lxgr_kern_ptr(mm)) {
			long n = lxgr_read_cmdline(mm, cmd, sizeof(cmd) - 1);
			if (n > 0 && lxgr_strstr(cmd, sub)) {
				*pid_out = *(unsigned long *)(p + LXGR_OFF_PID);
				return 0;
			}
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

/* Resolve the load base of the task's mapping of a named shared object (e.g.
 * libil2cpp.so) — replaces the /proc/<pid>/maps parser. Walks the target's
 * vm_area_struct list, and for each offset-0 mapping with a real file match
 * the file's leaf dentry name. Every kernel pointer is guarded by
 * lxgr_kern_ptr before deref, and a file backed by a live vma is itself held
 * alive by the mapping, so this cannot fault EL1. Returns the vm_start. */
static long lxgr_module_base(unsigned long pid, const char *lib,
			     unsigned long *base_out)
{
	unsigned long mm, vma;
	long r = lxgr_find_task(pid, &mm);
	int i;

	if (r || !mm || !lxgr_kern_ptr(mm))
		return -ESRCH;
	vma = *(unsigned long *)(mm + LXGR_OFF_MM_MMAP);

	for (i = 0; vma && i < 1048576; i++) {
		unsigned long pgoff, f, dentry, dn, dnlen;
		unsigned long next;

		if (!lxgr_kern_ptr(vma))
			break;
		next = *(unsigned long *)(vma + LXGR_OFF_VMA_NEXT);
		pgoff = *(unsigned long *)(vma + LXGR_OFF_VMA_PGOFF);
		f     = *(unsigned long *)(vma + LXGR_OFF_VMA_FILE);
		if (pgoff == 0 && f && lxgr_kern_ptr(f)) {
			dentry = *(unsigned long *)(f + LXGR_OFF_FILE_PATH +
						    LXGR_OFF_PATH_DENTRY);
			if (dentry && lxgr_kern_ptr(dentry)) {
				dn = *(unsigned long *)(dentry + LXGR_OFF_DENTRY_NAME +
							LXGR_OFF_QSTR_NAME);
				dnlen = *(unsigned long *)(dentry + LXGR_OFF_DENTRY_NAME +
							   LXGR_OFF_QSTR_LEN);
				if (dn && dnlen > 0 && dnlen < 128 && lxgr_kern_ptr(dn) &&
				    lxgr_name_eq((const unsigned char *)dn, dnlen, lib)) {
					*base_out = *(unsigned long *)(vma + LXGR_OFF_VMA_START);
					return 0;
				}
			}
		}
		vma = next;
	}
	return -ESRCH;
}

/* ================= page table walk =================================== */

/* Translate user VA to physical PA through mm->pgd (a linear-map VA of the
 * top-level table). Generic walk: 3 levels (39-bit VA, PGD/PMD/PTE) or
 * 4 levels (48-bit VA, PGD/PUD/PMD/PTE), with 1GB/2MB block descriptors at
 * the intermediate levels and 4K pages at the leaf. */
static long lxgr_translate(unsigned long pgd_va, unsigned long va,
			   unsigned long *pa_out)
{
	unsigned long e, lin;
	int lvl;

	if (va >= LXGR_USER_VA_TOP)
		return -EINVAL;

	/* level 0: entry is in the top-level table itself (pgd_va is a kernel VA). */
	lin = pgd_va;
	for (lvl = 0; lvl < LXGR_PGT_LEVELS; lvl++) {
		unsigned long idx = (va >> lxgr_lvl_shift[lvl]) & LXGR_IDX_MASK;
		unsigned long t;

		e = *(volatile unsigned long *)(lin + idx * 8);
		t = e & LXGR_DESC_MASK;

		if (t == LXGR_DESC_BLOCK) {
			/* block descriptor (1GB/2MB) at an intermediate level. */
			if (lvl == LXGR_PGT_LEVELS - 1)
				return -EFAULT;
			*pa_out = (e & lxgr_lvl_block[lvl]) +
				  (va & ((1UL << lxgr_lvl_shift[lvl]) - 1));
			return 0;
		}
		if (t != LXGR_DESC_TABLE)
			return -EFAULT;
		if (lvl == LXGR_PGT_LEVELS - 1)
			break;
		/* descend: the referenced page-table page must live in RAM. A
		 * stale/foreign descriptor (e.g. salvaged from a table the live
		 * game freed mid-walk) yields a PA outside the RAM window;
		 * dereferencing its linear address faults at EL1 (panic), so
		 * reject it up front. */
		lin = lxgr_safe_virt(e & LXGR_PA_MASK);
		if (!lin)
			return -EFAULT;
	}

	/* leaf PTE: valid page descriptor = 0b11. Final guard on the data
	 * page PA before exposing it to caller. */
	if (!lxgr_safe_virt(e & LXGR_PA_MASK))
		return -EFAULT;
	*pa_out = (e & LXGR_PA_MASK) + (va & (LXGR_PAGE_SIZE - 1));
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

/* ASCII payload for the `out` param (decimal pid / hex base). */
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
		if (n <= 0)
			goto bad;
		STAGE("derive");
		if (lxgr_derive_phys_off())
			goto fail;
		if (op == 'P') {
			unsigned long found;
			STAGE("pid");
			r = lxgr_find_task_by_name(name, &found);
			if (r == 0)
				lxgr_put_dec(found);
		} else {
			unsigned long base;
			STAGE("base");
			r = lxgr_module_base(bpid, name, &base);
			if (r == 0)
				lxgr_put_hex(base);
		}
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
	if (lxgr_derive_phys_off())
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
	if (rw_text_len > 0) {
		long m = rw_text_len;
		if (m > (long)RW_MAX_SIZE)
			m = (long)RW_MAX_SIZE;
		for (i = 0; i < m; i++)
			buf[i] = (char)rw_buf[i];
		buf[i] = '\0';
		lxgr_spin_unlock();
		return (int)m;
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
