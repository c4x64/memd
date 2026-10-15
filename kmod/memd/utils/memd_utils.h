#ifndef MEMD_UTILS_H
#define MEMD_UTILS_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include "memd_common.h"
#include "karray_list.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#define MM_WRITE_LOCK(mm) mmap_write_lock(mm);
#define MM_WRITE_UNLOCK(mm) mmap_write_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#define MM_WRITE_LOCK(mm) down_write(&(mm)->mmap_sem);
#define MM_WRITE_UNLOCK(mm) up_write(&(mm)->mmap_sem);
#endif

#define WMT_NORMAL 0
#define WMT_NORMAL_TAGGED 1
#define WMT_NORMAL_NC 2
#define WMT_NORMAL_WT 3
#define WMT_DEVICE_nGnRnE 4
#define WMT_DEVICE_nGnRE 5
#define WMT_DEVICE_GRE 6
#define WMT_NORMAL_iNC_oWB 7

bool is_file_exist(const char* filename);

pte_t* page_from_virt_user(struct mm_struct* mm, uintptr_t va);

uintptr_t vaddr_to_phy_addr(struct mm_struct* mm, uintptr_t va);

/* Runtime-resolved VFS file operations (avoid VFS namespace import). */
int memd_filp_open(const char* filename, int flags, umode_t mode, struct file** f);
int memd_filp_close(struct file** f, fl_owner_t id);

/* kernel_read without the import (GKI-protected on trimmed kernels). */
struct cred;
struct kernel_siginfo;
enum pid_type;
ssize_t memd_kernel_read(struct file *f, void *buf, size_t count, loff_t *pos);

/* __put_cred without the import. Drop-a-ref only; silent if unresolvable. */
void memd_put_cred(struct cred *cred);

/* Signal delivery without the send_signal import (trimmed on some
 * kernels): do_send_sig_info where it resolves. */
int memd_send_signal(int sig, struct kernel_siginfo *info,
                     struct task_struct *task, enum pid_type type);

/* Executable allocation without the vmalloc_exec import. */
void *memd_vmalloc_exec(unsigned long size);

/* struct input_dev plausibility without the input_dev_valid import. */
struct input_dev;
int memd_input_dev_ok(struct input_dev *dev);

/* Fault-safe kernel access (extable-guarded; no imports are required). */
int memd_safe_read64(const void *src, unsigned long *dst);
int memd_safe_read32(const void *src, unsigned int *dst);
int memd_safe_write64(void *dst, unsigned long v);
int memd_safe_write32(void *dst, unsigned int v);
/* Write a u64 to a possibly read-only kernel page (AP flip + TLBI). */
int memd_table_write64(unsigned long entry_va, unsigned long val);
/* Page permissions + phys for a kernel VA (descriptor metadata only). */
int memd_page_perms(uintptr_t va, uintptr_t *pa_out, unsigned *present_out,
                    unsigned *level_out, unsigned *ap_out, unsigned *xn_out,
                    unsigned long *desc_out);

struct page* vaddr_to_page(struct mm_struct* mm, uintptr_t va);

int translate_process_vaddr(pid_t pid, uintptr_t vaddr, uintptr_t* paddr_out);

unsigned long kallsyms_lookup_name_ex(const char* symbol_name);

/* pfn_valid without the import (see memd_utils.c for the chain). */
int memd_pfn_ok(unsigned long pfn);

struct task_struct* get_target_task(pid_t pid);

/* find_vma without the import: name differs by generation (find_vma vs
 * __find_vma), so resolve both at runtime. Fail-soft NULL when neither
 * resolves (callers treat as "no vma"). */
struct vm_area_struct* memd_find_vma(struct mm_struct* mm, unsigned long addr);

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2);
void compare_task_struct(struct task_struct* task1, struct task_struct* task2);

static __always_inline void set_current(struct task_struct* tsk) {
    unsigned long tmp = (unsigned long)tsk;

    asm volatile("msr sp_el0, %0" : : "r"(tmp) : "memory");
}

uintptr_t get_module_base(pid_t pid, char* name, int vm_flag);

int is_pid_alive(pid_t pid);

pid_t find_process_by_name(const char* name);

void show_module(void);
void hide_module(void);

int give_root(void);

int cfi_bypass(void);

void __iomem* memd_ioremap_prot(uintptr_t phys_addr, size_t size, pgprot_t prot);

int convert_wmt_to_pgprot(int wmt_type, pgprot_t* prot_out);

#endif // MEMD_UTILS_H
/* kmod/memd/utils/memd_utils.h[∂] */
