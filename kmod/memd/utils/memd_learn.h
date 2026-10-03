#ifndef MEMD_LEARN_H
#define MEMD_LEARN_H

#include <linux/types.h>

struct task_struct;
struct mm_struct;
struct vm_area_struct;
struct file;
struct file_operations;
struct dentry;

/* Runtime struct-offset learning (KPM-grade universality). Instead of
 * trusting build-header layouts on foreign kernels, derive critical
 * field offsets at init from LIVE anchors:
 * - task->pid/tgid: adjacent equal u32 pair matching task_pid_vnr /
 *   task_tgid_vnr of the loading task (single-threaded: pid == tgid).
 * - task->comm: get_task_comm value scanned as a string.
 * - task->mm: get_task_mm value scanned as a pointer.
 * - mm->pgd: TTBR0_EL1 value scanned in mm (validated by walk checks
 *   on every use — a wrong pgd fails closed, never mis-walks).
 * - vma->vm_start/vm_end: adjacent u64 pair bracketing a known address
 *   (from /proc/self/maps of the loading task), confirmed on two lines.
 *
 * Everything else (cosmetic/listing fields, stable structs) keeps
 * compiled offsets with per-generation CI asserts. Learned offsets
 * are per-boot constants (same kernel for every task).
 */
struct memd_learned {
    int t_pid;    /* task_struct.pid, -1 unknown */
    int t_tgid;   /* task_struct.tgid, -1 unknown */
    int t_comm;   /* task_struct.comm, -1 unknown */
    int t_mm;     /* task_struct.mm, -1 unknown */
    int t_cred;   /* task_struct.cred, -1 unknown */
    int m_pgd;    /* mm_struct.pgd, -1 unknown */
    int v_start;  /* vm_area_struct.vm_start, -1 unknown */
    int v_end;    /* vm_area_struct.vm_end, -1 unknown */
};

extern struct memd_learned memd_learned;

/* Learn all offsets. Always returns 0 (per-field fail-soft, loud). */
int memd_learn(void);
void memd_learn_vma_once(void);

/* Readers: learned offset when known, compiled fallback otherwise. */
pid_t memd_t_pid(struct task_struct *t);
pid_t memd_t_tgid(struct task_struct *t);
struct mm_struct *memd_t_mm(struct task_struct *t);
int memd_t_mm_null(struct task_struct *t);
void memd_t_comm(struct task_struct *t, char *buf, size_t cap);
unsigned long memd_m_pgd(struct mm_struct *mm);
/* Validated pgd (shape-checked table, fail-closed 0). Walk entry point. */
unsigned long memd_valid_pgd(struct mm_struct *mm);
unsigned long memd_v_start(struct vm_area_struct *vma);
unsigned long memd_v_end(struct vm_area_struct *vma);

/* struct file fields move per generation (6.6/6.12 rework): resolved by
 * running generation. Returns NULL/0 when unknown (callers fail soft). */
struct file_operations *memd_file_fop(struct file *f);
struct dentry *memd_file_dentry(struct file *f);

/* Privilege checks without build-header cred offsets (capable() inlines
 * task->cred from build headers — wrong on foreign kernels = crash).
 * Learned cred offset + stable struct cred layout (usage@0, uid@4,
 * cap_effective low word@56, CI-asserted per generation). Fail closed
 * (deny) when unlearned. */
int memd_capable(int cap);
unsigned int memd_uid(void);

/* vma->vm_file learned the same way (known pathname match). */
unsigned long memd_v_file(struct vm_area_struct *vma);

#endif /* MEMD_LEARN_H */
