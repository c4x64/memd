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
    int v_flags;  /* vm_area_struct.vm_flags, -1 unknown */
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
unsigned long memd_v_flags(struct vm_area_struct *vma);

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

/* Additional learned offsets for improved universality */
struct memd_learned_ext {
    int t_files;      /* task_struct.files */
    int t_signal;     /* task_struct.signal */
    int t_sighand;    /* task_struct.sighand */
    int t_thread;     /* task_struct.thread */
    int t_stack;      /* task_struct.stack */
    int t_pid_link;   /* task_struct.pids */
    int t_real_parent; /* task_struct.real_parent */
    int t_parent;     /* task_struct.parent */
    int t_group_leader; /* task_struct.group_leader */
    int t_nsproxy;    /* task_struct.nsproxy */
    int t_fs;         /* task_struct.fs */
    int t_io_context; /* task_struct.io_context */
    int t_cgroups;    /* task_struct.cgroups */
    int t_robust_list; /* task_struct.robust_list */
    int t_perf_event_ctxp; /* task_struct.perf_event_ctxp */
    int t_bts;        /* task_struct.bts */
    int m_mmap;       /* mm_struct.mmap */
    int m_mmap_cache; /* mm_struct.mmap_cache */
    int m_map_count;  /* mm_struct.map_count */
    int m_pgtables_bytes; /* mm_struct.pgtables_bytes */
    int m_hiwater_rss; /* mm_struct.hiwater_rss */
    int m_hiwater_vm;  /* mm_struct.hiwater_vm */
    int m_total_vm;    /* mm_struct.total_vm */
    int m_locked_vm;   /* mm_struct.locked_vm */
    int m_pinned_vm;   /* mm_struct.pinned_vm */
    int m_data_vm;     /* mm_struct.data_vm */
    int m_exec_vm;     /* mm_struct.exec_vm */
    int m_stack_vm;    /* mm_struct.stack_vm */
    int m_arg_lock;    /* mm_struct.arg_lock */
    int m_arg_start;   /* mm_struct.arg_start */
    int m_arg_end;     /* mm_struct.arg_end */
    int m_env_start;   /* mm_struct.env_start */
    int m_env_end;     /* mm_struct.env_end */
    int f_fpath;      /* struct file.f_path */
    int f_op;         /* struct file.f_op */
    int f_inode;      /* struct file.f_inode */
    int f_mapping;    /* struct file.f_mapping */
    int f_pos;        /* struct file.f_pos */
    int f_flags;      /* struct file.f_flags */
    int f_mode;       /* struct file.f_mode */
    int f_count;      /* struct file.f_count */
    int d_name;       /* struct dentry.d_name */
    int d_parent;     /* struct dentry.d_parent */
    int d_inode;      /* struct dentry.d_inode */
    int d_op;         /* struct dentry.d_op */
    int d_sb;         /* struct dentry.d_sb */
    int d_lock;       /* struct dentry.d_lock */
    int d_count;      /* struct dentry.d_count */
    int d_flags;      /* struct dentry.d_flags */
    int i_ino;        /* struct inode.i_ino */
    int i_mode;       /* struct inode.i_mode */
    int i_uid;        /* struct inode.i_uid */
    int i_gid;        /* struct inode.i_gid */
    int i_size;       /* struct inode.i_size */
    int i_blocks;     /* struct inode.i_blocks */
    int i_atime;      /* struct inode.i_atime */
    int i_mtime;      /* struct inode.i_mtime */
    int i_ctime;      /* struct inode.i_ctime */
    int i_blkbits;    /* struct inode.i_blkbits */
    int i_flags;      /* struct inode.i_flags */
    int i_sb;         /* struct inode.i_sb */
    int i_mapping;    /* struct inode.i_mapping */
    int i_dentry;     /* struct inode.i_dentry */
    int i_flock;      /* struct inode.i_flock */
    int i_lock;       /* struct inode.i_lock */
    int i_count;      /* struct inode.i_count */
    int s_id;         /* struct super_block.s_id */
    int s_op;         /* struct super_block.s_op */
    int s_root;       /* struct super_block.s_root */
    int s_dentry;     /* struct super_block.s_dentry */
    int s_files;      /* struct super_block.s_files */
    int s_mounts;     /* struct super_block.s_mounts */
    int s_instances;  /* struct super_block.s_instances */
    int s_list;       /* struct super_block.s_list */
    int s_dev;        /* struct super_block.s_dev */
    int s_blocksize;  /* struct super_block.s_blocksize */
    int s_blocksize_bits; /* struct super_block.s_blocksize_bits */
    int s_magic;      /* struct super_block.s_magic */
    int s_type;       /* struct super_block.s_type */
    int s_flags;      /* struct super_block.s_flags */
    int s_time_gran;  /* struct super_block.s_time_gran */
    int s_maxbytes;   /* struct super_block.s_maxbytes */
    int s_op_flags;   /* struct super_block.s_op_flags */

    /* Thread struct offsets */
    int t_thread_cpuctx;      /* thread_struct.cpu_context */
    int t_thread_fpsimd;      /* thread_struct.fpsimd_state */

    /* Signal struct offsets */
    int t_signal_shared_pending; /* signal_struct.shared_pending */
    int t_signal_cred_guard;     /* signal_struct.cred_guard_mutex */

    /* Sighand struct offsets */
    int t_sighand_action;       /* sighand_struct.action */

    /* Fs struct offsets */
    int t_fs_pwd;               /* fs_struct.pwd */
    int t_fs_root;              /* fs_struct.root */

    /* Nsproxy struct offsets */
    int t_nsproxy_mnt_ns;       /* nsproxy.mnt_ns */
    int t_nsproxy_pid_ns;       /* nsproxy.pid_ns_for_children */

    /* Cred struct offsets */
    int t_cred_cap_eff;         /* cred.cap_effective */
    int t_cred_cap_perm;        /* cred.cap_permitted */
    int t_cred_cap_inh;         /* cred.cap_inheritable */
    int t_cred_uid;             /* cred.uid */

    /* Verification */
    int t_sighand_verified;     /* sighand pointer verified */
};

extern struct memd_learned_ext memd_learned_ext;

/* Learn extended offsets for more universality */
int memd_learn_extended(void);

/* Readers for extended offsets */
#define memd_t_files(t) \
    (memd_learned_ext.t_files >= 0 ? \
     *(struct files_struct **)((char *)(t) + memd_learned_ext.t_files) : \
     (t)->files)

#define memd_t_signal(t) \
    (memd_learned_ext.t_signal >= 0 ? \
     *(struct signal_struct **)((char *)(t) + memd_learned_ext.t_signal) : \
     (t)->signal)

#define memd_t_sighand(t) \
    (memd_learned_ext.t_sighand >= 0 ? \
     *(struct sighand_struct **)((char *)(t) + memd_learned_ext.t_sighand) : \
     (t)->sighand)

#define memd_t_real_parent(t) \
    (memd_learned_ext.t_real_parent >= 0 ? \
     *(struct task_struct **)((char *)(t) + memd_learned_ext.t_real_parent) : \
     (t)->real_parent)

#define memd_f_path(f) \
    (memd_learned_ext.f_fpath >= 0 ? \
     *(struct path *)((char *)(f) + memd_learned_ext.f_fpath) : \
     (f)->f_path)

#define memd_f_op(f) \
    (memd_learned_ext.f_op >= 0 ? \
     *(struct file_operations **)((char *)(f) + memd_learned_ext.f_op) : \
     (f)->f_op)

#define memd_d_name(d) \
    (memd_learned_ext.d_name >= 0 ? \
     *(struct qstr *)((char *)(d) + memd_learned_ext.d_name) : \
     (d)->d_name)

#define memd_d_parent(d) \
    (memd_learned_ext.d_parent >= 0 ? \
     *(struct dentry **)((char *)(d) + memd_learned_ext.d_parent) : \
     (d)->d_parent)

#define memd_i_ino(i) \
    (memd_learned_ext.i_ino >= 0 ? \
     *(ino_t *)((char *)(i) + memd_learned_ext.i_ino) : \
     (i)->i_ino)

#define memd_s_root(s) \
    (memd_learned_ext.s_root >= 0 ? \
     *(struct dentry **)((char *)(s) + memd_learned_ext.s_root) : \
     (s)->s_root)

#define memd_m_mmap(mm) \
    (memd_learned_ext.m_mmap >= 0 ? \
     *(struct vm_area_struct **)((char *)(mm) + memd_learned_ext.m_mmap) : \
     (mm)->mmap)

#define memd_m_arg_lock(mm) \
    (memd_learned_ext.m_arg_lock >= 0 ? \
     *(spinlock_t *)((char *)(mm) + memd_learned_ext.m_arg_lock) : \
     (mm)->arg_lock)

#define memd_m_arg_start(mm) \
    (memd_learned_ext.m_arg_start >= 0 ? \
     *(unsigned long *)((char *)(mm) + memd_learned_ext.m_arg_start) : \
     (mm)->arg_start)

#define memd_m_arg_end(mm) \
    (memd_learned_ext.m_arg_end >= 0 ? \
     *(unsigned long *)((char *)(mm) + memd_learned_ext.m_arg_end) : \
     (mm)->arg_end)

#define memd_m_env_start(mm) \
    (memd_learned_ext.m_env_start >= 0 ? \
     *(unsigned long *)((char *)(mm) + memd_learned_ext.m_env_start) : \
     (mm)->env_start)

#define memd_m_env_end(mm) \
    (memd_learned_ext.m_env_end >= 0 ? \
     *(unsigned long *)((char *)(mm) + memd_learned_ext.m_env_end) : \
     (mm)->env_end)

/* Thread struct readers */
#define memd_t_thread_cpuctx(t) \
    (memd_learned_ext.t_thread_cpuctx >= 0 ? \
     *(void **)((char *)(t) + memd_learned_ext.t_thread_cpuctx) : \
     NULL)

#define memd_t_thread_fpsimd(t) \
    (memd_learned_ext.t_thread_fpsimd >= 0 ? \
     *(void **)((char *)(t) + memd_learned_ext.t_thread_fpsimd) : \
     NULL)

/* Signal struct readers */
#define memd_t_signal_shared_pending(t) \
    (memd_learned_ext.t_signal_shared_pending >= 0 ? \
     *(struct list_head **)((char *)memd_t_signal(t) + memd_learned_ext.t_signal_shared_pending) : \
     NULL)

#define memd_t_signal_cred_guard(t) \
    (memd_learned_ext.t_signal_cred_guard >= 0 ? \
     *(struct mutex **)((char *)memd_t_signal(t) + memd_learned_ext.t_signal_cred_guard) : \
     NULL)

/* Sighand struct readers */
#define memd_t_sighand_action(t) \
    (memd_learned_ext.t_sighand_action >= 0 ? \
     *(struct k_sigaction **)((char *)memd_t_sighand(t) + memd_learned_ext.t_sighand_action) : \
     NULL)

/* Fs struct readers */
#define memd_t_fs_pwd(t) \
    (memd_learned_ext.t_fs_pwd >= 0 ? \
     *(struct path **)((char *)memd_t_fs(t) + memd_learned_ext.t_fs_pwd) : \
     NULL)

#define memd_t_fs_root(t) \
    (memd_learned_ext.t_fs_root >= 0 ? \
     *(struct path **)((char *)memd_t_fs(t) + memd_learned_ext.t_fs_root) : \
     NULL)

/* Nsproxy struct readers */
#define memd_t_nsproxy_mnt_ns(t) \
    (memd_learned_ext.t_nsproxy_mnt_ns >= 0 ? \
     *(struct ns_common **)((char *)memd_t_nsproxy(t) + memd_learned_ext.t_nsproxy_mnt_ns) : \
     NULL)

#define memd_t_nsproxy_pid_ns(t) \
    (memd_learned_ext.t_nsproxy_pid_ns >= 0 ? \
     *(struct ns_common **)((char *)memd_t_nsproxy(t) + memd_learned_ext.t_nsproxy_pid_ns) : \
     NULL)

/* Cred struct readers */
#define memd_t_cred_cap_eff(t) \
    (memd_learned_ext.t_cred_cap_eff >= 0 ? \
     *(struct kernel_cap_struct *)((char *)memd_t_cred(t) + memd_learned_ext.t_cred_cap_eff) : \
     (struct kernel_cap_struct) {0})

#define memd_t_cred_cap_perm(t) \
    (memd_learned_ext.t_cred_cap_perm >= 0 ? \
     *(struct kernel_cap_struct *)((char *)memd_t_cred(t) + memd_learned_ext.t_cred_cap_perm) : \
     (struct kernel_cap_struct) {0})

#define memd_t_cred_cap_inh(t) \
    (memd_learned_ext.t_cred_cap_inh >= 0 ? \
     *(struct kernel_cap_struct *)((char *)memd_t_cred(t) + memd_learned_ext.t_cred_cap_inh) : \
     (struct kernel_cap_struct) {0})

#define memd_t_cred_uid(t) \
    (memd_learned_ext.t_cred_uid >= 0 ? \
     *(kuid_t *)((char *)memd_t_cred(t) + memd_learned_ext.t_cred_uid) : \
     (kuid_t) {0})

/* Comprehensive learning */
int memd_learn_comprehensive(void);

#endif /* MEMD_LEARN_H */
