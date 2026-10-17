/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MEMD_EBPF_OFFSETS_H
#define MEMD_EBPF_OFFSETS_H

enum memd_struct_id {
    MEMD_STRUCT_NONE = 0,
    MEMD_STRUCT_TASK,
    MEMD_STRUCT_MM,
    MEMD_STRUCT_VMA,
    MEMD_STRUCT_CRED,
    MEMD_STRUCT_FILE,
    MEMD_STRUCT_INODE,
    MEMD_STRUCT_KERNEL,
    MEMD_STRUCT_COUNT
};

enum memd_field_task {
    MEMD_TASK_PID = 0,
    MEMD_TASK_TGID,
    MEMD_TASK_COMM,
    MEMD_TASK_MM,
    MEMD_TASK_CRED,
    MEMD_TASK_REAL_PARENT,
    MEMD_TASK_STATE,
    MEMD_TASK_PRIO,
    MEMD_TASK_FILES,
    MEMD_TASK_THREAD,
    MEMD_TASK_COUNT
};

enum memd_field_mm {
    MEMD_MM_PGD = 0,
    MEMD_MM_MMAP,
    MEMD_MM_MM_USERS,
    MEMD_MM_MM_COUNT,
    MEMD_MM_ARG_START,
    MEMD_MM_ARG_END,
    MEMD_MM_START_CODE,
    MEMD_MM_END_CODE,
    MEMD_MM_START_DATA,
    MEMD_MM_END_DATA,
    MEMD_MM_BRK,
    MEMD_MM_START_STACK,
    MEMD_MM_COUNT
};

enum memd_field_vma {
    MEMD_VMA_VM_START = 0,
    MEMD_VMA_VM_END,
    MEMD_VMA_VM_NEXT,
    MEMD_VMA_VM_PREV,
    MEMD_VMA_VM_FLAGS,
    MEMD_VMA_VM_FILE,
    MEMD_VMA_VM_PG_OFF,
    MEMD_VMA_COUNT
};

enum memd_field_cred {
    MEMD_CRED_UID = 0,
    MEMD_CRED_GID,
    MEMD_CRED_EUID,
    MEMD_CRED_EGID,
    MEMD_CRED_SUID,
    MEMD_CRED_SGID,
    MEMD_CRED_FSUID,
    MEMD_CRED_FSGID,
    MEMD_CRED_COUNT
};

enum memd_field_file {
    MEMD_FILE_F_OP = 0,
    MEMD_FILE_F_INODE,
    MEMD_FILE_F_POS,
    MEMD_FILE_F_FLAGS,
    MEMD_FILE_F_MODE,
    MEMD_FILE_COUNT
};

enum memd_field_inode {
    MEMD_INODE_I_INO = 0,
    MEMD_INODE_I_MODE,
    MEMD_INODE_I_UID,
    MEMD_INODE_I_GID,
    MEMD_INODE_I_SIZE,
    MEMD_INODE_COUNT
};

static inline const char *memd_struct_name(unsigned int id)
{
    switch (id) {
    case MEMD_STRUCT_TASK:   return "task_struct";
    case MEMD_STRUCT_MM:     return "mm_struct";
    case MEMD_STRUCT_VMA:    return "vm_area_struct";
    case MEMD_STRUCT_CRED:   return "cred";
    case MEMD_STRUCT_FILE:   return "file";
    case MEMD_STRUCT_INODE:  return "inode";
    case MEMD_STRUCT_KERNEL: return "kernel";
    default:                 return "unknown";
    }
}

#endif /* MEMD_EBPF_OFFSETS_H */