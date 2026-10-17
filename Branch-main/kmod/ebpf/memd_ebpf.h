/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MEMD_EBPF_H
#define MEMD_EBPF_H

#include <linux/types.h>

#define MEMD_EBPF_OP_KREAD       1
#define MEMD_EBPF_OP_KWRITE      2
#define MEMD_EBPF_OP_UREAD       3
#define MEMD_EBPF_OP_UWRITE      4
#define MEMD_EBPF_OP_OFFSET      5
#define MEMD_EBPF_OP_TASK_READ   6
#define MEMD_EBPF_OP_PING        7
#define MEMD_EBPF_OP_KREAD_STR   8
#define MEMD_EBPF_OP_UREAD_STR   9
#define MEMD_EBPF_OP_MEMSET_USER 10
#define MEMD_EBPF_OP_CRC32       11
#define MEMD_EBPF_OP_STRLEN_USER 12

#define MEMD_EBPF_MAX_IO         (64 * 1024)
#define MEMD_EBPF_CHUNK          64

#define MEMD_EBPF_FLAG_FORCE     (1U << 0)
#define MEMD_EBPF_FLAG_VERIFY    (1U << 1)

struct memd_offset_key {
    __u32 struct_id;
    __u32 field_id;
};

struct memd_ebpf_req {
    __u32 op;
    __u32 flags;
    __u64 addr;
    __u64 len;
    __u64 user_buf;
    __u64 pid;
    __u64 aux;
    __u32 struct_id;
    __u32 field_id;
    __s32 status;
    __u32 done;
    __u64 offset_out;
    char sname[64];
    char fname[64];
};

#endif /* MEMD_EBPF_H */