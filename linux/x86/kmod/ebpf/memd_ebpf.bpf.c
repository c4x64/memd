/* SPDX-License-Identifier: GPL-2.0 */
/* memd_ebpf.bpf.c — core memory I/O helpers as eBPF programs.
 *
 * Replaces the .ko dependency on Android when BTF is available: the
 * running kernel exposes /sys/kernel/btf/vmlinux, bpftool generates
 * vmlinux.h, and this object is loaded with libbpf. Operations are
 * dispatched by a single SEC("syscall") program that receives a
 * memd_ebpf_req control block; maps cache resolved struct offsets.
 */

#if defined(__has_include) && __has_include("vmlinux.h")
#include "vmlinux.h"
#else
#error "vmlinux.h is required (generate from /sys/kernel/btf/vmlinux with gen_vmlinux.sh)"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "memd_ebpf.h"
#include "memd_offsets.h"

#define MEMD_BPF_MAX_CHUNK 64

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct memd_offset_key);
    __type(value, __u64);
} memd_offset_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} memd_stat_map SEC(".maps");

/* ---------- CO-RE offset resolvers ---------- */

static __always_inline __u64 memd_off_task_pid(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->pid,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_task_tgid(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->tgid,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_task_mm(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->mm,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_task_cred(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->cred,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_task_real_parent(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->real_parent,
                                         BPF_FIELD_BYTE_OFFSET);
}
/* state/__state field name varies by kernel version; omitted for portability. */
static __always_inline __u64 memd_off_task_prio(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->prio,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_task_comm(void)
{
    return __builtin_preserve_field_info(((struct task_struct *)0)->comm,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __always_inline __u64 memd_off_mm_pgd(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->pgd,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_mmap(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->mmap,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_mm_users(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->mm_users,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_mm_count(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->mm_count,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_arg_start(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->arg_start,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_arg_end(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->arg_end,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_start_code(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->start_code,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_end_code(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->end_code,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_start_data(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->start_data,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_end_data(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->end_data,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_brk(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->brk,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_mm_start_stack(void)
{
    return __builtin_preserve_field_info(((struct mm_struct *)0)->start_stack,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __always_inline __u64 memd_off_vma_vm_start(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_start,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_end(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_end,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_next(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_next,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_prev(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_prev,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_flags(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_flags,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_file(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_file,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_vma_vm_pgoff(void)
{
    return __builtin_preserve_field_info(((struct vm_area_struct *)0)->vm_pgoff,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __always_inline __u64 memd_off_cred_uid(void)
{
    return __builtin_preserve_field_info(((struct cred *)0)->uid,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_cred_gid(void)
{
    return __builtin_preserve_field_info(((struct cred *)0)->gid,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_cred_euid(void)
{
    return __builtin_preserve_field_info(((struct cred *)0)->euid,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_cred_egid(void)
{
    return __builtin_preserve_field_info(((struct cred *)0)->egid,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __always_inline __u64 memd_off_file_f_op(void)
{
    return __builtin_preserve_field_info(((struct file *)0)->f_op,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_file_f_inode(void)
{
    return __builtin_preserve_field_info(((struct file *)0)->f_inode,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_file_f_pos(void)
{
    return __builtin_preserve_field_info(((struct file *)0)->f_pos,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __always_inline __u64 memd_off_inode_i_ino(void)
{
    return __builtin_preserve_field_info(((struct inode *)0)->i_ino,
                                         BPF_FIELD_BYTE_OFFSET);
}
static __always_inline __u64 memd_off_inode_i_mode(void)
{
    return __builtin_preserve_field_info(((struct inode *)0)->i_mode,
                                         BPF_FIELD_BYTE_OFFSET);
}

static __u64 memd_resolve_core_offset(__u32 sid, __u32 fid)
{
    switch (sid) {
    case MEMD_STRUCT_TASK:
        switch (fid) {
        case MEMD_TASK_PID:          return memd_off_task_pid();
        case MEMD_TASK_TGID:         return memd_off_task_tgid();
        case MEMD_TASK_MM:           return memd_off_task_mm();
        case MEMD_TASK_CRED:         return memd_off_task_cred();
        case MEMD_TASK_REAL_PARENT:  return memd_off_task_real_parent();
        case MEMD_TASK_PRIO:         return memd_off_task_prio();
        case MEMD_TASK_COMM:         return memd_off_task_comm();
        default:                     return 0;
        }
    case MEMD_STRUCT_MM:
        switch (fid) {
        case MEMD_MM_PGD:            return memd_off_mm_pgd();
        case MEMD_MM_MMAP:           return memd_off_mm_mmap();
        case MEMD_MM_MM_USERS:       return memd_off_mm_mm_users();
        case MEMD_MM_MM_COUNT:       return memd_off_mm_mm_count();
        case MEMD_MM_ARG_START:      return memd_off_mm_arg_start();
        case MEMD_MM_ARG_END:        return memd_off_mm_arg_end();
        case MEMD_MM_START_CODE:     return memd_off_mm_start_code();
        case MEMD_MM_END_CODE:       return memd_off_mm_end_code();
        case MEMD_MM_START_DATA:     return memd_off_mm_start_data();
        case MEMD_MM_END_DATA:       return memd_off_mm_end_data();
        case MEMD_MM_BRK:            return memd_off_mm_brk();
        case MEMD_MM_START_STACK:    return memd_off_mm_start_stack();
        default:                     return 0;
        }
    case MEMD_STRUCT_VMA:
        switch (fid) {
        case MEMD_VMA_VM_START:      return memd_off_vma_vm_start();
        case MEMD_VMA_VM_END:        return memd_off_vma_vm_end();
        case MEMD_VMA_VM_NEXT:       return memd_off_vma_vm_next();
        case MEMD_VMA_VM_PREV:       return memd_off_vma_vm_prev();
        case MEMD_VMA_VM_FLAGS:      return memd_off_vma_vm_flags();
        case MEMD_VMA_VM_FILE:       return memd_off_vma_vm_file();
        case MEMD_VMA_VM_PG_OFF:     return memd_off_vma_vm_pgoff();
        default:                     return 0;
        }
    case MEMD_STRUCT_CRED:
        switch (fid) {
        case MEMD_CRED_UID:          return memd_off_cred_uid();
        case MEMD_CRED_GID:          return memd_off_cred_gid();
        case MEMD_CRED_EUID:         return memd_off_cred_euid();
        case MEMD_CRED_EGID:         return memd_off_cred_egid();
        default:                     return 0;
        }
    case MEMD_STRUCT_FILE:
        switch (fid) {
        case MEMD_FILE_F_OP:         return memd_off_file_f_op();
        case MEMD_FILE_F_INODE:      return memd_off_file_f_inode();
        case MEMD_FILE_F_POS:        return memd_off_file_f_pos();
        default:                     return 0;
        }
    case MEMD_STRUCT_INODE:
        switch (fid) {
        case MEMD_INODE_I_INO:       return memd_off_inode_i_ino();
        case MEMD_INODE_I_MODE:      return memd_off_inode_i_mode();
        default:                     return 0;
        }
    default:
        return 0;
    }
}

/* ---------- operation helpers ---------- */

static int op_kread(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 len = req->len;
    __u64 ubuf = req->user_buf;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !ubuf || !len)
        return -22; /* -EINVAL */
    if (len > MEMD_EBPF_MAX_IO)
        len = MEMD_EBPF_MAX_IO;

    while (done < len) {
        __u64 chunk = len - done;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_kernel(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        rc = bpf_copy_to_user((void *)(ubuf + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = 0;
    req->done = done;
    return 0;
}

static int op_kwrite(struct memd_ebpf_req *req)
{
    /* Kernel memory write is intentionally not exposed: eBPF has no safe
     * primitive for arbitrary kernel writes. Only user-memory writes are
     * supported via op_uwrite. */
    (void)req;
    req->status = -1; /* -EPERM */
    req->done = 0;
    return -1;
}

static int op_uread(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 len = req->len;
    __u64 ubuf = req->user_buf;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !ubuf || !len)
        return -22;
    if (len > MEMD_EBPF_MAX_IO)
        len = MEMD_EBPF_MAX_IO;

    while (done < len) {
        __u64 chunk = len - done;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_user(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        rc = bpf_copy_to_user((void *)(ubuf + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = 0;
    req->done = done;
    return 0;
}

static int op_uwrite(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 len = req->len;
    __u64 src = req->user_buf;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !src || !len)
        return -22;
    if (len > MEMD_EBPF_MAX_IO)
        len = MEMD_EBPF_MAX_IO;

    while (done < len) {
        __u64 chunk = len - done;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_copy_from_user(tmp, (const void *)(src + done), (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        rc = bpf_probe_write_user((void *)(addr + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = 0;
    req->done = done;
    return 0;
}

static int op_offset(struct memd_ebpf_req *req)
{
    struct memd_offset_key key;
    __u64 *cached;
    __u64 off;

    key.struct_id = req->struct_id;
    key.field_id = req->field_id;

    cached = bpf_map_lookup_elem(&memd_offset_map, &key);
    if (cached && *cached) {
        req->offset_out = *cached;
        req->status = 0;
        return 0;
    }

    off = memd_resolve_core_offset(req->struct_id, req->field_id);
    if (!off) {
        req->status = -2; /* -ENOENT */
        req->offset_out = 0;
        return -2;
    }

    bpf_map_update_elem(&memd_offset_map, &key, &off, BPF_ANY);
    req->offset_out = off;
    req->status = 0;
    return 0;
}

static int op_task_read(struct memd_ebpf_req *req)
{
    __u64 cur_pid = bpf_get_current_pid_tgid() >> 32;
    if (req->pid != 0 && req->pid != cur_pid)
        return -38; /* -ENOSYS for cross-process */
    return op_uread(req);
}

static int op_ping(struct memd_ebpf_req *req)
{
    req->status = 0;
    req->done = 0;
    return 0;
}

static void memd_bump_stat(void)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&memd_stat_map, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
    else {
        __u64 one = 1;
        bpf_map_update_elem(&memd_stat_map, &key, &one, BPF_ANY);
    }
}

static int op_kread_str(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 ubuf = req->user_buf;
    __u64 max = req->len ? req->len : 256;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !ubuf)
        return -22;
    if (max > MEMD_EBPF_MAX_IO)
        max = MEMD_EBPF_MAX_IO;

    while (done < max) {
        __u64 chunk = max - done;
        __u32 i;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_kernel(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        for (i = 0; i < (__u32)chunk; i++) {
            if (tmp[i] == '\0') {
                /* include terminator */
                rc = bpf_copy_to_user((void *)(ubuf + done), tmp, i + 1);
                if (rc < 0) {
                    req->status = rc;
                    req->done = done + i;
                    return rc;
                }
                req->status = 0;
                req->done = done + i + 1;
                return 0;
            }
        }
        rc = bpf_copy_to_user((void *)(ubuf + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = -36; /* -ENAMETOOLONG */
    req->done = done;
    return -36;
}

static int op_uread_str(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 ubuf = req->user_buf;
    __u64 max = req->len ? req->len : 256;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !ubuf)
        return -22;
    if (max > MEMD_EBPF_MAX_IO)
        max = MEMD_EBPF_MAX_IO;

    while (done < max) {
        __u64 chunk = max - done;
        __u32 i;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_user(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        for (i = 0; i < (__u32)chunk; i++) {
            if (tmp[i] == '\0') {
                rc = bpf_copy_to_user((void *)(ubuf + done), tmp, i + 1);
                if (rc < 0) {
                    req->status = rc;
                    req->done = done + i;
                    return rc;
                }
                req->status = 0;
                req->done = done + i + 1;
                return 0;
            }
        }
        rc = bpf_copy_to_user((void *)(ubuf + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = -36;
    req->done = done;
    return -36;
}

static int op_memset_user(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 len = req->len;
    unsigned char val = (unsigned char)(req->aux & 0xff);
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !len)
        return -22;
    if (len > MEMD_EBPF_MAX_IO)
        len = MEMD_EBPF_MAX_IO;

    for (done = 0; done < (MEMD_BPF_MAX_CHUNK); done++)
        tmp[done] = (char)val;

    done = 0;
    while (done < len) {
        __u64 chunk = len - done;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_write_user((void *)(addr + done), tmp, (__u32)chunk);
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        done += (__u32)chunk;
    }
    req->status = 0;
    req->done = done;
    return 0;
}

static int op_crc32(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 len = req->len;
    __u32 crc = 0xFFFFFFFFU;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr || !len)
        return -22;
    if (len > MEMD_EBPF_MAX_IO)
        len = MEMD_EBPF_MAX_IO;

    while (done < len) {
        __u64 chunk = len - done;
        __u32 i;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_kernel(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        for (i = 0; i < (__u32)chunk; i++) {
            crc ^= (unsigned char)tmp[i];
            /* polynomial 0xEDB88320 */
            /* unrolled 8 iterations */
            /* iteration 1 */
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320U; else crc >>= 1;
        }
        done += (__u32)chunk;
    }
    req->offset_out = crc ^ 0xFFFFFFFFU;
    req->status = 0;
    req->done = done;
    return 0;
}

static int op_strlen_user(struct memd_ebpf_req *req)
{
    __u64 addr = req->addr;
    __u64 max = req->len ? req->len : 4096;
    __u32 done = 0;
    char tmp[MEMD_BPF_MAX_CHUNK];

    if (!addr)
        return -22;
    if (max > MEMD_EBPF_MAX_IO)
        max = MEMD_EBPF_MAX_IO;

    while (done < max) {
        __u64 chunk = max - done;
        __u32 i;
        int rc;
        if (chunk > MEMD_BPF_MAX_CHUNK)
            chunk = MEMD_BPF_MAX_CHUNK;
        rc = bpf_probe_read_user(tmp, (__u32)chunk, (const void *)(addr + done));
        if (rc < 0) {
            req->status = rc;
            req->done = done;
            return rc;
        }
        for (i = 0; i < (__u32)chunk; i++) {
            if (tmp[i] == '\0') {
                req->offset_out = done + i;
                req->status = 0;
                req->done = done + i;
                return 0;
            }
        }
        done += (__u32)chunk;
    }
    req->status = -36;
    req->done = done;
    return -36;
}

SEC("syscall")
int memd_ebpf_dispatch(struct memd_ebpf_req *req)
{
    if (!req)
        return -22;

    memd_bump_stat();

    switch (req->op) {
    case MEMD_EBPF_OP_KREAD:      return op_kread(req);
    case MEMD_EBPF_OP_KWRITE:     return op_kwrite(req);
    case MEMD_EBPF_OP_UREAD:      return op_uread(req);
    case MEMD_EBPF_OP_UWRITE:     return op_uwrite(req);
    case MEMD_EBPF_OP_OFFSET:     return op_offset(req);
    case MEMD_EBPF_OP_TASK_READ:  return op_task_read(req);
    case MEMD_EBPF_OP_PING:       return op_ping(req);
    case MEMD_EBPF_OP_KREAD_STR:  return op_kread_str(req);
    case MEMD_EBPF_OP_UREAD_STR:  return op_uread_str(req);
    case MEMD_EBPF_OP_MEMSET_USER:return op_memset_user(req);
    case MEMD_EBPF_OP_CRC32:      return op_crc32(req);
    case MEMD_EBPF_OP_STRLEN_USER:return op_strlen_user(req);
    default:
        req->status = -22;
        req->done = 0;
        return -22;
    }
}

char LICENSE[] SEC("license") = "GPL";