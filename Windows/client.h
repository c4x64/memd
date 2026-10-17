/* client.h — Windows user-mode client for the MEMD kernel driver.
 * Provides the same ioctl interface as the Linux client.h, adapted
 * for Windows DeviceIoControl. */

#ifndef MEMD_CLIENT_H
#define MEMD_CLIENT_H

#ifdef _WIN32
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#else
#error "This header is for Windows targets only."
#endif

/* ---- constants ---- */
#define MEMD_DEVICE_NAME  "\\\\.\\MEMD"
#define MEMD_MAX_BULK_OFFSETS 32

/* ---- command structs (mirror of Linux ioctl commands) ---- */
typedef struct {
    uint32_t pid;
    uint64_t src_va;
    uint64_t dst_va;
    uint64_t size;
    int32_t result;
} memd_read_memory_cmd;

typedef struct {
    uint32_t pid;
    uint64_t src_va;
    uint64_t dst_va;
    uint64_t size;
    int32_t result;
} memd_write_memory_cmd;

typedef struct {
    uint32_t pid;
    char name[256];
    uint64_t base;
    uint32_t vm_flag;
    int32_t result;
} memd_get_module_base_cmd;

typedef struct {
    char name[256];
    uint32_t pid;
    int32_t result;
} memd_find_proc_cmd;

typedef struct {
    uint32_t pid;
    int32_t alive;
    int32_t result;
} memd_is_proc_alive_cmd;

typedef struct {
    uint32_t pid;
    int32_t hide;
    int32_t result;
} memd_hide_proc_cmd;

typedef struct {
    int32_t result;
} memd_give_root_cmd;

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    uint32_t abi;
    uint32_t flags;
    uint32_t gen;
    int32_t result;
} memd_version_cmd;

typedef struct {
    char field_name[32];
    int32_t offset;
    int32_t result;
} memd_offset_update_cmd;

typedef struct {
    uint32_t count;
    struct {
        char field_name[32];
        int32_t offset;
    } entries[MEMD_MAX_BULK_OFFSETS];
    int32_t result;
} memd_bulk_offset_update_cmd;

typedef struct {
    uint64_t kernel_base;
    uint64_t kaslr_slide;
    int32_t result;
} memd_kaslr_info_cmd;

/* ---- IOCTL codes ---- */
#define MEMD_IOCTL_BASE  0x8000
#define IOCTL_MEMD_READ_MEMORY           CTL_CODE(MEMD_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_WRITE_MEMORY          CTL_CODE(MEMD_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_GET_MODULE_BASE       CTL_CODE(MEMD_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_FIND_PROCESS          CTL_CODE(MEMD_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_IS_PROCESS_ALIVE      CTL_CODE(MEMD_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_HIDE_PROCESS          CTL_CODE(MEMD_IOCTL_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_GIVE_ROOT             CTL_CODE(MEMD_IOCTL_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_VERSION               CTL_CODE(MEMD_IOCTL_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_OFFSET_UPDATE         CTL_CODE(MEMD_IOCTL_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_BULK_OFFSET_UPDATE    CTL_CODE(MEMD_IOCTL_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_KASLR_INFO            CTL_CODE(MEMD_IOCTL_BASE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- client API ---- */
static inline HANDLE memd_open(void) {
    return CreateFileA(MEMD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static inline int memd_call(HANDLE h, DWORD code, void *in, DWORD in_sz,
                            void *out, DWORD out_sz) {
    DWORD ret = 0;
    return DeviceIoControl(h, code, in, in_sz, out, out_sz, &ret, NULL) ? 0 : -1;
}

static inline void memd_close(HANDLE h) {
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

static inline int memd_read_memory(HANDLE h, uint32_t pid, uintptr_t src,
                                   uintptr_t dst, size_t sz) {
    memd_read_memory_cmd cmd = {0};
    cmd.pid = pid; cmd.src_va = src; cmd.dst_va = dst; cmd.size = sz;
    return memd_call(h, IOCTL_MEMD_READ_MEMORY, &cmd, sizeof(cmd), &cmd, sizeof(cmd));
}

static inline int memd_write_memory(HANDLE h, uint32_t pid, uintptr_t src,
                                    uintptr_t dst, size_t sz) {
    memd_write_memory_cmd cmd = {0};
    cmd.pid = pid; cmd.src_va = src; cmd.dst_va = dst; cmd.size = sz;
    return memd_call(h, IOCTL_MEMD_WRITE_MEMORY, &cmd, sizeof(cmd), &cmd, sizeof(cmd));
}

static inline int memd_find_process(HANDLE h, const char *name, uint32_t *pid) {
    memd_find_proc_cmd cmd = {0};
    strncpy(cmd.name, name, sizeof(cmd.name) - 1);
    if (memd_call(h, IOCTL_MEMD_FIND_PROCESS, &cmd, sizeof(cmd), &cmd, sizeof(cmd)) < 0)
        return -1;
    *pid = cmd.pid;
    return cmd.result;
}

static inline int memd_is_process_alive(HANDLE h, uint32_t pid, int *alive) {
    memd_is_proc_alive_cmd cmd = {0};
    cmd.pid = pid;
    if (memd_call(h, IOCTL_MEMD_IS_PROCESS_ALIVE, &cmd, sizeof(cmd), &cmd, sizeof(cmd)) < 0)
        return -1;
    *alive = cmd.alive;
    return cmd.result;
}

static inline int memd_hide_process(HANDLE h, uint32_t pid, int hide) {
    memd_hide_proc_cmd cmd = {0};
    cmd.pid = pid; cmd.hide = hide;
    return memd_call(h, IOCTL_MEMD_HIDE_PROCESS, &cmd, sizeof(cmd), &cmd, sizeof(cmd));
}

static inline int memd_give_root(HANDLE h) {
    memd_give_root_cmd cmd = {0};
    return memd_call(h, IOCTL_MEMD_GIVE_ROOT, &cmd, sizeof(cmd), &cmd, sizeof(cmd));
}

static inline int memd_version(HANDLE h, memd_version_cmd *out) {
    memset(out, 0, sizeof(*out));
    return memd_call(h, IOCTL_MEMD_VERSION, out, sizeof(*out), out, sizeof(*out));
}

#endif /* MEMD_CLIENT_H */
/* Windows/client.h[∂] */