/* client.h — iOS/macOS user-mode client for the MEMD kernel extension.
 * Provides the same ioctl interface as the Linux client.h, adapted
 * for macOS/iOS ioctl conventions. */

#ifndef MEMD_IOS_CLIENT_H
#define MEMD_IOS_CLIENT_H

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#else
#error "This header is for Apple (iOS/macOS) targets only."
#endif

/* ---- constants ---- */
#define MEMD_DEVICE_PATH  "/dev/memd"
#define MEMD_MAX_BULK_OFFSETS 32

/* ---- command structs (mirror of Linux ioctl commands) ---- */
typedef struct memd_read_memory_cmd {
    uint32_t pid;
    uint64_t src_va;
    uint64_t dst_va;
    uint64_t size;
    int32_t result;
} memd_read_memory_cmd;

typedef struct memd_write_memory_cmd {
    uint32_t pid;
    uint64_t src_va;
    uint64_t dst_va;
    uint64_t size;
    int32_t result;
} memd_write_memory_cmd;

typedef struct memd_find_proc_cmd {
    char name[256];
    uint32_t pid;
    int32_t result;
} memd_find_proc_cmd;

typedef struct memd_is_proc_alive_cmd {
    uint32_t pid;
    int32_t alive;
    int32_t result;
} memd_is_proc_alive_cmd;

typedef struct memd_hide_proc_cmd {
    uint32_t pid;
    int32_t hide;
    int32_t result;
} memd_hide_proc_cmd;

typedef struct memd_give_root_cmd {
    int32_t result;
} memd_give_root_cmd;

typedef struct memd_version_cmd {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    uint32_t abi;
    uint32_t flags;
    uint32_t gen;
    int32_t result;
} memd_version_cmd;


/* ---- ioctl codes (must match kernel extension) ---- */
#define MEMD_IOC_MAGIC  'W'
#define MEMD_IOCTL_READ_MEMORY           _IOWR(MEMD_IOC_MAGIC, 9,  struct memd_read_memory_cmd)
#define MEMD_IOCTL_WRITE_MEMORY          _IOWR(MEMD_IOC_MAGIC, 12, struct memd_write_memory_cmd)
#define MEMD_IOCTL_FIND_PROCESS          _IOWR(MEMD_IOC_MAGIC, 11, struct memd_find_proc_cmd)
#define MEMD_IOCTL_IS_PROCESS_ALIVE      _IOWR(MEMD_IOC_MAGIC, 13, struct memd_is_proc_alive_cmd)
#define MEMD_IOCTL_HIDE_PROCESS          _IOWR(MEMD_IOC_MAGIC, 14, struct memd_hide_proc_cmd)
#define MEMD_IOCTL_GIVE_ROOT             _IOWR(MEMD_IOC_MAGIC, 15, struct memd_give_root_cmd)
#define MEMD_IOCTL_VERSION               _IOR(MEMD_IOC_MAGIC, 2,   struct memd_version_cmd)


/* ---- client API ---- */

static inline int memd_open(void) {
    return open(MEMD_DEVICE_PATH, O_RDWR);
}

static inline int memd_call(int fd, unsigned long cmd, void *arg) {
    if (fd < 0 || !arg) {
        errno = EINVAL;
        return -EINVAL;
    }
    if (ioctl(fd, cmd, arg) < 0)
        return -errno;
    return 0;
}

static inline void memd_close(int fd) {
    if (fd >= 0) close(fd);
}

static inline int memd_read_memory(int fd, uint32_t pid, uintptr_t src_va,
                                   uintptr_t dst_va, size_t size) {
    memd_read_memory_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(fd, MEMD_IOCTL_READ_MEMORY, &cmd);
}

static inline int memd_write_memory(int fd, uint32_t pid, uintptr_t src_va,
                                    uintptr_t dst_va, size_t size) {
    memd_write_memory_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(fd, MEMD_IOCTL_WRITE_MEMORY, &cmd);
}

static inline int memd_find_process(int fd, const char *name, uint32_t *out_pid) {
    memd_find_proc_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    strncpy(cmd.name, name, sizeof(cmd.name) - 1);
    if (memd_call(fd, MEMD_IOCTL_FIND_PROCESS, &cmd) < 0)
        return -1;
    *out_pid = cmd.pid;
    return cmd.result;
}

static inline int memd_is_process_alive(int fd, uint32_t pid, int *out_alive) {
    memd_is_proc_alive_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    if (memd_call(fd, MEMD_IOCTL_IS_PROCESS_ALIVE, &cmd) < 0)
        return -1;
    *out_alive = cmd.alive;
    return cmd.result;
}

static inline int memd_hide_process(int fd, uint32_t pid, int hide) {
    memd_hide_proc_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.hide = hide;
    return memd_call(fd, MEMD_IOCTL_HIDE_PROCESS, &cmd);
}

static inline int memd_give_root(int fd) {
    memd_give_root_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    return memd_call(fd, MEMD_IOCTL_GIVE_ROOT, &cmd);
}

static inline int memd_version(int fd, memd_version_cmd *out) {
    memset(out, 0, sizeof(*out));
    return memd_call(fd, MEMD_IOCTL_VERSION, out);
}

#endif /* MEMD_IOS_CLIENT_H */
/* iOS/client.h[∂] */