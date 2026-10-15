/* client.h — userspace client library for the memd/rwbridge driver.
 *
 * Single header, no dependencies beyond libc: include it from any client
 * binary (bionic or glibc, LP64 arm64) to talk to the driver. Contents:
 *   - transport open: memd_open() finds the driver's socket family the
 *     same way spx.c does (SEQPACKET probe -> ENOKEY marker -> RAW).
 *   - every product ioctl number (MEMD_IOCTL_*) and command struct, with
 *     userspace types. Layouts are LP64-identical to the kernel side by
 *     construction (fixed-width fields only); a CI gate
 *     (.github/scripts/check_client_h.py) re-verifies every number and
 *     every struct field against kmod/ on each push — this file must
 *     never drift from the kernel headers by hand.
 *   - thin typed wrappers (memd_*): validate like the kernel handlers
 *     do, then ioctl(). Return convention: 0 ok, -errno on failure;
 *     byte-count calls return bytes-read/written or -errno.
 *
 * Excluded on purpose (not in product builds): MEMD_IOCTL_DMA_BUF_CREATE
 * (MEMD_DISABLE_DMABUF) and MEMD_IOCTL_DISP_READBACK (MEMD_DISP_TEST).
 * hwbp opcodes are wired but the driver stubs them (-ENODEV) until the
 * debug_info-model rewrite lands.
 * Warning: this header is not the current stable api check @release for 
 * stable driver and its corresponding client headers. 
 * blame: c4x64@proton.me [100%]
 */
#ifndef MEMD_CLIENT_H
#define MEMD_CLIENT_H

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- transport discovery (mirrors spx.c proto_live) ---- */
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif
#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef PF_DECNET
#define PF_DECNET 12
#endif
#ifndef ENOKEY
#define ENOKEY 126
#endif

/* ---- memory protection types (WMT_*, for ioremap prot + SET_MEMORY_PROT) ---- */
#define MEMD_WMT_NORMAL 0
#define MEMD_WMT_NORMAL_TAGGED 1
#define MEMD_WMT_NORMAL_NC 2
#define MEMD_WMT_NORMAL_WT 3
#define MEMD_WMT_DEVICE_nGnRnE 4
#define MEMD_WMT_DEVICE_nGnRE 5
#define MEMD_WMT_DEVICE_GRE 6
#define MEMD_WMT_NORMAL_iNC_oWB 7

/* ---- VM permission filter bits for get_module_base (kernel VM_* values,
 * stable for decades; the driver tests vma->vm_flags & vm_flag) ---- */
#define MEMD_VM_READ 0x00000001u
#define MEMD_VM_WRITE 0x00000002u
#define MEMD_VM_EXEC 0x00000004u

/* ---- core address / process commands ---- */
struct memd_addr_translate_cmd {
    uintptr_t phy_addr; /* Output: Physical address after translation */
    pid_t pid; /* Input: Process ID owning the virtual address */
    uintptr_t va; /* Input: Virtual address to translate */
};

struct memd_debug_info_cmd {
    uint64_t ttbr0_el1;
    uint64_t task_struct;
    uint64_t mm_struct;
    uint64_t pgd_addr;
    uint64_t pgd_phys_addr;
    uint64_t mm_asid;
    uint32_t mm_right;
};

struct memd_at_s1e0r_cmd {
    uintptr_t phy_addr;
    pid_t pid;
    uintptr_t va;
};

/* Userspace mirror of the kernel's page descriptor snapshot. Kernel
 * flags is unsigned long (8B on LP64 arm64); atomic_t halves stay
 * int32_t. Layout must be flags@0, mapcount@8, refcount@12, phy@16. */
struct kernel_page {
    uint64_t flags;
    union {
        int32_t _mapcount;
        uint32_t page_type;
    };
    int32_t _refcount;
    uint64_t phy_addr;
};
/* C89/C++-compatible ABI pin: flags and phy_addr 8B, total 24B. */
typedef char memd_kernel_page_abi_check[
    (sizeof(struct kernel_page) == 24 &&
     sizeof(((struct kernel_page *)0)->flags) == 8 &&
     sizeof(((struct kernel_page *)0)->phy_addr) == 8) ? 1 : -1];

struct memd_page_info_cmd {
    pid_t pid;
    uintptr_t va;
    struct kernel_page page; /* Output: Page information */
};

struct memd_pte_mapping_cmd {
    pid_t pid;
    uintptr_t start_addr;
    size_t num_pages;
    int hide; /* Hide the page if true */
};

struct memd_page_table_walk_cmd {
    pid_t pid; /* Input: Process ID */
    uint64_t total_pte_count;
    uint64_t present_pte_count;
    uint64_t pmd_huge_count;
    uint64_t pud_huge_count;
};

struct memd_copy_process_cmd {
    pid_t pid;
    int (*fn)(void *);
    void *child_stack;
    size_t child_stack_size;
    uint64_t flags;
    void *arg;
    int *child_tid;
};

struct memd_read_physical_memory_cmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr; /* Output */
};

struct memd_write_physical_memory_cmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr; /* Output */
};

struct memd_get_module_base_cmd {
    pid_t pid; /* Input: Process ID */
    char name[256]; /* Input: Module name */
    uintptr_t base; /* Output: Base address of the module */
    int vm_flag; /* Input: VM flag to filter (e.g., MEMD_VM_EXEC) */
};

struct memd_find_proc_cmd {
    pid_t pid; /* Output: Process ID */
    char name[256]; /* Input: Process name */
};

struct memd_is_proc_alive_cmd {
    pid_t pid;
    int alive; /* Output: 1 if alive, 0 if not */
};

struct memd_hide_proc_cmd {
    pid_t pid; /* Input: Process ID */
    int hide; /* Input: 1 to hide, 0 to unhide */
};

struct memd_give_root_cmd {
    int result; /* Output: 0 on success, negative error code on failure */
};

struct memd_read_physical_memory_ioremap_cmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr; /* Output */
    int prot; /* Input: Memory protection type (use MEMD_WMT_*) */
};

struct memd_write_physical_memory_ioremap_cmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr; /* Output */
    int prot; /* Input: Memory protection type (use MEMD_WMT_*) */
};

struct memd_bind_proc_cmd {
    pid_t pid; /* Input: Process ID */
    int fd; /* Output: anon file descriptor for BP ioctls */
};

struct memd_list_processes_cmd {
    uint8_t *bitmap; /* Input: buffer, at least 8192 bytes (PID 0-65535) */
    size_t bitmap_size; /* Input: bytes (must be at least 8192) */
    size_t process_count; /* Output: number of set bits */
};

struct memd_get_proc_info_cmd {
    pid_t pid; /* Input: Process ID to query */
    pid_t tgid; /* Output: Thread group ID */
    char name[256]; /* Output: Process name (comm) */
    uid_t uid; /* Output: User ID */
    pid_t ppid; /* Output: Parent process ID */
    int prio; /* Output: Process priority */
};

struct memd_page_perms_cmd {
    uintptr_t va; /* Input: kernel virtual address */
    uintptr_t phy_addr; /* Output: physical address (0 if unmapped) */
    uint32_t present; /* Output: 1 if mapped at any level */
    uint32_t leaf_level; /* Output: 0 pud / 1 pmd / 2 pte / 3 missing */
    uint32_t ap; /* Output: AP[2:1] bits (0 RW, 2 RO) */
    uint32_t xn; /* Output: 1 if execute-never set */
    uint32_t idx0; /* Output: pgd index used by the walk */
    uint32_t idx1; /* Output: pud index used by the walk */
    uint64_t desc[4]; /* Output: raw pgd/pud/pmd/pte values seen */
};

struct memd_hide_status_cmd {
    int active; /* Output: 1 if the getdents64 filter is installed */
    int hidden_count; /* Output: pids currently in the hidden set */
};

struct memd_hide_install_cmd {
    int install; /* Input: 1 install, 0 uninstall */
    int result; /* Output: 0 ok, negative errno on failure */
};

/* NOTE: nr 21/22/23 are shared across features (e.g. HIDE_STATUS and
 * HWBP_INFO are both nr 21), but the full _IOWR codes differ via the
 * struct-size field — verified mechanically, no dispatch collision. */

#define MEMD_IOCTL_ADDR_TRANSLATE _IOWR('W', 1, struct memd_addr_translate_cmd)
#define MEMD_IOCTL_DEBUG_INFO _IOR('W', 2, struct memd_debug_info_cmd)
#define MEMD_IOCTL_AT_S1E0R _IOWR('W', 3, struct memd_at_s1e0r_cmd)
#define MEMD_IOCTL_PAGE_INFO _IOWR('W', 4, struct memd_page_info_cmd)
#define MEMD_IOCTL_PTE_MAPPING _IOWR('W', 6, struct memd_pte_mapping_cmd)
#define MEMD_IOCTL_PAGE_TABLE_WALK _IOWR('W', 7, struct memd_page_table_walk_cmd)
#define MEMD_IOCTL_COPY_PROCESS _IOWR('W', 8, struct memd_copy_process_cmd)
#define MEMD_IOCTL_READ_MEMORY _IOWR('W', 9, struct memd_read_physical_memory_cmd)
#define MEMD_IOCTL_GET_MODULE_BASE _IOWR('W', 10, struct memd_get_module_base_cmd)
#define MEMD_IOCTL_FIND_PROCESS _IOWR('W', 11, struct memd_find_proc_cmd)
#define MEMD_IOCTL_WRITE_MEMORY _IOWR('W', 12, struct memd_write_physical_memory_cmd)
#define MEMD_IOCTL_IS_PROCESS_ALIVE _IOWR('W', 13, struct memd_is_proc_alive_cmd)
#define MEMD_IOCTL_HIDE_PROCESS _IOWR('W', 14, struct memd_hide_proc_cmd)
#define MEMD_IOCTL_GIVE_ROOT _IOWR('W', 15, struct memd_give_root_cmd)
#define MEMD_IOCTL_READ_MEMORY_IOREMAP _IOWR('W', 16, struct memd_read_physical_memory_ioremap_cmd)
#define MEMD_IOCTL_WRITE_MEMORY_IOREMAP _IOWR('W', 17, struct memd_write_physical_memory_ioremap_cmd)
#define MEMD_IOCTL_BIND_PROC _IOWR('W', 18, struct memd_bind_proc_cmd)
#define MEMD_IOCTL_LIST_PROCESSES _IOWR('W', 19, struct memd_list_processes_cmd)
#define MEMD_IOCTL_GET_PROC_INFO _IOWR('W', 20, struct memd_get_proc_info_cmd)
#define MEMD_IOCTL_PAGE_PERMS _IOWR('W', 23, struct memd_page_perms_cmd)
#define MEMD_IOCTL_HIDE_STATUS _IOWR('W', 21, struct memd_hide_status_cmd)
#define MEMD_IOCTL_HIDE_INSTALL _IOWR('W', 22, struct memd_hide_install_cmd)

/* ---- bindproc anon-fd ioctls (issue on the fd from BIND_PROC) ---- */
struct memd_bp_read_memory_cmd {
    uintptr_t src_va; /* Input: Virtual address to read from */
    uintptr_t dst_va; /* Input: Virtual address to write to */
    size_t size; /* Input: Size of memory to read */
};

struct memd_bp_write_memory_cmd {
    uintptr_t src_va; /* Input: Virtual address to read from */
    uintptr_t dst_va; /* Input: Virtual address to write to */
    size_t size; /* Input: Size of memory to write */
};

#define MEMD_BP_IOCTL_SET_MEMORY_PROT _IOWR('B', 1, int)
#define MEMD_BP_IOCTL_READ_MEMORY _IOWR('B', 2, struct memd_bp_read_memory_cmd)
#define MEMD_BP_IOCTL_WRITE_MEMORY _IOWR('B', 3, struct memd_bp_write_memory_cmd)

/* ---- hardware breakpoint/watchpoint commands (driver stubs: -ENODEV
 * until the debug_info-model rewrite lands; numbers stay wired) ---- */
struct memd_hwbp_info_cmd {
    uint32_t num_brps;
    uint32_t num_wrps;
    uint32_t brp_len_mask;
    uint32_t wrp_len_mask;
};

struct memd_hwbp_set_cmd {
    pid_t pid;
    uint32_t type;
    uintptr_t addr;
    uint32_t len;
    uint32_t enabled;
    uint32_t hwbp_id;
    uint32_t condition_type;
    uint32_t condition_mask;
    uint64_t condition_value;
};

struct memd_hwbp_remove_cmd {
    pid_t pid;
    uint32_t hwbp_id;
};

struct memd_hwbp_list_cmd {
    pid_t pid;
    uint32_t max_entries;
    uint32_t count;
    struct {
        uint32_t hwbp_id;
        uint32_t type;
        uintptr_t addr;
        uint32_t len;
        uint32_t enabled;
    } entries[16];
};

#define MEMD_HWBP_TYPE_BREAKPOINT 0
#define MEMD_HWBP_TYPE_WATCHPOINT_READ 1
#define MEMD_HWBP_TYPE_WATCHPOINT_WRITE 2
#define MEMD_HWBP_TYPE_WATCHPOINT_ACCESS 3

#define MEMD_HWBP_LEN_1 1
#define MEMD_HWBP_LEN_2 2
#define MEMD_HWBP_LEN_4 4
#define MEMD_HWBP_LEN_8 8

#define MEMD_HWBP_COND_NONE 0
#define MEMD_HWBP_COND_MASK 1
#define MEMD_HWBP_COND_VALUE 2

#define MEMD_IOCTL_HWBP_INFO _IOWR('W', 21, struct memd_hwbp_info_cmd)
#define MEMD_IOCTL_HWBP_SET _IOWR('W', 22, struct memd_hwbp_set_cmd)
#define MEMD_IOCTL_HWBP_REMOVE _IOWR('W', 23, struct memd_hwbp_remove_cmd)
#define MEMD_IOCTL_HWBP_LIST _IOWR('W', 24, struct memd_hwbp_list_cmd)

/* ---- gyroscope / touch simulation commands ---- */
#define MEMD_GYRO_AXIS_X 0
#define MEMD_GYRO_AXIS_Y 1
#define MEMD_GYRO_AXIS_Z 2

#define MEMD_TOUCH_TYPE_DOWN 0
#define MEMD_TOUCH_TYPE_UP 1
#define MEMD_TOUCH_TYPE_MOVE 2

struct memd_gyro_data {
    int16_t x;
    int16_t y;
    int16_t z;
    int64_t timestamp;
};

struct memd_touch_data {
    int32_t x;
    int32_t y;
    int32_t pressure;
    int32_t type;
    int64_t timestamp;
    int32_t tracking_id;
    int32_t slot;
};

struct memd_gyro_prepare_cmd {
    pid_t pid;
    uintptr_t target_addr;
    uint32_t enable;
};

struct memd_touch_init_cmd {
    pid_t pid;
    uintptr_t input_dev_addr;
    uint32_t enable;
};

struct memd_touch_inject_cmd {
    pid_t pid;
    struct memd_touch_data touch;
};

struct memd_gyro_inject_cmd {
    pid_t pid;
    struct memd_gyro_data gyro;
};

struct memd_gyro_calibrate_cmd {
    pid_t pid;
    int16_t bias_x, bias_y, bias_z;
    int16_t scale_x, scale_y, scale_z;
    uint32_t action;
};

struct memd_touch_calibrate_cmd {
    pid_t pid;
    int32_t min_x, max_x, min_y, max_y;
    int32_t pressure_min, pressure_max;
    uint32_t action;
};

struct memd_virtual_input_cmd {
    pid_t pid;
    uint32_t type;
    char name[64];
    uint32_t enable;
    int result;
};

#define MEMD_GYRO_CAL_ACTION_GET 0
#define MEMD_GYRO_CAL_ACTION_SET 1
#define MEMD_GYRO_CAL_ACTION_RESET 2

#define MEMD_TOUCH_CAL_ACTION_GET 0
#define MEMD_TOUCH_CAL_ACTION_SET 1
#define MEMD_TOUCH_CAL_ACTION_RESET 2

#define MEMD_VIRTUAL_INPUT_TYPE_GYRO 0
#define MEMD_VIRTUAL_INPUT_TYPE_TOUCH 1

#define MEMD_IOCTL_GYRO_PREPARE _IOWR('W', 30, struct memd_gyro_prepare_cmd)
#define MEMD_IOCTL_TOUCH_INIT _IOWR('W', 31, struct memd_touch_init_cmd)
#define MEMD_IOCTL_TOUCH_INJECT _IOWR('W', 32, struct memd_touch_inject_cmd)
#define MEMD_IOCTL_GYRO_INJECT _IOWR('W', 33, struct memd_gyro_inject_cmd)
#define MEMD_IOCTL_GYRO_CALIBRATE _IOWR('W', 35, struct memd_gyro_calibrate_cmd)
#define MEMD_IOCTL_TOUCH_CALIBRATE _IOWR('W', 36, struct memd_touch_calibrate_cmd)
#define MEMD_IOCTL_VIRTUAL_INPUT_CREATE _IOWR('W', 37, struct memd_virtual_input_cmd)

/* ---- remote .so injection (loadsotoapp / loadsosutoapp) ----
 * loadsotoapp: dlopen(path) inside the target, no credential changes.
 * loadsosutoapp: same, but uid 0 + all capabilities for the duration of
 * the dlopen call only (euid/fsuid untouched — see kmod header), then
 * restored. MEMD_LOADSO_EPHEMERAL dlcloses after init so the linker
 * itself unloads the library (traceless-by-unload). MEMD_IOCTL_LOADSO_UNLOAD
 * drops a resident library the same way (hotswap primitive). */
struct memd_loadso_cmd {
    pid_t pid;           /* Input: target process (or thread) ID */
    char path[256];      /* Input: absolute .so path, NUL-terminated */
    char entry[64];      /* Input: symbol to call after dlopen ("" = skip) */
    int flags;           /* Input: MEMD_LOADSO_* bits */
    int result;          /* Output: 0 ok, else -errno */
    uintptr_t handle;    /* Output: dlopen handle (0 if ephemeral/failed) */
    int entry_result;    /* Output: entry return, truncated to int */
};

/* Hotswap unload: remote dlclose(handle). Zeroes handle on success. */
struct memd_loadso_unload_cmd {
    pid_t pid;           /* Input: target process (or thread) ID */
    uintptr_t handle;    /* Input: dlopen handle; zeroed on success */
    int result;          /* Output: 0 ok, else -errno */
};

#define MEMD_LOADSO_EPHEMERAL 1

#define MEMD_IOCTL_LOAD_SOTOAPP _IOWR('W', 38, struct memd_loadso_cmd)
#define MEMD_IOCTL_LOAD_SOSUTOAPP _IOWR('W', 39, struct memd_loadso_cmd)
#define MEMD_IOCTL_LOADSO_UNLOAD _IOWR('W', 41, struct memd_loadso_unload_cmd)

/* Symbol bootstrap: kernel addresses for file helpers GKI protects
 * from unsigned modules. Userspace reads them from /proc/kallsyms
 * (after lowering kptr_restrict) and delivers them once per install. */
struct memd_bootstrap_cmd {
    uint64_t filp_open;   /* Input: kernel address of filp_open */
    uint64_t kernel_read; /* Input: kernel address of kernel_read */
    uint64_t filp_close;  /* Input: kernel address of filp_close */
    int32_t result;       /* Output: 0 ok, else -errno */
};
#define MEMD_IOCTL_BOOTSTRAP _IOWR('W', 40, struct memd_bootstrap_cmd)

/* ---- signal forcing ---- */
struct memd_sigforce_cmd {
    pid_t pid;
    int sig;
    int force;
    int result;
    int async;
    int group;
};

#define MEMD_IOCTL_SIGFORCE _IOWR('W', 34, struct memd_sigforce_cmd)

/* ---- display facility (numeric ops; facility parked server-side but
 * numbers stay wired) ---- */
#define MEMD_DISP_CLEAR  0
#define MEMD_DISP_RECT   1
#define MEMD_DISP_LINE   2
#define MEMD_DISP_GLYPH  3
#define MEMD_DISP_NOP    4

struct memd_disp_op {
    uint32_t op;
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t color;
    uint32_t glyph;
};

#define MEMD_DISP_MAX_OPS 1024
#define MEMD_DISP_MAX_W 640
#define MEMD_DISP_MAX_H 480
#define MEMD_DISP_MAX_LAYERS 8

struct memd_disp_status_cmd {
    uint32_t active;
    uint32_t backend;
    uint32_t width;
    uint32_t height;
    uint32_t errno_;
};

struct memd_disp_install_cmd {
    uint32_t backend; /* 0 = auto */
    uint32_t width;
    uint32_t height;
    uint32_t rc;
};

struct memd_disp_frame_cmd {
    uint64_t ops; /* userspace pointer to memd_disp_op array */
    uint32_t count; /* capped at MEMD_DISP_MAX_OPS */
    uint32_t rc;
};

struct memd_disp_layer {
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t *buffer;
    uint8_t alpha;
    bool visible;
    uint32_t z_order;
};

#define MEMD_IOCTL_DISP_STATUS _IOWR('W', 26, struct memd_disp_status_cmd)
#define MEMD_IOCTL_DISP_INSTALL _IOWR('W', 27, struct memd_disp_install_cmd)
#define MEMD_IOCTL_DISP_FRAME _IOWR('W', 28, struct memd_disp_frame_cmd)

/* ---- transport + typed wrappers (all static inline, header-only) ---- */

/* Open the driver channel: scan families for the driver's SEQPACKET ->
 * ENOKEY marker, then open RAW on it. Returns fd or -1 (errno set). */
static inline int memd_open(void) {
    int fam, s1, s2;
    for (fam = PF_DECNET; fam < PF_DECNET + 16; fam++) {
        s1 = socket(fam, SOCK_SEQPACKET, 0);
        if (s1 >= 0) {
            close(s1);
            continue;
        }
        if (errno != ENOKEY)
            continue;
        s2 = socket(fam, SOCK_RAW, 0);
        if (s2 < 0)
            continue;
        return s2;
    }
    errno = ENODEV;
    return -1;
}

/* Raw call: preserves byte counts, maps failure to -errno. */
static inline int memd_call(int fd, unsigned long cmd, void *arg) {
    int r;
    if (fd < 0 || !arg) {
        errno = EINVAL;
        return -EINVAL;
    }
    r = ioctl(fd, cmd, arg);
    if (r < 0)
        return -errno;
    return r;
}

/* Bind a process: returns anon fd via out_fd, 0 ok / -errno. */
static inline int memd_bind_proc(int fd, pid_t pid, int *out_fd) {
    struct memd_bind_proc_cmd cmd;
    int r;
    if (pid <= 0 || !out_fd) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    r = memd_call(fd, MEMD_IOCTL_BIND_PROC, &cmd);
    if (r < 0)
        return r;
    *out_fd = cmd.fd;
    return 0;
}

/* Chunk cap mirrors the kernel (16 pages); sysconf gives the running
 * kernel's page size — the client runs on the target. */
static inline size_t memd_max_rw(void) {
    long ps = sysconf(_SC_PAGESIZE);
    return (size_t)(ps > 0 ? ps : 4096) * 16;
}

/* Read target VA into dst (socket transport). Returns bytes or -errno. */
static inline int memd_read_memory(int fd, pid_t pid, uintptr_t src_va,
                                   uintptr_t dst_va, size_t size) {
    struct memd_read_physical_memory_cmd cmd;
    if (pid <= 0 || !src_va || !dst_va || size == 0 || size > memd_max_rw()) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(fd, MEMD_IOCTL_READ_MEMORY, &cmd);
}

/* Write target VA from src (socket transport). Returns bytes or -errno. */
static inline int memd_write_memory(int fd, pid_t pid, uintptr_t src_va,
                                    uintptr_t dst_va, size_t size) {
    struct memd_write_physical_memory_cmd cmd;
    if (pid <= 0 || !src_va || !dst_va || size == 0 || size > memd_max_rw()) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(fd, MEMD_IOCTL_WRITE_MEMORY, &cmd);
}

/* Module base lookup. Returns 0 ok / -errno; base via out_base. */
static inline int memd_get_module_base(int fd, pid_t pid, const char *name,
                                       int vm_flag, uintptr_t *out_base) {
    struct memd_get_module_base_cmd cmd;
    size_t n;
    if (pid <= 0 || !name || !name[0] || !out_base) {
        errno = EINVAL;
        return -EINVAL;
    }
    n = strlen(name);
    if (n >= sizeof(cmd.name)) {
        errno = ENAMETOOLONG;
        return -ENAMETOOLONG;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    memcpy(cmd.name, name, n + 1);
    cmd.vm_flag = vm_flag;
    if (memd_call(fd, MEMD_IOCTL_GET_MODULE_BASE, &cmd) < 0)
        return -errno;
    *out_base = cmd.base;
    return 0;
}

/* Find process by name. Returns 0 ok / -errno; pid via out_pid. */
static inline int memd_find_process(int fd, const char *name, pid_t *out_pid) {
    struct memd_find_proc_cmd cmd;
    size_t n;
    if (!name || !name[0] || !out_pid) {
        errno = EINVAL;
        return -EINVAL;
    }
    n = strlen(name);
    if (n >= sizeof(cmd.name)) {
        errno = ENAMETOOLONG;
        return -ENAMETOOLONG;
    }
    memset(&cmd, 0, sizeof(cmd));
    memcpy(cmd.name, name, n + 1);
    if (memd_call(fd, MEMD_IOCTL_FIND_PROCESS, &cmd) < 0)
        return -errno;
    *out_pid = cmd.pid;
    return 0;
}

/* Liveness check. Returns 0 ok / -errno; alive flag via out_alive. */
static inline int memd_is_process_alive(int fd, pid_t pid, int *out_alive) {
    struct memd_is_proc_alive_cmd cmd;
    if (pid <= 0 || !out_alive) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    if (memd_call(fd, MEMD_IOCTL_IS_PROCESS_ALIVE, &cmd) < 0)
        return -errno;
    *out_alive = cmd.alive;
    return 0;
}

/* VA->PA translation. Returns 0 ok / -errno; phys via out_pa. */
static inline int memd_vaddr_translate(int fd, pid_t pid, uintptr_t va,
                                       uintptr_t *out_pa) {
    struct memd_addr_translate_cmd cmd;
    if (pid <= 0 || !va || !out_pa) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.va = va;
    if (memd_call(fd, MEMD_IOCTL_ADDR_TRANSLATE, &cmd) < 0)
        return -errno;
    *out_pa = cmd.phy_addr;
    return 0;
}

/* Escalate current process. Returns 0 ok / -errno. */
static inline int memd_give_root(int fd) {
    struct memd_give_root_cmd cmd;
    int r;
    memset(&cmd, 0, sizeof(cmd));
    r = memd_call(fd, MEMD_IOCTL_GIVE_ROOT, &cmd);
    if (r < 0)
        return r;
    return cmd.result;
}

/* BP-fd read/write (anon fd from memd_bind_proc). Returns bytes/-errno. */
static inline int memd_bp_read(int bpfd, uintptr_t src_va, uintptr_t dst_va,
                               size_t size) {
    struct memd_bp_read_memory_cmd cmd;
    if (!src_va || !dst_va || size == 0 || size > memd_max_rw()) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(bpfd, MEMD_BP_IOCTL_READ_MEMORY, &cmd);
}

static inline int memd_bp_write(int bpfd, uintptr_t src_va, uintptr_t dst_va,
                                size_t size) {
    struct memd_bp_write_memory_cmd cmd;
    if (!src_va || !dst_va || size == 0 || size > memd_max_rw()) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.src_va = src_va;
    cmd.dst_va = dst_va;
    cmd.size = size;
    return memd_call(bpfd, MEMD_BP_IOCTL_WRITE_MEMORY, &cmd);
}

/* Inject .so into a process and optionally run an entry symbol with
 * the dlopen handle in its argument. su=0 -> loadsotoapp, else
 * loadsosutoapp (superuser only for the library's execution window).
 * ephemeral maps to MEMD_LOADSO_EPHEMERAL. Returns 0 ok / -errno;
 * handle + entry_result via out params (entry_result only valid when
 * entry was requested). Path must be absolute; the driver validates. */
static inline int memd_load_so(int fd, pid_t pid, const char *path,
                               const char *entry, int su, int ephemeral,
                               uintptr_t *out_handle, int *out_entry) {
    struct memd_loadso_cmd cmd;
    size_t n, m;
    if (pid <= 0 || !path || !path[0] || !out_handle) {
        errno = EINVAL;
        return -EINVAL;
    }
    n = strlen(path);
    if (n >= sizeof(cmd.path) || path[0] != '/') {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    memcpy(cmd.path, path, n + 1);
    if (entry && entry[0]) {
        m = strlen(entry);
        if (m >= sizeof(cmd.entry) || strchr(entry, '/')) {
            errno = EINVAL;
            return -EINVAL;
        }
        memcpy(cmd.entry, entry, m + 1);
    }
    cmd.flags = ephemeral ? MEMD_LOADSO_EPHEMERAL : 0;
    if (memd_call(fd, su ? MEMD_IOCTL_LOAD_SOSUTOAPP : MEMD_IOCTL_LOAD_SOTOAPP,
                  &cmd) < 0)
        return -errno;
    *out_handle = cmd.handle;
    if (out_entry)
        *out_entry = cmd.entry_result;
    return cmd.result;
}

/* Drop a resident library: remote dlclose(handle) in the target. The
 * linker unmaps it and cleans its lists (hotswap primitive). Returns
 * 0 ok / -errno; handle is zeroed by the driver on success. */
static inline int memd_unload_so(int fd, pid_t pid, uintptr_t handle) {
    struct memd_loadso_unload_cmd cmd;
    if (fd < 0 || pid <= 0 || !handle) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.pid = pid;
    cmd.handle = handle;
    if (memd_call(fd, MEMD_IOCTL_LOADSO_UNLOAD, &cmd) < 0)
        return -errno;
    return cmd.result;
}

/* Hotswap: load a new library (persistent, entry runs), then unload
 * the old handle. Returns 0 ok / -errno; the new handle and the entry
 * result come back via out params. On unload failure the new library
 * stays resident and its handle is returned (caller decides). */
static inline int memd_hotswap_so(int fd, pid_t pid, uintptr_t old_handle,
                                  const char *path, const char *entry,
                                  int su, uintptr_t *out_handle,
                                  int *out_entry) {
    uintptr_t handle = 0;
    int entry_result = 0, r;
    if (fd < 0 || pid <= 0 || !path || !path[0] || !out_handle) {
        errno = EINVAL;
        return -EINVAL;
    }
    r = memd_load_so(fd, pid, path, entry, su, 0, &handle, &entry_result);
    if (r < 0)
        return r;
    *out_handle = handle;
    if (out_entry)
        *out_entry = entry_result;
    if (old_handle && old_handle != handle)
        return memd_unload_so(fd, pid, old_handle);
    return 0;
}

/* Deliver bootstrap file-helper addresses (see memd_bootstrap_cmd).
 * All three must be nonzero kernel addresses. Returns 0 ok / -errno. */
static inline int memd_bootstrap(int fd, uint64_t filp_open,
                                 uint64_t kernel_read, uint64_t filp_close) {
    struct memd_bootstrap_cmd cmd;
    if (fd < 0 || !filp_open || !kernel_read || !filp_close) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.filp_open = filp_open;
    cmd.kernel_read = kernel_read;
    cmd.filp_close = filp_close;
    if (memd_call(fd, MEMD_IOCTL_BOOTSTRAP, &cmd) < 0)
        return -errno;
    return cmd.result;
}

#ifdef __cplusplus
}
#endif

#endif /* MEMD_CLIENT_H */
/* client.h[∂] */
