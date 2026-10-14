#ifndef MEMD_HWBP_H
#define MEMD_HWBP_H

#include <linux/errno.h>
#include <linux/types.h>

struct task_struct;

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

struct memd_hwbp_info_cmd {
    u32 num_brps;
    u32 num_wrps;
    u32 brp_len_mask;
    u32 wrp_len_mask;
};

struct memd_hwbp_set_cmd {
    pid_t pid;
    u32 type;
    uintptr_t addr;
    u32 len;
    u32 enabled;
    u32 hwbp_id;
    u32 condition_type;
    u32 condition_mask;
    u64 condition_value;
};

struct memd_hwbp_remove_cmd {
    pid_t pid;
    u32 hwbp_id;
};

struct memd_hwbp_list_cmd {
    pid_t pid;
    u32 max_entries;
    u32 count;
    struct {
        u32 hwbp_id;
        u32 type;
        uintptr_t addr;
        u32 len;
        u32 enabled;
    } entries[16];
};

/* TODO(hwbp): implementation parked (memd_hwbp.c not in rwbridge-y).
 * It programs thread_struct.debug_monitors / struct debug_monitor_state,
 * removed on every matrix DDK (new model: thread debug_info + live
 * registers). Stubs keep the ioctl numbers wired and fail soft until
 * the rewrite lands. */
static inline int memd_hwbp_init(void) { return 0; }
static inline void memd_hwbp_cleanup(void) {}
static inline int memd_hwbp_get_info(struct memd_hwbp_info_cmd *info)
{
    (void)info;
    return -ENODEV;
}
static inline int memd_hwbp_set(struct task_struct *task, struct memd_hwbp_set_cmd *cmd)
{
    (void)task;
    (void)cmd;
    return -ENODEV;
}
static inline int memd_hwbp_remove(struct task_struct *task, u32 hwbp_id)
{
    (void)task;
    (void)hwbp_id;
    return -ENODEV;
}
static inline int memd_hwbp_list(struct task_struct *task, struct memd_hwbp_list_cmd *cmd)
{
    (void)task;
    (void)cmd;
    return -ENODEV;
}

#endif
/* kmod/memd/utils/memd_hwbp.h[∂] */
