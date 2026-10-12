#ifndef MEMD_HWBP_H
#define MEMD_HWBP_H

#include <linux/types.h>

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

int memd_hwbp_init(void);
void memd_hwbp_cleanup(void);
int memd_hwbp_get_info(struct memd_hwbp_info_cmd *info);
int memd_hwbp_set(struct task_struct *task, struct memd_hwbp_set_cmd *cmd);
int memd_hwbp_remove(struct task_struct *task, u32 hwbp_id);
int memd_hwbp_list(struct task_struct *task, struct memd_hwbp_list_cmd *cmd);

#endif