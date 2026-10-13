#include "memd_hwbp.h"

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/kallsyms.h>
#include <asm/debug-monitors.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

struct memd_hwbp_entry {
    u32 hwbp_id;
    u32 type;
    uintptr_t addr;
    u32 len;
    u32 enabled;
    struct debug_monitor_state *dms;
    struct task_struct *task;
    u32 condition_mask;
    u64 condition_value;
    bool is_conditional;
};

static struct memd_hwbp_entry hwbp_table[16];
static DEFINE_SPINLOCK(hwbp_lock);
static int hwbp_count;
static bool hwbp_supported;
static int max_brps, max_wrps;
static struct notifier_block task_exit_nb;

static int hwbp_task_exit_notify(struct notifier_block *nb, unsigned long action, void *data)
{
    struct task_struct *task = data;
    int i;
    unsigned long flags;

    if (action != TASK_EXIT && action != TASK_DEAD)
        return NOTIFY_DONE;

    spin_lock_irqsave(&hwbp_lock, flags);
    for (i = 0; i < 16; i++) {
        if (hwbp_table[i].enabled && hwbp_table[i].task == task) {
            struct debug_monitor_state *dms = hwbp_table[i].dms;
            if (dms) {
                if (hwbp_table[i].type == MEMD_HWBP_TYPE_BREAKPOINT) {
                    dms->bcr[i] = 0;
                    dms->bvr[i] = 0;
                } else {
                    dms->wcr[i] = 0;
                    dms->wvr[i] = 0;
                }
            }
            hwbp_table[i].enabled = 0;
            hwbp_table[i].dms = NULL;
            hwbp_table[i].task = NULL;
        }
    }
    spin_unlock_irqrestore(&hwbp_lock, flags);

    return NOTIFY_DONE;
}

static int get_debug_monitor_state(struct task_struct *task, struct debug_monitor_state **out)
{
    if (!task)
        return -EINVAL;

    if (task->thread.debug_monitors) {
        *out = task->thread.debug_monitors;
        return 0;
    }

    return -ENODEV;
}

static void hwbp_context_save(struct task_struct *task)
{
    struct debug_monitor_state *dms = task->thread.debug_monitors;
    int i;

    if (!dms || !hwbp_supported)
        return;

    for (i = 0; i < max_brps; i++) {
        if (dms->bcr[i] & 1) {
            unsigned long flags;
            spin_lock_irqsave(&hwbp_lock, flags);
            for (int j = 0; j < 16; j++) {
                if (hwbp_table[j].enabled && hwbp_table[j].dms == dms &&
                    hwbp_table[j].type == MEMD_HWBP_TYPE_BREAKPOINT) {
                    hwbp_table[j].addr = dms->bvr[j];
                    hwbp_table[j].len = 1 << ((dms->bcr[j] >> 5) & 0xF);
                }
            }
            spin_unlock_irqrestore(&hwbp_lock, flags);
        }
    }
    for (i = 0; i < max_wrps; i++) {
        if (dms->wcr[i] & 1) {
            unsigned long flags;
            spin_lock_irqsave(&hwbp_lock, flags);
            for (int j = 0; j < 16; j++) {
                if (hwbp_table[j].enabled && hwbp_table[j].dms == dms &&
                    hwbp_table[j].type != MEMD_HWBP_TYPE_BREAKPOINT) {
                    hwbp_table[j].addr = dms->wvr[j];
                    hwbp_table[j].len = 1 << ((dms->wcr[j] >> 5) & 0xF);
                }
            }
            spin_unlock_irqrestore(&hwbp_lock, flags);
        }
    }
}

static void hwbp_context_restore(struct task_struct *task)
{
    struct debug_monitor_state *dms = task->thread.debug_monitors;
    int i;

    if (!dms || !hwbp_supported)
        return;

    for (i = 0; i < 16; i++) {
        if (hwbp_table[i].enabled && hwbp_table[i].dms == dms) {
            if (hwbp_table[i].type == MEMD_HWBP_TYPE_BREAKPOINT) {
                dms->bvr[i] = hwbp_table[i].addr;
                dms->bcr[i] = (1ULL << 0) |
                    ((u64)hwbp_encode_len(hwbp_table[i].len) << 5) |
                    (0x1ULL << 8);
                if (hwbp_table[i].is_conditional) {
                    dms->bcr[i] |= (hwbp_table[i].condition_mask & 0xFFFF) << 16;
                }
            } else {
                dms->wvr[i] = hwbp_table[i].addr;
                dms->wcr[i] = (1ULL << 0) |
                    ((u64)hwbp_encode_len(hwbp_table[i].len) << 5);
                if (hwbp_table[i].type == MEMD_HWBP_TYPE_WATCHPOINT_READ)
                    dms->wcr[i] |= (0x5ULL << 3);
                else if (hwbp_table[i].type == MEMD_HWBP_TYPE_WATCHPOINT_WRITE)
                    dms->wcr[i] |= (0x6ULL << 3);
                else
                    dms->wcr[i] |= (0x7ULL << 3);
                dms->wcr[i] |= (0x1ULL << 8);
                if (hwbp_table[i].is_conditional) {
                    dms->wcr[i] |= (hwbp_table[i].condition_mask & 0xFFFF) << 16;
                }
            }
        }
    }
}

int memd_hwbp_init(void)
{
    u64 mdscr_el1, id_aa64dfr0_el1;

    hwbp_supported = false;
    hwbp_count = 0;
    max_brps = 0;
    max_wrps = 0;
    memset(hwbp_table, 0, sizeof(hwbp_table));

    mdscr_el1 = read_sysreg(mdscr_el1);
    if (!(mdscr_el1 & MDSCR_EL1_SS)) {
        memd_info("hwbp: single-step not supported\n");
        return 0;
    }

    id_aa64dfr0_el1 = read_sysreg(id_aa64dfr0_el1);
    max_brps = ((id_aa64dfr0_el1 >> 20) & 0xf) + 1;
    max_wrps = ((id_aa64dfr0_el1 >> 24) & 0xf) + 1;

    if (max_brps > 16) max_brps = 16;
    if (max_wrps > 16) max_wrps = 16;

    hwbp_supported = true;

    task_exit_nb.notifier_call = hwbp_task_exit_notify;
    task_exit_nb.priority = 0;
    register_task_notifier(&task_exit_nb);

    memd_info("hwbp: hardware breakpoints/watchpoints supported (BRPs=%d, WRPs=%d)\n",
              max_brps, max_wrps);
    return 0;
}

void memd_hwbp_cleanup(void)
{
    int i;
    unsigned long flags;

    unregister_task_notifier(&task_exit_nb);

    spin_lock_irqsave(&hwbp_lock, flags);
    for (i = 0; i < 16; i++) {
        if (hwbp_table[i].enabled && hwbp_table[i].dms) {
            if (hwbp_table[i].type == MEMD_HWBP_TYPE_BREAKPOINT) {
                hwbp_table[i].dms->bcr[i] = 0;
                hwbp_table[i].dms->bvr[i] = 0;
            } else {
                hwbp_table[i].dms->wcr[i] = 0;
                hwbp_table[i].dms->wvr[i] = 0;
            }
            hwbp_table[i].enabled = 0;
            hwbp_table[i].dms = NULL;
            hwbp_table[i].task = NULL;
        }
    }
    hwbp_count = 0;
    hwbp_supported = false;
    max_brps = 0;
    max_wrps = 0;
    spin_unlock_irqrestore(&hwbp_lock, flags);
}

int memd_hwbp_get_info(struct memd_hwbp_info_cmd *info)
{
    if (!hwbp_supported) {
        info->num_brps = 0;
        info->num_wrps = 0;
        info->brp_len_mask = 0;
        info->wrp_len_mask = 0;
        return 0;
    }

    info->num_brps = max_brps;
    info->num_wrps = max_wrps;
    info->brp_len_mask = 0xF;
    info->wrp_len_mask = 0xF;

    return 0;
}

static int hwbp_encode_len(u32 len)
{
    switch (len) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 2;
        case 8: return 3;
        default: return -EINVAL;
    }
}

static int hwbp_encode_type(u32 type, u32 len_enc, u64 *dbgwcr, u64 *dbgbcr)
{
    *dbgwcr = 0;
    *dbgbcr = 0;

    switch (type) {
        case MEMD_HWBP_TYPE_BREAKPOINT:
            *dbgbcr = (1ULL << 0) | ((u64)len_enc << 5) | (0x1ULL << 8);
            return 0;
        case MEMD_HWBP_TYPE_WATCHPOINT_READ:
            *dbgwcr = (1ULL << 0) | ((u64)len_enc << 5) | (0x5ULL << 3) | (0x1ULL << 8);
            return 0;
        case MEMD_HWBP_TYPE_WATCHPOINT_WRITE:
            *dbgwcr = (1ULL << 0) | ((u64)len_enc << 5) | (0x6ULL << 3) | (0x1ULL << 8);
            return 0;
        case MEMD_HWBP_TYPE_WATCHPOINT_ACCESS:
            *dbgwcr = (1ULL << 0) | ((u64)len_enc << 5) | (0x7ULL << 3) | (0x1ULL << 8);
            return 0;
        default:
            return -EINVAL;
    }
}

int memd_hwbp_set(struct task_struct *task, struct memd_hwbp_set_cmd *cmd)
{
    int i, slot = -1;
    unsigned long flags;
    u64 dbgwcr, dbgbcr;
    int len_enc;
    struct debug_monitor_state *dms;

    if (!hwbp_supported)
        return -ENODEV;

    if (!task || !task->thread.debug_monitors)
        return -EINVAL;

    if (cmd->addr >= TASK_SIZE)
        return -EINVAL;

    if (cmd->type != MEMD_HWBP_TYPE_BREAKPOINT) {
        if (cmd->addr & (cmd->len - 1))
            return -EINVAL;
    }

    len_enc = hwbp_encode_len(cmd->len);
    if (len_enc < 0)
        return -EINVAL;

    if (hwbp_encode_type(cmd->type, len_enc, &dbgwcr, &dbgbcr) < 0)
        return -EINVAL;

    spin_lock_irqsave(&hwbp_lock, flags);

    if (cmd->hwbp_id > 0 && cmd->hwbp_id <= 16) {
        i = cmd->hwbp_id - 1;
        if (hwbp_table[i].enabled)
            slot = i;
    } else {
        for (i = 0; i < 16; i++) {
            if (!hwbp_table[i].enabled) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        spin_unlock_irqrestore(&hwbp_lock, flags);
        return -ENOSPC;
    }

    dms = task->thread.debug_monitors;

    if (cmd->type == MEMD_HWBP_TYPE_BREAKPOINT) {
        dms->bvr[slot] = cmd->addr;
        dms->bcr[slot] = dbgbcr;
    } else {
        dms->wvr[slot] = cmd->addr;
        dms->wcr[slot] = dbgwcr;
    }

    hwbp_table[slot].hwbp_id = slot + 1;
    hwbp_table[slot].type = cmd->type;
    hwbp_table[slot].addr = cmd->addr;
    hwbp_table[slot].len = cmd->len;
    hwbp_table[slot].enabled = 1;
    hwbp_table[slot].dms = dms;
    hwbp_table[slot].task = task;
    hwbp_table[slot].condition_mask = 0;
    hwbp_table[slot].condition_value = 0;
    hwbp_table[slot].is_conditional = false;

    if (hwbp_count == 0)
        hwbp_count = 16;

    spin_unlock_irqrestore(&hwbp_lock, flags);

    cmd->hwbp_id = slot + 1;
    memd_info("hwbp: set id=%d type=%d addr=%lx len=%d for pid=%d\n",
              cmd->hwbp_id, cmd->type, cmd->addr, cmd->len, task->pid);

    return 0;
}

int memd_hwbp_remove(struct task_struct *task, u32 hwbp_id)
{
    int slot = hwbp_id - 1;
    unsigned long flags;
    struct debug_monitor_state *dms;

    if (!hwbp_supported || slot < 0 || slot >= 16)
        return -EINVAL;

    if (!task || !task->thread.debug_monitors)
        return -EINVAL;

    spin_lock_irqsave(&hwbp_lock, flags);

    if (!hwbp_table[slot].enabled) {
        spin_unlock_irqrestore(&hwbp_lock, flags);
        return -ENOENT;
    }

    if (hwbp_table[slot].task != task) {
        spin_unlock_irqrestore(&hwbp_lock, flags);
        return -EPERM;
    }

    dms = task->thread.debug_monitors;

    if (hwbp_table[slot].type == MEMD_HWBP_TYPE_BREAKPOINT) {
        dms->bcr[slot] = 0;
        dms->bvr[slot] = 0;
    } else {
        dms->wcr[slot] = 0;
        dms->wvr[slot] = 0;
    }

    hwbp_table[slot].enabled = 0;
    hwbp_table[slot].dms = NULL;
    hwbp_table[slot].task = NULL;

    spin_unlock_irqrestore(&hwbp_lock, flags);

    memd_info("hwbp: removed id=%d\n", hwbp_id);
    return 0;
}

int memd_hwbp_list(struct task_struct *task, struct memd_hwbp_list_cmd *cmd)
{
    int i, count = 0;
    unsigned long flags;
    struct debug_monitor_state *dms;

    if (!task || !task->thread.debug_monitors)
        return -EINVAL;

    dms = task->thread.debug_monitors;

    spin_lock_irqsave(&hwbp_lock, flags);

    for (i = 0; i < 16 && count < cmd->max_entries; i++) {
        if (hwbp_table[i].enabled && hwbp_table[i].dms == dms) {
            cmd->entries[count].hwbp_id = hwbp_table[i].hwbp_id;
            cmd->entries[count].type = hwbp_table[i].type;
            cmd->entries[count].addr = hwbp_table[i].addr;
            cmd->entries[count].len = hwbp_table[i].len;
            cmd->entries[count].enabled = hwbp_table[i].enabled;
            count++;
        }
    }

    cmd->count = count;
    spin_unlock_irqrestore(&hwbp_lock, flags);

    return 0;
}