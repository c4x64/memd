#ifndef MEMD_MEMD_PROC_H
#define MEMD_MEMD_PROC_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/pid_namespace.h>
#include "memd_common.h"
#include <linux/sched.h>

int is_invisible(pid_t pid);
bool memd_hide_check_visibility(pid_t pid, struct pid_namespace *ns);
int memd_hide_get_hidden_pids(pid_t *buf, size_t buf_size, size_t *count);
int memd_hide_get_ns_hidden_pids(pid_t *buf, size_t buf_size, size_t *count, struct pid_namespace *ns);

#endif // MEMD_MEMD_PROC_H
/* kmod/memd/proc/memd_proc.h[∂] */
