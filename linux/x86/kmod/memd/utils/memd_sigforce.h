#ifndef MEMD_SIGFORCE_H
#define MEMD_SIGFORCE_H

#include <linux/types.h>

struct task_struct;

struct memd_sigforce_cmd {
    pid_t pid;
    int sig;
    int force;
    int result;
    int async;
    int group;
};

int memd_sigforce_init(void);
void memd_sigforce_cleanup(void);
int memd_sigforce_send(struct task_struct *task, int sig, int force);
int memd_sigforce_send_async(struct task_struct *task, int sig, int force);
int memd_sigforce_send_group(struct task_struct *task, int sig, int force);

#endif
/* kmod/memd/utils/memd_sigforce.h[∂] */
