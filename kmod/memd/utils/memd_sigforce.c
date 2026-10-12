#include "memd_sigforce.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>
#include <linux/errno.h>

#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

static DEFINE_SPINLOCK(sigforce_lock);
static bool sigforce_initialized = false;

int memd_sigforce_init(void)
{
    sigforce_initialized = true;
    memd_info("sigforce: initialized\n");
    return 0;
}

void memd_sigforce_cleanup(void)
{
    sigforce_initialized = false;
    memd_info("sigforce: cleaned up\n");
}

static int memd_sigforce_deliver(struct task_struct *task, int sig, int force)
{
    struct siginfo info;
    unsigned long flags;
    int ret = 0;
    
    if (!task)
        return -ESRCH;
    
    if (sig < 1 || sig > 64)
        return -EINVAL;
    
    if (!memd_capable(CAP_KILL) && !memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = SI_KERNEL;
    info.si_pid = task_pid_vnr(current);
    info.si_uid = memd_uid();
    
    spin_lock_irqsave(&sigforce_lock, flags);
    
    if (force) {
        struct sighand_struct *sighand = memd_t_sighand(task);
        if (sighand) {
            spin_lock(&sighand->siglock);
            if (!(task->flags & PF_KTHREAD)) {
                task->signal->flags &= ~SIGNAL_GROUP_EXIT;
                task->flags &= ~PF_EXITING;
                task->signal->group_exit_code = 0;
                task->signal->group_stop_count = 0;
            }
            spin_unlock(&sighand->siglock);
        }
    }
    
    ret = send_signal(sig, &info, task, PIDTYPE_PID);
    
    if (force && ret == 0) {
        if (sig == SIGKILL || sig == SIGSTOP) {
            task->flags &= ~PF_EXITING;
            wake_up_process(task);
        }
    }
    
    spin_unlock_irqrestore(&sigforce_lock, flags);
    
    return ret;
}

int memd_sigforce_send(struct task_struct *task, int sig, int force)
{
    if (!sigforce_initialized)
        return -ENODEV;
    
    return memd_sigforce_deliver(task, sig, force);
}