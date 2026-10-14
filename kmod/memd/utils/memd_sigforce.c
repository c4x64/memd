#include "memd_sigforce.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>
#include <linux/errno.h>
#include <linux/sched/task.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

static DEFINE_SPINLOCK(sigforce_lock);
static bool sigforce_initialized = false;

struct sigforce_pending {
    struct task_struct *task;
    int sig;
    int force;
    struct siginfo info;
    struct completion done;
    int result;
    struct list_head list;
};

static LIST_HEAD(sigforce_pending_list);
static DEFINE_MUTEX(sigforce_pending_lock);
static struct task_struct *sigforce_worker_task = NULL;
static DECLARE_WAIT_QUEUE_HEAD(sigforce_worker_wq);
static atomic_t sigforce_pending_count = ATOMIC_INIT(0);

static int memd_sigforce_worker(void *data)
 {
    struct sigforce_pending *pending;

    while (!kthread_should_stop()) {
        wait_event_interruptible(sigforce_worker_wq,
                                atomic_read(&sigforce_pending_count) > 0 ||
                                kthread_should_stop());

        if (kthread_should_stop())
            break;

        mutex_lock(&sigforce_pending_lock);
        if (list_empty(&sigforce_pending_list)) {
            mutex_unlock(&sigforce_pending_lock);
            continue;
        }

        pending = list_first_entry(&sigforce_pending_list, struct sigforce_pending, list);
        list_del(&pending->list);
        atomic_dec(&sigforce_pending_count);
        mutex_unlock(&sigforce_pending_lock);

        if (!pending->task || pending->task->flags & PF_EXITING) {
            pending->result = -ESRCH;
            complete(&pending->done);
            continue;
        }

        pending->result = send_signal(pending->sig, &pending->info, pending->task, PIDTYPE_PID);

        if (pending->force && pending->result == 0) {
            if (pending->sig == SIGKILL || pending->sig == SIGSTOP) {
                pending->task->flags &= ~PF_EXITING;
                wake_up_process(pending->task);
            }
        }

        complete(&pending->done);
    }

    return 0;
}

int memd_sigforce_init(void)
 {
    sigforce_initialized = true;

    sigforce_worker_task = kthread_run(memd_sigforce_worker, NULL, "memd_sigforce");
    if (IS_ERR(sigforce_worker_task)) {
        memd_err("sigforce: failed to create worker thread\n");
        sigforce_worker_task = NULL;
        return PTR_ERR(sigforce_worker_task);
    }

    memd_info("sigforce: initialized with async worker\n");
    return 0;
}

void memd_sigforce_cleanup(void)
 {
    struct sigforce_pending *pending, *tmp;

    if (sigforce_worker_task) {
        kthread_stop(sigforce_worker_task);
        sigforce_worker_task = NULL;
    }

    mutex_lock(&sigforce_pending_lock);
    list_for_each_entry_safe(pending, tmp, &sigforce_pending_list, list) {
        list_del(&pending->list);
        pending->result = -ENODEV;
        complete(&pending->done);
    }
    mutex_unlock(&sigforce_pending_lock);

    sigforce_initialized = false;
    memd_info("sigforce: cleaned up\n");
}

static int memd_sigforce_deliver_sync(struct task_struct *task, int sig, int force)
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

    if (task->flags & PF_EXITING)
        return -ESRCH;

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

static int memd_sigforce_deliver_async(struct task_struct *task, int sig, int force)
 {
    struct sigforce_pending *pending;
    struct siginfo info;
    int ret;

    if (!task || task->flags & PF_EXITING)
        return -ESRCH;

    if (sig < 1 || sig > 64)
        return -EINVAL;

    if (!memd_capable(CAP_KILL) && !memd_capable(CAP_SYS_ADMIN))
        return -EPERM;

    pending = kmalloc(sizeof(*pending), GFP_KERNEL);
    if (!pending)
        return -ENOMEM;

    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = SI_KERNEL;
    info.si_pid = task_pid_vnr(current);
    info.si_uid = memd_uid();

    pending->task = task;
    pending->sig = sig;
    pending->force = force;
    pending->info = info;
    init_completion(&pending->done);
    pending->result = 0;

    mutex_lock(&sigforce_pending_lock);
    list_add_tail(&pending->list, &sigforce_pending_list);
    atomic_inc(&sigforce_pending_count);
    mutex_unlock(&sigforce_pending_lock);

    wake_up(&sigforce_worker_wq);

    wait_for_completion(&pending->done);
    ret = pending->result;
    kfree(pending);

    return ret;
}

int memd_sigforce_send(struct task_struct *task, int sig, int force)
 {
    if (!sigforce_initialized)
        return -ENODEV;

    return memd_sigforce_deliver_sync(task, sig, force);
}

int memd_sigforce_send_async(struct task_struct *task, int sig, int force)
 {
    if (!sigforce_initialized)
        return -ENODEV;

    return memd_sigforce_deliver_async(task, sig, force);
}

int memd_sigforce_send_group(struct task_struct *task, int sig, int force)
 {
    struct task_struct *p;
    int ret = 0;

    if (!sigforce_initialized)
        return -ENODEV;

    if (!task)
        return -ESRCH;

    if (sig < 1 || sig > 64)
        return -EINVAL;

    if (!memd_capable(CAP_KILL) && !memd_capable(CAP_SYS_ADMIN))
        return -EPERM;

    rcu_read_lock();
    for_each_process(p) {
        if (p->signal == task->signal) {
            ret = memd_sigforce_deliver_sync(p, sig, force);
            if (ret)
                break;
        }
    }
    rcu_read_unlock();

    return ret;
}
/* kmod/memd/utils/memd_sigforce.c[∂] */
