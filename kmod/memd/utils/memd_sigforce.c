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
#include <linux/jiffies.h>
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
/* True when no worker thread exists: set only after the NULLer's
 * kthread_stop has returned (thread joined), so a waiter that sees
 * (NULL + true) under the lock knows no in-flight touch can still
 * arrive. False while a worker exists OR a stop is in progress. */
static bool sigforce_worker_stopped = true;
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
        list_del_init(&pending->list);
        atomic_dec(&sigforce_pending_count);
        mutex_unlock(&sigforce_pending_lock);

        if (!pending->task || pending->task->flags & PF_EXITING) {
            pending->result = -ESRCH;
            complete(&pending->done);
            continue;
        }

        pending->result = memd_send_signal(pending->sig, &pending->info, pending->task, PIDTYPE_PID);

        /* Same no-clear rule as the sync path: the pre-queue check
         * raced with do_exit, so a clear here fires exactly when the
         * target began a genuine exit -- corrupting exit state without
         * resurrecting it. Wake only. */
        if (pending->force && pending->result == 0) {
            if (pending->sig == SIGKILL || pending->sig == SIGSTOP) {
                wake_up_process(pending->task);
            }
        }

        complete(&pending->done);
    }

    return 0;
}

int memd_sigforce_init(void)
 {
    struct task_struct *worker;
    struct task_struct *stale;
    int err;

    mutex_lock(&sigforce_pending_lock);
    if (sigforce_worker_task || sigforce_initialized) {
        /* A kthread has no mm (OOM skips it) and ignores signals, but
         * an oops/panic path can still reap it. The zombie stays valid
         * until kthread_stop, so this deref is safe while the pointer
         * is non-NULL. Reap and recreate instead of wedging forever
         * on a stale pointer (old code returned 0 without a worker). */
        if (!sigforce_worker_task ||
            (!(sigforce_worker_task->flags & PF_EXITING) &&
             !sigforce_worker_task->exit_state)) {
            mutex_unlock(&sigforce_pending_lock);
            return 0;
        }
        stale = sigforce_worker_task;
        sigforce_worker_task = NULL;
        sigforce_initialized = false;
        mutex_unlock(&sigforce_pending_lock);
        kthread_stop(stale);
        mutex_lock(&sigforce_pending_lock);
    }
    worker = kthread_run(memd_sigforce_worker, NULL, "memd_sigforce");
    if (IS_ERR(worker)) {
        err = PTR_ERR(worker);
        sigforce_worker_task = NULL;
        sigforce_initialized = false;
        sigforce_worker_stopped = true;
        mutex_unlock(&sigforce_pending_lock);
        memd_err("sigforce: failed to create worker thread\n");
        return err;
    }
    sigforce_worker_task = worker;
    sigforce_initialized = true;
    sigforce_worker_stopped = false;
    mutex_unlock(&sigforce_pending_lock);

    memd_info("sigforce: initialized with async worker\n");
    return 0;
}

void memd_sigforce_cleanup(void)
 {
    struct sigforce_pending *pending, *tmp;
    struct task_struct *worker;

    /* Refuse new queuers first: anything queued after the worker is
     * gone would wait forever. Handoff under the same lock the queuers
     * re-check, and stop outside it (kthread_stop sleeps). */
    mutex_lock(&sigforce_pending_lock);
    sigforce_initialized = false;
    worker = sigforce_worker_task;
    sigforce_worker_task = NULL;
    mutex_unlock(&sigforce_pending_lock);

    if (worker)
        kthread_stop(worker);

    mutex_lock(&sigforce_pending_lock);
    list_for_each_entry_safe(pending, tmp, &sigforce_pending_list, list) {
        list_del_init(&pending->list);
        pending->result = -ENODEV;
        complete(&pending->done);
    }
    atomic_set(&sigforce_pending_count, 0);
    /* After kthread_stop returned the thread is joined: no in-flight
     * touch of an off-list entry can still arrive. Publish under the
     * same lock waiters check, so (NULL + true) means reclaim-safe. */
    sigforce_worker_stopped = true;
    mutex_unlock(&sigforce_pending_lock);

    memd_info("sigforce: cleaned up\n");
}

static int memd_sigforce_deliver_sync(struct task_struct *task, int sig, int force)
 {
    struct siginfo info;
    unsigned long flags;
    int ret = 0;
    /* Resolved sleepable, before the lock: the send entry's lazy resolve
     * sleeps (kallsyms file IO + GFP_KERNEL), and a bootstrap re-arm
     * between a pure warm and the send would re-dirty the table and
     * sleep again under sigforce_lock below. Locals pin kernel text
     * addresses (stable across re-arms, never imports); the send path
     * itself is siglock + GFP_ATOMIC and never sleeps. */
    int (*fn_send)(int, struct kernel_siginfo *,
                   struct task_struct *, enum pid_type);
    int (*fn_do)(int, struct kernel_siginfo *,
                 struct task_struct *, enum pid_type);

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

    /* Resolve here, sleepable, so nothing under sigforce_lock below
     * can sleep even if a bootstrap re-arms the table mid-call. */
    fn_send = (void *)kallsyms_lookup_name_ex("send_signal");
    fn_do = (void *)kallsyms_lookup_name_ex("do_send_sig_info");

    spin_lock_irqsave(&sigforce_lock, flags);

    if (force) {
        struct sighand_struct *sighand = memd_t_sighand(task);
        if (sighand) {
            spin_lock(&sighand->siglock);
            /* Re-check under siglock: the entry test raced with do_exit.
             * Stripping PF_EXITING/SIGNAL_GROUP_EXIT (and zeroing the
             * group exit code) from a task that began a genuine exit
             * since would corrupt exit/wait state without resurrecting
             * it (do_exit never re-checks the flag to abort). Fail
             * closed: report -ESRCH and leave exit state alone. */
            if (task->flags & PF_EXITING) {
                spin_unlock(&sighand->siglock);
                spin_unlock_irqrestore(&sigforce_lock, flags);
                return -ESRCH;
            }
            if (!(task->flags & PF_KTHREAD) && task->signal) {
                task->signal->flags &= ~SIGNAL_GROUP_EXIT;
                task->flags &= ~PF_EXITING;
                task->signal->group_exit_code = 0;
                task->signal->group_stop_count = 0;
            }
            spin_unlock(&sighand->siglock);
        }
    }

    /* Direct call on the pre-resolved locals: a concurrent re-arm
     * cannot dirty these, so nothing here sleeps. Fail closed with
     * -ESRCH when neither entry resolves (same as memd_send_signal,
     * e.g. kptr_restrict hides every address). */
    if (fn_send)
        ret = fn_send(sig, (struct kernel_siginfo *)&info, task, PIDTYPE_PID);
    else if (fn_do)
        ret = fn_do(sig, (struct kernel_siginfo *)&info, task, PIDTYPE_PID);
    else
        ret = -ESRCH;

    if (force && ret == 0) {
        if (sig == SIGKILL || sig == SIGSTOP) {
            /* No flag clear here: reaching this point means the target
             * was not exiting at the siglock re-check, so clearing
             * PF_EXITING would be a no-op -- unless the target began a
             * genuine exit during the send, in which case clearing it
             * corrupts exit state. Wake only; waking an exiting task
             * is harmless. */
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
    unsigned long tmo;
    int dead;
    int gone;
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
    INIT_LIST_HEAD(&pending->list);

    /* Pin the target across the queue: without a ref the worker could
     * dereference a reaped task_struct. The waiter drops it after the
     * worker (or the cleanup drain) completes this entry. */
    get_task_struct(task);

    mutex_lock(&sigforce_pending_lock);
    /* Wrapper checked initialized, but cleanup may have stopped the
     * worker and drained the list since: queueing now would wait on a
     * completion nobody completes. Fail closed, undo the task ref. */
    if (!sigforce_initialized || !sigforce_worker_task) {
        mutex_unlock(&sigforce_pending_lock);
        put_task_struct(task);
        kfree(pending);
        return -ENODEV;
    }
    /* Dead worker (see init): queueing would wait forever. The zombie
     * stays valid until kthread_stop, so this deref is safe here. */
    if ((sigforce_worker_task->flags & PF_EXITING) ||
        sigforce_worker_task->exit_state) {
        mutex_unlock(&sigforce_pending_lock);
        put_task_struct(task);
        kfree(pending);
        return -ENODEV;
    }
    list_add_tail(&pending->list, &sigforce_pending_list);
    atomic_inc(&sigforce_pending_count);
    mutex_unlock(&sigforce_pending_lock);

    wake_up(&sigforce_worker_wq);

    /* Unbounded wait_for_completion on a dead worker hangs unkillably.
     * Bound it: reclaim the entry if it is still queued (the worker
     * dequeues with list_del_init, so non-empty under the lock means
     * it never picked this entry up). */
    tmo = wait_for_completion_timeout(&pending->done,
                                      msecs_to_jiffies(30000));
    if (!tmo) {
        mutex_lock(&sigforce_pending_lock);
        if (!list_empty(&pending->list)) {
            list_del_init(&pending->list);
            atomic_dec(&sigforce_pending_count);
            mutex_unlock(&sigforce_pending_lock);
            put_task_struct(task);
            kfree(pending);
            return -ETIMEDOUT;
        }
        mutex_unlock(&sigforce_pending_lock);
        /* Dequeued but uncompleted: list_del_init under the lock passed
         * ownership to the worker, which touches the entry only inside
         * the dequeue-to-complete window (non-sleeping send + wake +
         * complete, no stop checkpoint). A normal kthread_stop therefore
         * sets PF_EXITING/exit_state only AFTER that window's complete
         * (thread exit follows worker-fn return); an abnormal death
         * inside the window enters do_exit WITHOUT completing and never
         * resumes. So a non-NULL worker sighted dead under the lock will
         * never touch this entry again, and (NULL + stopped) means the
         * NULLer's kthread_stop already joined the thread. Either way no
         * future touch pairs the reclaim; anything else (live worker, or
         * NULL with a stop still in flight, which may still complete this
         * entry) keeps bounded re-waiting. Each wait is bounded; the
         * loop exits only via completion (return result) or proven death
         * (return -ETIMEDOUT). Fail closed, waiter is the single freer. */
        for (;;) {
            tmo = wait_for_completion_timeout(&pending->done,
                                              msecs_to_jiffies(5000));
            if (tmo)
                break;
            /* Timeout and completion raced: prefer the worker's result
             * over -ETIMEDOUT when it already completed-then-died. */
            if (completion_done(&pending->done))
                break;
            mutex_lock(&sigforce_pending_lock);
            dead = (sigforce_worker_task &&
                    ((sigforce_worker_task->flags & PF_EXITING) ||
                     sigforce_worker_task->exit_state)) ? 1 : 0;
            gone = (!sigforce_worker_task &&
                    sigforce_worker_stopped) ? 1 : 0;
            mutex_unlock(&sigforce_pending_lock);
            if (dead || gone) {
                put_task_struct(task);
                kfree(pending);
                return -ETIMEDOUT;
            }
        }
    }
    ret = pending->result;
    put_task_struct(task);
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
    struct task_struct *target = NULL;
    struct signal_struct *wanted;
    int ret = 0;

    if (!sigforce_initialized)
        return -ENODEV;

    if (!task)
        return -ESRCH;

    if (sig < 1 || sig > 64)
        return -EINVAL;

    if (!memd_capable(CAP_KILL) && !memd_capable(CAP_SYS_ADMIN))
        return -EPERM;

    /* for_each_process needs RCU, but the send must not run under it:
     * first-use resolution inside memd_send_signal sleeps (kallsyms file
     * IO), and sleeping inside rcu_read_lock is never legal. Leaders own
     * a unique signal_struct (vfork/CLONE_SIGHAND share mm/sighand, never
     * signal across leaders), so at most one match; pin it with a ref
     * (legal under RCU) and send after unlock. The pointer is loaded
     * inside the critical section because signal_struct is RCU-freed. */
    rcu_read_lock();
    wanted = task->signal;
    if (!wanted) {
        rcu_read_unlock();
        return -ESRCH;
    }
    for_each_process(p) {
        if (p->signal == wanted) {
            get_task_struct(p);
            target = p;
            break;
        }
    }
    rcu_read_unlock();

    if (!target)
        return 0;
    ret = memd_sigforce_deliver_sync(target, sig, force);
    put_task_struct(target);

    return ret;
}
/* kmod/memd/utils/memd_sigforce.c[∂] */
