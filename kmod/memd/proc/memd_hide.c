#include "memd_hide.h"

#include <linux/spinlock.h>
#include <linux/pid_namespace.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

#define MEMD_HIDE_HASH_BITS 8
#define MEMD_HIDE_HASH_SIZE (1 << MEMD_HIDE_HASH_BITS)

struct memd_hide_entry {
    struct hlist_node node;
    pid_t pid;
    struct pid_namespace *ns;
    struct pid *pid_struct;
    u32 flags;
};

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
    struct pid_namespace *ns;
    unsigned long flags;
    unsigned int hash;

    if (pid <= 0)
        return -EINVAL;

    rcu_read_lock();
    struct task_struct *task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    ns = get_pid_ns(task->pid_ns);
    rcu_read_unlock();

    if (!ns)
        return -ESRCH;

    spin_lock_irqsave(&hide_lock, flags);

    if (hide_find_entry(pid, ns)) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        return 0;
    }

    if (hide_total_count >= MEMD_HIDE_MAX) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        return -ENOMEM;
    }

    entry->pid = pid;
    entry->ns = ns;
    entry->pid_struct = find_get_pid(pid);
    entry->flags = 0;

    hash = hide_hash_fn(pid, ns);
    hlist_add_head(&entry->node, &hide_hash[hash]);
    hide_total_count++;

    spin_unlock_irqrestore(&hide_lock, flags);

    spin_lock_irqsave(&hide_ns_lock, flags);
    ns_entry = hide_find_ns(ns);
    if (!ns_entry) {
        ns_entry = kmalloc(sizeof(*ns_entry), GFP_ATOMIC);
        if (ns_entry) {
            ns_entry->ns = ns;
            ns_entry->count = 1;
            unsigned int ns_hash = hash_long((unsigned long)ns, MEMD_HIDE_HASH_BITS);
            hlist_add_head(&ns_entry->node, &hide_ns_hash[ns_hash]);
        }
    } else {
        ns_entry->count++;
    }
    spin_unlock_irqrestore(&hide_ns_lock, flags);

    return 0;
}

int memd_hide_add_ns(pid_t pid, struct pid_namespace *ns)
{
    struct memd_hide_entry *entry;
    unsigned long flags;
    unsigned int hash;

    if (pid <= 0 || !ns)
        return -EINVAL;

    spin_lock_irqsave(&hide_lock, flags);

    if (hide_find_entry(pid, ns)) {
        spin_unlock_irqrestore(&hide_lock, flags);
        return 0;
    }

    if (hide_total_count >= MEMD_HIDE_MAX) {
        spin_unlock_irqrestore(&hide_lock, flags);
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_irqrestore(&hide_lock, flags);
        return -ENOMEM;
    }

    entry->pid = pid;
    entry->ns = get_pid_ns(ns);
    entry->pid_struct = find_get_pid(pid);
    entry->flags = 0;

    hash = hide_hash_fn(pid, ns);
    hlist_add_head(&entry->node, &hide_hash[hash]);
    hide_total_count++;

    spin_unlock_irqrestore(&hide_lock, flags);
    return 0;
}

int memd_hide_del(pid_t pid)
{
    struct memd_hide_entry *entry;
    struct pid_namespace *ns;
    unsigned long flags;

    if (pid <= 0)
        return -EINVAL;

    rcu_read_lock();
    struct task_struct *task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    ns = get_pid_ns(task->pid_ns);
    rcu_read_unlock();

    if (!ns)
        return -ESRCH;

    spin_lock_irqsave(&hide_lock, flags);

    entry = hide_find_entry(pid, ns);
    if (!entry) {
        spin_unlock_irqrestore(&hide_lock, flags);
        put_pid_ns(ns);
        return -ESRCH;
    }

    hlist_del(&entry->node);
    hide_total_count--;

    if (entry->pid_struct)
        put_pid(entry->pid_struct);
    put_pid_ns(entry->ns);
    kfree(entry);

    spin_unlock_irqrestore(&hide_lock, flags);

    spin_lock_irqsave(&hide_ns_lock, flags);
    struct memd_hide_ns_entry *ns_entry = hide_find_ns(ns);
    if (ns_entry) {
        ns_entry->count--;
        if (ns_entry->count == 0) {
            hlist_del(&ns_entry->node);
            put_pid_ns(ns_entry->ns);
            kfree(ns_entry);
        }
    }
    put_pid_ns(ns);
    spin_unlock_irqrestore(&hide_ns_lock, flags);

    return 0;
}

void memd_hide_clear(void)
{
    struct memd_hide_entry *entry, *tmp;
    struct memd_hide_ns_entry *ns_entry, *ns_tmp;
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &hide_hash[i], node) {
            hlist_del(&entry->node);
            if (entry->pid_struct)
                put_pid(entry->pid_struct);
            put_pid_ns(entry->ns);
            kfree(entry);
        }
    }
    hide_total_count = 0;
    spin_unlock_irqrestore(&hide_lock, flags);

    spin_lock_irqsave(&hide_ns_lock, flags);
    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry_safe(ns_entry, ns_tmp, &hide_ns_hash[i], node) {
            hlist_del(&ns_entry->node);
            put_pid_ns(ns_entry->ns);
            kfree(ns_entry);
        }
    }
    spin_unlock_irqrestore(&hide_ns_lock, flags);
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
    bool found = false;
    unsigned long flags;

    rcu_read_lock();
    struct task_struct *task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return false;
    }
    ns = get_pid_ns(task->pid_ns);
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

struct memd_hide_entry *memd_hide_get_first(void)
{
    int i;
    struct memd_hide_entry *entry;

    for (i = 0; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry(entry, &hide_hash[i], node) {
            return entry;
        }
    }
    return NULL;
}

struct memd_hide_entry *memd_hide_get_next(struct memd_hide_entry *entry)
{
    struct memd_hide_entry *next;
    unsigned int hash;

    if (!entry)
        return NULL;

    hash = hide_hash_fn(entry->pid, entry->ns);
    next = hlist_entry_safe(entry->node.next, typeof(*entry), node);
    if (next)
        return next;

    for (unsigned int i = hash + 1; i < MEMD_HIDE_HASH_SIZE; i++) {
        hlist_for_each_entry(next, &hide_hash[i], node) {
            return next;
        }
    }
    return NULL;
}
