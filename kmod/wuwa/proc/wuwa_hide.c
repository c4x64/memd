#include "wuwa_hide.h"

#include <linux/spinlock.h>

static pid_t hidden[WUWA_HIDE_MAX];
static int hidden_nr;
static DEFINE_SPINLOCK(hide_lock);

int wuwa_hide_add(pid_t pid)
{
    int i;
    unsigned long flags;

    if (pid <= 0)
        return -EINVAL;
    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < hidden_nr; i++) {
        if (hidden[i] == pid) {
            spin_unlock_irqrestore(&hide_lock, flags);
            return 0;
        }
    }
    if (hidden_nr >= WUWA_HIDE_MAX) {
        spin_unlock_irqrestore(&hide_lock, flags);
        return -ENOSPC;
    }
    hidden[hidden_nr++] = pid;
    spin_unlock_irqrestore(&hide_lock, flags);
    return 0;
}

int wuwa_hide_del(pid_t pid)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < hidden_nr; i++) {
        if (hidden[i] == pid) {
            hidden[i] = hidden[--hidden_nr];
            hidden[hidden_nr] = 0;
            spin_unlock_irqrestore(&hide_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return -ESRCH;
}

void wuwa_hide_clear(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < hidden_nr; i++)
        hidden[i] = 0;
    hidden_nr = 0;
    spin_unlock_irqrestore(&hide_lock, flags);
}

int wuwa_hide_count(void)
{
    int n;
    unsigned long flags;

    spin_lock_irqsave(&hide_lock, flags);
    n = hidden_nr;
    spin_unlock_irqrestore(&hide_lock, flags);
    return n;
}

bool wuwa_hide_contains(pid_t pid)
{
    int i;
    bool found = false;
    unsigned long flags;

    /* Hot path (every getdents64 on non-root): linear scan over <= 16. */
    spin_lock_irqsave(&hide_lock, flags);
    for (i = 0; i < hidden_nr; i++) {
        if (hidden[i] == pid) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hide_lock, flags);
    return found;
}
