#include "memd_region.h"

#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>

#include "karray_list.h"
#include "memd_common.h"

struct unsafe_region_area {
    u64 addr;
    u32 nums_page;
    uid_t uid;
    pid_t session_pid;
    u32 prot;
    u32 flags;
    u64 start_time;
    u64 access_count;
    struct rb_node rb_node;
    struct list_head list;
} __aligned(sizeof(u64));

struct unsafe_region_tree {
    struct rb_root root;
    struct list_head all_regions;
    u64 total_pages;
    u32 region_count;
    u32 max_regions_per_session;
    spinlock_t lock;
};

static struct unsafe_region_tree *g_region_tree = NULL;

static int region_cmp(struct unsafe_region_area *a, struct unsafe_region_area *b)
 {
    if (a->addr < b->addr)
        return -1;
    if (a->addr > b->addr)
        return 1;
    return 0;
}

static struct unsafe_region_area *region_find(uintptr_t addr)
 {
    struct rb_node *node = g_region_tree->root.rb_node;
    while (node) {
        struct unsafe_region_area *area = rb_entry(node, struct unsafe_region_area, rb_node);
        if (addr < area->addr)
            node = node->rb_left;
        else if (addr >= area->addr + (area->nums_page << PAGE_SHIFT))
            node = node->rb_right;
        else
            return area;
    }
    return NULL;
}

static bool region_overlaps(struct unsafe_region_area *new_area)
 {
    struct rb_node *node = g_region_tree->root.rb_node;
    uintptr_t new_end = new_area->addr + (new_area->nums_page << PAGE_SHIFT);
    while (node) {
        struct unsafe_region_area *area = rb_entry(node, struct unsafe_region_area, rb_node);
        uintptr_t area_end = area->addr + (area->nums_page << PAGE_SHIFT);
        if (new_area->addr < area_end && new_area->addr + (new_area->nums_page << PAGE_SHIFT) > area->addr)
            return true;
        if (new_area->addr < area->addr)
            node = node->rb_left;
        else
            node = node->rb_right;
    }
    return false;
}

static void region_insert(struct unsafe_region_area *area)
 {
    struct rb_node **link = &g_region_tree->root.rb_node;
    struct rb_node *parent = NULL;
    while (*link) {
        parent = *link;
        struct unsafe_region_area *this = rb_entry(parent, struct unsafe_region_area, rb_node);
        if (area->addr < this->addr)
            link = &parent->rb_left;
        else
            link = &parent->rb_right;
    }
    rb_link_node(&area->rb_node, parent, link);
    rb_insert_color(&area->rb_node, &g_region_tree->root);
    list_add_tail(&area->list, &g_region_tree->all_regions);
    g_region_tree->region_count++;
    g_region_tree->total_pages += area->nums_page;
}

static void region_remove(struct unsafe_region_area *area)
 {
    rb_erase(&area->rb_node, &g_region_tree->root);
    list_del(&area->list);
    g_region_tree->region_count--;
    g_region_tree->total_pages -= area->nums_page;
}

int memd_region_init(void)
 {
    g_region_tree = kzalloc(sizeof(*g_region_tree), GFP_KERNEL);
    if (!g_region_tree) {
        memd_err("failed to create region tree\n");
        return -ENOMEM;
    }
    g_region_tree->root = RB_ROOT;
    INIT_LIST_HEAD(&g_region_tree->all_regions);
    g_region_tree->max_regions_per_session = 256;
    spin_lock_init(&g_region_tree->lock);
    return 0;
}

void memd_region_cleanup(void)
 {
    unsigned long flags;
    struct unsafe_region_tree *tree;
    struct unsafe_region_area *area, *tmp;

    /* Single global; init/cleanup run at module load/unload, so a plain
     * NULL test before taking the in-tree lock is sufficient here. */
    tree = g_region_tree;
    if (!tree)
        return;

    /* Detach everything under the lock, drop the global, unlock, and
     * only then free: unlocking through freed memory is a UAF. */
    spin_lock_irqsave(&tree->lock, flags);
    list_for_each_entry_safe(area, tmp, &tree->all_regions, list) {
        rb_erase(&area->rb_node, &tree->root);
        list_del(&area->list);
        kfree(area);
    }
    tree->region_count = 0;
    tree->total_pages = 0;
    g_region_tree = NULL;
    spin_unlock_irqrestore(&tree->lock, flags);
    kfree(tree);
}

int memd_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page)
 {
    struct unsafe_region_area *area;
    struct unsafe_region_area *iter;
    unsigned long flags;
    unsigned long span;
    u32 session_count = 0;

    if (num_page == 0 || num_page > (1UL << 20))
        return -EINVAL;
    if (start & (PAGE_SIZE - 1))
        return -EINVAL;

    /* Shift must not discard bits, and the span must not wrap: either
     * would admit an overlapping region or break region_find. */
    span = num_page << PAGE_SHIFT;
    if ((span >> PAGE_SHIFT) != num_page)
        return -EINVAL;
    if (start + span < start)
        return -EINVAL;

    if (!g_region_tree)
        return -ENODEV;

    area = kzalloc(sizeof(*area), GFP_KERNEL);
    if (!area) {
        memd_err("failed to allocate memory for unsafe region area\n");
        return -ENOMEM;
    }

    area->addr = start;
    area->nums_page = num_page;
    area->uid = uid;
    area->session_pid = session;
    area->prot = 0;
    area->flags = 0;
    area->start_time = ktime_get_real_ns();
    area->access_count = 0;
    INIT_LIST_HEAD(&area->list);

    spin_lock_irqsave(&g_region_tree->lock, flags);

    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        kfree(area);
        return -ENODEV;
    }

    /* Check per-session quota */
    list_for_each_entry(iter, &g_region_tree->all_regions, list) {
        if (iter->session_pid == session)
            session_count++;
    }
    if (session_count >= g_region_tree->max_regions_per_session) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        kfree(area);
        return -ENOSPC;
    }

    if (region_overlaps(area)) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        kfree(area);
        return -EEXIST;
    }

    region_insert(area);
    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return 0;
}

int memd_del_unsafe_region(pid_t pid)
 {
    unsigned long flags;
    struct unsafe_region_area *area, *tmp;
    int removed = 0;

    if (!g_region_tree)
        return -ENODEV;

    spin_lock_irqsave(&g_region_tree->lock, flags);

    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return -ENODEV;
    }

    list_for_each_entry_safe(area, tmp, &g_region_tree->all_regions, list) {
        if (area->session_pid == pid) {
            region_remove(area);
            kfree(area);
            removed++;
        }
    }

    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return removed ? 0 : -ENOENT;
}

/* Enhanced API functions */

int memd_find_region(uintptr_t addr, void *out)
 {
    unsigned long flags;
    struct unsafe_region_area *area;
    struct unsafe_region_area *o = (struct unsafe_region_area *)out;

    if (!g_region_tree)
        return -ENODEV;

    spin_lock_irqsave(&g_region_tree->lock, flags);
    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return -ENODEV;
    }
    area = region_find(addr);
    if (area) {
        if (o)
            *o = *area;
        area->access_count++;
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return -ENOENT;
}

int memd_region_iterate(int (*callback)(void *area, void *data), void *data)
 {
    unsigned long flags;
    struct unsafe_region_area *area, *tmp;
    int ret = 0;

    if (!callback)
        return -EINVAL;
    if (!g_region_tree)
        return -ENODEV;

    /* Callback runs under the tree spinlock: it must be atomic (no
     * sleep, no region-tree calls). Safe iteration so a callback that
     * drops its current entry cannot corrupt the walk. */
    spin_lock_irqsave(&g_region_tree->lock, flags);
    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return -ENODEV;
    }
    list_for_each_entry_safe(area, tmp, &g_region_tree->all_regions, list) {
        area->access_count++;
        ret = callback(area, data);
        if (ret)
            break;
    }
    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return ret;
}

int memd_get_region_stats(u64 *total_pages, u32 *region_count)
 {
    unsigned long flags;

    if (!g_region_tree)
        return -ENODEV;
    spin_lock_irqsave(&g_region_tree->lock, flags);
    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return -ENODEV;
    }
    if (total_pages)
        *total_pages = g_region_tree->total_pages;
    if (region_count)
        *region_count = g_region_tree->region_count;
    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return 0;
}

int memd_set_session_quota(pid_t session, u32 max_regions)
 {
    unsigned long flags;

    (void)session;
    /* Zero would brick every future add; unbounded quotas invite
     * exhaustion. Fail closed on both. */
    if (max_regions == 0 || max_regions > 4096)
        return -EINVAL;
    if (!g_region_tree)
        return -ENODEV;
    spin_lock_irqsave(&g_region_tree->lock, flags);
    if (!g_region_tree) {
        spin_unlock_irqrestore(&g_region_tree->lock, flags);
        return -ENODEV;
    }
    g_region_tree->max_regions_per_session = max_regions;
    spin_unlock_irqrestore(&g_region_tree->lock, flags);
    return 0;
}
/* kmod/memd/utils/memd_region.c[∂] */
