#include "wuwa_region.h"

#include <linux/spinlock.h>
#include <linux/slab.h>

#include "karray_list.h"
#include "wuwa_common.h"

struct unsafe_region_area {
    u64 addr;
    u32 nums_page;
    uid_t uid;
    pid_t session_pid;
} __aligned(sizeof(u64));

static struct karray_list* unsafe_region_areas = NULL;
static DEFINE_RWLOCK(unsafe_region_areas_lock);

int wuwa_region_init(void)
{
    unsafe_region_areas = arraylist_create(ARRAYLIST_DEFAULT_CAPACITY);
    if (!unsafe_region_areas) {
        wuwa_err("failed to create unsafe region areas list\n");
        return -ENOMEM;
    }
    return 0;
}

void wuwa_region_cleanup(void)
{
    int i;

    write_lock(&unsafe_region_areas_lock);
    if (unsafe_region_areas) {
        if (unsafe_region_areas->data) {
            for (i = 0; i < unsafe_region_areas->size; ++i) {
                void* element = unsafe_region_areas->data[i];
                if (element)
                    kvfree(element);
            }
        }
        arraylist_destroy(unsafe_region_areas);
        unsafe_region_areas = NULL;
    }
    write_unlock(&unsafe_region_areas_lock);
}

int wuwa_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page)
{
    struct unsafe_region_area* area;

    write_lock(&unsafe_region_areas_lock);

    if (!unsafe_region_areas) {
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }

    area = kvzalloc(sizeof(*area), GFP_KERNEL);
    if (!area) {
        wuwa_err("failed to allocate memory for unsafe region area\n");
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }
    area->addr = start;
    area->nums_page = num_page;
    area->uid = uid;
    area->session_pid = session;

    if (arraylist_add(unsafe_region_areas, area)) {
        write_unlock(&unsafe_region_areas_lock);
        wuwa_err("failed to add unsafe region area\n");
        return -ENOMEM;
    }

    write_unlock(&unsafe_region_areas_lock);
    return 0;
}

int wuwa_del_unsafe_region(pid_t pid)
{
    int i;

    write_lock(&unsafe_region_areas_lock);

    if (!unsafe_region_areas) {
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }

    if (!unsafe_region_areas->data) {
        write_unlock(&unsafe_region_areas_lock);
        wuwa_err("unsafe region areas list is empty\n");
        return -ENOENT;
    }

    for (i = 0; i < unsafe_region_areas->size; ++i) {
        struct unsafe_region_area* area = unsafe_region_areas->data[i];
        if (area && area->session_pid == pid) {
            void* removed = arraylist_remove(unsafe_region_areas, i);
            if (removed) {
                kvfree(removed);
            } else {
                wuwa_err("failed to remove unsafe region area for pid %d\n", pid);
            }
        }
    }

    write_unlock(&unsafe_region_areas_lock);
    return 0;
}
