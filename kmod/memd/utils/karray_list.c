#include "karray_list.h"

#include <linux/errno.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>

struct karray_list* arraylist_create(size_t initial_capacity) {
    struct karray_list* list = kmalloc(sizeof(*list), GFP_KERNEL);
    if (!list)
        return NULL;

    if (initial_capacity < ARRAYLIST_DEFAULT_CAPACITY)
        initial_capacity = ARRAYLIST_DEFAULT_CAPACITY;

    list->data = kmalloc_array(initial_capacity, sizeof(void*), GFP_KERNEL);
    if (!list->data) {
        kfree(list);
        return NULL;
    }

    list->size = 0;
    list->capacity = initial_capacity;
    spin_lock_init(&list->lock);
    list->thread_safe = false;
    return list;
}

static int ensure_capacity_gfp(struct karray_list* list, size_t min_capacity, gfp_t gfp) {
    size_t new_capacity;
    size_t bytes;
    void **new_data;

    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (min_capacity <= list->capacity)
        return 0;

    /* Growth addition can wrap near SIZE_MAX; fall back to min_capacity. */
    if (check_add_overflow(list->capacity, list->capacity >> 1, &new_capacity) ||
        new_capacity < min_capacity)
        new_capacity = min_capacity;
    /* krealloc_array without the import (missing from trimmed DDK
     * maps): overflow-checked kmalloc + copy + free. */
    if (check_mul_overflow(new_capacity, sizeof(void *), &bytes))
        return -ENOMEM;
    new_data = kmalloc(bytes, gfp);
    if (!new_data)
        return -ENOMEM;
    if (list->size > 0)
        memcpy(new_data, list->data, list->size * sizeof(void *));
    kfree(list->data);

    list->data = new_data;
    list->capacity = new_capacity;
    return 0;
}

static int ensure_capacity(struct karray_list* list, size_t min_capacity) {
    return ensure_capacity_gfp(list, min_capacity, GFP_KERNEL);
}

int arraylist_add(struct karray_list* list, void* element) {
    int ret = 0;

    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (list->size == (size_t)-1)
        return -ENOMEM;

    if (ensure_capacity(list, list->size + 1)) {
        ret = -ENOMEM;
        goto out;
    }

    list->data[list->size++] = element;

out:
    return ret;
}

void* arraylist_get(struct karray_list* list, size_t index) {
    void* element = NULL;

    if (!list || !list->data)
        return NULL;
    if (index < list->size)
        element = list->data[index];
    return element;
}

void* arraylist_remove(struct karray_list* list, size_t index) {
    void* element = NULL;

    if (!list || !list->data)
        return NULL;
    if (index >= list->size)
        goto out;

    element = list->data[index];
    memmove(&list->data[index], &list->data[index + 1], (list->size - index - 1) * sizeof(void*));
    list->size--;

out:
    return element;
}

void arraylist_clear(struct karray_list* list) {
    if (!list)
        return;
    list->size = 0;
}

void arraylist_destroy(struct karray_list* list) {
    if (!list)
        return;
    if (list->data)
        kfree(list->data);
    kfree(list);
}

/* Thread-safe operations */

int arraylist_add_ts(struct karray_list* list, void* element) {
    unsigned long flags;
    int ret = 0;

    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (!list->thread_safe)
        return arraylist_add(list, element);

    /* GFP_ATOMIC: sleeping allocs are forbidden under the spinlock. */
    spin_lock_irqsave(&list->lock, flags);
    if (list->size == (size_t)-1) {
        ret = -ENOMEM;
    } else {
        ret = ensure_capacity_gfp(list, list->size + 1, GFP_ATOMIC);
        if (!ret)
            list->data[list->size++] = element;
    }
    spin_unlock_irqrestore(&list->lock, flags);
    return ret;
}

void* arraylist_get_ts(struct karray_list* list, size_t index) {
    unsigned long flags;
    void* element = NULL;

    if (!list || !list->data)
        return NULL;
    if (!list->thread_safe)
        return arraylist_get(list, index);

    spin_lock_irqsave(&list->lock, flags);
    if (index < list->size)
        element = list->data[index];
    spin_unlock_irqrestore(&list->lock, flags);
    return element;
}

void* arraylist_remove_ts(struct karray_list* list, size_t index) {
    unsigned long flags;
    void* element = NULL;

    if (!list || !list->data)
        return NULL;
    if (!list->thread_safe)
        return arraylist_remove(list, index);

    spin_lock_irqsave(&list->lock, flags);
    if (index < list->size) {
        element = list->data[index];
        memmove(&list->data[index], &list->data[index + 1], (list->size - index - 1) * sizeof(void*));
        list->size--;
    }
    spin_unlock_irqrestore(&list->lock, flags);
    return element;
}

size_t arraylist_size_ts(struct karray_list* list) {
    unsigned long flags;
    size_t size = 0;

    if (!list)
        return 0;
    if (!list->thread_safe)
        return list->size;

    spin_lock_irqsave(&list->lock, flags);
    size = list->size;
    spin_unlock_irqrestore(&list->lock, flags);
    return size;
}

/* Iterator support */

static void* arraylist_iter_next(struct karray_iterator* iter) {
    void* element;

    if (!iter || !iter->list || !iter->list->data)
        return NULL;
    if (iter->index >= iter->list->size)
        return NULL;
    element = iter->list->data[iter->index++];
    return element;
}

static void arraylist_iter_release(struct karray_iterator* iter) {
    if (iter)
        kfree(iter);
}

struct karray_iterator* arraylist_iterator_create(struct karray_list* list) {
    struct karray_iterator* iter;

    if (!list || !list->data)
        return NULL;
    iter = kmalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return NULL;
    iter->list = list;
    iter->index = 0;
    iter->next = arraylist_iter_next;
    iter->release = arraylist_iter_release;
    return iter;
}

void* arraylist_iterator_next(struct karray_iterator* iter) {
    if (!iter || !iter->next)
        return NULL;
    return iter->next(iter);
}

void arraylist_iterator_release(struct karray_iterator* iter) {
    if (iter && iter->release)
        iter->release(iter);
}

/* Search and utility operations */

int arraylist_find(struct karray_list* list, void* element, int (*cmp)(void*, void*)) {
    size_t i;

    if (!list || !list->data)
        return -EINVAL;
    if (!cmp)
        return -EINVAL;

    for (i = 0; i < list->size; i++) {
        if (cmp(list->data[i], element) == 0)
            return (int)i;
    }
    return -ENOENT;
}

int arraylist_insert(struct karray_list* list, size_t index, void* element) {
    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (index > list->size)
        return -EINVAL;
    if (list->size == (size_t)-1)
        return -ENOMEM;

    if (ensure_capacity(list, list->size + 1))
        return -ENOMEM;

    if (index < list->size)
        memmove(&list->data[index + 1], &list->data[index], (list->size - index) * sizeof(void*));

    list->data[index] = element;
    list->size++;
    return 0;
}

int arraylist_set(struct karray_list* list, size_t index, void* element) {
    if (!list || !list->data)
        return -EINVAL;
    if (index >= list->size)
        return -EINVAL;

    list->data[index] = element;
    return 0;
}

void* arraylist_pop(struct karray_list* list) {
    if (!list || !list->data)
        return NULL;
    if (list->size == 0)
        return NULL;
    return list->data[--list->size];
}

void* arraylist_peek(struct karray_list* list) {
    if (!list || !list->data)
        return NULL;
    if (list->size == 0)
        return NULL;
    return list->data[list->size - 1];
}

void arraylist_reverse(struct karray_list* list) {
    size_t i;
    size_t n;

    if (!list || !list->data)
        return;
    n = list->size;
    for (i = 0; i < n / 2; i++) {
        void* tmp = list->data[i];
        list->data[i] = list->data[n - 1 - i];
        list->data[n - 1 - i] = tmp;
    }
}

/* NOTE: comparator is const-correct (matches kernel sort()/qsort):
 * casting a (void*,void*) fn to it trips -Wcast-function-type-strict
 * on newer clangs. No in-tree callers; future callers must comply. */
void arraylist_sort(struct karray_list* list, int (*cmp)(const void*, const void*)) {
    if (!list || !list->data)
        return;
    if (!cmp || list->size < 2)
        return;
    sort(list->data, list->size, sizeof(void*), cmp, NULL);
}

void arraylist_for_each(struct karray_list* list, void (*fn)(void*, void*), void* data) {
    size_t i;

    if (!list || !list->data)
        return;
    if (!fn)
        return;
    for (i = 0; i < list->size; i++)
        fn(list->data[i], data);
}

void arraylist_for_each_ts(struct karray_list* list, void (*fn)(void*, void*), void* data) {
    unsigned long flags;
    size_t i = 0;
    void *element;

    if (!list || !list->data)
        return;
    if (!fn)
        return;
    if (!list->thread_safe)
        return arraylist_for_each(list, fn, data);

    /* Fetch under lock, call without it: fn may sleep and must never
     * run in atomic context. Resyncs the index each round so a
     * concurrent remove only skips/dups instead of going OOB. */
    for (;;) {
        spin_lock_irqsave(&list->lock, flags);
        if (i >= list->size) {
            spin_unlock_irqrestore(&list->lock, flags);
            break;
        }
        element = list->data[i];
        spin_unlock_irqrestore(&list->lock, flags);
        fn(element, data);
        i++;
    }
}

/* Capacity management */

int arraylist_reserve(struct karray_list* list, size_t capacity) {
    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (capacity <= list->capacity)
        return 0;
    return ensure_capacity(list, capacity);
}

int arraylist_shrink_to_fit(struct karray_list* list) {
    size_t bytes;
    void **new_data;

    if (!list)
        return -EINVAL;
    if (!list->data && list->size != 0)
        return -EINVAL;
    if (list->size == list->capacity)
        return 0;

    /* kmalloc(0) is ambiguous (NULL vs ZERO_SIZE_PTR); empty stays NULL. */
    if (list->size == 0) {
        kfree(list->data);
        list->data = NULL;
        list->capacity = 0;
        return 0;
    }
    if (check_mul_overflow(list->size, sizeof(void *), &bytes))
        return -ENOMEM;
    new_data = kmalloc(bytes, GFP_KERNEL);
    if (!new_data)
        return -ENOMEM;
    memcpy(new_data, list->data, list->size * sizeof(void *));
    kfree(list->data);

    list->data = new_data;
    list->capacity = list->size;
    return 0;
}

size_t arraylist_capacity(struct karray_list* list) {
    if (!list)
        return 0;
    return list->capacity;
}

/* Thread safety control */

void arraylist_set_thread_safe(struct karray_list* list, bool enable) {
    if (!list)
        return;
    list->thread_safe = enable;
}
/* kmod/memd/utils/karray_list.c[∂] */
