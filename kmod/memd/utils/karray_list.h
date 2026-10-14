#ifndef ANDROID_MEMD_KARRAY_LIST_H
#define ANDROID_MEMD_KARRAY_LIST_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#define ARRAYLIST_DEFAULT_CAPACITY 16

struct karray_list {
    void** data;
    size_t size;
    size_t capacity;
    spinlock_t lock;           /* For thread-safe access */
    bool thread_safe;          /* Enable/disable thread safety */
};

struct karray_list* arraylist_create(size_t initial_capacity);
void arraylist_destroy(struct karray_list* list);
void* arraylist_remove(struct karray_list* list, size_t index);
void* arraylist_get(struct karray_list* list, size_t index);
int arraylist_add(struct karray_list* list, void* element);
void arraylist_clear(struct karray_list* list);

/* Thread-safe operations */
int arraylist_add_ts(struct karray_list* list, void* element);
void* arraylist_get_ts(struct karray_list* list, size_t index);
void* arraylist_remove_ts(struct karray_list* list, size_t index);
size_t arraylist_size_ts(struct karray_list* list);

/* Iterator support */
struct karray_iterator {
    struct karray_list* list;
    size_t index;
    void* (*next)(struct karray_iterator* iter);
    void (*release)(struct karray_iterator* iter);
};

struct karray_iterator* arraylist_iterator_create(struct karray_list* list);
void* arraylist_iterator_next(struct karray_iterator* iter);
void arraylist_iterator_release(struct karray_iterator* iter);

/* Search and utility operations */
int arraylist_find(struct karray_list* list, void* element, int (*cmp)(void*, void*));
int arraylist_insert(struct karray_list* list, size_t index, void* element);
int arraylist_set(struct karray_list* list, size_t index, void* element);
void* arraylist_pop(struct karray_list* list);
void* arraylist_peek(struct karray_list* list);
void arraylist_reverse(struct karray_list* list);
void arraylist_sort(struct karray_list* list, int (*cmp)(const void*, const void*));
void arraylist_for_each(struct karray_list* list, void (*fn)(void*, void*), void* data);
void arraylist_for_each_ts(struct karray_list* list, void (*fn)(void*, void*), void* data);

/* Capacity management */
int arraylist_reserve(struct karray_list* list, size_t capacity);
int arraylist_shrink_to_fit(struct karray_list* list);
size_t arraylist_capacity(struct karray_list* list);

/* Thread safety control */
void arraylist_set_thread_safe(struct karray_list* list, bool enable);

#endif // ANDROID_MEMD_KARRAY_LIST_H
/* kmod/memd/utils/karray_list.h[∂] */
