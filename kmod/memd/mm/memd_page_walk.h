#ifndef MEMD_PAGE_WALK_H
#define MEMD_PAGE_WALK_H

#include <linux/mm_types.h>
#include <linux/types.h>

#define PAGE_WALK_REGIONS     (1 << 0)
#define PAGE_WALK_PERMS       (1 << 1)
#define PAGE_WALK_TYPE        (1 << 2)
#define PAGE_WALK_SWAP        (1 << 3)

struct page_walk_stats {
    u64 total_pte_count;
    u64 present_pte_count;
    u64 pmd_huge_count;
    u64 pud_huge_count;
    u64 swap_entries;
    u64 file_pages;
    u64 anon_pages;
    u64 pages_by_prot[8];
};

struct page_info {
    u64 pfn;
    u32 page_size;
    bool present;
    bool huge;
    bool swapped;
    bool read;
    bool write;
    bool exec;
    bool dirty;
    bool young;
    bool user;
    u32 swap_offset;
    u32 swap_type;
};

struct page_walk_context;

int memd_page_walk(struct mm_struct *mm, struct page_walk_context *ctx);
int memd_get_page_info(struct mm_struct *mm, unsigned long addr, struct page_info *info);
int memd_walk_page_range(struct mm_struct *mm, unsigned long start, unsigned long end,
                          int (*callback)(pte_t *pte, unsigned long addr, unsigned long end, void *data),
                          void *data);

void traverse_page_tables(struct mm_struct *mm, struct page_walk_stats *stats);

#endif // MEMD_PAGE_WALK_H
/* kmod/memd/mm/memd_page_walk.h[∂] */
