#include "memd_page_walk.h"
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

struct page_walk_context {
    struct mm_struct *mm;
    struct page_walk_stats *stats;
    unsigned long *region_start;
    unsigned long *region_end;
    int (*pte_callback)(pte_t *pte, unsigned long addr, unsigned long end, void *data);
    int (*pmd_callback)(pmd_t *pmd, unsigned long addr, unsigned long end, void *data);
    int (*pud_callback)(pud_t *pud, unsigned long addr, unsigned long end, void *data);
    int (*pgd_callback)(pgd_t *pgd, unsigned long addr, unsigned long end, void *data);
    void *data;
    bool include_kernel;
    bool include_swap;
    unsigned long flags;
};

// Function to merge and print contiguous memory regions
static void print_merged_region(unsigned long* start, unsigned long* end) {
    if (*start != -1UL) {
        // [start, end) is the format used by /proc/pid/maps
        memd_info("Found region: 0x%lx - 0x%lx\n", *start, *end + 1);
    }
    *start = -1UL;
    *end = -1UL;
}

// Walk the Page Table Entries (PTEs)
static void walk_pte_level(pmd_t* pmd, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end, struct page_walk_stats* stats) {
#if defined(PTE_WALK)
    pte_t *ptep, pte;
    unsigned long current_addr;
    unsigned long pte_end;

    pte_end = (addr + PMD_SIZE) & PMD_MASK;
    if (end < pte_end)
        pte_end = end;

    ptep = pte_offset_kernel(pmd, addr);
    ptep = NULL;
    if (!ptep) {
        return;
    }

    for (current_addr = addr; current_addr < pte_end; current_addr += PAGE_SIZE) {
        pte = *ptep;
        if (stats) {
            stats->total_pte_count++;
        }
        if (pte_present(pte)) {
            if (stats) {
                stats->present_pte_count++;
            }
            // Found a mapped page
            if (*region_start != -1UL && current_addr != *region_end + PAGE_SIZE) {
                print_merged_region(region_start, region_end);
            }

            if (*region_start == -1UL) {
                *region_start = current_addr;
            }
            *region_end = current_addr;
        } else {
            // Gap detected, print the last region if it exists
            print_merged_region(region_start, region_end);
        }
        ptep++;
    }

    pte_unmap(ptep - ((pte_end - addr) >> PAGE_SHIFT));
#else
    memd_err("PTE walk not supported on this architecture.\n");
#endif
}

// Walk the Page Middle Directories (PMDs)
static void walk_pmd_level(pud_t* pud, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end, struct page_walk_stats* stats) {
    pmd_t* pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);

    do {
        next = pmd_addr_end(addr, end);
        if (pmd_present(*pmd) && !pmd_none(*pmd)) {
            if (pmd_huge(*pmd)) {
                if (stats) {
                    stats->pmd_huge_count++;
                }
                if (*region_start != -1UL && addr != *region_end + PAGE_SIZE) {
                    print_merged_region(region_start, region_end);
                }
                if (*region_start == -1UL) {
                    *region_start = addr;
                }
                *region_end = next - PAGE_SIZE;
            } else {
                walk_pte_level(pmd, addr, next, region_start, region_end, stats);
            }
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        pmd++;
    } while (addr < end);
}

// Walk the Page Upper Directories (PUDs)
static void walk_pud_level(p4d_t* p4d, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end, struct page_walk_stats* stats) {
    pud_t* pud;
    unsigned long next;

    pud = pud_offset(p4d, addr);

    do {
        next = pud_addr_end(addr, end);
        if (pud_present(*pud) && !pud_none(*pud)) {
            if (pud_huge(*pud)) {
                if (stats) {
                    stats->pud_huge_count++;
                }
                if (*region_start != -1UL && addr != *region_end + PAGE_SIZE) {
                    print_merged_region(region_start, region_end);
                }
                if (*region_start == -1UL) {
                    *region_start = addr;
                }
                *region_end = next - PAGE_SIZE;
            } else {
                walk_pmd_level(pud, addr, next, region_start, region_end, stats);
            }
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        pud++;
    } while (addr < end);
}

// Walk the Page 4th-level Directories (P4Ds)
static void walk_p4d_level(pgd_t* pgd, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end, struct page_walk_stats* stats) {
    p4d_t* p4d;
    unsigned long next;

    p4d = p4d_offset(pgd, addr);

    do {
        next = p4d_addr_end(addr, end);
        if (p4d_present(*p4d) && !p4d_none(*p4d)) {
            walk_pud_level(p4d, addr, next, region_start, region_end, stats);
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        p4d++;
    } while (addr < end);
}

void traverse_page_tables(struct mm_struct* mm, struct page_walk_stats* stats) {
    unsigned long addr = 0;
    unsigned long region_start = -1UL, region_end = -1UL;
    pgd_t* pgd;
    unsigned long next;

    if (!mm) {
        return;
    }

    // Initialize stats if provided
    if (stats) {
        stats->total_pte_count = 0;
        stats->present_pte_count = 0;
        stats->pmd_huge_count = 0;
        stats->pud_huge_count = 0;
    }

    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */

    pgd = memd_m_pgd(mm);

    do {
        next = pgd_addr_end(addr, TASK_SIZE);
        if (pgd_present(*pgd) && !pgd_none(*pgd)) {
            walk_p4d_level(pgd, addr, next, &region_start, &region_end, stats);
        } else {
            print_merged_region(&region_start, &region_end);
        }
        addr = next;
        pgd++;
    } while (addr < TASK_SIZE && addr != 0);

    print_merged_region(&region_start, &region_end);

    /* no mmap_lock: universal image (offset varies); mm pinned + fail-closed walk */
}

static int walk_pte_level_ctx(pmd_t *pmd, unsigned long addr, unsigned long end,
                               struct page_walk_context *ctx)
 {
    pte_t *ptep;
    unsigned long pte_end;
    int ret = 0;

    pte_end = (addr + PMD_SIZE) & PMD_MASK;
    if (end < pte_end)
        pte_end = end;

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep)
        return 0;

    for (unsigned long current_addr = addr; current_addr < pte_end; current_addr += PAGE_SIZE) {
        pte_t pte = *ptep;

        if (ctx->stats) {
            ctx->stats->total_pte_count++;
        }

        if (pte_present(pte)) {
            if (ctx->stats) {
                ctx->stats->present_pte_count++;
            }

            if (ctx->pte_callback) {
                ret = ctx->pte_callback(ptep, current_addr, pte_end, ctx->data);
                if (ret)
                    goto out;
            }

            if (ctx->flags & PAGE_WALK_REGIONS) {
                if (*ctx->region_start != -1UL && current_addr != *ctx->region_end + PAGE_SIZE) {
                    print_merged_region(ctx->region_start, ctx->region_end);
                }
                if (*ctx->region_start == -1UL) {
                    *ctx->region_start = current_addr;
                }
                *ctx->region_end = current_addr;
            }

            if (ctx->flags & PAGE_WALK_PERMS) {
                unsigned int prot = 0;
                if (pte_read(pte)) prot |= PROT_READ;
                if (pte_write(pte)) prot |= PROT_WRITE;
                if (pte_exec(pte)) prot |= PROT_EXEC;
                if (ctx->stats)
                    ctx->stats->pages_by_prot[prot]++;
            }

            if (ctx->flags & PAGE_WALK_TYPE) {
                bool is_file = false;
                struct vm_area_struct *vma = find_vma(ctx->mm, current_addr);
                if (vma && vma->vm_file)
                    is_file = true;
                if (ctx->stats) {
                    if (is_file)
                        ctx->stats->file_pages++;
                    else
                        ctx->stats->anon_pages++;
                }
            }
        } else if (ctx->include_swap && is_swap_pte(pte)) {
            if (ctx->stats)
                ctx->stats->swap_entries++;

            if (ctx->pte_callback) {
                ret = ctx->pte_callback(ptep, current_addr, pte_end, ctx->data);
                if (ret)
                    goto out;
            }
        } else {
            if (ctx->flags & PAGE_WALK_REGIONS) {
                print_merged_region(ctx->region_start, ctx->region_end);
            }
        }
        ptep++;
    }

out:
    pte_unmap(ptep - ((pte_end - addr) >> PAGE_SHIFT));
    return ret;
}

static int walk_pmd_level_ctx(pud_t *pud, unsigned long addr, unsigned long end,
                               struct page_walk_context *ctx)
 {
    pmd_t *pmd;
    unsigned long next;
    int ret = 0;

    pmd = pmd_offset(pud, addr);

    do {
        next = pmd_addr_end(addr, end);
        if (pmd_present(*pmd) && !pmd_none(*pmd)) {
            if (pmd_huge(*pmd)) {
                if (ctx->stats) {
                    ctx->stats->pmd_huge_count++;
                }

                if (ctx->pmd_callback) {
                    ret = ctx->pmd_callback(pmd, addr, next, ctx->data);
                    if (ret)
                        return ret;
                }

                if (ctx->flags & PAGE_WALK_REGIONS) {
                    if (*ctx->region_start != -1UL && addr != *ctx->region_end + PAGE_SIZE) {
                        print_merged_region(ctx->region_start, ctx->region_end);
                    }
                    if (*ctx->region_start == -1UL) {
                        *ctx->region_start = addr;
                    }
                    *ctx->region_end = next - PAGE_SIZE;
                }
            } else {
                ret = walk_pte_level_ctx(pmd, addr, next, ctx);
                if (ret)
                    return ret;
            }
        } else {
            if (ctx->flags & PAGE_WALK_REGIONS) {
                print_merged_region(ctx->region_start, ctx->region_end);
            }
        }
        addr = next;
        pmd++;
    } while (addr < end);

    return 0;
}

static int walk_pud_level_ctx(p4d_t *p4d, unsigned long addr, unsigned long end,
                               struct page_walk_context *ctx)
 {
    pud_t *pud;
    unsigned long next;
    int ret = 0;

    pud = pud_offset(p4d, addr);

    do {
        next = pud_addr_end(addr, end);
        if (pud_present(*pud) && !pud_none(*pud)) {
            if (pud_huge(*pud)) {
                if (ctx->stats) {
                    ctx->stats->pud_huge_count++;
                }

                if (ctx->pud_callback) {
                    ret = ctx->pud_callback(pud, addr, next, ctx->data);
                    if (ret)
                        return ret;
                }

                if (ctx->flags & PAGE_WALK_REGIONS) {
                    if (*ctx->region_start != -1UL && addr != *ctx->region_end + PAGE_SIZE) {
                        print_merged_region(ctx->region_start, ctx->region_end);
                    }
                    if (*ctx->region_start == -1UL) {
                        *ctx->region_start = addr;
                    }
                    *ctx->region_end = next - PAGE_SIZE;
                }
            } else {
                ret = walk_pmd_level_ctx(pud, addr, next, ctx);
                if (ret)
                    return ret;
            }
        } else {
            if (ctx->flags & PAGE_WALK_REGIONS) {
                print_merged_region(ctx->region_start, ctx->region_end);
            }
        }
        addr = next;
        pud++;
    } while (addr < end);

    return 0;
}

static int walk_p4d_level_ctx(pgd_t *pgd, unsigned long addr, unsigned long end,
                               struct page_walk_context *ctx)
 {
    p4d_t *p4d;
    unsigned long next;
    int ret = 0;

    p4d = p4d_offset(pgd, addr);

    do {
        next = p4d_addr_end(addr, end);
        if (p4d_present(*p4d) && !p4d_none(*p4d)) {
            ret = walk_pud_level_ctx(p4d, addr, next, ctx);
            if (ret)
                return ret;
        } else {
            if (ctx->flags & PAGE_WALK_REGIONS) {
                print_merged_region(ctx->region_start, ctx->region_end);
            }
        }
        addr = next;
        p4d++;
    } while (addr < end);

    return 0;
}

static int walk_pgd_level_ctx(struct mm_struct *mm, unsigned long start, unsigned long end,
                               struct page_walk_context *ctx)
 {
    pgd_t *pgd;
    unsigned long addr = start;
    unsigned long next;
    int ret = 0;

    pgd = pgd_offset(mm, start);

    do {
        next = pgd_addr_end(addr, end);
        if (pgd_present(*pgd) && !pgd_none(*pgd)) {
            if (ctx->pgd_callback) {
                ret = ctx->pgd_callback(pgd, addr, next, ctx->data);
                if (ret)
                    return ret;
            }
            ret = walk_p4d_level_ctx(pgd, addr, next, ctx);
            if (ret)
                return ret;
        } else {
            if (ctx->flags & PAGE_WALK_REGIONS) {
                print_merged_region(ctx->region_start, ctx->region_end);
            }
        }
        addr = next;
        pgd++;
    } while (addr < end && addr != 0);

    return 0;
}

int memd_page_walk(struct mm_struct *mm, struct page_walk_context *ctx)
 {
    if (!mm || !ctx)
        return -EINVAL;

    if (ctx->stats) {
        ctx->stats->total_pte_count = 0;
        ctx->stats->present_pte_count = 0;
        ctx->stats->pmd_huge_count = 0;
        ctx->stats->pud_huge_count = 0;
    }

    ctx->mm = mm;
    unsigned long start = ctx->include_kernel ? 0 : TASK_SIZE_MIN;
    unsigned long end = ctx->include_kernel ? ULONG_MAX : TASK_SIZE;

    return walk_pgd_level_ctx(mm, start, end, ctx);
}

int memd_get_page_info(struct mm_struct *mm, unsigned long addr, struct page_info *info)
 {
    pte_t *ptep;
    pmd_t *pmd;
    pud_t *pud;
    p4d_t *p4d;
    pgd_t *pgd;

    if (!mm || !info)
        return -EINVAL;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -ENOENT;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -ENOENT;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return -ENOENT;

    if (pud_huge(*pud)) {
        info->page_size = PUD_SIZE;
        info->pfn = pud_pfn(*pud);
        info->present = true;
        info->huge = true;
        return 0;
    }

    if (pud_bad(*pud))
        return -ENOENT;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -ENOENT;

    if (pmd_huge(*pmd)) {
        info->page_size = PMD_SIZE;
        info->pfn = pmd_pfn(*pmd);
        info->present = true;
        info->huge = true;
        return 0;
    }

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep)
        return -ENOENT;

    pte_t pte = *ptep;
    if (!pte_present(pte)) {
        if (is_swap_pte(pte)) {
            info->swapped = true;
            info->swap_offset = pte_swp_offset(pte);
            info->swap_type = pte_swp_type(pte);
        }
        return -ENOENT;
    }

    info->page_size = PAGE_SIZE;
    info->pfn = pte_pfn(pte);
    info->present = true;
    info->read = pte_read(pte);
    info->write = pte_write(pte);
    info->exec = pte_exec(pte);
    info->dirty = pte_dirty(pte);
    info->young = pte_young(pte);
    info->user = pte_user(pte);
    info->huge = false;

    return 0;
}

int memd_walk_page_range(struct mm_struct *mm, unsigned long start, unsigned long end,
                          int (*callback)(pte_t *pte, unsigned long addr, unsigned long end, void *data),
                          void *data)
 {
    struct page_walk_context ctx = {
        .mm = mm,
        .region_start = (unsigned long[]) {-1UL},
        .region_end = (unsigned long[]) {-1UL},
        .pte_callback = callback,
        .data = data,
        .flags = PAGE_WALK_REGIONS,
    };

    return memd_page_walk(mm, &ctx);
}
