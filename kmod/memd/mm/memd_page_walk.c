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
#include <linux/mman.h>
#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

struct page_walk_context {
    struct mm_struct* mm;
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

/* ARM64 PTE bit ops without the pte_read/pte_exec/pte_swp_* imports
 * (may be unavailable on some kernels). Bit positions are ARMv8 page-table
 * architecture (AP[2:1] at [7:6], UXN at [54], swap type/offset at
 * [7:3]/[57:8]), identical to the generic pte_* semantics. */
#define MEMD_PTE_USER_BIT (1UL << 6)
#define MEMD_PTE_RDONLY_BIT (1UL << 7)
#define MEMD_PTE_UXN_BIT (1UL << 54)
static inline int memd_pte_read(pte_t pte)
 {
    unsigned long v = pte_val(pte);
    return (v & MEMD_PTE_USER_BIT) && !(v & MEMD_PTE_RDONLY_BIT);
}
static inline int memd_pte_exec(pte_t pte)
 {
    unsigned long v = pte_val(pte);
    return (v & MEMD_PTE_USER_BIT) && !(v & MEMD_PTE_UXN_BIT);
}
static inline unsigned long memd_pte_swp_type(pte_t pte)
 {
    return (pte_val(pte) >> 3) & 0x1fUL;
}
static inline unsigned long memd_pte_swp_offset(pte_t pte)
 {
    return (pte_val(pte) >> 8) & ((1UL << 50) - 1);
}
/* Generic is_swap_pte/pte_user without the imports (both missing from
 * inline to avoid denied imports): a non-present entry with nonzero bits is swap;
 * USER lives at ARMv8 AP[1] (bit 6) on every generation. */
static inline int memd_is_swap_pte(pte_t pte)
 {
    return !pte_present(pte) && pte_val(pte);
}
static inline int memd_pte_user(pte_t pte)
 {
    return !!(pte_val(pte) & (1UL << 6));
}

// Function to merge and print contiguous memory regions
static void print_merged_region(unsigned long* start, unsigned long* end) {
    if (*start != -1UL) {
        // [start, end) is the format used by /proc/pid/maps.
        // region_end stores the START of the last page, so the
        // exclusive end is region_end + PAGE_SIZE (not + 1).
        memd_info("Found region: 0x%lx - 0x%lx\n", *start, *end + PAGE_SIZE);
    }
    *start = -1UL;
    *end = -1UL;
}

// Walk the Page Table Entries (PTEs)
static void walk_pte_level(pmd_t* pmd, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end, struct page_walk_stats* stats) {
    pte_t *ptep, pte;
    pte_t *ptep_start;
    unsigned long current_addr;
    unsigned long pte_end;

    pte_end = (addr + PMD_SIZE) & PMD_MASK;
    if (end < pte_end)
        pte_end = end;

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) {
        return;
    }
    ptep_start = ptep;

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

    pte_unmap(ptep_start);
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
            if (memd_pmd_huge(*pmd)) {
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
            if (memd_pud_huge(*pud)) {
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

    /* Hold the MM read lock across the descent: get_task_mm (caller)
     * pins only the mm_struct; exit_mmap can still tear down tables
     * underneath us. The lock serializes against that teardown, so a
     * dying mm yields empty tables (clean -ENOENT paths) instead of
     * a use-after-free oops. Macro is generation-proof (mmap_lock on
     * 5.8+, mmap_sem below); no mm layout offset is needed. */

    MM_READ_LOCK(mm);
    pgd = (pgd_t *)memd_valid_pgd(mm);
    if (!pgd) {
        MM_READ_UNLOCK(mm);
        return;
    }

    do {
        next = pgd_addr_end(addr, TASK_SIZE_64);
        if (pgd_present(*pgd) && !pgd_none(*pgd)) {
            walk_p4d_level(pgd, addr, next, &region_start, &region_end, stats);
        } else {
            print_merged_region(&region_start, &region_end);
        }
        addr = next;
        pgd++;
    } while (addr < TASK_SIZE_64 && addr != 0);

    print_merged_region(&region_start, &region_end);

    /* Paired with the MM_READ_LOCK above: the walk ran under the read
     * lock so exit_mmap could not free tables mid-descent. */
    MM_READ_UNLOCK(mm);
}

static int walk_pte_level_ctx(pmd_t *pmd, unsigned long addr, unsigned long end,
                                struct page_walk_context *ctx)
  {
     pte_t *ptep;
     pte_t *ptep_start;
     unsigned long pte_end;
     unsigned long current_addr;
     pte_t pte;
     int ret = 0;

     pte_end = (addr + PMD_SIZE) & PMD_MASK;
     if (end < pte_end)
         pte_end = end;

     ptep = pte_offset_kernel(pmd, addr);
     if (!ptep)
         return 0;
     ptep_start = ptep;

     for (current_addr = addr; current_addr < pte_end; current_addr += PAGE_SIZE) {
         pte = *ptep;

         if (ctx->stats) {
             ctx->stats->total_pte_count++;
         }

         if (pte_present(pte)) {
             if (ctx->stats) {
                 ctx->stats->present_pte_count++;
             }

             if (ctx->pte_callback) {
                 ret = ctx->pte_callback(ptep, current_addr, current_addr + PAGE_SIZE, ctx->data);
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
                if (memd_pte_read(pte)) prot |= PROT_READ;
                if (pte_write(pte)) prot |= PROT_WRITE;
                if (memd_pte_exec(pte)) prot |= PROT_EXEC;
                if (ctx->stats)
                    ctx->stats->pages_by_prot[prot]++;
            }

            if (ctx->flags & PAGE_WALK_TYPE) {
                bool is_file = false;
                struct vm_area_struct *vma = memd_find_vma(ctx->mm, current_addr);
                if (vma && memd_v_file(vma))
                    is_file = true;
                if (ctx->stats) {
                    if (is_file)
                        ctx->stats->file_pages++;
                    else
                        ctx->stats->anon_pages++;
                }
            }
        } else if (ctx->include_swap && memd_is_swap_pte(pte)) {
            if (ctx->stats)
                ctx->stats->swap_entries++;

             if (ctx->pte_callback) {
                 ret = ctx->pte_callback(ptep, current_addr, current_addr + PAGE_SIZE, ctx->data);
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
     pte_unmap(ptep_start);
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
            if (memd_pmd_huge(*pmd)) {
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
            if (memd_pud_huge(*pud)) {
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
     pgd_t *pgd_base;
     unsigned long addr = start;
     unsigned long next;
     int ret = 0;

     /* Never trust the build-time mm->pgd offset on foreign kernels:
      * derive the table base from the runtime-learned, shape-checked
      * pgd and fail closed when it is unavailable. */
     pgd_base = (pgd_t *)memd_valid_pgd(mm);
     if (!pgd_base)
         return -ENOENT;
     pgd = pgd_base + pgd_index(start);

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
     unsigned long start;
     unsigned long end;
     int ret;

     if (!mm || !ctx)
         return -EINVAL;

     if (ctx->stats) {
         ctx->stats->total_pte_count = 0;
         ctx->stats->present_pte_count = 0;
         ctx->stats->pmd_huge_count = 0;
         ctx->stats->pud_huge_count = 0;
     }

     ctx->mm = mm;
     /* User range starts at 0. End at
      * TASK_SIZE_64 (not build-time TASK_SIZE: a 5.10-built image on a
      * 52-bit-VA 6.x kernel must still reach high mappings; the extra
      * range is unmapped holes elsewhere and walks fail closed). */
     start = 0;
     end = ctx->include_kernel ? ULONG_MAX : TASK_SIZE_64;

     /* Serialize against exit_mmap: get_task_mm pins only the
      * mm_struct, not its tables. Without the read lock a racing
      * teardown frees table pages mid-descent (oops); with it the
      * walk either completes first or blocks until teardown ends and
      * then fails closed on empty tables. Callbacks run under this
      * lock: they must not take the mmap write lock. */
     MM_READ_LOCK(mm);
     ret = walk_pgd_level_ctx(mm, start, end, ctx);
     MM_READ_UNLOCK(mm);
     return ret;
 }

int memd_get_page_info(struct mm_struct *mm, unsigned long addr, struct page_info *info)
  {
     pte_t *ptep;
     pmd_t *pmd;
     pud_t *pud;
     p4d_t *p4d;
     pgd_t *pgd;
     pte_t pte;
     int ret;

     if (!mm || !info)
         return -EINVAL;

     info->present = false;
     info->swapped = false;

     /* Read lock across the whole descent (same reason as in
      * memd_page_walk): without it a racing exit_mmap frees tables
      * under these direct walks. */
     MM_READ_LOCK(mm);

     /* Runtime-learned pgd base (verified); fail closed. The lower
      * levels are indexed from live table contents, not structs. */
     pgd = (pgd_t *)memd_valid_pgd(mm);
     if (!pgd) {
         ret = -ENOENT;
         goto out;
     }
     pgd = pgd + pgd_index(addr);
     if (pgd_none(*pgd) || pgd_bad(*pgd)) {
         ret = -ENOENT;
         goto out;
     }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        ret = -ENOENT;
        goto out;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        ret = -ENOENT;
        goto out;
    }

     if (memd_pud_huge(*pud)) {
         info->page_size = PUD_SIZE;
         info->pfn = pud_pfn(*pud);
         info->present = true;
         info->huge = true;
         ret = 0;
         goto out;
     }

     pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        ret = -ENOENT;
        goto out;
    }

    if (memd_pmd_huge(*pmd)) {
        info->page_size = PMD_SIZE;
        info->pfn = pmd_pfn(*pmd);
        info->present = true;
        info->huge = true;
        ret = 0;
        goto out;
    }

     ptep = pte_offset_kernel(pmd, addr);
     if (!ptep) {
         ret = -ENOENT;
         goto out;
     }

     pte = *ptep;
     pte_unmap(ptep);
     if (!pte_present(pte)) {
        if (memd_is_swap_pte(pte)) {
            info->swapped = true;
            info->swap_offset = memd_pte_swp_offset(pte);
            info->swap_type = memd_pte_swp_type(pte);
        }
        ret = -ENOENT;
        goto out;
    }

    info->page_size = PAGE_SIZE;
    info->pfn = pte_pfn(pte);
    info->present = true;
    info->read = memd_pte_read(pte);
    info->write = pte_write(pte);
    info->exec = memd_pte_exec(pte);
    info->dirty = pte_dirty(pte);
    info->young = pte_young(pte);
    info->user = memd_pte_user(pte);
    info->huge = false;

    ret = 0;

 out:
    MM_READ_UNLOCK(mm);
    return ret;
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
     unsigned long aligned_start;
     unsigned long aligned_end;
     int ret;

     if (!mm || !callback || start >= end)
         return -EINVAL;

     /* Align the range out to page boundaries: walk_pte_level_ctx
      * derives the PTE index from addr >> PAGE_SHIFT but reports addr
      * verbatim, so an unaligned start would hand the callback an
      * unaligned addr/end for a whole-page PTE. Fail closed on end
      * wrap. */
     aligned_start = start & PAGE_MASK;
     if (end > ULONG_MAX - (PAGE_SIZE - 1))
         return -EINVAL;
     aligned_end = (end + (PAGE_SIZE - 1)) & PAGE_MASK;
     if (aligned_end <= aligned_start)
         return -EINVAL;

     /* Honor the caller's range (the old code ignored start/end and
      * always walked the whole address space). Same exit_mmap
      * serialization as memd_page_walk; the callback runs under the
      * read lock and must not take the mmap write lock. */
     MM_READ_LOCK(mm);
     ret = walk_pgd_level_ctx(mm, aligned_start, aligned_end, &ctx);
     MM_READ_UNLOCK(mm);
     return ret;
 }
/* kmod/memd/mm/memd_page_walk.c[∂] */
