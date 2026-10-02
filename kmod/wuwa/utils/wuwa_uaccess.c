/* GUP + kmap user copies. See header for why inline uaccess is banned
 * in the universal image. Batch-pinned (16 pages) so large R/W works
 * without pinning megabytes at once. Process context only (ioctl path
 * can sleep: kmap, not kmap_atomic). */
#include "wuwa_uaccess.h"

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/sched.h>

#define WUWA_GUP_BATCH 16

static unsigned long wuwa_gup_copy(char *dst, const char *src,
                                   unsigned long len, int to_user)
{
    unsigned long done = 0;
    if (!len)
        return 0;
    if (!dst || !src)
        return len;
    while (done < len) {
        unsigned long addr = (unsigned long)(to_user ? dst : src) + done;
        unsigned long page_start = addr & PAGE_MASK;
        unsigned long off = addr & ~PAGE_MASK;
        unsigned long chunk = len - done;
        unsigned long first_end = PAGE_SIZE - off;
        unsigned long npages, i;
        struct page *pages[WUWA_GUP_BATCH];
        int got;
        if (chunk > first_end) {
            /* span pages: pin up to batch */
            unsigned long remain = chunk - first_end;
            npages = 1 + (remain + PAGE_SIZE - 1) / PAGE_SIZE;
            if (npages > WUWA_GUP_BATCH)
                npages = WUWA_GUP_BATCH;
            if (chunk > first_end + (npages - 1) * PAGE_SIZE)
                chunk = first_end + (npages - 1) * PAGE_SIZE;
        } else {
            npages = 1;
        }
        got = get_user_pages(page_start, (unsigned long)npages,
                             to_user ? FOLL_WRITE : 0, pages, NULL);
        if (got <= 0)
            return len - done;
        {
            unsigned long left = chunk;
            unsigned long o = off;
            for (i = 0; i < (unsigned long)got && left; i++) {
                unsigned long take = PAGE_SIZE - o;
                char *k;
                if (take > left)
                    take = left;
                k = (char *)kmap(pages[i]);
                if (!k)
                    break;
                if (to_user)
                    memcpy(k + o, src + done, take);
                else
                    memcpy(dst + done, k + o, take);
                kunmap(pages[i]);
                done += take;
                left -= take;
                o = 0;
            }
        }
        for (i = 0; i < (unsigned long)got; i++) {
            if (!PageReserved(pages[i]))
                SetPageDirty(pages[i]);
            put_page(pages[i]);
        }
        if (got < (int)npages)
            return len - done;
    }
    return 0;
}

unsigned long wuwa_copy_from_user(void *dst, const void *src,
                                  unsigned long len)
{
    return wuwa_gup_copy((char *)dst, (const char *)src, len, 0);
}

unsigned long wuwa_copy_to_user(void *dst, const void *src,
                                unsigned long len)
{
    return wuwa_gup_copy((char *)dst, (const char *)src, len, 1);
}
