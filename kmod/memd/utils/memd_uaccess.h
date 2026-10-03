#ifndef MEMD_UACCESS_H
#define MEMD_UACCESS_H

/* Universal user-copy (KPM-grade universality). copy_to/from_user are
 * INLINE on arm64 (PAN/UAO sequences baked from build headers): a
 * 5.10-built inline fails on 5.15+ (proven: 8-byte stack copy returns
 * all-remaining = EFAULT while the 5.15-built identical call succeeds).
 * These replacements use only ancient stable EXPORTED functions
 * (get_user_pages_fast, kmap/kunmap, put_page) — no inline uaccess —
 * so one image copies correctly on every generation. Same semantics
 * as the originals (0 success, >0 bytes remaining).
 */
unsigned long memd_copy_from_user(void *dst, const void *src, unsigned long len);
unsigned long memd_copy_to_user(void *dst, const void *src, unsigned long len);

/* Cross-process user copies (KPTI-safe: kernel resolves target tables,
 * no pgd offsets, no mmap_lock in our image). Chunked. Returns bytes
 * remaining (0 = full success). Task ref held by caller. */
struct task_struct;
unsigned long memd_copy_from_task(struct task_struct *t, void *dst_kernel,
                                  unsigned long src_user, unsigned long len);
unsigned long memd_copy_to_task(struct task_struct *t, unsigned long dst_user,
                                const void *src_kernel, unsigned long len);

#endif /* MEMD_UACCESS_H */
