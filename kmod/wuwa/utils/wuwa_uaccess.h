#ifndef WUWA_UACCESS_H
#define WUWA_UACCESS_H

/* Universal user-copy (KPM-grade universality). copy_to/from_user are
 * INLINE on arm64 (PAN/UAO sequences baked from build headers): a
 * 5.10-built inline fails on 5.15+ (proven: 8-byte stack copy returns
 * all-remaining = EFAULT while the 5.15-built identical call succeeds).
 * These replacements use only ancient stable EXPORTED functions
 * (get_user_pages_fast, kmap/kunmap, put_page) — no inline uaccess —
 * so one image copies correctly on every generation. Same semantics
 * as the originals (0 success, >0 bytes remaining).
 */
unsigned long wuwa_copy_from_user(void *dst, const void *src, unsigned long len);
unsigned long wuwa_copy_to_user(void *dst, const void *src, unsigned long len);

#endif /* WUWA_UACCESS_H */
