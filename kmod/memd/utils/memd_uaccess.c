/* Universal user-copy via access_process_vm (stable out-of-line MM API:
 * same (tsk, addr, buf, len, gup_flags) signature on 5.10 through 6.12,
 * no inline pinner/uaccess code in our image). Chunked (32K) so large
 * R/W never pins excessively. Same semantics as copy_*_user (0 ok).
 * Process context only (current caller's buffers). */
#include "memd_uaccess.h"

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define MEMD_UC_CHUNK (32UL * 1024UL)

static unsigned long memd_uc_copy(char *dst, const char *src,
                                  unsigned long len, int to_user)
{
    unsigned long done = 0;
    if (!len)
        return 0;
    if (!dst || !src)
        return len;
    while (done < len) {
        unsigned long chunk = len - done;
        int ret;
        if (chunk > MEMD_UC_CHUNK)
            chunk = MEMD_UC_CHUNK;
        if (to_user)
            ret = access_process_vm(current, (unsigned long)(dst + done),
                                    (void *)(src + done), (int)chunk,
                                    FOLL_WRITE);
        else
            ret = access_process_vm(current, (unsigned long)(src + done),
                                    (void *)(dst + done), (int)chunk, 0);
        if (ret <= 0)
            return len - done;
        done += (unsigned long)ret;
        if ((unsigned long)ret < chunk)
            return len - done;
    }
    return 0;
}

unsigned long memd_copy_from_user(void *dst, const void *src, unsigned long len)
{
    return memd_uc_copy((char *)dst, (const char *)src, len, 0);
}

unsigned long memd_copy_to_user(void *dst, const void *src, unsigned long len)
{
    return memd_uc_copy((char *)dst, (const char *)src, len, 1);
}

#define MEMD_TASK_CHUNK (64UL * 1024UL)

static unsigned long memd_task_copy(struct task_struct *t, char *kbuf,
                                    unsigned long uaddr, unsigned long len,
                                    int to_task)
{
    unsigned long done = 0;
    if (!t || !kbuf || !len)
        return len;
    while (done < len) {
        unsigned long chunk = len - done;
        int ret;
        if (chunk > MEMD_TASK_CHUNK)
            chunk = MEMD_TASK_CHUNK;
        if (to_task)
            ret = access_process_vm(t, uaddr + done, kbuf + done,
                                    (int)chunk, FOLL_WRITE);
        else
            ret = access_process_vm(t, uaddr + done, kbuf + done,
                                    (int)chunk, 0);
        if (ret <= 0)
            return len - done;
        done += (unsigned long)ret;
        if ((unsigned long)ret < chunk)
            return len - done;
    }
    return 0;
}

unsigned long memd_copy_from_task(struct task_struct *t, void *dst_kernel,
                                  unsigned long src_user, unsigned long len)
{
    return memd_task_copy(t, (char *)dst_kernel, src_user, len, 0);
}

unsigned long memd_copy_to_task(struct task_struct *t, unsigned long dst_user,
                                const void *src_kernel, unsigned long len)
{
    /* access_process_vm takes non-const buf; our src is kernel-read, safe. */
    return memd_task_copy(t, (char *)src_kernel, dst_user, len, 1);
}

/* Enhanced uaccess with error reporting */

int memd_copy_from_user_full(void *dst, const void *src, unsigned long len,
                             unsigned long *bytes_copied)
{
    unsigned long remaining = memd_copy_from_user(dst, src, len);
    if (bytes_copied)
        *bytes_copied = len - remaining;
    return remaining == 0 ? 0 : -EFAULT;
}

int memd_copy_to_user_full(void *dst, const void *src, unsigned long len,
                           unsigned long *bytes_copied)
{
    unsigned long remaining = memd_copy_to_user(dst, src, len);
    if (bytes_copied)
        *bytes_copied = len - remaining;
    return remaining == 0 ? 0 : -EFAULT;
}

int memd_copy_from_task_full(struct task_struct *t, void *dst_kernel,
                             unsigned long src_user, unsigned long len,
                             unsigned long *bytes_copied)
{
    unsigned long remaining = memd_copy_from_task(t, dst_kernel, src_user, len);
    if (bytes_copied)
        *bytes_copied = len - remaining;
    return remaining == 0 ? 0 : -EFAULT;
}

int memd_copy_to_task_full(struct task_struct *t, unsigned long dst_user,
                           const void *src_kernel, unsigned long len,
                           unsigned long *bytes_copied)
{
    unsigned long remaining = memd_copy_to_task(t, dst_user, src_kernel, len);
    if (bytes_copied)
        *bytes_copied = len - remaining;
    return remaining == 0 ? 0 : -EFAULT;
}

/* Safe string copying */

int memd_strncpy_from_user(char *dst, const void *src, size_t max_len)
{
    if (!dst || !src || max_len == 0)
        return -EINVAL;

    size_t copied = 0;
    while (copied < max_len - 1) {
        char c;
        unsigned long remaining = memd_copy_from_user(&c, (char *)src + copied, 1);
        if (remaining != 0)
            break;
        dst[copied++] = c;
        if (c == '\0')
            break;
    }
    dst[copied] = '\0';
    return copied;
}

int memd_strncpy_to_user(void *dst, const char *src, size_t max_len)
{
    if (!dst || !src || max_len == 0)
        return -EINVAL;

    size_t copied = 0;
    while (copied < max_len - 1) {
        unsigned long remaining = memd_copy_to_user((char *)dst + copied, &src[copied], 1);
        if (remaining != 0)
            break;
        if (src[copied] == '\0') {
            copied++;
            break;
        }
        copied++;
    }
    return copied;
}

/* Memory region validation */

bool memd_uaccess_validate_range(unsigned long addr, unsigned long len)
{
    if (len == 0)
        return true;

    unsigned long end = addr + len;
    if (end < addr)  /* overflow */
        return false;

    if (addr >= TASK_SIZE_MAX || end > TASK_SIZE_MAX)
        return false;

    return true;
}

bool memd_task_uaccess_validate_range(struct task_struct *t,
                                      unsigned long addr, unsigned long len)
{
    if (!t || !t->mm)
        return false;

    if (len == 0)
        return true;

    unsigned long end = addr + len;
    if (end < addr)  /* overflow */
        return false;

    if (addr >= TASK_SIZE_MAX || end > TASK_SIZE_MAX)
        return false;

    return true;
}

/* Batch operations for efficiency */

int memd_copy_from_user_iovec(void *dst, const struct iovec *iov,
                              unsigned long nr_segs, unsigned long len,
                              unsigned long *bytes_copied)
{
    if (!dst || !iov || nr_segs == 0)
        return -EINVAL;

    unsigned long total_copied = 0;
    char *kdst = (char *)dst;

    for (unsigned long i = 0; i < nr_segs; i++) {
        unsigned long seg_len = iov[i].iov_len;
        if (total_copied + seg_len > len)
            seg_len = len - total_copied;
        if (seg_len == 0)
            break;

        unsigned long remaining = memd_copy_from_user(kdst, iov[i].iov_base, seg_len);
        unsigned long copied = seg_len - remaining;
        total_copied += copied;
        kdst += copied;

        if (remaining != 0)
            break;
        if (total_copied >= len)
            break;
    }

    if (bytes_copied)
        *bytes_copied = total_copied;

    return total_copied == len ? 0 : -EFAULT;
}

int memd_copy_to_user_iovec(void *dst, const struct iovec *iov,
                            unsigned long nr_segs, unsigned long len,
                            unsigned long *bytes_copied)
{
    if (!dst || !iov || nr_segs == 0)
        return -EINVAL;

    unsigned long total_copied = 0;
    const char *kdst = (const char *)dst;

    for (unsigned long i = 0; i < nr_segs; i++) {
        unsigned long seg_len = iov[i].iov_len;
        if (total_copied + seg_len > len)
            seg_len = len - total_copied;
        if (seg_len == 0)
            break;

        unsigned long remaining = memd_copy_to_user((void *)iov[i].iov_base, kdst, seg_len);
        unsigned long copied = seg_len - remaining;
        total_copied += copied;
        kdst += copied;

        if (remaining != 0)
            break;
        if (total_copied >= len)
            break;
    }

    if (bytes_copied)
        *bytes_copied = total_copied;

    return total_copied == len ? 0 : -EFAULT;
}
