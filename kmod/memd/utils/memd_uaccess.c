/* Universal user-copy via access_process_vm (stable out-of-line MM API:
 * same (tsk, addr, buf, len, gup_flags) signature on 5.10 through 6.12,
 * no inline pinner/uaccess code in our image). Chunked (32K) so large
 * R/W never pins excessively. Same semantics as copy_*_user (0 ok).
 * Process context only (current caller's buffers). */
#include "memd_uaccess.h"

#include <linux/mm.h>
#include <linux/sched.h>

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

unsigned long memd_copy_from_user(void *dst, const void *src,
                                  unsigned long len)
{
    return memd_uc_copy((char *)dst, (const char *)src, len, 0);
}

unsigned long memd_copy_to_user(void *dst, const void *src,
                                unsigned long len)
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
