#ifndef MEMD_COMMON_H
#define MEMD_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include "memd_utils.h"

/* printk ABI pin: 5.10-baseline headers emit a direct printk reference,
 * but some vendor kernels (proven: Samsung 5.15) export only _printk
 * (5.15+ headers emit that form via their own macro, skipped here).
 * Redirect every printk call site to _printk: present in the 5.10
 * baseline map (CI-gated above) and on all newer targets (proven by
 * the matrix builds, which already import it). Same signature family
 * — behavior-identical. */
#ifndef printk
#define printk _printk
#endif

#define MEMD_LOG_PREFIX "[memd] "
#define memd_info(fmt, ...) pr_info(MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_warn(fmt, ...) pr_warn(MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_err(fmt, ...) pr_err(MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_debug(fmt, ...) pr_debug(MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)

#define ovo_info(fmt, ...) pr_info(MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_warn(fmt, ...) pr_warn(MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_err(fmt, ...) pr_err(MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_debug(fmt, ...) pr_debug(MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define LUCKY_LUO 0x00000000faceb00c

#define CONFIG_COMPARE_TASK 0
#define CONFIG_COMPARE_PT_REGS 0

#define CONFIG_COPY_PROCESS 0
/*
 * !!!Poor performance!!!
 */
#define CONFIG_REDIRECT_VIA_ABORT 0

/*
 * !!!!Poor performance!!!
 * The LR address redirection is achieved by using the Linux signal processor mechanism.
 *  > is unsafe and has competition risks.
 *  > is only used for learning and verification that
 *     it can be injected into the executable memory and executed normally without any trace.
 */
#define CONFIG_REDIRECT_VIA_SIGNAL 0

#define CMD_MAX_BYTES (50 * 1024 * 1024)
#define CMD_MAX_PAGES (CMD_MAX_BYTES / PAGE_SIZE)

struct memd_sock {
    struct sock sk;

    /* Slack: the running kernel's struct sock may exceed the build
     * baseline's (5.10 headers on newer targets — proven: total grows
     * per generation). Tail fields live past any plausible true size
     * (deltas are tens of bytes; this is 2K) and the slab, sized by
     * sizeof, covers everything. Without this, the slab object is
     * smaller than the kernel's sock (heap overflow on first socket)
     * and our tail overwrites live sock state. */
    char priv_pad[2048];

    int version;

    pid_t session;

    struct karray_list* used_pages;
};

#endif /* MEMD_COMMON_H */
