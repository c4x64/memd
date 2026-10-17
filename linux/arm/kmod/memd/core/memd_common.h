#ifndef MEMD_COMMON_H
#define MEMD_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include "memd_utils.h"

/* Logging without the _printk import (missing from trimmed DDK maps
 * and GKI-protected on trimmed kernels): everything routes through
 * memd_printk, which calls a runtime-resolved vprintk and silently
 * drops messages until the bootstrap ioctl lands. Format-checked via
 * __printf attribute. Debug variants are hard no-ops (their two call
 * sites pass side-effect-free args; release builds emitted nothing
 * anyway since DBG only adds -g, never -DDEBUG). */
#define MEMD_LOG_PREFIX "[memd] "
#define memd_info(fmt, ...) memd_printk(KERN_INFO MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_warn(fmt, ...) memd_printk(KERN_WARNING MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_err(fmt, ...) memd_printk(KERN_ERR MEMD_LOG_PREFIX fmt, ##__VA_ARGS__)
#define memd_debug(fmt, ...) do { } while (0)

#define ovo_info(fmt, ...) memd_printk(KERN_INFO MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_warn(fmt, ...) memd_printk(KERN_WARNING MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_err(fmt, ...) memd_printk(KERN_ERR MEMD_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_debug(fmt, ...) do { } while (0)

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

/* struct memd_sock lives in memd/net/memd_sock.h (single definition —
 * a stale duplicate here broke every matrix build with "redefinition").
 * All field users already include memd_sock.h directly. */

#endif /* MEMD_COMMON_H */
/* kmod/memd/core/memd_common.h[∂] */
