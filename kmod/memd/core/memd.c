#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "memd_common.h"
#include "memd_kallsyms.h"
#include "memd_protocol.h"
#include "memd_sock.h"
#include "memd_syshook.h"
#include "memd_display.h"
#include "memd_learn.h"
#include "memd_utils.h"
#include "memd_region.h"
#include "memd_hwbp.h"
#include "memd_gyro.h"
#include "memd_sigforce.h"
#include "hijack_arm64.h"

/* No header declares these (BUILD_HIDE_SIGNAL-only); forward-declare
 * locally so enabling the flag cannot regress to an implicit decl. */
#if defined(BUILD_HIDE_SIGNAL)
extern int memd_safe_signal_init(void);
extern void memd_safe_signal_cleanup(void);
#endif

/* Owned by proc/memd_hide.c; dropped at exit so kmalloc'd entries do
 * not leak on unload (no new include: single prototype). */
void memd_hide_clear(void);

static int __init memd_init(void) {
    int ret;
    memd_info("helo!\n");

    /* No kprobe-blacklist handling: this image installs no kprobes (all
     * kallsyms comes from /proc self-parse), so there is nothing to
     * unblacklist on any kernel. */

    ret = init_arch();
    if (ret) {
        memd_err("init_arch failed: %d\n", ret);
        return ret;
    }

    /* Runtime offset learning (fail-soft per field, loud): task/mm/vma
     * layouts come from live anchors, never build headers. */
    memd_learn_comprehensive();

    ret = memd_proto_init();
    if (ret) {
        memd_err("memd_socket_init failed: %d\n", ret);
        goto out;
    }

    ret = memd_region_init();
    if (ret) {
        memd_err("memd_region_init failed: %d\n", ret);
        goto clean_proto;
    }

    ret = memd_hwbp_init();
    if (ret) {
        memd_err("memd_hwbp_init failed: %d\n", ret);
        goto clean_region;
    }

    ret = memd_gyro_init();
    if (ret) {
        memd_err("memd_gyro_init failed: %d\n", ret);
        goto clean_hwbp;
    }

    ret = memd_sigforce_init();
    if (ret) {
        memd_err("memd_sigforce_init failed: %d\n", ret);
        goto clean_gyro;
    }

    /* Re-call is idempotent-safe: memd_learn_comprehensive already ran
     * this, and the extended learners only assign on a unique hit
     * (n == 1) and never write back failure, so a second pass can only
     * confirm the same per-boot-constant offsets, never clobber them. */
    memd_learn_extended();

#if defined(BUILD_HIDE_SIGNAL)
    ret = memd_safe_signal_init();
    if (ret) {
        memd_err("memd_safe_signal_init failed: %d\n", ret);
        goto clean_sigforce;
    }
#endif


#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    memd_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    return 0;

#if defined(BUILD_HIDE_SIGNAL)
clean_sigforce:
    memd_sigforce_cleanup();
#endif
clean_gyro:
    memd_gyro_cleanup();
clean_hwbp:
    memd_hwbp_cleanup();
clean_region:
    memd_region_cleanup();
clean_proto:
    memd_proto_cleanup();

out:
    return ret;
}

static void __exit memd_exit(void) {
    int r;
    memd_info("bye!\n");
    /* Restore hooks FIRST: a dangling /proc iterate pointer or a
     * programmed overlay plane after unload would panic/wedge the next
     * reader. In-flight hook calls hold module refs, so rmmod already
     * waited for them. */
    r = memd_hide_uninstall();
    if (r == -EBUSY) {
        memd_warn("hide uninstall at exit: table owned by someone else; unloading without our hook (safe)\n");
    } else if (r) {
        memd_printk(KERN_EMERG MEMD_LOG_PREFIX "hide uninstall at exit failed: %d; /proc iterate still points at freed module text, next /proc readdir may panic — avoid /proc listings and reboot\n", r);
    }
    r = memd_disp_uninstall();
    if (r && r != -ENODEV)
        memd_err("display uninstall at exit failed: %d\n", r);
    /* Drop the hidden-pid set while no reader can be active (hooks are
     * gone and rmmod fenced in-flight calls): entries are kmalloc'd
     * and would otherwise leak on unload. */
    memd_hide_clear();
#if defined(BUILD_HIDE_SIGNAL)
    memd_safe_signal_cleanup();
#endif
    memd_sigforce_cleanup();
    memd_gyro_cleanup();
    memd_hwbp_cleanup();
    memd_region_cleanup();
    memd_proto_cleanup();
}

module_init(memd_init);
module_exit(memd_exit);

MODULE_AUTHOR("Genghis Khan");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/c4x64/memd");
MODULE_VERSION("1.0.5");

/* kmod/memd/core/memd.c[∂] */
