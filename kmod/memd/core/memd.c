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
#include "hijack_arm64.h"

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
    memd_learn();

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

#if defined(BUILD_HIDE_SIGNAL)
    ret = memd_safe_signal_init();
    if (ret) {
        memd_err("memd_safe_signal_init failed: %d\n", ret);
        goto clean_sig;
    }
#endif


#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    memd_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    return 0;

clean_proto:
    memd_proto_cleanup();

#if defined(BUILD_HIDE_SIGNAL)
clean_d0:
    memd_safe_signal_cleanup();

clean_sig:
    memd_proto_cleanup();
#endif


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
    if (r)
        memd_err("hide uninstall at exit failed: %d\n", r);
    r = memd_disp_uninstall();
    if (r && r != -ENODEV)
        memd_err("display uninstall at exit failed: %d\n", r);
    memd_region_cleanup();
    memd_proto_cleanup();
#if defined(BUILD_HIDE_SIGNAL)
    memd_safe_signal_cleanup();
#endif
}

module_init(memd_init);
module_exit(memd_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/android-memd");
MODULE_VERSION("1.0.5");

