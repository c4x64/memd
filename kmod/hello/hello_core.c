#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/* Probe: init body in CORE .text instead of .init.text. If this prints
 * while the normal variant stays silent, Samsung's init_layout placement
 * is at fault and init-in-core is the workaround. */
#undef __init
#define __init

static int __init hello_core_init(void)
{
	pr_info("[hellocore] init running\n");
	return 0;
}

static void __exit hello_core_exit(void)
{
	pr_info("[hellocore] exit\n");
}

module_init(hello_core_init);
module_exit(hello_core_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("core-init probe (temporary)");
