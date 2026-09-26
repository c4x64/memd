#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
static int __init hello_nofn_init(void)
{
	pr_info("[hellonofn] init running\n");
	return 0;
}
static void __exit hello_nofn_exit(void)
{
	pr_info("[hellonofn] exit\n");
}
module_init(hello_nofn_init);
module_exit(hello_nofn_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("no-fnsections probe (temporary)");
