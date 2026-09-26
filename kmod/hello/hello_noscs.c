#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
static int __init hello_noscs_init(void)
{
	pr_info("[hellonoscs] init running\n");
	return 0;
}
static void __exit hello_noscs_exit(void)
{
	pr_info("[hellonoscs] exit\n");
}
module_init(hello_noscs_init);
module_exit(hello_noscs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("no-scs probe (temporary)");
