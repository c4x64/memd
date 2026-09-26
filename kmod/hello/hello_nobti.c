#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
static int __init hello_nobti_init(void)
{
	pr_info("[hellonobti] init running\n");
	return 0;
}
static void __exit hello_nobti_exit(void)
{
	pr_info("[hellonobti] exit\n");
}
module_init(hello_nobti_init);
module_exit(hello_nobti_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("no-bti probe (temporary)");
