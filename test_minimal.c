/* Minimal test: just register /dev/testdev, no memremap. */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

static const struct file_operations test_fops = {
    .owner = THIS_MODULE,
};

static struct miscdevice test_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "testdev",
    .fops  = &test_fops,
};

static int __init test_init(void)
{
    return misc_register(&test_dev);
}
module_init(test_init);

static void __exit test_exit(void)
{
    misc_deregister(&test_dev);
}
module_exit(test_exit);

MODULE_LICENSE("GPL");
