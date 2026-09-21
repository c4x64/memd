/* probe_touch — TEMPORARY init-execution witness (full kbuild artifact).
 * init creates/writes /data/local/tmp/PROBE via the file API and returns 0.
 * File present after insmod  => init RAN.
 * Live without file         => init skipped.
 * Uses __init/__exit (proper .init.text/.exit.text) to also test whether
 * init-section presence matters. Removed after the experiment.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

/* Empty __versions (same idiom as rwbridge.c): MODVERSIONS kernels refuse
 * CRC-less modules SILENTLY unless the section exists; zero entries take
 * the warn-and-pass branch per lookup. */
__asm__(".section __versions,\"a\",@progbits\n"
	".previous\n");

static int __init probe_touch_init(void)
{
	struct file *f;
	char b = 'K';
	loff_t pos = 0;

	f = filp_open("/data/local/tmp/PROBE", O_WRONLY | O_CREAT | O_TRUNC,
		      0600);
	if (IS_ERR(f))
		return 0;
	kernel_write(f, &b, 1, &pos);
	filp_close(f, NULL);
	return 0;
}

static void __exit probe_touch_exit(void)
{
}

module_init(probe_touch_init);
module_exit(probe_touch_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("temporary init-execution witness (file touch)");
