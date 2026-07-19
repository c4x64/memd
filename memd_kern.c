/*
 * memd_kern — /dev/memd: direct physical memory access
 *
 * Reads/writes any physical RAM page via memremap().  No PID,
 * no task_struct, no page-table walk — just a physical address
 * and a copy.  Completely invisible from the target's perspective:
 * no /proc/<pid>/mem, no process_vm_readv, no ptrace, no get_user_pages.
 * The only observable host-side activity is the ioctl() on /dev/memd.
 *
 * Protocol (ioctl MEMD_IOC_XFER):
 *   struct memd_req {
 *       uint64_t phys_addr;     // physical address to access
 *       uint32_t size;          // bytes (max PAGE_SIZE)
 *       uint8_t  write;         // 0 = read, 1 = write
 *       uint64_t user_buf_ptr;  // userspace data buffer
 *   } __attribute__((packed));
 *
 * On return req.size contains the actual byte count transferred.
 * ioctl returns that count (positive) on success.
 *
 * Build (from kernel tree root):
 *   ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- \
 *       make -C <kernel-tree> M=$(pwd) modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>

#define DEVICE_NAME    "memd"
#define MEMD_IOC_MAGIC 0xed
#define MEMD_IOC_XFER  _IOWR(MEMD_IOC_MAGIC, 1, struct memd_req)
#define MAX_XFER       PAGE_SIZE

struct __attribute__((packed)) memd_req {
    uint64_t phys_addr;
    uint32_t size;
    uint8_t  write;
    uint64_t user_buf_ptr;
};

static long memd_xfer(struct memd_req *req, char __user *user_buf, int is_write)
{
    size_t size = req->size;
    void *vaddr;
    if (size == 0 || size > MAX_XFER)
        return -EINVAL;
    if (req->phys_addr + size < req->phys_addr)
        return -EINVAL;

    vaddr = memremap(req->phys_addr, size, MEMREMAP_WB);
    if (!vaddr)
        return -EFAULT;

    if (is_write) {
        if (copy_from_user(vaddr, user_buf, size)) {
            memunmap(vaddr);
            return -EFAULT;
        }
    } else {
        if (copy_to_user(user_buf, vaddr, size)) {
            memunmap(vaddr);
            return -EFAULT;
        }
    }
    memunmap(vaddr);
    return size;
}

static long memd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct memd_req req;
    char __user *user_buf;
    long ret;

    if (_IOC_TYPE(cmd) != MEMD_IOC_MAGIC || _IOC_NR(cmd) != 1)
        return -ENOTTY;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    user_buf = (char __user *)(uintptr_t)req.user_buf_ptr;
    ret = memd_xfer(&req, user_buf, req.write);

    if (ret >= 0)
        req.size = (uint32_t)ret;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;

    return ret;
}

static ssize_t memd_write(struct file *filp, const char __user *buf,
                           size_t len, loff_t *off)
{
    struct memd_req *req;
    char __user *user_buf;
    long ret;

    if (len < sizeof(struct memd_req) ||
        len > sizeof(struct memd_req) + MAX_XFER)
        return -EINVAL;

    req = kmalloc(len, GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    if (copy_from_user(req, buf, len)) {
        kfree(req);
        return -EFAULT;
    }

    user_buf = (char __user *)(uintptr_t)req->user_buf_ptr;
    ret = memd_xfer(req, user_buf, req->write);
    kfree(req);

    return ret;
}

static const struct file_operations memd_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = memd_ioctl,
    .write          = memd_write,
};

static struct miscdevice memd_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &memd_fops,
    .mode  = 0660,
};

static int __init memd_init(void)
{
    return misc_register(&memd_misc);
}

static void __exit memd_exit(void)
{
    misc_deregister(&memd_misc);
}

module_init(memd_init);
module_exit(memd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("memd_kern — silent physical memory access via memremap, no process artifacts");
