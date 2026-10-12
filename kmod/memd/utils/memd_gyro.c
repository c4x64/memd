#include "memd_gyro.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>

#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

static struct input_dev *gyro_input_dev = NULL;
static struct input_dev *touch_input_dev = NULL;
static DEFINE_MUTEX(gyro_lock);
static DEFINE_MUTEX(touch_lock);
static bool gyro_initialized = false;
static bool touch_initialized = false;

int memd_gyro_init(void)
{
    memd_info("gyro: initializing gyroscope/touch simulation\n");
    return 0;
}

void memd_gyro_cleanup(void)
{
    mutex_lock(&gyro_lock);
    if (gyro_input_dev) {
        input_unregister_device(gyro_input_dev);
        gyro_input_dev = NULL;
    }
    gyro_initialized = false;
    mutex_unlock(&gyro_lock);
    
    mutex_lock(&touch_lock);
    if (touch_input_dev) {
        input_unregister_device(touch_input_dev);
        touch_input_dev = NULL;
    }
    touch_initialized = false;
    mutex_unlock(&touch_lock);
    
    memd_info("gyro: cleaned up\n");
}

static struct input_dev *memd_find_input_device(struct task_struct *task, const char *name)
{
    struct input_dev *dev = NULL;
    struct input_handle *handle;
    struct file *filp;
    int i;
    
    if (!task || !task->files)
        return NULL;
    
    spin_lock(&task->files->file_lock);
    for (i = 0; i < task->files->max_fds; i++) {
        filp = rcu_dereference_raw(task->files->fd_array[i]);
        if (!filp)
            continue;
        
        if (filp->f_op && filp->f_op->unlocked_ioctl) {
            handle = filp->private_data;
            if (handle && handle->dev && handle->dev->name &&
                strstr(handle->dev->name, name)) {
                dev = handle->dev;
                break;
            }
        }
    }
    spin_unlock(&task->files->file_lock);
    
    return dev;
}

int memd_gyro_prepare_target(struct task_struct *task, struct memd_gyro_prepare_cmd *cmd)
{
    struct input_dev *dev = NULL;
    
    if (!task)
        return -EINVAL;
    
    mutex_lock(&gyro_lock);
    
    if (cmd->enable) {
        if (cmd->target_addr) {
            dev = (struct input_dev *)cmd->target_addr;
            if (!input_dev_valid(dev)) {
                mutex_unlock(&gyro_lock);
                return -EINVAL;
            }
        } else {
            dev = memd_find_input_device(task, "gyro");
            if (!dev)
                dev = memd_find_input_device(task, "sensor");
            if (!dev)
                dev = memd_find_input_device(task, "accel");
        }
        
        if (!dev) {
            mutex_unlock(&gyro_lock);
            memd_err("gyro: no suitable input device found\n");
            return -ENODEV;
        }
        
        gyro_input_dev = input_get_device(dev);
        gyro_initialized = true;
        memd_info("gyro: prepared target device %s\n", dev->name);
    } else {
        if (gyro_input_dev) {
            input_put_device(gyro_input_dev);
            gyro_input_dev = NULL;
        }
        gyro_initialized = false;
    }
    
    mutex_unlock(&gyro_lock);
    return 0;
}

int memd_touch_init(struct task_struct *task, struct memd_touch_init_cmd *cmd)
{
    struct input_dev *dev = NULL;
    
    if (!task)
        return -EINVAL;
    
    mutex_lock(&touch_lock);
    
    if (cmd->enable) {
        if (cmd->input_dev_addr) {
            dev = (struct input_dev *)cmd->input_dev_addr;
            if (!input_dev_valid(dev)) {
                mutex_unlock(&touch_lock);
                return -EINVAL;
            }
        } else {
            dev = memd_find_input_device(task, "touch");
            if (!dev)
                dev = memd_find_input_device(task, "ts");
            if (!dev)
                dev = memd_find_input_device(task, "screen");
        }
        
        if (!dev) {
            mutex_unlock(&touch_lock);
            memd_err("touch: no suitable input device found\n");
            return -ENODEV;
        }
        
        if (!(dev->evbit[0] & (1 << EV_ABS)) ||
            !(dev->absbit[0] & ((1 << ABS_MT_POSITION_X) | (1 << ABS_MT_POSITION_Y)))) {
            mutex_unlock(&touch_lock);
            memd_err("touch: device does not support MT protocol\n");
            return -ENOTSUPP;
        }
        
        touch_input_dev = input_get_device(dev);
        touch_initialized = true;
        memd_info("touch: initialized device %s\n", dev->name);
    } else {
        if (touch_input_dev) {
            input_put_device(touch_input_dev);
            touch_input_dev = NULL;
        }
        touch_initialized = false;
    }
    
    mutex_unlock(&touch_lock);
    return 0;
}

int memd_touch_inject(struct task_struct *task, struct memd_touch_inject_cmd *cmd)
{
    struct memd_touch_data *touch = &cmd->touch;
    struct input_dev *dev;
    int slot = touch->slot >= 0 ? touch->slot : 0;
    
    (void)task;
    
    mutex_lock(&touch_lock);
    
    if (!touch_initialized || !touch_input_dev) {
        mutex_unlock(&touch_lock);
        return -ENODEV;
    }
    
    dev = touch_input_dev;
    
    input_mt_slot(dev, slot);
    
    switch (touch->type) {
        case MEMD_TOUCH_TYPE_DOWN:
            input_mt_report_slot_state(dev, MT_TOOL_FINGER, true);
            input_report_abs(dev, ABS_MT_POSITION_X, touch->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, touch->y);
            if (touch->pressure > 0)
                input_report_abs(dev, ABS_MT_PRESSURE, touch->pressure);
            if (touch->tracking_id >= 0)
                input_report_abs(dev, ABS_MT_TRACKING_ID, touch->tracking_id);
            break;
            
        case MEMD_TOUCH_TYPE_MOVE:
            input_report_abs(dev, ABS_MT_POSITION_X, touch->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, touch->y);
            if (touch->pressure > 0)
                input_report_abs(dev, ABS_MT_PRESSURE, touch->pressure);
            break;
            
        case MEMD_TOUCH_TYPE_UP:
            input_mt_report_slot_state(dev, MT_TOOL_FINGER, false);
            if (touch->tracking_id >= 0)
                input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
            break;
            
        default:
            mutex_unlock(&touch_lock);
            return -EINVAL;
    }
    
    input_sync(dev);
    mutex_unlock(&touch_lock);
    
    return 0;
}

int memd_gyro_inject(struct task_struct *task, struct memd_gyro_inject_cmd *cmd)
{
    struct memd_gyro_data *gyro = &cmd->gyro;
    struct input_dev *dev;
    
    (void)task;
    
    mutex_lock(&gyro_lock);
    
    if (!gyro_initialized || !gyro_input_dev) {
        mutex_unlock(&gyro_lock);
        return -ENODEV;
    }
    
    dev = gyro_input_dev;
    
    if (dev->evbit[0] & (1 << EV_REL)) {
        input_report_rel(dev, REL_RX, gyro->x);
        input_report_rel(dev, REL_RY, gyro->y);
        input_report_rel(dev, REL_RZ, gyro->z);
    } else if (dev->evbit[0] & (1 << EV_ABS)) {
        input_report_abs(dev, ABS_RX, gyro->x);
        input_report_abs(dev, ABS_RY, gyro->y);
        input_report_abs(dev, ABS_RZ, gyro->z);
    }
    
    input_sync(dev);
    mutex_unlock(&gyro_lock);
    
    return 0;
}