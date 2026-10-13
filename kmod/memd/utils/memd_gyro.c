#include "memd_gyro.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/string.h>

#include "memd_common.h"
#include "memd_utils.h"
#include "memd_learn.h"

struct memd_virtual_input {
    struct input_dev *dev;
    struct list_head list;
    bool is_virtual;
};

static struct input_dev *gyro_input_dev = NULL;
static struct input_dev *touch_input_dev = NULL;
static DEFINE_MUTEX(gyro_lock);
static DEFINE_MUTEX(touch_lock);
static bool gyro_initialized = false;
static bool touch_initialized = false;

static LIST_HEAD(virtual_inputs);
static DEFINE_MUTEX(virtual_input_lock);

static struct workqueue_struct *gyro_wq = NULL;

struct gyro_calibration {
    int16_t bias_x, bias_y, bias_z;
    int16_t scale_x, scale_y, scale_z;
    bool calibrated;
};

static struct gyro_calibration gyro_cal = {0};

struct touch_calibration {
    int32_t min_x, max_x, min_y, max_y;
    int32_t pressure_min, pressure_max;
    bool calibrated;
};

static struct touch_calibration touch_cal = {0};

static int32_t last_touch_x[10] = {0};
static int32_t last_touch_y[10] = {0};
static int64_t last_touch_time[10] = {0};
static int touch_slot_count = 0;

int memd_gyro_init(void)
 {
    gyro_wq = alloc_workqueue("memd_gyro", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!gyro_wq) {
        memd_err("gyro: failed to create workqueue\n");
        return -ENOMEM;
    }

    memd_info("gyro: initializing gyroscope/touch simulation\n");
    return 0;
}

void memd_gyro_cleanup(void)
 {
    struct memd_virtual_input *vi, *tmp;

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

    mutex_lock(&virtual_input_lock);
    list_for_each_entry_safe(vi, tmp, &virtual_inputs, list) {
        list_del(&vi->list);
        if (vi->dev) {
            input_unregister_device(vi->dev);
        }
        kfree(vi);
    }
    mutex_unlock(&virtual_input_lock);

    if (gyro_wq) {
        destroy_workqueue(gyro_wq);
        gyro_wq = NULL;
    }

    memd_info("gyro: cleaned up\n");
}

static struct input_dev *memd_find_input_device(struct task_struct *task, const char *name)
 {
    struct input_dev *dev = NULL;
    struct input_handle *handle;
    struct file *filp;
    struct files_struct *files;
    struct fdtable *fdt;
    int i;

    if (!task || !name)
        return NULL;

    /* Learned outer pointer (compiled fallback). The fdtable walk below
     * uses files->fdt->fd/max_fds: files->fd_array/max_fds only cover
     * the embedded default table and went stale upstream, so walk the
     * real table. Layout ancient-stable (CI-dumped per generation). */
    files = memd_t_files(task);
    if (!files)
        return NULL;

    rcu_read_lock();
    fdt = rcu_dereference(files->fdt);
    if (!fdt) {
        rcu_read_unlock();
        return NULL;
    }
    spin_lock(&files->file_lock);
    for (i = 0; i < fdt->max_fds; i++) {
        struct file_operations *fop;
        filp = rcu_dereference(fdt->fd[i]);
        if (!filp)
            continue;

        /* Per-generation f_op (6.6/6.12 rework file); NULL on unknown
         * gen means skip, never a wrong-offset read. */
        fop = memd_file_fop(filp);
        if (fop && fop->unlocked_ioctl) {
            handle = filp->private_data;
            if (handle && handle->dev && handle->dev->name &&
                strstr(handle->dev->name, name)) {
                dev = input_get_device(handle->dev);
                break;
            }
        }
    }
    spin_unlock(&files->file_lock);
    rcu_read_unlock();

    return dev;
}

static int memd_create_virtual_input(const char *name, bool is_touch, struct input_dev **out_dev)
 {
    struct input_dev *dev;
    struct memd_virtual_input *vi;
    int ret;

    dev = input_allocate_device();
    if (!dev)
        return -ENOMEM;

    dev->name = kstrdup(name, GFP_KERNEL);
    if (!dev->name) {
        input_free_device(dev);
        return -ENOMEM;
    }

    dev->id.bustype = BUS_VIRTUAL;
    dev->id.vendor = 0x1234;
    dev->id.product = 0x5678;
    dev->id.version = 0x0100;

    if (is_touch) {
        __set_bit(EV_ABS, dev->evbit);
        __set_bit(ABS_MT_POSITION_X, dev->absbit);
        __set_bit(ABS_MT_POSITION_Y, dev->absbit);
        __set_bit(ABS_MT_PRESSURE, dev->absbit);
        __set_bit(ABS_MT_TRACKING_ID, dev->absbit);
        __set_bit(ABS_MT_TOUCH_MAJOR, dev->absbit);
        __set_bit(ABS_MT_TOUCH_MINOR, dev->absbit);
        __set_bit(ABS_MT_ORIENTATION, dev->absbit);
        input_mt_init_slots(dev, 10, INPUT_MT_DIRECT);
    } else {
        __set_bit(EV_REL, dev->evbit);
        __set_bit(REL_RX, dev->relbit);
        __set_bit(REL_RY, dev->relbit);
        __set_bit(REL_RZ, dev->relbit);
        __set_bit(EV_ABS, dev->evbit);
        __set_bit(ABS_RX, dev->absbit);
        __set_bit(ABS_RY, dev->absbit);
        __set_bit(ABS_RZ, dev->absbit);
    }

    ret = input_register_device(dev);
    if (ret) {
        input_free_device(dev);
        return ret;
    }

    vi = kzalloc(sizeof(*vi), GFP_KERNEL);
    if (!vi) {
        input_unregister_device(dev);
        return -ENOMEM;
    }

    vi->dev = dev;
    vi->is_virtual = true;
    mutex_lock(&virtual_input_lock);
    list_add(&vi->list, &virtual_inputs);
    mutex_unlock(&virtual_input_lock);

    *out_dev = dev;
    return 0;
}

int memd_gyro_prepare_target(struct task_struct *task, struct memd_gyro_prepare_cmd *cmd)
 {
    struct input_dev *dev = NULL;
    int ret;

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
            dev = input_get_device(dev);
        } else {
            dev = memd_find_input_device(task, "gyro");
            if (!dev)
                dev = memd_find_input_device(task, "sensor");
            if (!dev)
                dev = memd_find_input_device(task, "accel");
        }

        if (!dev) {
            ret = memd_create_virtual_input("memd_virtual_gyro", false, &dev);
            if (ret) {
                mutex_unlock(&gyro_lock);
                memd_err("gyro: failed to create virtual input device: %d\n", ret);
                return ret;
            }
            memd_info("gyro: created virtual input device\n");
        }

        gyro_input_dev = dev;
        gyro_initialized = true;
        memd_info("gyro: prepared target device %s\n", dev->name);
    } else {
        if (gyro_input_dev) {
            input_put_device(gyro_input_dev);
            gyro_input_dev = NULL;
        }
        gyro_initialized = false;
        memset(&gyro_cal, 0, sizeof(gyro_cal));
    }

    mutex_unlock(&gyro_lock);
    return 0;
}

int memd_touch_init(struct task_struct *task, struct memd_touch_init_cmd *cmd)
 {
    struct input_dev *dev = NULL;
    int ret;

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
            dev = input_get_device(dev);
        } else {
            dev = memd_find_input_device(task, "touch");
            if (!dev)
                dev = memd_find_input_device(task, "ts");
            if (!dev)
                dev = memd_find_input_device(task, "screen");
        }

        if (!dev) {
            ret = memd_create_virtual_input("memd_virtual_touch", true, &dev);
            if (ret) {
                mutex_unlock(&touch_lock);
                memd_err("touch: failed to create virtual input device: %d\n", ret);
                return ret;
            }
            memd_info("touch: created virtual input device\n");
        }

        /* test_bit, not (1 << code): MT codes exceed 31 (int width). */
        if (!test_bit(EV_ABS, dev->evbit) ||
            !(test_bit(ABS_MT_POSITION_X, dev->absbit) && test_bit(ABS_MT_POSITION_Y, dev->absbit))) {
            if (dev != touch_input_dev)
                input_put_device(dev);
            mutex_unlock(&touch_lock);
            memd_err("touch: device does not support MT protocol\n");
            return -ENOTSUPP;
        }

        touch_input_dev = dev;
        touch_initialized = true;
        touch_slot_count = 0;
        memset(last_touch_x, 0, sizeof(last_touch_x));
        memset(last_touch_y, 0, sizeof(last_touch_y));
        memset(last_touch_time, 0, sizeof(last_touch_time));
        memd_info("touch: initialized device %s\n", dev->name);
    } else {
        if (touch_input_dev) {
            input_put_device(touch_input_dev);
            touch_input_dev = NULL;
        }
        touch_initialized = false;
        memset(&touch_cal, 0, sizeof(touch_cal));
    }

    mutex_unlock(&touch_lock);
    return 0;
}

static void memd_touch_calibrate_sample(struct memd_touch_data *touch)
 {
    if (!touch_cal.calibrated) {
        if (touch_cal.min_x == 0 && touch_cal.max_x == 0) {
            touch_cal.min_x = touch_cal.max_x = touch->x;
            touch_cal.min_y = touch_cal.max_y = touch->y;
            touch_cal.pressure_min = touch_cal.pressure_max = touch->pressure;
        } else {
            if (touch->x < touch_cal.min_x) touch_cal.min_x = touch->x;
            if (touch->x > touch_cal.max_x) touch_cal.max_x = touch->x;
            if (touch->y < touch_cal.min_y) touch_cal.min_y = touch->y;
            if (touch->y > touch_cal.max_y) touch_cal.max_y = touch->y;
            if (touch->pressure < touch_cal.pressure_min) touch_cal.pressure_min = touch->pressure;
            if (touch->pressure > touch_cal.pressure_max) touch_cal.pressure_max = touch->pressure;
        }
        if (touch_cal.max_x - touch_cal.min_x > 100 && touch_cal.max_y - touch_cal.min_y > 100)
            touch_cal.calibrated = true;
    }

    if (touch_cal.calibrated) {
        touch->x = (touch->x - touch_cal.min_x) * 32767 / (touch_cal.max_x - touch_cal.min_x);
        touch->y = (touch->y - touch_cal.min_y) * 32767 / (touch_cal.max_y - touch_cal.min_y);
        if (touch_cal.pressure_max > touch_cal.pressure_min)
            touch->pressure = (touch->pressure - touch_cal.pressure_min) * 32767 / (touch_cal.pressure_max - touch_cal.pressure_min);
    }
}

static void memd_touch_detect_gesture(struct memd_touch_data *touch, int slot)
 {
    int64_t now = ktime_get_real_ns();
    int32_t dx = touch->x - last_touch_x[slot];
    int32_t dy = touch->y - last_touch_y[slot];
    int64_t dt = now - last_touch_time[slot];

    if (dt > 0 && dt < 500000000) {
        int32_t dist = dx * dx + dy * dy;
        if (dist > 10000 && dt < 300000000) {
            touch->type = MEMD_TOUCH_TYPE_MOVE;
        }
    }

    last_touch_x[slot] = touch->x;
    last_touch_y[slot] = touch->y;
    last_touch_time[slot] = now;
}

int memd_touch_inject(struct task_struct *task, struct memd_touch_inject_cmd *cmd)
 {
    struct memd_touch_data *touch = &cmd->touch;
    struct input_dev *dev;
    int slot = touch->slot >= 0 ? touch->slot : 0;

    (void)task;

    if (slot >= 10)
        slot = 9;

    mutex_lock(&touch_lock);

    if (!touch_initialized || !touch_input_dev) {
        mutex_unlock(&touch_lock);
        return -ENODEV;
    }

    dev = touch_input_dev;

    memd_touch_calibrate_sample(touch);
    memd_touch_detect_gesture(touch, slot);

    input_mt_slot(dev, slot);

    switch (touch->type) {
        case MEMD_TOUCH_TYPE_DOWN:
            if (slot >= touch_slot_count)
                touch_slot_count = slot + 1;
            input_mt_report_slot_state(dev, MT_TOOL_FINGER, true);
            input_report_abs(dev, ABS_MT_POSITION_X, touch->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, touch->y);
            if (touch->pressure > 0)
                input_report_abs(dev, ABS_MT_PRESSURE, touch->pressure);
            if (touch->tracking_id >= 0)
                input_report_abs(dev, ABS_MT_TRACKING_ID, touch->tracking_id);
            input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 10);
            input_report_abs(dev, ABS_MT_TOUCH_MINOR, 10);
            break;

        case MEMD_TOUCH_TYPE_MOVE:
            input_report_abs(dev, ABS_MT_POSITION_X, touch->x);
            input_report_abs(dev, ABS_MT_POSITION_Y, touch->y);
            if (touch->pressure > 0)
                input_report_abs(dev, ABS_MT_PRESSURE, touch->pressure);
            input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 10);
            input_report_abs(dev, ABS_MT_TOUCH_MINOR, 10);
            break;

        case MEMD_TOUCH_TYPE_UP:
            input_mt_report_slot_state(dev, MT_TOOL_FINGER, false);
            if (touch->tracking_id >= 0)
                input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
            if (slot + 1 == touch_slot_count)
                touch_slot_count = slot;
            break;

        default:
            mutex_unlock(&touch_lock);
            return -EINVAL;
    }

    input_sync(dev);
    mutex_unlock(&touch_lock);

    return 0;
}

static void memd_gyro_calibrate_sample(struct memd_gyro_data *gyro)
 {
    if (!gyro_cal.calibrated) {
        if (gyro_cal.bias_x == 0 && gyro_cal.bias_y == 0 && gyro_cal.bias_z == 0) {
            gyro_cal.bias_x = gyro->x;
            gyro_cal.bias_y = gyro->y;
            gyro_cal.bias_z = gyro->z;
            gyro_cal.scale_x = gyro_cal.scale_y = gyro_cal.scale_z = 32767;
        } else {
            gyro_cal.bias_x = (gyro_cal.bias_x * 15 + gyro->x) / 16;
            gyro_cal.bias_y = (gyro_cal.bias_y * 15 + gyro->y) / 16;
            gyro_cal.bias_z = (gyro_cal.bias_z * 15 + gyro->z) / 16;
        }
    }

    if (gyro_cal.calibrated || (gyro_cal.scale_x > 0 && gyro_cal.scale_y > 0 && gyro_cal.scale_z > 0)) {
        gyro->x = (gyro->x - gyro_cal.bias_x) * 32767 / gyro_cal.scale_x;
        gyro->y = (gyro->y - gyro_cal.bias_y) * 32767 / gyro_cal.scale_y;
        gyro->z = (gyro->z - gyro_cal.bias_z) * 32767 / gyro_cal.scale_z;
    }
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

    memd_gyro_calibrate_sample(gyro);

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

int memd_gyro_calibrate(struct task_struct *task, struct memd_gyro_calibrate_cmd *cmd)
 {
    (void)task;

    mutex_lock(&gyro_lock);

    switch (cmd->action) {
        case MEMD_GYRO_CAL_ACTION_GET:
            cmd->bias_x = gyro_cal.bias_x;
            cmd->bias_y = gyro_cal.bias_y;
            cmd->bias_z = gyro_cal.bias_z;
            cmd->scale_x = gyro_cal.scale_x;
            cmd->scale_y = gyro_cal.scale_y;
            cmd->scale_z = gyro_cal.scale_z;
            break;

        case MEMD_GYRO_CAL_ACTION_SET:
            gyro_cal.bias_x = cmd->bias_x;
            gyro_cal.bias_y = cmd->bias_y;
            gyro_cal.bias_z = cmd->bias_z;
            gyro_cal.scale_x = cmd->scale_x ? cmd->scale_x : 32767;
            gyro_cal.scale_y = cmd->scale_y ? cmd->scale_y : 32767;
            gyro_cal.scale_z = cmd->scale_z ? cmd->scale_z : 32767;
            gyro_cal.calibrated = true;
            break;

        case MEMD_GYRO_CAL_ACTION_RESET:
            memset(&gyro_cal, 0, sizeof(gyro_cal));
            break;

        default:
            mutex_unlock(&gyro_lock);
            return -EINVAL;
    }

    mutex_unlock(&gyro_lock);
    return 0;
}

int memd_touch_calibrate(struct task_struct *task, struct memd_touch_calibrate_cmd *cmd)
 {
    (void)task;

    mutex_lock(&touch_lock);

    switch (cmd->action) {
        case MEMD_TOUCH_CAL_ACTION_GET:
            cmd->min_x = touch_cal.min_x;
            cmd->max_x = touch_cal.max_x;
            cmd->min_y = touch_cal.min_y;
            cmd->max_y = touch_cal.max_y;
            cmd->pressure_min = touch_cal.pressure_min;
            cmd->pressure_max = touch_cal.pressure_max;
            break;

        case MEMD_TOUCH_CAL_ACTION_SET:
            touch_cal.min_x = cmd->min_x;
            touch_cal.max_x = cmd->max_x;
            touch_cal.min_y = cmd->min_y;
            touch_cal.max_y = cmd->max_y;
            touch_cal.pressure_min = cmd->pressure_min;
            touch_cal.pressure_max = cmd->pressure_max;
            touch_cal.calibrated = true;
            break;

        case MEMD_TOUCH_CAL_ACTION_RESET:
            memset(&touch_cal, 0, sizeof(touch_cal));
            break;

        default:
            mutex_unlock(&touch_lock);
            return -EINVAL;
    }

    mutex_unlock(&touch_lock);
    return 0;
}

int memd_virtual_input_create(struct task_struct *task, struct memd_virtual_input_cmd *cmd)
 {
    struct input_dev *dev = NULL;
    int ret;

    (void)task;

    if (cmd->enable) {
        if (cmd->type == MEMD_VIRTUAL_INPUT_TYPE_GYRO) {
            ret = memd_create_virtual_input(cmd->name[0] ? cmd->name : "memd_virtual_gyro", false, &dev);
        } else if (cmd->type == MEMD_VIRTUAL_INPUT_TYPE_TOUCH) {
            ret = memd_create_virtual_input(cmd->name[0] ? cmd->name : "memd_virtual_touch", true, &dev);
        } else {
            return -EINVAL;
        }

        if (ret) {
            cmd->result = ret;
            return ret;
        }

        if (cmd->type == MEMD_VIRTUAL_INPUT_TYPE_GYRO) {
            mutex_lock(&gyro_lock);
            if (gyro_input_dev)
                input_put_device(gyro_input_dev);
            gyro_input_dev = dev;
            gyro_initialized = true;
            mutex_unlock(&gyro_lock);
        } else {
            mutex_lock(&touch_lock);
            if (touch_input_dev)
                input_put_device(touch_input_dev);
            touch_input_dev = dev;
            touch_initialized = true;
            mutex_unlock(&touch_lock);
        }

        cmd->result = 0;
    } else {
        if (cmd->type == MEMD_VIRTUAL_INPUT_TYPE_GYRO) {
            mutex_lock(&gyro_lock);
            if (gyro_input_dev) {
                input_put_device(gyro_input_dev);
                gyro_input_dev = NULL;
            }
            gyro_initialized = false;
            mutex_unlock(&gyro_lock);
        } else if (cmd->type == MEMD_VIRTUAL_INPUT_TYPE_TOUCH) {
            mutex_lock(&touch_lock);
            if (touch_input_dev) {
                input_put_device(touch_input_dev);
                touch_input_dev = NULL;
            }
            touch_initialized = false;
            mutex_unlock(&touch_lock);
        }
        cmd->result = 0;
    }

    return 0;
}