#ifndef MEMD_GYRO_H
#define MEMD_GYRO_H

#include <linux/types.h>

struct task_struct;

#define MEMD_GYRO_AXIS_X 0
#define MEMD_GYRO_AXIS_Y 1
#define MEMD_GYRO_AXIS_Z 2

#define MEMD_TOUCH_TYPE_DOWN 0
#define MEMD_TOUCH_TYPE_UP 1
#define MEMD_TOUCH_TYPE_MOVE 2

struct memd_gyro_data {
    int16_t x;
    int16_t y;
    int16_t z;
    int64_t timestamp;
};

struct memd_touch_data {
    int32_t x;
    int32_t y;
    int32_t pressure;
    int32_t type;
    int64_t timestamp;
    int32_t tracking_id;
    int32_t slot;
};

struct memd_gyro_prepare_cmd {
    pid_t pid;
    uintptr_t target_addr;
    u32 enable;
};

struct memd_touch_init_cmd {
    pid_t pid;
    uintptr_t input_dev_addr;
    u32 enable;
};

struct memd_touch_inject_cmd {
    pid_t pid;
    struct memd_touch_data touch;
};

struct memd_gyro_inject_cmd {
    pid_t pid;
    struct memd_gyro_data gyro;
};

struct memd_gyro_calibrate_cmd {
    pid_t pid;
    int16_t bias_x, bias_y, bias_z;
    int16_t scale_x, scale_y, scale_z;
    u32 action;
};

struct memd_touch_calibrate_cmd {
    pid_t pid;
    int32_t min_x, max_x, min_y, max_y;
    int32_t pressure_min, pressure_max;
    u32 action;
};

struct memd_virtual_input_cmd {
    pid_t pid;
    u32 type;
    char name[64];
    u32 enable;
    int result;
};

#define MEMD_GYRO_CAL_ACTION_GET 0
#define MEMD_GYRO_CAL_ACTION_SET 1
#define MEMD_GYRO_CAL_ACTION_RESET 2

#define MEMD_TOUCH_CAL_ACTION_GET 0
#define MEMD_TOUCH_CAL_ACTION_SET 1
#define MEMD_TOUCH_CAL_ACTION_RESET 2

#define MEMD_VIRTUAL_INPUT_TYPE_GYRO 0
#define MEMD_VIRTUAL_INPUT_TYPE_TOUCH 1

int memd_gyro_init(void);
void memd_gyro_cleanup(void);
int memd_gyro_prepare_target(struct task_struct *task, struct memd_gyro_prepare_cmd *cmd);
int memd_touch_init(struct task_struct *task, struct memd_touch_init_cmd *cmd);
int memd_touch_inject(struct task_struct *task, struct memd_touch_inject_cmd *cmd);
int memd_gyro_inject(struct task_struct *task, struct memd_gyro_inject_cmd *cmd);
int memd_gyro_calibrate(struct task_struct *task, struct memd_gyro_calibrate_cmd *cmd);
int memd_touch_calibrate(struct task_struct *task, struct memd_touch_calibrate_cmd *cmd);
int memd_virtual_input_create(struct task_struct *task, struct memd_virtual_input_cmd *cmd);

#endif