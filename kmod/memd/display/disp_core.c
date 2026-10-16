/* Display core: double-buffer + dirty + mutex + backend dispatch.
 * install/status/uninstall/frame entry points (called by ioctl, same
 * signatures as before — ioctl layer untouched). */
#include "disp_core.h"
#include "memd_display.h"
#include "memd_raster.h"

#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>

extern const struct memd_disp_backend memd_be_exynos;
extern const struct memd_disp_backend memd_be_simplefb;
extern const struct memd_disp_backend memd_be_drm;
#ifdef MEMD_DISP_TEST
extern const struct memd_disp_backend memd_be_ram;
#endif

static const struct memd_disp_backend *memd_backends[] = {
    &memd_be_drm,
    &memd_be_simplefb,
    &memd_be_exynos,
#ifdef MEMD_DISP_TEST
    /* RAM last: hardware preferred; RAM catches the no-panel case. */
    &memd_be_ram,
#endif
};

static DEFINE_MUTEX(g_core_mu);

static struct task_struct *g_refresh_task;
static struct workqueue_struct *g_flip_wq = NULL;

static struct {
    __u32 *front;
    __u32 *back;
    __u32 w;
    __u32 h;
    struct memd_dirty dirty;
    const struct memd_disp_backend *be;
    int last_errno;

    /* Enhanced features */
    struct memd_disp_vsync vsync;
    struct memd_disp_edid edid;
    struct memd_disp_mode current_mode;
    struct memd_disp_mode available_modes[16];
    __u32 mode_count;
    int dpms_mode;
    __u32 gamma_lut_r[256];
    __u32 gamma_lut_g[256];
    __u32 gamma_lut_b[256];
    __u32 gamma_size;
    bool gamma_dirty;
    struct memd_disp_layer layers[MEMD_DISP_MAX_LAYERS];
    __u32 layer_count;
    __u32 cursor_x, cursor_y;
    bool cursor_visible;
    __u32 cursor_w, cursor_h;
    __u32 *cursor_fb;
    bool tear_free;
    int64_t frame_interval_ns;
    int64_t last_flip_ns;
    atomic_t frame_count;
} g_core = {
    .front = NULL,
    .back = NULL,
    .w = 0,
    .h = 0,
    .be = NULL,
    .last_errno = 0,
    .vsync = {.enabled = false, .next_vsync_ns = 0, .frame_interval_ns = 0, .frame_pending = ATOMIC_INIT(0)},
    .edid = {.len = 0, .valid = false},
    .current_mode = {0},
    .mode_count = 0,
    .dpms_mode = 0,
    .gamma_size = 256,
    .gamma_dirty = false,
    .layer_count = 0,
    .cursor_x = 0,
    .cursor_y = 0,
    .cursor_visible = false,
    .cursor_w = 0,
    .cursor_h = 0,
    .cursor_fb = NULL,
    .tear_free = true,
    .frame_interval_ns = 16666666,
    .last_flip_ns = 0,
    .frame_count = ATOMIC_INIT(0),
};

/* Refresh thread: re-presents the stable front at MEMD_DISP_REFRESH_MS
 * for backends that ask (simplefb vs fbcon overwrites). Kernel thread:
 * immune to LMK/force-stop, outlives userspace death; only rmmod or
 * uninstall stops it. Per-tick work is one locked full present. */
static int memd_refresh_fn(void *data)
 {
    (void)data;
    while (!kthread_should_stop()) {
        struct memd_dirty full;
        msleep_interruptible(MEMD_DISP_REFRESH_MS);
        if (kthread_should_stop())
            break;
        mutex_lock(&g_core_mu);
        if (g_core.be && g_core.be->refresh && g_core.front &&
            g_core.be->present) {
            full.x0 = 0;
            full.y0 = 0;
            full.x1 = g_core.w;
            full.y1 = g_core.h;
            full.valid = true;
            g_core.be->present(g_core.front, g_core.w, g_core.h, &full);
        }
        mutex_unlock(&g_core_mu);
    }
    return 0;
}


static void memd_dirty_add(__u32 x, __u32 y, __u32 w, __u32 h)
 {
    __u32 x1, y1;
    if (!w || !h || x >= g_core.w || y >= g_core.h)
        return;
    /* Saturating add (x < g_core.w, so g_core.w - x is valid). */
    if (w > g_core.w - x)
        x1 = g_core.w;
    else
        x1 = x + w;
    if (h > g_core.h - y)
        y1 = g_core.h;
    else
        y1 = y + h;
    if (!g_core.dirty.valid) {
        g_core.dirty.x0 = x;
        g_core.dirty.y0 = y;
        g_core.dirty.x1 = x1;
        g_core.dirty.y1 = y1;
        g_core.dirty.valid = true;
        return;
    }
    if (x < g_core.dirty.x0)
        g_core.dirty.x0 = x;
    if (y < g_core.dirty.y0)
        g_core.dirty.y0 = y;
    if (x1 > g_core.dirty.x1)
        g_core.dirty.x1 = x1;
    if (y1 > g_core.dirty.y1)
        g_core.dirty.y1 = y1;
}

static int64_t memd_get_time_ns(void)
 {
    /* Monotonic: wall clock jumps (NTP/settimeofday) must not skew
     * vsync targets. */
    return ktime_get_ns();
}

static void memd_vsync_init(void)
 {
    g_core.vsync.enabled = g_core.tear_free;
    if (g_core.frame_interval_ns > 0)
        g_core.vsync.frame_interval_ns = g_core.frame_interval_ns;
    else
        g_core.vsync.frame_interval_ns = 16666666;
    g_core.vsync.next_vsync_ns = memd_get_time_ns() + g_core.vsync.frame_interval_ns;
    init_waitqueue_head(&g_core.vsync.wq);
    atomic_set(&g_core.vsync.frame_pending, 0);
}

/* Lock-free sleep: shared fields are snapshotted/updated under
 * g_core_mu; the wait itself holds no mutex (callers may or may not
 * hold it). */
static int memd_vsync_wait_internal(int64_t timeout_ns)
 {
    int64_t target, interval;
    int enabled;
    int64_t remaining;
    int ret;
    int64_t now;
    if (timeout_ns < 0)
        timeout_ns = 0;

    mutex_lock(&g_core_mu);
    enabled = g_core.vsync.enabled ? 1 : 0;
    target = g_core.vsync.next_vsync_ns;
    interval = g_core.vsync.frame_interval_ns;
    mutex_unlock(&g_core_mu);
    if (!enabled)
        return 0;
    if (interval <= 0)
        interval = 16666666;

    atomic_inc(&g_core.vsync.frame_pending);

    while ((now = memd_get_time_ns()) < target) {
        remaining = target - now;
        if (remaining > timeout_ns)
            remaining = timeout_ns;
        if (remaining <= 0)
            break;

        ret = wait_event_interruptible_timeout(g_core.vsync.wq,
            memd_get_time_ns() >= target || kthread_should_stop(),
            msecs_to_jiffies((unsigned long)(remaining / 1000000) + 1));
        if (ret == -ERESTARTSYS || kthread_should_stop())
            break;
        if (timeout_ns == 0)
            break;
    }

    atomic_dec(&g_core.vsync.frame_pending);

    now = memd_get_time_ns();
    mutex_lock(&g_core_mu);
    g_core.last_flip_ns = now;
    if (g_core.vsync.frame_interval_ns <= 0)
        g_core.vsync.frame_interval_ns = interval;
    g_core.vsync.next_vsync_ns = now + g_core.vsync.frame_interval_ns;
    mutex_unlock(&g_core_mu);
    atomic_inc(&g_core.frame_count);

    return 0;
}

static void memd_vsync_notify(void)
 {
    wake_up_all(&g_core.vsync.wq);
}

static void memd_flip_work(struct work_struct *work)
 {
    int rc = -ENODEV;
    (void)work;
    mutex_lock(&g_core_mu);
    if (g_core.be && g_core.be->present && g_core.front &&
        g_core.dirty.valid) {
        rc = g_core.be->present(g_core.front, g_core.w, g_core.h,
                                &g_core.dirty);
    }
    /* Keep the region on failure so the next frame retries it. */
    if (!rc)
        g_core.dirty.valid = false;
    mutex_unlock(&g_core_mu);

    memd_vsync_notify();
}

static DECLARE_WORK(g_flip_work, memd_flip_work);

static int memd_schedule_flip(void)
 {
    if (!g_flip_wq)
        return -ENODEV;
    return queue_work(g_flip_wq, &g_flip_work) ? 0 : -EBUSY;
}

/* Saturated span for LINE dirty (|a - b| + 8, never wraps). */
static __u32 memd_span8(__u32 a, __u32 b)
 {
    __u64 d;
    if (a < b)
        d = (__u64)b - (__u64)a + (__u64)8;
    else
        d = (__u64)a - (__u64)b + (__u64)8;
    if (d > (__u64)4294967295u)
        d = (__u64)4294967295u;
    return (__u32)d;
}

static const struct memd_disp_backend *memd_find_be(__u32 id)
 {
    unsigned long i;
    for (i = 0; i < sizeof(memd_backends) / sizeof(memd_backends[0]); i++) {
        if (memd_backends[i]->id == (int)id)
            return memd_backends[i];
    }
    return NULL;
}

/* Must hold g_core_mu. Starts the refresh thread once (idempotent:
 * kthread_run is non-blocking; the thread blocks on the mutex). */
static void memd_refresh_start_locked(void)
 {
    if (g_refresh_task)
        return;
    g_refresh_task = kthread_run(memd_refresh_fn, NULL, "memd_disp");
    if (IS_ERR(g_refresh_task))
        g_refresh_task = NULL;

    if (!g_flip_wq) {
        g_flip_wq = alloc_workqueue("memd_disp_flip", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    }
}

int memd_core_install(__u32 backend, __u32 width, __u32 height)
 {
    size_t px = 0, bytes = 0;
    const struct memd_disp_backend *be = NULL;
    unsigned long i;
    int rc;

    if (MEMD_DISP_TODO)
        return -EOPNOTSUPP;
    if (width == 0 || height == 0)
        return -EINVAL;
    if (width > MEMD_DISP_MAX_W)
        width = MEMD_DISP_MAX_W;
    if (height > MEMD_DISP_MAX_H)
        height = MEMD_DISP_MAX_H;
    if (check_mul_overflow((size_t)width, (size_t)height, &px) ||
        check_mul_overflow(px, (size_t)4, &bytes) || bytes == 0)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    /* Tear down any previous session first (clean slate). */
    if (g_core.be && g_core.be->close)
        g_core.be->close();
    if (g_core.front)
        vfree(g_core.front);
    if (g_core.back)
        vfree(g_core.back);
    g_core.front = NULL;
    g_core.back = NULL;
    g_core.w = 0;
    g_core.h = 0;
    g_core.be = NULL;
    g_core.dirty.valid = false;
    /* Drop queued flips before reusing buffers (worker needs the
     * mutex, so flush without holding it). */
    if (g_flip_wq) {
        mutex_unlock(&g_core_mu);
        flush_workqueue(g_flip_wq);
        mutex_lock(&g_core_mu);
    }
    /* Free core-owned overlays (leaked before: memset discarded them). */
    if (g_core.cursor_fb) {
        kfree(g_core.cursor_fb);
        g_core.cursor_fb = NULL;
    }
    for (i = 0; i < g_core.layer_count && i < MEMD_DISP_MAX_LAYERS; i++) {
        if (g_core.layers[i].buffer) {
            kfree(g_core.layers[i].buffer);
            g_core.layers[i].buffer = NULL;
        }
    }
    /* Wake stale waiters before recycling the waitqueue (guarded:
     * the queue is only valid after a prior init). */
    if (g_core.vsync.frame_interval_ns)
        wake_up_all(&g_core.vsync.wq);

    /* Initialize new features */
    memset(&g_core.vsync, 0, sizeof(g_core.vsync));
    memset(&g_core.edid, 0, sizeof(g_core.edid));
    memset(&g_core.current_mode, 0, sizeof(g_core.current_mode));
    memset(g_core.available_modes, 0, sizeof(g_core.available_modes));
    g_core.mode_count = 0;
    g_core.dpms_mode = 0;
    g_core.gamma_size = 256;
    for (i = 0; i < 256; i++) {
        g_core.gamma_lut_r[i] = i << 8;
        g_core.gamma_lut_g[i] = i << 8;
        g_core.gamma_lut_b[i] = i << 8;
    }
    g_core.gamma_dirty = false;
    memset(g_core.layers, 0, sizeof(g_core.layers));
    g_core.layer_count = 0;
    g_core.cursor_x = 0;
    g_core.cursor_y = 0;
    g_core.cursor_visible = false;
    g_core.cursor_w = 0;
    g_core.cursor_h = 0;
    g_core.cursor_fb = NULL;
    g_core.tear_free = true;
    g_core.frame_interval_ns = 16666666;
    g_core.last_flip_ns = 0;
    atomic_set(&g_core.frame_count, 0);
    memd_vsync_init();

    if (backend != 0) {
        be = memd_find_be(backend);
        if (!be) {
            g_core.last_errno = -ENODEV;
            mutex_unlock(&g_core_mu);
            return -ENODEV;
        }
        g_core.front = vmalloc(bytes);
        g_core.back = vmalloc(bytes);
        if (!g_core.front || !g_core.back)
            goto nomem;
        g_core.w = width;
        g_core.h = height;
        rc = be->open(width, height);
        if (rc) {
            g_core.last_errno = rc;
            goto fail_open;
        }
        g_core.be = be;
        g_core.last_errno = 0;
        memd_raster_clear(g_core.front, width, height, 0x00000000u);
        memd_raster_clear(g_core.back, width, height, 0x00000000u);
        memd_refresh_start_locked();
#ifdef MEMD_DISP_TEST
        memd_vnc_start();
#endif
        mutex_unlock(&g_core_mu);
        return 0;
    }
    /* Auto: simplefb (bootloader-lit, zero programming) first, then
     * DECON raw probe (fail-closed), then DRM discovery. First success
     * wins; nothing retained on failure (each open cleans itself). */
    for (i = 0; i < sizeof(memd_backends) / sizeof(memd_backends[0]); i++) {
        be = memd_backends[i];
        g_core.front = vmalloc(bytes);
        g_core.back = vmalloc(bytes);
        if (!g_core.front || !g_core.back) {
            if (g_core.front)
                vfree(g_core.front);
            if (g_core.back)
                vfree(g_core.back);
            g_core.front = g_core.back = NULL;
            g_core.last_errno = -ENOMEM;
            mutex_unlock(&g_core_mu);
            return -ENOMEM;
        }
        g_core.w = width;
        g_core.h = height;
        rc = be->open(width, height);
        if (!rc) {
            g_core.be = be;
            g_core.last_errno = 0;
            memd_raster_clear(g_core.front, width, height, 0x00000000u);
            memd_raster_clear(g_core.back, width, height, 0x00000000u);
            memd_refresh_start_locked();
#ifdef MEMD_DISP_TEST
        memd_vnc_start();
#endif
            mutex_unlock(&g_core_mu);
            return 0;
        }
        g_core.last_errno = rc;
        vfree(g_core.front);
        vfree(g_core.back);
        g_core.front = g_core.back = NULL;
        g_core.w = g_core.h = 0;
    }
    mutex_unlock(&g_core_mu);
    return -ENODEV;

nomem:
    if (g_core.front)
        vfree(g_core.front);
    if (g_core.back)
        vfree(g_core.back);
    g_core.front = g_core.back = NULL;
    g_core.last_errno = -ENOMEM;
    mutex_unlock(&g_core_mu);
    return -ENOMEM;

fail_open:
    vfree(g_core.front);
    vfree(g_core.back);
    g_core.front = g_core.back = NULL;
    g_core.w = g_core.h = 0;
    mutex_unlock(&g_core_mu);
    return rc;
}

int memd_core_uninstall(void)
 {
    struct task_struct *t;
    unsigned long i;
    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    t = g_refresh_task;
    g_refresh_task = NULL;
    mutex_unlock(&g_core_mu);
    if (t)
        kthread_stop(t);
#ifdef MEMD_DISP_TEST
    memd_vnc_stop();
#endif
    if (g_flip_wq)
        flush_workqueue(g_flip_wq);
    mutex_lock(&g_core_mu);
    if (g_core.be && g_core.be->close)
        g_core.be->close();
    if (g_core.front)
        vfree(g_core.front);
    if (g_core.back)
        vfree(g_core.back);
    g_core.front = g_core.back = NULL;
    g_core.w = g_core.h = 0;
    g_core.be = NULL;
    g_core.dirty.valid = false;
    if (g_core.cursor_fb) {
        kfree(g_core.cursor_fb);
        g_core.cursor_fb = NULL;
    }
    g_core.cursor_w = g_core.cursor_h = 0;
    g_core.cursor_x = g_core.cursor_y = 0;
    g_core.cursor_visible = false;
    for (i = 0; i < g_core.layer_count && i < MEMD_DISP_MAX_LAYERS; i++) {
        if (g_core.layers[i].buffer) {
            kfree(g_core.layers[i].buffer);
            g_core.layers[i].buffer = NULL;
        }
    }
    memset(g_core.layers, 0, sizeof(g_core.layers));
    g_core.layer_count = 0;
    wake_up_all(&g_core.vsync.wq);
    mutex_unlock(&g_core_mu);
    return 0;
}

int memd_core_active(void)
 {
    int a;
    mutex_lock(&g_core_mu);
    a = g_core.be ? 1 : 0;
    mutex_unlock(&g_core_mu);
    return a;
}

int memd_core_status(__u32 *backend, __u32 *w, __u32 *h, __u32 *err)
 {
    mutex_lock(&g_core_mu);
    if (backend)
        *backend = g_core.be ? (__u32)g_core.be->id : 0;
    if (w)
        *w = g_core.w;
    if (h)
        *h = g_core.h;
    if (err)
        *err = (__u32)(-(g_core.last_errno));
    if (g_core.be && g_core.be->status) {
        __u32 bw = 0, bh = 0, be = 0;
        g_core.be->status(&bw, &bh, &be);
        if (w)
            *w = bw;
        if (h)
            *h = bh;
        if (err && be)
            *err = be;
    }
    mutex_unlock(&g_core_mu);
    return 0;
}

int memd_core_frame(const struct memd_disp_op *ops, __u32 count)
 {
    __u32 i;
    __u32 *tmp;
    int rc = 0;

    if (!ops)
        return -EINVAL;
    if (count > MEMD_DISP_MAX_OPS)
        count = MEMD_DISP_MAX_OPS;
    mutex_lock(&g_core_mu);
    if (!g_core.be || !g_core.front || !g_core.back) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    for (i = 0; i < count; i++) {
        switch (ops[i].op) {
        case MEMD_DISP_CLEAR:
            memd_raster_clear(g_core.back, g_core.w, g_core.h,
                              ops[i].color);
            memd_dirty_add(0, 0, g_core.w, g_core.h);
            break;
        case MEMD_DISP_RECT:
            memd_raster_rect(g_core.back, g_core.w, g_core.h,
                             ops[i].x, ops[i].y, ops[i].w, ops[i].h,
                             ops[i].color);
            memd_dirty_add(ops[i].x, ops[i].y, ops[i].w, ops[i].h);
            break;
        case MEMD_DISP_LINE:
            memd_raster_line(g_core.back, g_core.w, g_core.h,
                             ops[i].x, ops[i].y, ops[i].w, ops[i].h,
                             ops[i].color);
            memd_dirty_add(ops[i].x < ops[i].w ? ops[i].x : ops[i].w,
                          ops[i].y < ops[i].h ? ops[i].y : ops[i].h,
                          memd_span8(ops[i].x, ops[i].w),
                          memd_span8(ops[i].y, ops[i].h));
            break;
        case MEMD_DISP_GLYPH:
            memd_raster_glyph(g_core.back, g_core.w, g_core.h,
                              ops[i].x, ops[i].y, ops[i].glyph,
                              ops[i].color);
            memd_dirty_add(ops[i].x, ops[i].y, 8, 8);
            break;
        case MEMD_DISP_NOP:
        default:
            break;
        }
    }
    /* Flip: front becomes the stable snapshot for present. */
    tmp = g_core.front;
    g_core.front = g_core.back;
    g_core.back = tmp;

    /* Apply gamma correction if needed */
    if (g_core.gamma_dirty) {
        memd_raster_apply_gamma(g_core.front, g_core.w, g_core.h,
                                g_core.gamma_lut_r, g_core.gamma_lut_g, g_core.gamma_lut_b,
                                g_core.gamma_size);
        g_core.gamma_dirty = false;
    }

    /* Composite layers if any */
    if (g_core.layer_count > 0) {
        memd_raster_composite_layers(g_core.front, g_core.w, g_core.h,
                                     g_core.layers, g_core.layer_count);
    }

    /* Composite cursor if visible */
    if (g_core.cursor_visible && g_core.cursor_fb) {
        memd_raster_composite_cursor(g_core.front, g_core.w, g_core.h,
                                     g_core.cursor_fb, g_core.cursor_w, g_core.cursor_h,
                                     g_core.cursor_x, g_core.cursor_y);
    }

    /* Exactly one present per frame: async flip owns dirty when
     * queued; otherwise synchronous fallback (also covers !tear_free).
     * Dirty clears only on success so failures retry next frame. */
    if (g_core.tear_free) {
        int q = memd_schedule_flip();
        int want_wait = g_core.vsync.enabled ? 1 : 0;
        int64_t wait_ns = g_core.vsync.frame_interval_ns * 2;
        if (!q) {
            mutex_unlock(&g_core_mu);
            if (want_wait)
                memd_vsync_wait_internal(wait_ns);
            return 0;
        }
        /* Queue busy/missing: fall through to synchronous present. */
    }

    if (g_core.be->present) {
        rc = g_core.be->present(g_core.front, g_core.w, g_core.h,
                                &g_core.dirty);
    }
    if (!rc)
        g_core.dirty.valid = false;
    {
        int want_wait = g_core.vsync.enabled ? 1 : 0;
        int64_t wait_ns = g_core.vsync.frame_interval_ns;
        mutex_unlock(&g_core_mu);

        if (want_wait)
            memd_vsync_wait_internal(wait_ns);

        return rc;
    }
}

#ifdef MEMD_DISP_TEST
#include "memd_uaccess.h"

int memd_core_readback(__u64 dst, __u32 size, __u32 *w, __u32 *h)
 {
    size_t need = 0;
    int rc = 0;
    if (!w || !h)
        return -EINVAL;
    mutex_lock(&g_core_mu);
    if (!g_core.be || !g_core.front || !g_core.w || !g_core.h) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    if (check_mul_overflow((size_t)g_core.w, (size_t)g_core.h, &need) ||
        check_mul_overflow(need, (size_t)4, &need) || !need ||
        (size_t)size < need) {
        mutex_unlock(&g_core_mu);
        return -EINVAL;
    }
    *w = g_core.w;
    *h = g_core.h;
    rc = memd_copy_to_user((void *)(uintptr_t)dst, g_core.front, need) ?
        -EFAULT : 0;
    mutex_unlock(&g_core_mu);
    return rc;
}

/* Snapshot the stable front for the TEST VNC tap (lock, copy, out —
 * the streamer byte-swaps and sends from its own buffer, never under
 * the core lock). */
int memd_core_copy_front(__u32 *dst, __u32 max_bytes, __u32 *w, __u32 *h)
 {
    size_t need = 0;
    if (!dst || !w || !h)
        return -EINVAL;
    mutex_lock(&g_core_mu);
    if (!g_core.be || !g_core.front || !g_core.w || !g_core.h) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    if (check_mul_overflow((size_t)g_core.w, (size_t)g_core.h, &need) ||
        check_mul_overflow(need, (size_t)4, &need) || !need ||
        need > (size_t)max_bytes) {
        mutex_unlock(&g_core_mu);
        return -EINVAL;
    }
    memcpy(dst, g_core.front, need);
    *w = g_core.w;
    *h = g_core.h;
    mutex_unlock(&g_core_mu);
    return 0;
}
#endif

/* New API implementations */

int memd_core_set_mode(const struct memd_disp_mode *mode)
 {
    int rc = 0;

    if (!mode)
        return -EINVAL;
    if (!mode->w || !mode->h || !mode->refresh_rate)
        return -EINVAL;
    if (mode->w > MEMD_DISP_MAX_W || mode->h > MEMD_DISP_MAX_H)
        return -EINVAL;
    if (mode->refresh_rate > 1000)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (g_core.be->set_mode) {
        rc = g_core.be->set_mode(mode);
        if (!rc) {
            g_core.current_mode = *mode;
            g_core.frame_interval_ns = 1000000000LL / (int64_t)mode->refresh_rate;
            g_core.vsync.frame_interval_ns = g_core.frame_interval_ns;
        }
    } else {
        rc = -ENOTSUPP;
    }

    mutex_unlock(&g_core_mu);
    return rc;
}

int memd_core_get_modes(struct memd_disp_mode *modes, __u32 max_modes)
 {
    int rc = 0;

    if (!modes || max_modes == 0)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (g_core.be->get_modes) {
        rc = g_core.be->get_modes(modes, max_modes);
    } else if (g_core.mode_count > 0) {
        __u32 count = max_modes < g_core.mode_count ? max_modes : g_core.mode_count;
        memcpy(modes, g_core.available_modes, count * sizeof(struct memd_disp_mode));
        rc = count;
    } else {
        rc = -ENOTSUPP;
    }

    mutex_unlock(&g_core_mu);
    return rc;
}

int memd_core_get_edid(struct memd_disp_edid *edid)
 {
    int rc = 0;

    if (!edid)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (g_core.be->get_edid) {
        rc = g_core.be->get_edid(edid);
    } else if (g_core.edid.valid) {
        memcpy(edid, &g_core.edid, sizeof(struct memd_disp_edid));
        rc = 0;
    } else {
        rc = -ENOTSUPP;
    }

    mutex_unlock(&g_core_mu);
    return rc;
}

int memd_core_dpms(int mode)
 {
    int rc = 0;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (g_core.be->dpms) {
        rc = g_core.be->dpms(mode);
        if (!rc)
            g_core.dpms_mode = mode;
    } else {
        rc = -ENOTSUPP;
    }

    mutex_unlock(&g_core_mu);
    return rc;
}

int memd_core_vsync_wait(int64_t timeout_ns)
 {
    /* Internal snapshots enabled/interval under lock; no unlocked
     * access here. */
    return memd_vsync_wait_internal(timeout_ns);
}

int memd_core_cursor_set(const __u32 *cursor_fb, __u32 w, __u32 h, __u32 x, __u32 y)
 {
    int rc = 0;
    size_t px = 0, bytes = 0;
    __u32 *fresh = NULL;

    if (!cursor_fb || w == 0 || h == 0)
        return -EINVAL;
    if (w > MEMD_DISP_MAX_W || h > MEMD_DISP_MAX_H)
        return -EINVAL;
    if (check_mul_overflow((size_t)w, (size_t)h, &px) ||
        check_mul_overflow(px, (size_t)4, &bytes) || !bytes)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (g_core.be->cursor_set) {
        rc = g_core.be->cursor_set(cursor_fb, w, h, x, y);
        if (rc) {
            mutex_unlock(&g_core_mu);
            return rc;
        }
    }

    fresh = kmalloc(bytes, GFP_KERNEL);
    if (!fresh) {
        mutex_unlock(&g_core_mu);
        return -ENOMEM;
    }
    memcpy(fresh, cursor_fb, bytes);
    if (g_core.cursor_fb)
        kfree(g_core.cursor_fb);
    g_core.cursor_fb = fresh;
    g_core.cursor_w = w;
    g_core.cursor_h = h;
    g_core.cursor_x = x;
    g_core.cursor_y = y;
    g_core.cursor_visible = true;

    mutex_unlock(&g_core_mu);
    return 0;
}

int memd_core_cursor_move(__u32 x, __u32 y)
 {
    int rc = 0;
    mutex_lock(&g_core_mu);
    g_core.cursor_x = x;
    g_core.cursor_y = y;
    if (g_core.be && g_core.be->cursor_move)
        rc = g_core.be->cursor_move(x, y);
    mutex_unlock(&g_core_mu);

    return rc;
}

int memd_core_cursor_show(bool show)
 {
    int rc = 0;
    mutex_lock(&g_core_mu);
    g_core.cursor_visible = show;
    if (g_core.be && g_core.be->cursor_show)
        rc = g_core.be->cursor_show(show);
    mutex_unlock(&g_core_mu);

    return rc;
}

int memd_core_layer_add(struct memd_disp_layer *layer)
 {
    size_t px = 0, bytes = 0;
    __u32 *fresh = NULL;
    __u32 *src = NULL;
    int rc = 0;
    if (!layer || layer->w == 0 || layer->h == 0)
        return -EINVAL;
    if (layer->w > MEMD_DISP_MAX_W || layer->h > MEMD_DISP_MAX_H)
        return -EINVAL;
    if (check_mul_overflow((size_t)layer->w, (size_t)layer->h, &px) ||
        check_mul_overflow(px, (size_t)4, &bytes) || !bytes)
        return -EINVAL;

    /* Allocate first so a backend add is never left dangling on
     * allocation failure. */
    fresh = kmalloc(bytes, GFP_KERNEL);
    if (!fresh)
        return -ENOMEM;
    src = layer->buffer;
    if (src)
        memcpy(fresh, src, bytes);
    else
        memset(fresh, 0, bytes);

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        kfree(fresh);
        return -ENODEV;
    }

    if (g_core.layer_count >= MEMD_DISP_MAX_LAYERS) {
        mutex_unlock(&g_core_mu);
        kfree(fresh);
        return -ENOSPC;
    }

    if (g_core.be->layer_add) {
        rc = g_core.be->layer_add(layer);
        if (rc) {
            mutex_unlock(&g_core_mu);
            kfree(fresh);
            return rc;
        }
    }

    layer->buffer = fresh;
    g_core.layers[g_core.layer_count++] = *layer;
    mutex_unlock(&g_core_mu);
    return 0;
}

int memd_core_layer_remove(struct memd_disp_layer *layer)
 {
    unsigned long i;
    if (!layer)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    /* Core stores a copy on add, so the caller's pointer never equals
     * an array element: match by the core-owned buffer instead. */
    for (i = 0; i < g_core.layer_count; i++) {
        if (g_core.layers[i].buffer && layer->buffer &&
            g_core.layers[i].buffer == layer->buffer) {
            if (g_core.be->layer_remove)
                g_core.be->layer_remove(&g_core.layers[i]);

            kfree(g_core.layers[i].buffer);

            if (i + 1 < g_core.layer_count) {
                memmove(&g_core.layers[i], &g_core.layers[i + 1],
                        (g_core.layer_count - i - 1) *
                        sizeof(struct memd_disp_layer));
            } else {
                memset(&g_core.layers[i], 0,
                       sizeof(struct memd_disp_layer));
            }
            g_core.layer_count--;
            layer->buffer = NULL;
            mutex_unlock(&g_core_mu);
            return 0;
        }
    }

    mutex_unlock(&g_core_mu);
    return -ENOENT;
}

int memd_core_layer_update(struct memd_disp_layer *layer)
 {
    if (!layer)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    {
        unsigned long i;
        for (i = 0; i < g_core.layer_count; i++) {
            if (g_core.layers[i].buffer && layer->buffer &&
                g_core.layers[i].buffer == layer->buffer) {
                /* Buffer is core-owned: resize needs remove+add
                 * (avoids leaking or aliasing the old buffer). */
                if (layer->w != g_core.layers[i].w ||
                    layer->h != g_core.layers[i].h) {
                    mutex_unlock(&g_core_mu);
                    return -EINVAL;
                }
                if (g_core.be->layer_update)
                    g_core.be->layer_update(&g_core.layers[i]);
                g_core.layers[i].x = layer->x;
                g_core.layers[i].y = layer->y;
                g_core.layers[i].alpha = layer->alpha;
                g_core.layers[i].visible = layer->visible;
                g_core.layers[i].z_order = layer->z_order;
                mutex_unlock(&g_core_mu);
                return 0;
            }
        }
    }

    mutex_unlock(&g_core_mu);
    return -ENOENT;
}

int memd_core_gamma_set(const __u16 *r, const __u16 *g, const __u16 *b, __u32 size)
 {
    if (!r || !g || !b || size == 0 || size > 256)
        return -EINVAL;

    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }

    if (size != g_core.gamma_size) {
        g_core.gamma_size = size;
    }

    {
        unsigned long i;
        for (i = 0; i < size; i++) {
            g_core.gamma_lut_r[i] = (__u32)r[i] << 8;
            g_core.gamma_lut_g[i] = (__u32)g[i] << 8;
            g_core.gamma_lut_b[i] = (__u32)b[i] << 8;
        }
    }

    g_core.gamma_dirty = true;

    if (g_core.be->gamma_set) {
        int rc = g_core.be->gamma_set(r, g, b, size);
        mutex_unlock(&g_core_mu);
        return rc;
    }

    mutex_unlock(&g_core_mu);
    return 0;
}
/* kmod/memd/display/disp_core.c[∂] */
