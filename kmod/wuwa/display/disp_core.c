/* Display core: double-buffer + dirty + mutex + backend dispatch.
 * install/status/uninstall/frame entry points (called by ioctl, same
 * signatures as before — ioctl layer untouched). */
#include "disp_core.h"
#include "wuwa_display.h"
#include "wuwa_raster.h"

#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>

extern const struct wuwa_disp_backend wuwa_be_exynos;
extern const struct wuwa_disp_backend wuwa_be_simplefb;
extern const struct wuwa_disp_backend wuwa_be_drm;

static const struct wuwa_disp_backend *wuwa_backends[] = {
    &wuwa_be_simplefb,
    &wuwa_be_exynos,
    &wuwa_be_drm,
};

static DEFINE_MUTEX(g_core_mu);

static struct {
    __u32 *front;
    __u32 *back;
    __u32 w;
    __u32 h;
    struct wuwa_dirty dirty;
    const struct wuwa_disp_backend *be;
    int last_errno;
} g_core = {
    .front = NULL,
    .back = NULL,
    .w = 0,
    .h = 0,
    .be = NULL,
    .last_errno = 0,
};

static void wuwa_dirty_add(__u32 x, __u32 y, __u32 w, __u32 h)
{
    __u32 x1, y1;
    if (!w || !h || x >= g_core.w || y >= g_core.h)
        return;
    x1 = x + w;
    y1 = y + h;
    if (x1 > g_core.w)
        x1 = g_core.w;
    if (y1 > g_core.h)
        y1 = g_core.h;
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

static const struct wuwa_disp_backend *wuwa_find_be(__u32 id)
{
    unsigned long i;
    for (i = 0; i < sizeof(wuwa_backends) / sizeof(wuwa_backends[0]); i++) {
        if (wuwa_backends[i]->id == (int)id)
            return wuwa_backends[i];
    }
    return NULL;
}

int wuwa_core_install(__u32 backend, __u32 width, __u32 height)
{
    size_t px = 0, bytes = 0;
    const struct wuwa_disp_backend *be = NULL;
    unsigned long i;
    int rc;

    if (width == 0 || height == 0)
        return -EINVAL;
    if (width > WUWA_DISP_MAX_W)
        width = WUWA_DISP_MAX_W;
    if (height > WUWA_DISP_MAX_H)
        height = WUWA_DISP_MAX_H;
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

    if (backend != 0) {
        be = wuwa_find_be(backend);
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
        wuwa_raster_clear(g_core.front, width, height, 0x00000000u);
        wuwa_raster_clear(g_core.back, width, height, 0x00000000u);
        mutex_unlock(&g_core_mu);
        return 0;
    }
    /* Auto: simplefb (bootloader-lit, zero programming) first, then
     * DECON raw probe (fail-closed), then DRM discovery. First success
     * wins; nothing retained on failure (each open cleans itself). */
    for (i = 0; i < sizeof(wuwa_backends) / sizeof(wuwa_backends[0]); i++) {
        be = wuwa_backends[i];
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
            wuwa_raster_clear(g_core.front, width, height, 0x00000000u);
            wuwa_raster_clear(g_core.back, width, height, 0x00000000u);
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

int wuwa_core_uninstall(void)
{
    mutex_lock(&g_core_mu);
    if (!g_core.be) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    if (g_core.be->close)
        g_core.be->close();
    if (g_core.front)
        vfree(g_core.front);
    if (g_core.back)
        vfree(g_core.back);
    g_core.front = g_core.back = NULL;
    g_core.w = g_core.h = 0;
    g_core.be = NULL;
    g_core.dirty.valid = false;
    mutex_unlock(&g_core_mu);
    return 0;
}

int wuwa_core_active(void)
{
    int a;
    mutex_lock(&g_core_mu);
    a = g_core.be ? 1 : 0;
    mutex_unlock(&g_core_mu);
    return a;
}

int wuwa_core_status(__u32 *backend, __u32 *w, __u32 *h, __u32 *err)
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

int wuwa_core_frame(const struct wuwa_disp_op *ops, __u32 count)
{
    __u32 i;
    __u32 *tmp;
    int rc = 0;

    if (!ops)
        return -EINVAL;
    if (count > WUWA_DISP_MAX_OPS)
        count = WUWA_DISP_MAX_OPS;
    mutex_lock(&g_core_mu);
    if (!g_core.be || !g_core.front || !g_core.back) {
        mutex_unlock(&g_core_mu);
        return -ENODEV;
    }
    for (i = 0; i < count; i++) {
        switch (ops[i].op) {
        case WUWA_DISP_CLEAR:
            wuwa_raster_clear(g_core.back, g_core.w, g_core.h,
                              ops[i].color);
            wuwa_dirty_add(0, 0, g_core.w, g_core.h);
            break;
        case WUWA_DISP_RECT:
            wuwa_raster_rect(g_core.back, g_core.w, g_core.h,
                             ops[i].x, ops[i].y, ops[i].w, ops[i].h,
                             ops[i].color);
            wuwa_dirty_add(ops[i].x, ops[i].y, ops[i].w, ops[i].h);
            break;
        case WUWA_DISP_LINE:
            wuwa_raster_line(g_core.back, g_core.w, g_core.h,
                             ops[i].x, ops[i].y, ops[i].w, ops[i].h,
                             ops[i].color);
            wuwa_dirty_add(ops[i].x < ops[i].w ? ops[i].x : ops[i].w,
                           ops[i].y < ops[i].h ? ops[i].y : ops[i].h,
                           ops[i].x < ops[i].w ? ops[i].w - ops[i].x + 8 :
                                                 ops[i].x - ops[i].w + 8,
                           ops[i].y < ops[i].h ? ops[i].h - ops[i].y + 8 :
                                                 ops[i].y - ops[i].h + 8);
            break;
        case WUWA_DISP_GLYPH:
            wuwa_raster_glyph(g_core.back, g_core.w, g_core.h,
                              ops[i].x, ops[i].y, ops[i].glyph,
                              ops[i].color);
            wuwa_dirty_add(ops[i].x, ops[i].y, 8, 8);
            break;
        case WUWA_DISP_NOP:
        default:
            break;
        }
    }
    /* Flip: front becomes the stable snapshot for present. */
    tmp = g_core.front;
    g_core.front = g_core.back;
    g_core.back = tmp;
    if (g_core.be->present)
        rc = g_core.be->present(g_core.front, g_core.w, g_core.h,
                                &g_core.dirty);
    g_core.dirty.valid = false;
    mutex_unlock(&g_core_mu);
    return rc;
}
