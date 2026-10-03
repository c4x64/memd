/* DRM client backend: discovery only (modeset needs hardware proof).
 *
 * Direction (owner-ordered): be a DRM client instead of a register
 * driver. exynos-drm already knows clocks, power, SysMMU, shadow
 * update and vsync; a second driver poking DECON would conflict with
 * it (claimed regions, double power handling, register fights). The
 * CPU raster draws into a dumb buffer and DRM core programs planes
 * via atomic commit — no guessed offsets, no empty winmap, no vsync
 * TODO. Per-SoC code becomes one generic backend.
 *
 * This commit wires DISCOVERY ONLY (stable core APIs, zero DRM struct
 * access): resolve drm_class, find a card* device, report presence.
 * Modeset/commit (drm_client_init, framebuffer_create, modeset_commit
 * via kallsyms, no imports) lands next with CI header-signature dumps
 * in hand + Exynos+DRM hardware proof. open() refuses until then
 * (distinct log; status carries ENODEV). Fail-closed here (no DRM on
 * dummy-virt), zero crash surface anywhere (no struct access, no
 * calls made until proven).
 */
#include "disp_core.h"
#include "wuwa_display.h"
#include "wuwa_kallsyms.h"
#include "wuwa_utils.h"

#include <linux/device.h>
#include <linux/string.h>
#include <linux/kernel.h>

#define WUWA_DISP_BACKEND_DRM 3

static struct {
    int seen;
    int last_errno;
} g_drm;

static int wuwa_drm_match(struct device *dev, const void *data)
{
    const char *n;
    (void)data;
    n = dev_name(dev);
    if (!n)
        return 0;
    if (!strncmp(n, "card", 4))
        return 1;
    return 0;
}

static int wuwa_drm_open(__u32 w, __u32 h)
{
    struct device *d = NULL;
    (void)w;
    (void)h;
    g_drm.last_errno = -ENODEV;
    g_drm.seen = 0;
    /* drm_class lives in drm.ko (modular): resolve at runtime, never
     * import (import would fail the gate where DRM is not built-in,
     * and fail insmod where drm.ko is absent). Missing stack here is
     * the normal fail-closed case (simplefb/DECON next). */
    {
        unsigned long cls_addr = wuwa_kallsyms("drm_class");
        struct class *cls = NULL;
        if (!cls_addr)
            return -ENODEV;
        if (wuwa_safe_read64((void *)cls_addr, (unsigned long *)&cls) ||
            !cls)
            return -ENODEV;
        d = class_find_device(cls, NULL, NULL, wuwa_drm_match);
    }
    if (!d)
        return -ENODEV;
    g_drm.seen = 1;
    put_device(d);
    /* Modeset path pending Exynos+DRM hardware proof (next commit with
     * header-verified signatures). Presence detection is real and
     * useful (routes auto-order); programming refused until proven. */
    return -ENODEV;
}

static void wuwa_drm_close(void)
{
}

static int wuwa_drm_present(const __u32 *fb, __u32 w, __u32 h,
                            const struct wuwa_dirty *dirty)
{
    (void)fb;
    (void)w;
    (void)h;
    (void)dirty;
    return -ENODEV;
}

static int wuwa_drm_active(void)
{
    return 0;
}

static void wuwa_drm_status(__u32 *w, __u32 *h, __u32 *err)
{
    if (w)
        *w = 0;
    if (h)
        *h = 0;
    if (err)
        *err = (__u32)(-(g_drm.last_errno));
}

const struct wuwa_disp_backend wuwa_be_drm = {
    .id = WUWA_DISP_BACKEND_DRM,
    .name = "drm",
    .open = wuwa_drm_open,
    .close = wuwa_drm_close,
    .present = wuwa_drm_present,
    .active = wuwa_drm_active,
    .status = wuwa_drm_status,
};
