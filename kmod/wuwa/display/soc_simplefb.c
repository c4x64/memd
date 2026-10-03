/* simple-framebuffer backend: bootloader-lit panel, zero programming.
 *
 * If the bootloader lit the display, DT carries a simple-framebuffer
 * node (address, size, stride, format). We draw straight into that
 * buffer: no plane programming, no clocks, no power domains, no
 * controller registers — the safest pixels on an unverified SoC.
 * The DECON raw path then only matters when no lit panel exists.
 *
 * Strict format gate (standard simple-framebuffer binding strings):
 * only 32-bit XRGB/ARGB with R/G/B in our positions (direct copy).
 * Anything else (swapped channels, 16-bit, etc.) refuses — wrong
 * colors are worse than no display. Panel must fit our UI
 * (panel_w/h >= w/h, stride/size validated with overflow checks);
 * we draw top-left w*h, the rest of the panel untouched.
 * Uninstall unmaps only (last frame persists on-panel, harmless —
 * the simplefb driver keeps scanning out; we never owned the pipe).
 */
#include "disp_core.h"
#include "wuwa_display.h"

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/overflow.h>

#define WUWA_DISP_BACKEND_SIMPLEFB 2

static struct {
    void *base;
    size_t size;
    __u32 stride;
    __u32 w;
    __u32 h;
    int last_errno;
} g_sfb;

static int wuwa_sfb_open(__u32 w, __u32 h)
{
    struct device_node *np = NULL;
    const char *fmt = NULL;
    __u32 pw = 0, ph = 0, stride = 0;
    struct resource res;
    size_t need = 0;
    void *base;

    g_sfb.last_errno = -ENODEV;
    np = of_find_compatible_node(NULL, NULL, "simple-framebuffer");
    if (!np)
        return -ENODEV;
    if (!of_device_is_available(np)) {
        of_node_put(np);
        return -ENODEV;
    }
    if (of_property_read_string(np, "format", &fmt) || !fmt) {
        of_node_put(np);
        return -ENODEV;
    }
    if (strcmp(fmt, "x8r8g8b8") && strcmp(fmt, "a8r8g8b8")) {
        of_node_put(np);
        return -ENODEV;
    }
    if (of_property_read_u32(np, "width", &pw) ||
        of_property_read_u32(np, "height", &ph) ||
        of_property_read_u32(np, "stride", &stride) ||
        !pw || !ph || !stride || pw > 4096 || ph > 4096) {
        of_node_put(np);
        return -ENODEV;
    }
    if (pw < w || ph < h) {
        of_node_put(np);
        return -ENODEV;
    }
    if (check_mul_overflow((size_t)stride, (size_t)h, &need) || !need) {
        of_node_put(np);
        return -ENODEV;
    }
    if (of_address_to_resource(np, 0, &res)) {
        of_node_put(np);
        return -ENODEV;
    }
    of_node_put(np);
    if (resource_size(&res) < need)
        return -ENODEV;
    base = memremap(res.start, resource_size(&res), MEMREMAP_WB);
    if (!base)
        return -ENODEV;
    g_sfb.base = base;
    g_sfb.size = (size_t)resource_size(&res);
    g_sfb.stride = stride;
    g_sfb.w = w;
    g_sfb.h = h;
    g_sfb.last_errno = 0;
    return 0;
}

static void wuwa_sfb_close(void)
{
    if (g_sfb.base)
        memunmap(g_sfb.base);
    g_sfb.base = NULL;
    g_sfb.size = 0;
    g_sfb.stride = 0;
    g_sfb.w = 0;
    g_sfb.h = 0;
}

static int wuwa_sfb_present(const __u32 *fb, __u32 w, __u32 h,
                            const struct wuwa_dirty *dirty)
{
    __u32 y0, y1, y;
    if (!g_sfb.base || !fb || !dirty || !dirty->valid)
        return -ENODEV;
    if (w != g_sfb.w || h != g_sfb.h)
        return -EINVAL;
    y0 = dirty->y0;
    y1 = dirty->y1;
    if (y0 >= h || y1 <= y0)
        return 0;
    if (y1 > h)
        y1 = h;
    for (y = y0; y < y1; y++) {
        memcpy((char *)g_sfb.base + (size_t)y * g_sfb.stride,
               (const char *)fb + (size_t)y * w * 4, (size_t)w * 4);
    }
    return 0;
}

static int wuwa_sfb_active(void)
{
    return g_sfb.base ? 1 : 0;
}

static void wuwa_sfb_status(__u32 *w, __u32 *h, __u32 *err)
{
    if (w)
        *w = g_sfb.w;
    if (h)
        *h = g_sfb.h;
    if (err)
        *err = (__u32)(-(g_sfb.last_errno));
}

const struct wuwa_disp_backend wuwa_be_simplefb = {
    .id = WUWA_DISP_BACKEND_SIMPLEFB,
    .name = "simplefb",
    .open = wuwa_sfb_open,
    .close = wuwa_sfb_close,
    .present = wuwa_sfb_present,
    .active = wuwa_sfb_active,
    .status = wuwa_sfb_status,
    /* fbcon / splash / other writers can paint over our region behind
     * our back — core re-presents the stable front at 10Hz. */
    .refresh = true,
};
