/* RAM backend (TEST ONLY): present into a vmalloc buffer, no hardware.
 *
 * Purpose: prove the ko raster pipeline (ops -> raster -> double-buffer
 * -> dirty -> present) on hardware without a panel, with pixels verified
 * host-side via the TEST readback opcode. No DT, no registers, no DMA,
 * no clocks: cannot wedge anything (there is nothing to wedge).
 * Never shipped (gated by WUWA_DISP_TEST with the readback opcode).
 */
#ifdef WUWA_DISP_TEST

#include "disp_core.h"
#include "wuwa_display.h"

#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/overflow.h>

#define WUWA_DISP_BACKEND_RAM 4

static struct {
    __u32 *fb;
    __u32 w;
    __u32 h;
} g_ram;

static int wuwa_ram_open(__u32 w, __u32 h)
{
    size_t px = 0, bytes = 0;
    if (!w || !h)
        return -EINVAL;
    if (check_mul_overflow((size_t)w, (size_t)h, &px) ||
        check_mul_overflow(px, (size_t)4, &bytes) || !bytes)
        return -EINVAL;
    g_ram.fb = vmalloc(bytes);
    if (!g_ram.fb)
        return -ENOMEM;
    memset(g_ram.fb, 0, bytes);
    g_ram.w = w;
    g_ram.h = h;
    return 0;
}

static void wuwa_ram_close(void)
{
    if (g_ram.fb)
        vfree(g_ram.fb);
    g_ram.fb = NULL;
    g_ram.w = g_ram.h = 0;
}

static int wuwa_ram_present(const __u32 *fb, __u32 w, __u32 h,
                            const struct wuwa_dirty *dirty)
{
    __u32 y0, y1, y;
    if (!g_ram.fb || !fb || !dirty || !dirty->valid)
        return -ENODEV;
    if (w != g_ram.w || h != g_ram.h)
        return -EINVAL;
    y0 = dirty->y0;
    y1 = dirty->y1;
    if (y0 >= h || y1 <= y0)
        return 0;
    if (y1 > h)
        y1 = h;
    for (y = y0; y < y1; y++) {
        memcpy((char *)g_ram.fb + (size_t)y * w * 4,
               (const char *)fb + (size_t)y * w * 4, (size_t)w * 4);
    }
    return 0;
}

static int wuwa_ram_active(void)
{
    return g_ram.fb ? 1 : 0;
}

static void wuwa_ram_status(__u32 *w, __u32 *h, __u32 *err)
{
    if (w)
        *w = g_ram.w;
    if (h)
        *h = g_ram.h;
    if (err)
        *err = 0;
}

const struct wuwa_disp_backend wuwa_be_ram = {
    .id = WUWA_DISP_BACKEND_RAM,
    .name = "ram",
    .open = wuwa_ram_open,
    .close = wuwa_ram_close,
    .present = wuwa_ram_present,
    .active = wuwa_ram_active,
    .status = wuwa_ram_status,
};

#endif /* WUWA_DISP_TEST */
