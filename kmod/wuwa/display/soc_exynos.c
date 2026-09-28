/* Exynos DECON overlay-plane backend.
 *
 * Probe-only until a per-SoC window register map is verified on real
 * hardware: programming an overlay plane through guessed offsets would
 * wedge the display, so install FAILS CLOSED with -ENODEV naming the
 * DTB compatible. What IS implemented and verified:
 * - DTB match on samsung,exynos-decon* compatibles (no hardcoded base).
 * - Register mapping via the DTB reg range + readback sanity (a global
 *   control word of all-0/all-1 refuses: mapping is wrong or the
 *   controller is gated).
 * - Framebuffer allocation via dma_alloc_coherent on the DECON device.
 * - Full status surface (backend id, dimensions, last errno).
 *
 * Enabling a new SoC: verify its window-map on hardware, add the map to
 * the table below with the exact compatible string, and only then allow
 * plane programming for that entry. Never guess.
 */
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include "wuwa_display.h"
#include "wuwa_raster.h"

#define WUWA_DISP_BACKEND_EXYNOS 1
#define WUWA_DISP_MAX_W 640
#define WUWA_DISP_MAX_H 480

struct wuwa_decon_state {
    struct device *dev;
    void __iomem *regs;
    resource_size_t regs_size;
    __u32 *fb_virt;
    dma_addr_t fb_phys;
    size_t fb_size;
    __u32 width;
    __u32 height;
    int last_errno;
    char compat[64];
};

static struct wuwa_decon_state g_decon;

/* Verified per-SoC window maps. Empty until hardware-verified. */
struct wuwa_winmap {
    const char *compat;
    __u32 wincon_off;   /* window control register offset */
    __u32 win_en_bit;   /* enable bit within WINCON */
    __u32 addr_off;     /* framebuffer address register offset */
    __u32 size_off;     /* window size register offset */
};

static const struct wuwa_winmap wuwa_winmaps[] = {
    /* No entries: every controller is NO-GO until verified on hardware. */
};

int wuwa_decon_probe(void)
{
    struct device_node *np = NULL;
    struct platform_device *pdev;
    const struct wuwa_winmap *map = NULL;
    unsigned long i;
    __u32 probe0, probe1;

    /* Match any Exynos DECON compatible; record the exact string. */
    np = of_find_compatible_node(NULL, NULL, "samsung,exynos-decon");
    if (!np)
        return -ENODEV;
    {
        const char *c = NULL;
        if (of_property_read_string(np, "compatible", &c) == 0 && c) {
            size_t n = strlen(c);
            if (n >= sizeof(g_decon.compat))
                n = sizeof(g_decon.compat) - 1;
            memcpy(g_decon.compat, c, n);
            g_decon.compat[n] = '\0';
        }
    }

    pdev = of_find_device_by_node(np);
    if (!pdev) {
        of_node_put(np);
        return -ENODEV;
    }
    g_decon.dev = &pdev->dev;

    g_decon.regs = of_iomap(np, 0);
    of_node_put(np);
    if (!g_decon.regs)
        return -ENODEV;

    /* Readback sanity: two words must be neither all-0 nor all-1
     * (wrong mapping or gated controller). */
    /* Volatile dereference (not readl/__raw_readl): MMIO wrappers pull
     * version-specific trace imports (__log_read_mmio on some baselines,
     * log_read_mmio on others) that vendor kernels may not export. A
     * volatile load + dsb is stable on every baseline and correct for
     * probe reads. */
    probe0 = *(volatile __u32 *)g_decon.regs;
    asm volatile("dsb ish" ::: "memory");
    probe1 = *(volatile __u32 *)(g_decon.regs + 4);
    asm volatile("dsb ish" ::: "memory");
    if ((probe0 == 0 && probe1 == 0) ||
        (probe0 == 0xFFFFFFFFu && probe1 == 0xFFFFFFFFu)) {
        iounmap(g_decon.regs);
        g_decon.regs = NULL;
        return -ENODEV;
    }

    /* No verified window map for this compatible -> NO-GO by policy. */
    for (i = 0; i < sizeof(wuwa_winmaps) / sizeof(wuwa_winmaps[0]); i++) {
        if (!strcmp(g_decon.compat, wuwa_winmaps[i].compat)) {
            map = &wuwa_winmaps[i];
            break;
        }
    }
    if (!map) {
        iounmap(g_decon.regs);
        g_decon.regs = NULL;
        return -ENODEV;
    }
    return 0;
}

int wuwa_disp_install(__u32 backend, __u32 width, __u32 height)
{
    size_t want;

    if (g_decon.fb_virt)
        return -EBUSY;
    if (backend != 0 && backend != WUWA_DISP_BACKEND_EXYNOS)
        return -ENODEV;
    if (width == 0 || height == 0)
        return -EINVAL;
    if (width > WUWA_DISP_MAX_W)
        width = WUWA_DISP_MAX_W;
    if (height > WUWA_DISP_MAX_H)
        height = WUWA_DISP_MAX_H;

    if (wuwa_decon_probe()) {
        g_decon.last_errno = -ENODEV;
        return -ENODEV;
    }

    want = (size_t)width * (size_t)height * 4;
    g_decon.fb_virt = dma_alloc_coherent(g_decon.dev, want,
                                         &g_decon.fb_phys, GFP_KERNEL);
    if (!g_decon.fb_virt) {
        iounmap(g_decon.regs);
        g_decon.regs = NULL;
        g_decon.last_errno = -ENOMEM;
        return -ENOMEM;
    }
    g_decon.fb_size = want;
    g_decon.width = width;
    g_decon.height = height;
    g_decon.last_errno = 0;
    wuwa_raster_clear(g_decon.fb_virt, width, height, 0x00000000u);
    return 0;
}

int wuwa_disp_uninstall(void)
{
    if (!g_decon.fb_virt)
        return -ENODEV;
    /* Window restore happens here once a winmap exists (disable the
     * overlay window first, then free). Probe-only today: nothing
     * programmed, so just release. */
    if (g_decon.regs) {
        iounmap(g_decon.regs);
        g_decon.regs = NULL;
    }
    dma_free_coherent(g_decon.dev, g_decon.fb_size,
                      g_decon.fb_virt, g_decon.fb_phys);
    g_decon.fb_virt = NULL;
    g_decon.fb_size = 0;
    g_decon.width = 0;
    g_decon.height = 0;
    return 0;
}

int wuwa_disp_active(void)
{
    return g_decon.fb_virt ? 1 : 0;
}

int wuwa_disp_status(struct wuwa_disp_status_cmd *out)
{
    if (!out)
        return -EINVAL;
    out->active = g_decon.fb_virt ? 1 : 0;
    out->backend = g_decon.fb_virt ? WUWA_DISP_BACKEND_EXYNOS : 0;
    out->width = g_decon.width;
    out->height = g_decon.height;
    out->errno_ = (__u32)(-(g_decon.last_errno));
    return 0;
}

int wuwa_disp_frame(const struct wuwa_disp_op *ops, __u32 count)
{
    __u32 i;

    if (!g_decon.fb_virt)
        return -ENODEV;
    if (!ops)
        return -EINVAL;
    if (count > WUWA_DISP_MAX_OPS)
        count = WUWA_DISP_MAX_OPS;
    for (i = 0; i < count; i++) {
        switch (ops[i].op) {
        case WUWA_DISP_CLEAR:
            wuwa_raster_clear(g_decon.fb_virt, g_decon.width,
                              g_decon.height, ops[i].color);
            break;
        case WUWA_DISP_RECT:
            wuwa_raster_rect(g_decon.fb_virt, g_decon.width,
                             g_decon.height, ops[i].x, ops[i].y,
                             ops[i].w, ops[i].h, ops[i].color);
            break;
        case WUWA_DISP_LINE:
            wuwa_raster_line(g_decon.fb_virt, g_decon.width,
                             g_decon.height, ops[i].x, ops[i].y,
                             ops[i].w, ops[i].h, ops[i].color);
            break;
        case WUWA_DISP_GLYPH:
            wuwa_raster_glyph(g_decon.fb_virt, g_decon.width,
                              g_decon.height, ops[i].x, ops[i].y,
                              ops[i].glyph, ops[i].color);
            break;
        case WUWA_DISP_NOP:
        default:
            break;
        }
    }
    /* Plane programming lands here with the first verified winmap.
     * Until then the framebuffer rasterizes but is never displayed. */
    return 0;
}
