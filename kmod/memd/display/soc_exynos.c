/* Exynos DECON backend (probe-only) + memd_disp_* entry points.
 *
 * Hazard-fixed probe (bus hangs are worse than ENODEV): available check
 * -> resource claim (drm conflict fails here, nothing touched) ->
 * clocks by index + power domains -> map -> readback -> full cleanup.
 * Reading a clock/power-gated block can hang the bus or raise SError
 * (not return garbage), so a probe that reads first is never safe.
 * Zero clocks acquired -> readback refused outright (fail closed).
 * Everything acquired is released on every path (probe retains nothing;
 * install re-probes statelessly — install is once-per-boot rare).
 *
 * DMA note: DECON sits behind a SysMMU, so the programmed address must
 * be the DMA/IOVA address from the DECON device, not phys. Allocation
 * uses the DECON platform device with a checked 32-bit mask (fail
 * closed); the per-SoC mask lands with the winmap (TRM). Unreachable
 * today (empty table -> ENODEV before alloc).
 *
 * Window maps come from documentation (Linux exynos-drm DECON driver +
 * vendor TRM: WINCON, buffer start, size, position), confirmed on
 * hardware — never discovered by probing. Each entry carries its
 * silicon revision gate (compatible + version register offset/value:
 * right string on wrong silicon still fails closed) and, when
 * programming lands, shadow-update + frame-done IRQ completion
 * (stage all window regs, latch atomically; vsync TODO hooks there —
 * never raw vsync, never guessed bits/IRQs: confirm names in the TRM
 * for the part at verification time).
 */
#include "disp_core.h"
#include "memd_display.h"
#include "memd_raster.h"

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/pm_runtime.h>
#include <linux/device.h>

#define MEMD_DISP_BACKEND_EXYNOS 1

struct memd_decon_state {
    int last_errno;
    char compat[64];
};

static struct memd_decon_state g_decon;

/* Verified per-SoC window maps. EMPTY until hardware-verified from
 * exynos-drm + TRM (offsets, enable bit, shadow bit, IRQ name, revision
 * register + reset value). No entries: every controller is NO-GO. */
struct memd_winmap {
    const char *compat;
    __u32 rev_off;      /* version register offset */
    __u32 rev_expect;   /* expected reset value */
    __u32 wincon_off;
    __u32 win_en_bit;
    __u32 addr_off;
    __u32 size_off;
    __u32 shadow_off;   /* shadow-update latch register */
    __u32 shadow_bit;   /* latch bit */
    const char *irq_name; /* frame-done/vsync IRQ (TRM name) */
};

static const struct memd_winmap memd_winmaps[] = {
    /* No entries: every controller is NO-GO until verified on hardware. */
};

#define MEMD_DECON_MAX_CLOCKS 8

/* Full probe with hazard ordering. Returns 0 with *map set (never
 * today), negative errno otherwise. Retains nothing on any path. */
static int memd_decon_probe(const struct memd_winmap **map_out)
{
    struct device_node *np = NULL;
    struct platform_device *pdev = NULL;
    struct resource res;
    struct clk *clks[MEMD_DECON_MAX_CLOCKS];
    int nclks = 0;
    void __iomem *regs = NULL;
    __u32 probe0, probe1;
    int i, rc = -ENODEV;
    bool pm_on = false;
    bool claimed = false;

    *map_out = NULL;
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
    if (!of_device_is_available(np)) {
        of_node_put(np);
        return -ENODEV;
    }
    pdev = of_find_device_by_node(np);
    if (!pdev) {
        of_node_put(np);
        return -ENODEV;
    }
    if (of_address_to_resource(np, 0, &res)) {
        goto out_put;
    }
    /* Claim first: a bound exynos-drm fails here cleanly (we touch
     * nothing — no struct device field reads, no register access). */
    if (!request_mem_region(res.start, resource_size(&res),
                            "memd-decon-probe")) {
        rc = -EBUSY;
        goto out_put;
    }
    claimed = true;
    /* Clocks by index (no SoC-specific names — never guess strings). */
    for (i = 0; i < MEMD_DECON_MAX_CLOCKS; i++) {
        struct clk *c = of_clk_get(np, i);
        if (IS_ERR(c))
            break;
        if (clk_prepare_enable(c)) {
            clk_put(c);
            goto out_clocks;
        }
        clks[nclks++] = c;
    }
    if (!nclks) {
        /* No gateable clocks visible: cannot prove the block is
         * powered — refuse the readback rather than risk a bus hang. */
        goto out_release;
    }
    /* Power domains (generic PM, no SoC knowledge). Balanced below. */
    pm_runtime_enable(&pdev->dev);
    if (pm_runtime_get_sync(&pdev->dev) < 0) {
        pm_runtime_put_sync(&pdev->dev);
        pm_runtime_disable(&pdev->dev);
        goto out_clocks;
    }
    pm_on = true;
    regs = ioremap(res.start, resource_size(&res));
    if (!regs)
        goto out_pm;
    /* Volatile loads (no readl/__raw_readl: traced MMIO wrappers pull
     * version-specific imports vendors strip). dsb pairs the reads. */
    probe0 = *(volatile __u32 *)regs;
    asm volatile("dsb ish" ::: "memory");
    probe1 = *(volatile __u32 *)((char *)regs + 4);
    asm volatile("dsb ish" ::: "memory");
    if ((probe0 == 0 && probe1 == 0) ||
        (probe0 == 0xFFFFFFFFu && probe1 == 0xFFFFFFFFu)) {
        goto out_unmap;
    }
    /* Revision gate + winmap match (empty table: always NO-GO today).
     * When entries exist: compat match AND version register match,
     * else refuse (right string, wrong silicon). */
    for (i = 0; i < (int)(sizeof(memd_winmaps) / sizeof(memd_winmaps[0])); i++) {
        __u32 rev;
        if (strcmp(g_decon.compat, memd_winmaps[i].compat))
            continue;
        rev = *(volatile __u32 *)((char *)regs + memd_winmaps[i].rev_off);
        asm volatile("dsb ish" ::: "memory");
        if (rev != memd_winmaps[i].rev_expect)
            continue;
        *map_out = &memd_winmaps[i];
        break;
    }
    iounmap(regs);
    pm_runtime_put_sync(&pdev->dev);
    pm_runtime_disable(&pdev->dev);
    for (i = 0; i < nclks; i++) {
        clk_disable_unprepare(clks[i]);
        clk_put(clks[i]);
    }
    release_mem_region(res.start, resource_size(&res));
    of_node_put(np);
    put_device(&pdev->dev);
    return *map_out ? 0 : -ENODEV;

out_unmap:
    iounmap(regs);
out_pm:
    if (pm_on) {
        pm_runtime_put_sync(&pdev->dev);
        pm_runtime_disable(&pdev->dev);
    }
out_clocks:
    for (i = 0; i < nclks; i++) {
        clk_disable_unprepare(clks[i]);
        clk_put(clks[i]);
    }
out_release:
    if (claimed)
        release_mem_region(res.start, resource_size(&res));
out_put:
    of_node_put(np);
    put_device(&pdev->dev);
    return rc;
}

static int memd_decon_open(__u32 w, __u32 h)
{
    const struct memd_winmap *map = NULL;
    int rc;
    (void)w;
    (void)h;
    g_decon.last_errno = 0;
    rc = memd_decon_probe(&map);
    if (rc) {
        g_decon.last_errno = rc;
        return rc;
    }
    /* A verified map exists (not today): DMA alloc against the DECON
     * device (IOVA, not phys) with checked mask would happen here,
     * then plane programming with shadow-update + IRQ completion.
     * Unreachable with an empty table. */
    g_decon.last_errno = -ENODEV;
    return -ENODEV;
}

static void memd_decon_close(void)
{
    g_decon.last_errno = 0;
}

static int memd_decon_present(const __u32 *fb, __u32 w, __u32 h,
                              const struct memd_dirty *dirty)
{
    /* Probe-only: rasterize only, never display (no map, no plane). */
    (void)fb;
    (void)w;
    (void)h;
    (void)dirty;
    return 0;
}

static int memd_decon_active(void)
{
    return 0;
}

static void memd_decon_status(__u32 *w, __u32 *h, __u32 *err)
{
    if (w)
        *w = 0;
    if (h)
        *h = 0;
    if (err)
        *err = (__u32)(-(g_decon.last_errno));
}

const struct memd_disp_backend memd_be_exynos = {
    .id = MEMD_DISP_BACKEND_EXYNOS,
    .name = "exynos",
    .open = memd_decon_open,
    .close = memd_decon_close,
    .present = memd_decon_present,
    .active = memd_decon_active,
    .status = memd_decon_status,
};

/* Entry points (ioctl layer calls these; signatures unchanged). */
int memd_disp_install(__u32 backend, __u32 width, __u32 height)
{
    return memd_core_install(backend, width, height);
}

int memd_disp_uninstall(void)
{
    int rc = memd_core_uninstall();
    return rc == -ENODEV ? -ENODEV : rc;
}

int memd_disp_active(void)
{
    return memd_core_active();
}

int memd_disp_status(struct memd_disp_status_cmd *out)
{
    __u32 be = 0, w = 0, h = 0, e = 0;
    if (!out)
        return -EINVAL;
    memd_core_status(&be, &w, &h, &e);
    out->active = memd_core_active() ? 1 : 0;
    out->backend = be;
    out->width = w;
    out->height = h;
    out->errno_ = e;
    return 0;
}

int memd_disp_frame(const struct memd_disp_op *ops, __u32 count)
{
    return memd_core_frame(ops, count);
}
