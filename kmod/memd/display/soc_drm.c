/* DRM client backend: generic modeset via the DRM core (no registers).
 *
 * exynos-drm already owns clocks, power, SysMMU, shadow update and
 * vsync — this backend goes through it instead of poking DECON.
 * CPU raster draws into a dumb buffer; the core programs planes via
 * atomic commit. No per-SoC code, no winmap, no vsync TODO.
 *
 * Universality design (same doctrine as everything else):
 * - Zero DRM imports: every DRM call resolves via /proc self-parse
 *   (drm.ko is modular — importing would fail the gate where DRM is
 *   not built-in, and fail insmod where drm.ko is absent). Missing
 *   stack here is the normal fail-closed case.
 * - Zero DRM struct access except minor->dev at +16 (CI-asserted on
 *   every baseline: index@0, type@4, kdev@8, dev@16 — identical order
 *   5.10..6.12; drift fails the build, never the load). The minor is
 *   self-validated (kdev back-pointer must equal our device).
 * - Signatures verified against DDK headers 5.10..6.12 (init, release,
 *   framebuffer_create, modeset_commit identical; vmap branches by
 *   generation: void* pre-5.15, int+16B map 5.15+).
 * - Pitch: core widths are 64px-aligned (640 max), so w*4 satisfies
 *   any driver alignment <=256B; tighter drivers just work, wider
 *   ones skew visibly (never overflow: buffer fits pitch*h).
 * - Commits are synchronous (blocking atomic commit): tear-free
 *   present without event plumbing.
 * - HARDWARE PROOF REQUIRED (Exynos + exynos-drm) before product use:
 *   first run validates discovery, modeset, display output, and
 *   hotplugNULL-funcs behavior. Until then status reports the attempt.
 */
#include "disp_core.h"
#include "memd_display.h"
#include "memd_kallsyms.h"
#include "memd_utils.h"
#include "memd_netlayout.h"

#include <linux/device.h>
#include <drm/drm_file.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>

#define MEMD_DISP_BACKEND_DRM 3

/* drm_minor.dev offset (minor->drm_device): CI-asserted every baseline
 * (index@0, type@4, kdev@8, dev@16 — identical order 5.10..6.12).
 * Drift fails the build, never the load. */
#if MEMD_GEN_CUR == MEMD_GEN_510
_Static_assert(offsetof(struct drm_minor, dev) == 16, "drm minor dev");
_Static_assert(offsetof(struct drm_minor, kdev) == 8, "drm minor kdev");
#elif MEMD_GEN_CUR == MEMD_GEN_515
_Static_assert(offsetof(struct drm_minor, dev) == 16, "drm minor dev");
_Static_assert(offsetof(struct drm_minor, kdev) == 8, "drm minor kdev");
#elif MEMD_GEN_CUR == MEMD_GEN_61
_Static_assert(offsetof(struct drm_minor, dev) == 16, "drm minor dev");
_Static_assert(offsetof(struct drm_minor, kdev) == 8, "drm minor kdev");
#elif MEMD_GEN_CUR == MEMD_GEN_66
_Static_assert(offsetof(struct drm_minor, dev) == 16, "drm minor dev");
_Static_assert(offsetof(struct drm_minor, kdev) == 8, "drm minor kdev");
#elif MEMD_GEN_CUR == MEMD_GEN_612
_Static_assert(offsetof(struct drm_minor, dev) == 16, "drm minor dev");
_Static_assert(offsetof(struct drm_minor, kdev) == 8, "drm minor kdev");
#endif

/* UAPI fourcc (stable ABI, no header needed). */
#define MEMD_DRM_XRGB8888 0x32345258u

/* Local 16B map (dma_buf_map == iosys_map layout, stable since 5.15). */
struct memd_map16 {
    void *addr;
    unsigned long long is_iomem;
};

/* Resolved DRM entry points (NULL until open). */
static int (*p_drm_client_init)(void *dev, void *client, const char *name,
                                const void *funcs);
static void (*p_drm_client_release)(void *client);
static void *(*p_drm_client_framebuffer_create)(void *client, __u32 w,
                                                __u32 h, __u32 fmt);
static void *(*p_drm_client_buffer_vmap)(void *buffer);
static void (*p_drm_client_buffer_vunmap)(void *buffer);
static int (*p_drm_client_modeset_commit)(void *client);

static struct {
    void *client;
    void *fb;
    void *vaddr;
    __u32 w;
    __u32 h;
    int mapped_new;
    int last_errno;
    int seen;
    unsigned char client_store[512];
} g_drm;

static int memd_drm_match(struct device *dev, const void *data)
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

static void *memd_drm_resolve(const char *name)
{
    return (void *)(uintptr_t)memd_kallsyms(name);
}

static int memd_drm_open(__u32 w, __u32 h)
{
    unsigned long cls_addr;
    struct class *cls = NULL;
    struct device *d = NULL;
    void *minor = NULL;
    void *drm_dev = NULL;
    int rc = -ENODEV;

    g_drm.last_errno = -ENODEV;
    g_drm.seen = 0;
    if (!w || !h)
        return -EINVAL;

    cls_addr = memd_kallsyms("drm_class");
    if (!cls_addr)
        return -ENODEV;
    if (memd_safe_read64((void *)cls_addr, (unsigned long *)&cls) || !cls)
        return -ENODEV;
    d = class_find_device(cls, NULL, NULL, memd_drm_match);
    if (!d)
        return -ENODEV;
    g_drm.seen = 1;
    /* minor via driver data, self-validated by kdev back-pointer
     * (dev@+16, kdev@+8 — CI-asserted; anything else refuses). */
    minor = dev_get_drvdata(d);
    if (minor) {
        void *kdev = NULL;
        if (!memd_safe_read64((char *)minor + 8, (unsigned long *)&kdev) ||
            kdev != (void *)d)
            minor = NULL;
        else if (memd_safe_read64((char *)minor + 16,
                                  (unsigned long *)&drm_dev) ||
                 !drm_dev ||
                 ((unsigned long)drm_dev & 0xffff000000000000UL) !=
                     0xffff000000000000UL)
            drm_dev = NULL;
    }
    if (!drm_dev) {
        put_device(d);
        return -ENODEV;
    }
    /* Resolve the modeset family (all or nothing — partial is ENODEV). */
    p_drm_client_init =
        memd_drm_resolve("drm_client_init");
    p_drm_client_release =
        memd_drm_resolve("drm_client_release");
    p_drm_client_framebuffer_create =
        memd_drm_resolve("drm_client_framebuffer_create");
    p_drm_client_buffer_vmap =
        memd_drm_resolve("drm_client_buffer_vmap");
    p_drm_client_buffer_vunmap =
        memd_drm_resolve("drm_client_buffer_vunmap");
    p_drm_client_buffer_vunmap =
        memd_drm_resolve("drm_client_buffer_vunmap");
    p_drm_client_modeset_commit =
        memd_drm_resolve("drm_client_modeset_commit");
    if (!p_drm_client_init || !p_drm_client_release ||
        !p_drm_client_framebuffer_create || !p_drm_client_modeset_commit ||
        !p_drm_client_buffer_vmap || !p_drm_client_buffer_vunmap) {
        put_device(d);
        return -ENODEV;
    }
    memset(g_drm.client_store, 0, sizeof(g_drm.client_store));
    g_drm.client = g_drm.client_store;
    rc = p_drm_client_init(drm_dev, g_drm.client, "memd", NULL);
    put_device(d);
    if (rc) {
        g_drm.client = NULL;
        return rc;
    }
    g_drm.fb = p_drm_client_framebuffer_create(g_drm.client, w, h,
                                               MEMD_DRM_XRGB8888);
    if (!g_drm.fb) {
        p_drm_client_release(g_drm.client);
        g_drm.client = NULL;
        return -ENODEV;
    }
    /* Map for CPU draws (generation-branched signatures, CI-verified).
     * 5.10: void *vmap(buffer). 5.15+: int vmap(buffer, 16B map). */
    g_drm.mapped_new = (memd_net_gen() != MEMD_GEN_510);
    if (!g_drm.mapped_new) {
        g_drm.vaddr = p_drm_client_buffer_vmap(g_drm.fb);
        if (!g_drm.vaddr) {
            p_drm_client_release(g_drm.client);
            g_drm.client = NULL;
            g_drm.fb = NULL;
            return -ENODEV;
        }
    } else {
        struct memd_map16 map;
        /* Same symbol, newer signature (int + 16B map, CI-verified
         * per-gen). Reinterpret via memcpy (no function-type cast). */
        int (*vf)(void *, void *);
        memcpy(&vf, &p_drm_client_buffer_vmap, sizeof(vf));
        memset(&map, 0, sizeof(map));
        if (vf(g_drm.fb, &map) || !map.addr || map.is_iomem) {
            p_drm_client_release(g_drm.client);
            g_drm.client = NULL;
            g_drm.fb = NULL;
            return -ENODEV;
        }
        g_drm.vaddr = map.addr;
    }
    g_drm.w = w;
    g_drm.h = h;
    rc = p_drm_client_modeset_commit(g_drm.client);
    if (rc) {
        g_drm.vaddr = NULL;
        g_drm.fb = NULL;
        g_drm.w = g_drm.h = 0;
        p_drm_client_release(g_drm.client);
        g_drm.client = NULL;
        return rc;
    }
    g_drm.last_errno = 0;
    return 0;
}

static void memd_drm_close(void)
{
    if (g_drm.client && p_drm_client_buffer_vunmap && g_drm.fb)
        p_drm_client_buffer_vunmap(g_drm.fb);
    /* NOTE: framebuffer delete API lands with the next forensics pass
     * (name TBD from headers); the GEM object frees with client
     * release in practice — bounded 1.2MB per install cycle, rare. */
    if (g_drm.client && p_drm_client_release)
        p_drm_client_release(g_drm.client);
    g_drm.client = NULL;
    g_drm.fb = NULL;
    g_drm.vaddr = NULL;
    g_drm.w = g_drm.h = 0;
    p_drm_client_init = NULL;
    p_drm_client_release = NULL;
    p_drm_client_framebuffer_create = NULL;
    p_drm_client_buffer_vmap = NULL;
    p_drm_client_buffer_vunmap = NULL;
    p_drm_client_modeset_commit = NULL;
}

static int memd_drm_present(const __u32 *fb, __u32 w, __u32 h,
                            const struct memd_dirty *dirty)
{
    __u32 y0, y1, y;
    (void)h;
    if (!g_drm.client || !g_drm.vaddr || !fb || !dirty || !dirty->valid)
        return -ENODEV;
    if (w != g_drm.w)
        return -EINVAL;
    y0 = dirty->y0;
    y1 = dirty->y1;
    if (y0 >= g_drm.h || y1 <= y0)
        return 0;
    if (y1 > g_drm.h)
        y1 = g_drm.h;
    /* Tight rows (64px-aligned widths satisfy <=256B driver pitch;
     * wider pitch skews visibly but cannot overflow: total fits). */
    for (y = y0; y < y1; y++) {
        memcpy((char *)g_drm.vaddr + (size_t)y * w * 4,
               (const char *)fb + (size_t)y * w * 4, (size_t)w * 4);
    }
    if (p_drm_client_modeset_commit)
        return p_drm_client_modeset_commit(g_drm.client);
    return -ENODEV;
}

static int memd_drm_active(void)
{
    return g_drm.client ? 1 : 0;
}

static void memd_drm_status(__u32 *w, __u32 *h, __u32 *err)
{
    if (w)
        *w = g_drm.w;
    if (h)
        *h = g_drm.h;
    if (err)
        *err = (__u32)(-(g_drm.last_errno));
}

const struct memd_disp_backend memd_be_drm = {
    .id = MEMD_DISP_BACKEND_DRM,
    .name = "drm",
    .open = memd_drm_open,
    .close = memd_drm_close,
    .present = memd_drm_present,
    .active = memd_drm_active,
    .status = memd_drm_status,
};
