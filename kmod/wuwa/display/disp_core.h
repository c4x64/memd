#ifndef WUWA_DISP_CORE_H
#define WUWA_DISP_CORE_H

/* Display core: double-buffered CPU raster + dirty tracking + submit
 * serialization, shared by all backends (simplefb blit, DRM upload,
 * DECON probe-only rasterize). Backends present the FRONT buffer (stable
 * snapshot); drawing always targets BACK then flips. Dimensions capped
 * at WUWA_DISP_MAX_* (bounded memory + blit cost; fullscreen needs a
 * plane/DRM modeset, not a bigger shadow).
 *
 * All math uses check_mul_overflow (stable linux/overflow.h). Buffers
 * are vmalloc (no device, no DMA). One mutex serializes draw/submit
 * (ioctl process context, sleepable). Glyphs stay our own 8x8 table:
 * kernel lib/fonts (font_8x8) would add a Kconfig dependency that fails
 * universal loads where CONFIG_FONT_8x8=n — dedup is not worth bricking
 * R/W for. Format/layout certainty beats reuse here.
 */
#include <linux/types.h>

#include "wuwa_display.h"

struct wuwa_dirty {
    __u32 x0;
    __u32 y0;
    __u32 x1;
    __u32 y1;
    bool valid;
};

struct wuwa_disp_backend {
    int id;
    const char *name;
    /* Probe + attach for w*h (backend caps applied inside). 0 ok,
     * negative errno (fail closed, nothing retained on failure). */
    int (*open)(__u32 w, __u32 h);
    void (*close)(void);
    /* Present front buffer's dirty region (already flipped + locked by
     * core; backend must not sleep unbounded — vmalloc memcpy and
     * synchronous commits only). */
    int (*present)(const __u32 *fb, __u32 w, __u32 h,
                   const struct wuwa_dirty *dirty);
    int (*active)(void);
    void (*status)(__u32 *w, __u32 *h, __u32 *err);
    /* Refresh need: backend whose display can be overwritten behind
     * its back (fbcon on simplefb) sets true; core re-presents the
     * stable front at WUWA_DISP_REFRESH_MS. DRM (commit persists) and
     * probe-only/RAM leave false. */
    bool refresh;
};

/* Refresh period (simplefb heartbeat vs fbcon overwrites). Present on
 * submit stays immediate; this only repaints persistence. */
#define WUWA_DISP_REFRESH_MS 100

int wuwa_core_install(__u32 backend, __u32 width, __u32 height);
int wuwa_core_uninstall(void);
int wuwa_core_active(void);
int wuwa_core_status(__u32 *backend, __u32 *w, __u32 *h, __u32 *err);
int wuwa_core_frame(const struct wuwa_disp_op *ops, __u32 count);

#ifdef WUWA_DISP_TEST
int wuwa_core_readback(__u64 dst, __u32 size, __u32 *w, __u32 *h);
#endif

#endif /* WUWA_DISP_CORE_H */
