#ifndef MEMD_DISP_CORE_H
#define MEMD_DISP_CORE_H

/* Display core: double-buffered CPU raster + dirty tracking + submit
 * serialization, shared by all backends (simplefb blit, DRM upload,
 * DECON probe-only rasterize). Backends present the FRONT buffer (stable
 * snapshot); drawing always targets BACK then flips. Dimensions capped
 * at MEMD_DISP_MAX_* (bounded memory + blit cost; fullscreen needs a
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

#include "memd_display.h"

struct memd_dirty {
    __u32 x0;
    __u32 y0;
    __u32 x1;
    __u32 y1;
    bool valid;
};

struct memd_disp_backend {
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
                   const struct memd_dirty *dirty);
    int (*active)(void);
    void (*status)(__u32 *w, __u32 *h, __u32 *err);
    /* Refresh need: backend whose display can be overwritten behind
     * its back (fbcon on simplefb) sets true; core re-presents the
     * stable front at MEMD_DISP_REFRESH_MS. DRM (commit persists) and
     * probe-only/RAM leave false. */
    bool refresh;
};

/* Refresh period (simplefb heartbeat vs fbcon overwrites). Present on
 * submit stays immediate; this only repaints persistence. */
#define MEMD_DISP_REFRESH_MS 100

/* TODO(display): facility parked — complete but unwired. Backends
 * (exynos/DECON probe, simplefb, DRM client, RAM), the refresh thread,
 * the VNC tap and the readback opcode are all implemented and stay
 * compile-checked, but install refuses until this is flipped. The rest
 * of the core needs no changes: with install refusing, no backend ever
 * activates, no thread ever spawns, and status/frame/readback report
 * inactive. Set to 0 to activate. */
#define MEMD_DISP_TODO 1

int memd_core_install(__u32 backend, __u32 width, __u32 height);
int memd_core_uninstall(void);
int memd_core_active(void);
int memd_core_status(__u32 *backend, __u32 *w, __u32 *h, __u32 *err);
int memd_core_frame(const struct memd_disp_op *ops, __u32 count);

#ifdef MEMD_DISP_TEST
int memd_core_readback(__u64 dst, __u32 size, __u32 *w, __u32 *h);
int memd_core_copy_front(__u32 *dst, __u32 max_bytes, __u32 *w, __u32 *h);
void memd_vnc_start(void);
void memd_vnc_stop(void);
#endif

#endif /* MEMD_DISP_CORE_H */
