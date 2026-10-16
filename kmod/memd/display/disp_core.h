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
#include <linux/wait.h>
#include <linux/atomic.h>

#include "memd_display.h"

/* Core-internal descriptors (fields from disp_core.c use). Backends only
 * ever see pointers to these, so per-SoC code needs no layout trust. */
struct memd_disp_vsync {
    bool enabled;
    int64_t next_vsync_ns;
    int64_t frame_interval_ns;
    wait_queue_head_t wq;
    atomic_t frame_pending;
};

struct memd_disp_edid {
    __u8 data[256];   /* Raw EDID block bytes */
    __u32 len;        /* Valid bytes in data */
    bool valid;
};

struct memd_disp_mode {
    __u32 w;
    __u32 h;
    __u32 refresh_rate;   /* Hz; core derives frame_interval_ns from it */
};

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
    /* Optional operations below are checked for NULL at every call site.
     * A backend that does not implement one reports -ENOTSUPP or skips it. */
    int (*set_mode)(const struct memd_disp_mode *mode);
    int (*get_modes)(struct memd_disp_mode *modes, __u32 max_modes);
    int (*get_edid)(struct memd_disp_edid *edid);
    int (*dpms)(int mode);
    int (*cursor_set)(const __u32 *cursor_fb, __u32 w, __u32 h, __u32 x, __u32 y);
    int (*cursor_move)(__u32 x, __u32 y);
    int (*cursor_show)(bool show);
    int (*gamma_set)(const __u16 *r, const __u16 *g, const __u16 *b, __u32 size);
    int (*layer_add)(struct memd_disp_layer *layer);
    int (*layer_remove)(struct memd_disp_layer *layer);
    int (*layer_update)(struct memd_disp_layer *layer);
    /* Refresh need: backend whose display can be overwritten behind
     * its back (fbcon on simplefb) sets true; core re-presents the
     * stable front at MEMD_DISP_REFRESH_MS. DRM (commit persists) and
     * probe-only/RAM leave false. */
    bool refresh;
};

/* Refresh period (simplefb heartbeat vs fbcon overwrites). Present on
 * submit stays immediate; this only repaints persistence. */
#define MEMD_DISP_REFRESH_MS 100

/* Facility gate (ex-TODO(display): parked while unwired). Backends
 * (exynos/DECON probe, simplefb, DRM client, RAM), the refresh thread,
 * the VNC tap and the readback opcode are all implemented and stay
 * compile-checked. When 1, install refuses closed (-EOPNOTSUPP): no
 * backend activates, no thread spawns, and status/frame/readback
 * report inactive. Currently 0 (active). */
#define MEMD_DISP_TODO 0

/* Caller-pointer contract for every declaration below that takes a
 * pointer: KERNEL addresses only. The core dereferences / memcpys them
 * directly (cursor pixels, layer buffers, gamma/mode/edid structs, frame
 * ops). The only userspace-reachable paths today (do_disp_install /
 * do_disp_frame via memd_disp_*) bounce through copy_from_user before the
 * core; the TEST-only do_disp_readback passes its destination as a plain
 * integer and the core copies via memd_copy_to_user (never a direct
 * deref). Cursor / layer / gamma / mode / edid helpers have no ioctl
 * wiring at all (no in-tree caller). Any future ioctl wiring for those
 * helpers must copy_from_user into a kernel buffer first — never hand a
 * __user pointer to these entries. */
int memd_core_install(__u32 backend, __u32 width, __u32 height);
int memd_core_uninstall(void);
int memd_core_active(void);
int memd_core_status(__u32 *backend, __u32 *w, __u32 *h, __u32 *err);
int memd_core_frame(const struct memd_disp_op *ops, __u32 count);
int memd_core_set_mode(const struct memd_disp_mode *mode);
int memd_core_get_modes(struct memd_disp_mode *modes, __u32 max_modes);
int memd_core_get_edid(struct memd_disp_edid *edid);
int memd_core_dpms(int mode);
int memd_core_vsync_wait(int64_t timeout_ns);
int memd_core_cursor_set(const __u32 *cursor_fb, __u32 w, __u32 h, __u32 x, __u32 y);
int memd_core_cursor_move(__u32 x, __u32 y);
int memd_core_cursor_show(bool show);
int memd_core_layer_add(struct memd_disp_layer *layer);
int memd_core_layer_remove(struct memd_disp_layer *layer);
int memd_core_layer_update(struct memd_disp_layer *layer);
int memd_core_gamma_set(const __u16 *r, const __u16 *g, const __u16 *b, __u32 size);

#ifdef MEMD_DISP_TEST
int memd_core_readback(__u64 dst, __u32 size, __u32 *w, __u32 *h);
int memd_core_copy_front(__u32 *dst, __u32 max_bytes, __u32 *w, __u32 *h);
void memd_vnc_start(void);
void memd_vnc_stop(void);
#endif

#endif /* MEMD_DISP_CORE_H */
/* kmod/memd/display/disp_core.h[∂] */
