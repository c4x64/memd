#ifndef WUWA_DISPLAY_H
#define WUWA_DISPLAY_H

/* Kernel display facility: CPU raster + per-SoC overlay-plane backend.
 *
 * Owner override permits inline hooks ONLY for this facility (and process
 * hiding). Rules, enforced here, not documented elsewhere:
 * - Everything is numeric: draw ops carry widget IDs, rects, colors,
 *   glyph indices. No strings, no labels, no layout content in git.
 * - Per-site fail-closed: backend probes its controller (DTB compatible
 *   + register readback). Unknown controller -> explicit NO-GO, install
 *   refused, module still serves R/W (display is never load-bearing).
 * - Verify-before-patch + restore-on-exit: every controller register
 *   write is read back; uninstall/rmmod restores original window state.
 *   A dangling programmed plane after unload would wedge the display.
 * - One overlay window only, and only when firmware left it disabled.
 *   A window already owned by the OS compositor is never touched.
 *
 * Frame pacing: programmed on FRAME submit (tearing possible). A vsync
 * source per SoC is a tracked TODO; no vsync is ever guessed.
 */

#include <linux/types.h>

struct wuwa_disp_status_cmd {
    __u32 active;   /* Output: 1 when a backend is installed */
    __u32 backend;  /* Output: backend id (0 = none) */
    __u32 width;    /* Output: framebuffer width */
    __u32 height;   /* Output: framebuffer height */
    __u32 errno_;   /* Output: last install errno (0 = none) */
};

struct wuwa_disp_install_cmd {
    __u32 backend;  /* Input: 0 = auto (DTB match), else backend id */
    __u32 width;    /* Input: requested width (clamped to backend max) */
    __u32 height;   /* Input: requested height (clamped to backend max) */
    __u32 rc;       /* Output: 0 ok, else -errno */
};

/* Numeric draw ops. Coordinates are framebuffer pixels. Color is
 * ARGB8888. Glyph is a printable-ASCII index (32..126). */
#define WUWA_DISP_CLEAR  0  /* color = clear color */
#define WUWA_DISP_RECT   1  /* x,y,w,h,color */
#define WUWA_DISP_LINE   2  /* x,y -> w,h endpoints, color */
#define WUWA_DISP_GLYPH  3  /* glyph index at x,y in color on transparent bg */
#define WUWA_DISP_NOP    4

struct wuwa_disp_op {
    __u32 op;
    __u32 x;
    __u32 y;
    __u32 w;
    __u32 h;
    __u32 color;
    __u32 glyph;
};

#define WUWA_DISP_MAX_OPS 1024

/* UI dimensions cap (bounded shadow memory + blit/upload cost).
 * Fullscreen needs a plane/DRM modeset, not a bigger shadow. */
#define WUWA_DISP_MAX_W 640
#define WUWA_DISP_MAX_H 480

struct wuwa_disp_frame_cmd {
    __u64 ops;      /* Input: userspace pointer to wuwa_disp_op array */
    __u32 count;    /* Input: op count (capped at WUWA_DISP_MAX_OPS) */
    __u32 rc;       /* Output: 0 ok, else -errno */
};

#ifdef WUWA_DISP_TEST
/* TEST ONLY (never ship): read back the front buffer for host-side
 * pixel verification (no panel hardware needed). Product builds omit
 * the opcode entirely (dispatch returns ENOTTY). */
struct wuwa_disp_readback_cmd {
    __u64 dst;      /* Input: userspace pointer for ARGB8888 pixels */
    __u32 size;     /* Input: dst capacity in bytes */
    __u32 rc;       /* Output: 0 ok, else -errno */
    __u32 w;        /* Output: framebuffer width */
    __u32 h;        /* Output: framebuffer height */
};

int wuwa_disp_readback(__u64 dst, __u32 size, __u32 *w, __u32 *h);
#endif

int wuwa_disp_install(__u32 backend, __u32 width, __u32 height);
int wuwa_disp_uninstall(void);
int wuwa_disp_active(void);
int wuwa_disp_status(struct wuwa_disp_status_cmd *out);
int wuwa_disp_frame(const struct wuwa_disp_op *ops, __u32 count);

#endif /* WUWA_DISPLAY_H */
