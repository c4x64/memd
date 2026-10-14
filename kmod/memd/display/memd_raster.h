#ifndef MEMD_RASTER_H
#define MEMD_RASTER_H

/* CPU rasterizer: ARGB8888 framebuffer, numeric ops only.
 * No strings, no fonts with meaning — an 8x8 bitmap for printable ASCII
 * so the server-driven layer can address glyphs by index. Clipping is
 * always on; out-of-range ops are skipped, never wrapped. */

#include <linux/types.h>
#include "memd_display.h"

void memd_raster_clear(__u32 *fb, __u32 w, __u32 h, __u32 color);
void memd_raster_rect(__u32 *fb, __u32 w, __u32 h,
                      __u32 x, __u32 y, __u32 rw, __u32 rh, __u32 color);
void memd_raster_line(__u32 *fb, __u32 w, __u32 h,
                      __u32 x0, __u32 y0, __u32 x1, __u32 y1, __u32 color);
void memd_raster_glyph(__u32 *fb, __u32 w, __u32 h,
                       __u32 x, __u32 y, __u32 glyph, __u32 color);

/* Composite operations for layer and cursor support */
void memd_raster_composite_layers(__u32 *fb, __u32 w, __u32 h,
                                  struct memd_disp_layer *layers, __u32 layer_count);
void memd_raster_composite_cursor(__u32 *fb, __u32 w, __u32 h,
                                  const __u32 *cursor_fb, __u32 cw, __u32 ch,
                                  __u32 x, __u32 y);

/* Gamma correction application */
void memd_raster_apply_gamma(__u32 *fb, __u32 w, __u32 h,
                             const __u32 *lut_r, const __u32 *lut_g, const __u32 *lut_b,
                             __u32 size);

#endif /* MEMD_RASTER_H */
/* kmod/memd/display/memd_raster.h[∂] */
