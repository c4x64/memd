#ifndef MEMD_RASTER_H
#define MEMD_RASTER_H

/* CPU rasterizer: ARGB8888 framebuffer, numeric ops only.
 * No strings, no fonts with meaning — an 8x8 bitmap for printable ASCII
 * so the server-driven layer can address glyphs by index. Clipping is
 * always on; out-of-range ops are skipped, never wrapped. */

#include <linux/types.h>

void memd_raster_clear(__u32 *fb, __u32 w, __u32 h, __u32 color);
void memd_raster_rect(__u32 *fb, __u32 w, __u32 h,
                      __u32 x, __u32 y, __u32 rw, __u32 rh, __u32 color);
void memd_raster_line(__u32 *fb, __u32 w, __u32 h,
                      __u32 x0, __u32 y0, __u32 x1, __u32 y1, __u32 color);
void memd_raster_glyph(__u32 *fb, __u32 w, __u32 h,
                       __u32 x, __u32 y, __u32 glyph, __u32 color);

#endif /* MEMD_RASTER_H */
