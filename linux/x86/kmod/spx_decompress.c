/* spx_decompress.c — LZ4 decompressor for rwbridge-spx.lz4
 * Embedded in run.sh wrapper to decompress SPX at runtime.
 * Uses the LZ4 frame format; no external library is required.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

/* LZ4 Frame Format constants */
#define LZ4_MAGIC 0x184D2204
#define LZ4_BLOCK_MAX_SIZE (1 << 20)  /* 1MB default */
#define LZ4_HEADER_SIZE 7

/* Simple LZ4 frame decompressor */
static unsigned int read_le32(const unsigned char *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static int lz4_decompress_block(const unsigned char *src, int src_len,
                                 unsigned char *dst, int dst_cap) {
    const unsigned char *ip = src;
    const unsigned char *const iend = src + src_len;
    unsigned char *op = dst;
    unsigned char *const oend = dst + dst_cap;
    unsigned int token, len, match_len, offset;

    while (ip < iend) {
        if (ip >= iend) return -1;
        token = *ip++;

        /* Literals length */
        len = token >> 4;
        if (len == 15) {
            unsigned int add;
            do {
                if (ip >= iend) return -1;
                add = *ip++;
                len += add;
            } while (add == 255);
        }

        if (ip + len > iend) return -1;
        if (op + len > oend) return -1;
        memcpy(op, ip, len);
        ip += len;
        op += len;

        if (ip >= iend) break;

        /* Match */
        if (ip + 2 > iend) return -1;
        offset = ip[0] | (ip[1] << 8);
        ip += 2;
        if (offset == 0) return -1;
        if (offset > (unsigned int)(op - dst)) return -1;

        match_len = token & 15;
        if (match_len == 15) {
            unsigned int add;
            do {
                if (ip >= iend) return -1;
                add = *ip++;
                match_len += add;
            } while (add == 255);
        }
        match_len += 4;  /* MINMATCH */

        if (op + match_len > oend) return -1;
        /* Copy from dictionary (overlapping copy) */
        const unsigned char *match_ptr = op - offset;
        while (match_len--) {
            *op++ = *match_ptr++;
        }
    }
    return op - dst;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.lz4> <output>\n", argv[0]);
        return 1;
    }

    int fd_in = open(argv[1], O_RDONLY);
    if (fd_in < 0) {
        perror("open input");
        return 1;
    }

    struct stat st;
    if (fstat(fd_in, &st) < 0) {
        perror("fstat");
        close(fd_in);
        return 1;
    }

    size_t in_size = st.st_size;
    void *in_map = mmap(NULL, in_size, PROT_READ, MAP_PRIVATE, fd_in, 0);
    if (in_map == MAP_FAILED) {
        perror("mmap");
        close(fd_in);
        return 1;
    }
    close(fd_in);

    unsigned char *in = (unsigned char *)in_map;

    /* Check magic */
    if (in_size < 8 || read_le32(in) != LZ4_MAGIC) {
        fprintf(stderr, "Not a valid LZ4 frame\n");
        munmap(in_map, in_size);
        return 1;
    }

    /* Skip frame header (simplified: assume no checksum, no dict) */
    size_t pos = 7;  /* magic(4) + flg(1) + bd(1) + hc(1) */

    /* Allocate output buffer (estimate: 4x compressed) */
    size_t out_cap = in_size * 4;
    unsigned char *out = malloc(out_cap);
    if (!out) {
        fprintf(stderr, "out of memory\n");
        munmap(in_map, in_size);
        return 1;
    }

    unsigned char *out_ptr = out;
    size_t out_len = 0;

    while (pos + 4 <= in_size) {
        unsigned int block_size = read_le32(in + pos);
        pos += 4;

        if (block_size == 0) break;  /* End mark */

        int compressed = block_size & 0x7FFFFFFF;
        int is_compressed = block_size & 0x80000000;

        if (pos + compressed > in_size) {
            fprintf(stderr, "Truncated block\n");
            free(out);
            munmap(in_map, in_size);
            return 1;
        }

        int decoded;
        if (is_compressed) {
            decoded = lz4_decompress_block(in + pos, compressed,
                                           out_ptr, out_cap - out_len);
            if (decoded < 0) {
                fprintf(stderr, "Decompression failed\n");
                free(out);
                munmap(in_map, in_size);
                return 1;
            }
        } else {
            if (out_len + compressed > out_cap) {
                fprintf(stderr, "Output buffer overflow\n");
                free(out);
                munmap(in_map, in_size);
                return 1;
            }
            memcpy(out_ptr, in + pos, compressed);
            decoded = compressed;
        }

        out_ptr += decoded;
        out_len += decoded;
        pos += compressed;
    }

    munmap(in_map, in_size);

    /* Write output */
    int fd_out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd_out < 0) {
        perror("open output");
        free(out);
        return 1;
    }

    ssize_t written = write(fd_out, out, out_len);
    close(fd_out);
    free(out);

    if (written != (ssize_t)out_len) {
        fprintf(stderr, "Short write\n");
        return 1;
    }

    fprintf(stderr, "Decompressed %zu -> %zu bytes\n", in_size, out_len);
    return 0;
}
/* kmod/spx_decompress.c[∂] */
