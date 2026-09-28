#ifndef WUWA_NETLAYOUT_H
#define WUWA_NETLAYOUT_H

/* Runtime kernel-struct layouts for socket registration (KPM-grade
 * universality). A 5.10-built struct proto/proto_ops mis-registers on
 * newer kernels (proven: init hangs in proto_register on 5.15 — obj_size
 * alone moved 256->264->272). Instead of compiling per-generation
 * tables, the image carries per-generation OFFSETS and builds the
 * registration structs at init for the RUNNING kernel.
 *
 * Values below are hand-computed LP64 offsets from DDK headers; every
 * matrix job re-proves them against ITS OWN headers via the anchor
 * asserts in wuwa_protocol.c (a drift fails the build, never the load).
 *
 * Only fields the kernel reads are populated (name/owner/obj_size for
 * proto; the 15 callbacks + owner for proto_ops); everything else stays
 * zero — identical to the minimal static tables that work per-gen.
 * Buffers are max-size across generations. Unknown generation at
 * runtime -> explicit NO-GO (refuse socket init, never guess).
 *
 * Kernel-struct offsets for OUR OWN registration are framework data
 * (same bar as the struct-module shift), never game content.
 */

#include <linux/version.h>

/* Generation index by (major, minor). */
#define WUWA_GEN_510 0
#define WUWA_GEN_515 1
#define WUWA_GEN_61  2
#define WUWA_GEN_66  3
#define WUWA_GEN_612 4
#define WUWA_GEN_N 5

/* Current compile-time generation (for static asserts only). */
#define WUWA_MAJ (((LINUX_VERSION_CODE) >> 16) & 0xff)
#define WUWA_MIN (((LINUX_VERSION_CODE) >> 8) & 0xff)
#if WUWA_MAJ == 5 && WUWA_MIN == 10
#define WUWA_GEN_CUR WUWA_GEN_510
#elif WUWA_MAJ == 5 && WUWA_MIN == 15
#define WUWA_GEN_CUR WUWA_GEN_515
#elif WUWA_MAJ == 6 && WUWA_MIN == 1
#define WUWA_GEN_CUR WUWA_GEN_61
#elif WUWA_MAJ == 6 && WUWA_MIN == 6
#define WUWA_GEN_CUR WUWA_GEN_66
#elif WUWA_MAJ == 6 && WUWA_MIN == 12
#define WUWA_GEN_CUR WUWA_GEN_612
#else
#define WUWA_GEN_CUR -1
#endif

/* struct proto field offsets per generation. Owner is a reserved hole
 * on 5.10 (WUWA_P_510_HAS_OWNER 0): do not write it there. */
#define WUWA_P_510_NAME 320
#define WUWA_P_510_HAS_OWNER 0
#define WUWA_P_510_OWNER 0 /* hole: never written (guarded) */
#define WUWA_P_510_OBJ 256
#define WUWA_P_510_SLAB 248
#define WUWA_P_515_NAME 328
#define WUWA_P_515_HAS_OWNER 1
#define WUWA_P_515_OWNER 320
#define WUWA_P_515_OBJ 264
#define WUWA_P_515_SLAB 256
#define WUWA_P_61_NAME 336
#define WUWA_P_61_HAS_OWNER 1
#define WUWA_P_61_OWNER 328
#define WUWA_P_61_OBJ 272
#define WUWA_P_61_SLAB 264
#define WUWA_P_66_NAME 344
#define WUWA_P_66_HAS_OWNER 1
#define WUWA_P_66_OWNER 336
#define WUWA_P_66_OBJ 272
#define WUWA_P_66_SLAB 264
#define WUWA_P_612_NAME 344
#define WUWA_P_612_HAS_OWNER 1
#define WUWA_P_612_OWNER 336
#define WUWA_P_612_OBJ 272
#define WUWA_P_612_SLAB 264

/* struct proto_ops callback slots per generation (owner unwritten on
 * 5.10: reserved hole). family is 0 everywhere (asserted). */
#define WUWA_O_510_REL 8
#define WUWA_O_510_BIND 16
#define WUWA_O_510_CONN 24
#define WUWA_O_510_PAIR 32
#define WUWA_O_510_ACCEPT 40
#define WUWA_O_510_GETNAME 48
#define WUWA_O_510_POLL 56
#define WUWA_O_510_IOCTL 64
#define WUWA_O_510_LISTEN 72
#define WUWA_O_510_SHUT 80
#define WUWA_O_510_SETOPT 88
#define WUWA_O_510_GETOPT 96
#define WUWA_O_510_SEND 112
#define WUWA_O_510_RECV 120
#define WUWA_O_510_MMAP 128
#define WUWA_O_510_OWNER -1
#define WUWA_O_515_REL 16
#define WUWA_O_515_BIND 24
#define WUWA_O_515_CONN 32
#define WUWA_O_515_PAIR 40
#define WUWA_O_515_ACCEPT 48
#define WUWA_O_515_GETNAME 56
#define WUWA_O_515_POLL 64
#define WUWA_O_515_IOCTL 72
#define WUWA_O_515_LISTEN 80
#define WUWA_O_515_SHUT 88
#define WUWA_O_515_SETOPT 96
#define WUWA_O_515_GETOPT 104
#define WUWA_O_515_SEND 120
#define WUWA_O_515_RECV 128
#define WUWA_O_515_MMAP 136
#define WUWA_O_515_OWNER 8
#define WUWA_O_61_REL 16
#define WUWA_O_61_BIND 24
#define WUWA_O_61_CONN 32
#define WUWA_O_61_PAIR 40
#define WUWA_O_61_ACCEPT 48
#define WUWA_O_61_GETNAME 56
#define WUWA_O_61_POLL 64
#define WUWA_O_61_IOCTL 72
#define WUWA_O_61_LISTEN 80
#define WUWA_O_61_SHUT 88
#define WUWA_O_61_SETOPT 96
#define WUWA_O_61_GETOPT 104
#define WUWA_O_61_SEND 120
#define WUWA_O_61_RECV 128
#define WUWA_O_61_MMAP 136
#define WUWA_O_61_OWNER 8
#define WUWA_O_66_REL 16
#define WUWA_O_66_BIND 24
#define WUWA_O_66_CONN 32
#define WUWA_O_66_PAIR 40
#define WUWA_O_66_ACCEPT 48
#define WUWA_O_66_GETNAME 56
#define WUWA_O_66_POLL 64
#define WUWA_O_66_IOCTL 72
#define WUWA_O_66_LISTEN 80
#define WUWA_O_66_SHUT 88
#define WUWA_O_66_SETOPT 96
#define WUWA_O_66_GETOPT 104
#define WUWA_O_66_SEND 120
#define WUWA_O_66_RECV 128
#define WUWA_O_66_MMAP 136
#define WUWA_O_66_OWNER 8
#define WUWA_O_612_REL 16
#define WUWA_O_612_BIND 24
#define WUWA_O_612_CONN 32
#define WUWA_O_612_PAIR 40
#define WUWA_O_612_ACCEPT 48
#define WUWA_O_612_GETNAME 56
#define WUWA_O_612_POLL 64
#define WUWA_O_612_IOCTL 72
#define WUWA_O_612_LISTEN 80
#define WUWA_O_612_SHUT 88
#define WUWA_O_612_SETOPT 96
#define WUWA_O_612_GETOPT 104
#define WUWA_O_612_SEND 120
#define WUWA_O_612_RECV 128
#define WUWA_O_612_MMAP 136
#define WUWA_O_612_OWNER 8

struct wuwa_proto_off {
    short name;      /* char[32] */
    short owner;     /* struct module * (see has_owner) */
    short has_owner;
    short obj_size;  /* unsigned int */
    short slab;
};

struct wuwa_ops_off {
    short release;
    short bind;
    short connect;
    short socketpair;
    short accept;
    short getname;
    short poll;
    short ioctl;
    short listen;
    short shutdown;
    short setsockopt;
    short getsockopt;
    short sendmsg;
    short recvmsg;
    short mmap;
    short owner;     /* -1 when hole (5.10) */
};

#define WUWA_MKPROTO(sfx) \
    { WUWA_P_##sfx##_NAME, WUWA_P_##sfx##_OWNER, WUWA_P_##sfx##_HAS_OWNER, \
      WUWA_P_##sfx##_OBJ, WUWA_P_##sfx##_SLAB }
#define WUWA_MKOPS(sfx) \
    { WUWA_O_##sfx##_REL, WUWA_O_##sfx##_BIND, WUWA_O_##sfx##_CONN, \
      WUWA_O_##sfx##_PAIR, WUWA_O_##sfx##_ACCEPT, WUWA_O_##sfx##_GETNAME, \
      WUWA_O_##sfx##_POLL, WUWA_O_##sfx##_IOCTL, WUWA_O_##sfx##_LISTEN, \
      WUWA_O_##sfx##_SHUT, WUWA_O_##sfx##_SETOPT, WUWA_O_##sfx##_GETOPT, \
      WUWA_O_##sfx##_SEND, WUWA_O_##sfx##_RECV, WUWA_O_##sfx##_MMAP, \
      WUWA_O_##sfx##_OWNER }

static const struct wuwa_proto_off wuwa_proto_offs[WUWA_GEN_N] = {
    WUWA_MKPROTO(510),
    WUWA_MKPROTO(515),
    WUWA_MKPROTO(61),
    WUWA_MKPROTO(66),
    WUWA_MKPROTO(612),
};

static const struct wuwa_ops_off wuwa_ops_offs[WUWA_GEN_N] = {
    WUWA_MKOPS(510),
    WUWA_MKOPS(515),
    WUWA_MKOPS(61),
    WUWA_MKOPS(66),
    WUWA_MKOPS(612),
};

#undef WUWA_MKPROTO
#undef WUWA_MKOPS

/* Buffers cover the largest known layout plus slack. */
#define WUWA_PROTO_BUF 512
#define WUWA_OPS_BUF 256

/* Resolve the running kernel to a generation index, or -1. */
int wuwa_net_gen(void);

/* Build registration structs into the internal static buffers.
 * Returns 0 ok, -1 unknown generation (caller refuses init). */
int wuwa_build_proto(void);
int wuwa_build_ops(void);
void wuwa_ops_set_family(int family);
struct proto_ops *wuwa_ops_ptr(void);
struct proto *wuwa_proto_ptr(void);

#endif /* WUWA_NETLAYOUT_H */
