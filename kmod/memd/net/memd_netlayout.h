#ifndef MEMD_NETLAYOUT_H
#define MEMD_NETLAYOUT_H

/* Runtime kernel-struct layouts for socket registration (KPM-grade
 * universality). A 5.10-built struct proto/proto_ops mis-registers on
 * newer kernels (proven: init hangs in proto_register on 5.15 — obj_size
 * alone moved 256->264->272). Instead of compiling per-generation
 * tables, the image carries per-generation OFFSETS and builds the
 * registration structs at init for the RUNNING kernel.
 *
 * Values below are hand-computed LP64 offsets from DDK headers; every
 * matrix job re-proves them against ITS OWN headers via the anchor
 * asserts in memd_protocol.c (a drift fails the build, never the load).
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
#include <linux/types.h>

/* Generation index by (major, minor). All six LTS generations below are
 * supported on Android GKI and normal/mainline Linux alike: the gen is
 * derived solely from (major, minor), never from an "android"/vendor
 * token in the release string. MEMD_GEN_54 is live. */
#define MEMD_GEN_54   0
#define MEMD_GEN_510  1
#define MEMD_GEN_515  2
#define MEMD_GEN_61   3
#define MEMD_GEN_66   4
#define MEMD_GEN_612  5
#define MEMD_GEN_N    6

/* Sentinel returned for kernels whose (major, minor) is not in the
 * supported set. Callers must treat this as NO-GO and refuse socket
 * init rather than guessing offsets. */
#define MEMD_GEN_UNKNOWN (-1)

/* Convenience bounds for table indexing and validation. */
#define MEMD_GEN_FIRST   0
#define MEMD_GEN_LAST    (MEMD_GEN_N - 1)

/* Current compile-time generation (for static asserts only). */
#define MEMD_MAJ (((LINUX_VERSION_CODE) >> 16) & 0xff)
#define MEMD_MIN (((LINUX_VERSION_CODE) >> 8) & 0xff)
#if MEMD_MAJ == 5 && MEMD_MIN == 4
#define MEMD_GEN_CUR MEMD_GEN_54
#elif MEMD_MAJ == 5 && MEMD_MIN == 10
#define MEMD_GEN_CUR MEMD_GEN_510
#elif MEMD_MAJ == 5 && MEMD_MIN == 15
#define MEMD_GEN_CUR MEMD_GEN_515
#elif MEMD_MAJ == 6 && MEMD_MIN == 1
#define MEMD_GEN_CUR MEMD_GEN_61
#elif MEMD_MAJ == 6 && MEMD_MIN == 6
#define MEMD_GEN_CUR MEMD_GEN_66
#elif MEMD_MAJ == 6 && MEMD_MIN == 12
#define MEMD_GEN_CUR MEMD_GEN_612
#else
#define MEMD_GEN_CUR -1
#endif

/* struct proto field offsets per generation. Owner is a reserved hole
 * on 5.10 (MEMD_P_510_HAS_OWNER 0): do not write it there. */
#define MEMD_P_54_NAME 344
#define MEMD_P_54_HAS_OWNER 1
#define MEMD_P_54_OWNER 336
#define MEMD_P_54_OBJ 288
#define MEMD_P_54_SLAB 280
#define MEMD_P_510_NAME 360
#define MEMD_P_510_HAS_OWNER 1
#define MEMD_P_510_OWNER 352
#define MEMD_P_510_OBJ 304
#define MEMD_P_510_SLAB 296
#define MEMD_P_515_NAME 376
#define MEMD_P_515_HAS_OWNER 1
#define MEMD_P_515_OWNER 368
#define MEMD_P_515_OBJ 320
#define MEMD_P_515_SLAB 312
#define MEMD_P_61_NAME 392
#define MEMD_P_61_HAS_OWNER 1
#define MEMD_P_61_OWNER 384
#define MEMD_P_61_OBJ 336
#define MEMD_P_61_SLAB 328
#define MEMD_P_66_NAME 400
#define MEMD_P_66_HAS_OWNER 1
#define MEMD_P_66_OWNER 392
#define MEMD_P_66_OBJ 336
#define MEMD_P_66_SLAB 328
#define MEMD_P_612_NAME 400
#define MEMD_P_612_HAS_OWNER 1
#define MEMD_P_612_OWNER 392
#define MEMD_P_612_OBJ 336
#define MEMD_P_612_SLAB 328

/* struct proto_ops callback slots per generation (owner unwritten on
 * 5.10: reserved hole). family is 0 everywhere (asserted). */
#define MEMD_O_54_REL 16
#define MEMD_O_54_BIND 24
#define MEMD_O_54_CONN 32
#define MEMD_O_54_PAIR 40
#define MEMD_O_54_ACCEPT 48
#define MEMD_O_54_GETNAME 56
#define MEMD_O_54_POLL 64
#define MEMD_O_54_IOCTL 72
#define MEMD_O_54_LISTEN 96
#define MEMD_O_54_SHUT 104
#define MEMD_O_54_SETOPT 112
#define MEMD_O_54_GETOPT 120
#define MEMD_O_54_SEND 136
#define MEMD_O_54_RECV 144
#define MEMD_O_54_MMAP 152
#define MEMD_O_54_OWNER 8
#define MEMD_O_510_REL 16
#define MEMD_O_510_BIND 24
#define MEMD_O_510_CONN 32
#define MEMD_O_510_PAIR 40
#define MEMD_O_510_ACCEPT 48
#define MEMD_O_510_GETNAME 56
#define MEMD_O_510_POLL 64
#define MEMD_O_510_IOCTL 72
#define MEMD_O_510_LISTEN 96
#define MEMD_O_510_SHUT 104
#define MEMD_O_510_SETOPT 112
#define MEMD_O_510_GETOPT 120
#define MEMD_O_510_SEND 136
#define MEMD_O_510_RECV 144
#define MEMD_O_510_MMAP 152
#define MEMD_O_510_OWNER 8
#define MEMD_O_515_REL 16
#define MEMD_O_515_BIND 24
#define MEMD_O_515_CONN 32
#define MEMD_O_515_PAIR 40
#define MEMD_O_515_ACCEPT 48
#define MEMD_O_515_GETNAME 56
#define MEMD_O_515_POLL 64
#define MEMD_O_515_IOCTL 72
#define MEMD_O_515_LISTEN 96
#define MEMD_O_515_SHUT 104
#define MEMD_O_515_SETOPT 112
#define MEMD_O_515_GETOPT 120
#define MEMD_O_515_SEND 136
#define MEMD_O_515_RECV 144
#define MEMD_O_515_MMAP 152
#define MEMD_O_515_OWNER 8
#define MEMD_O_61_REL 16
#define MEMD_O_61_BIND 24
#define MEMD_O_61_CONN 32
#define MEMD_O_61_PAIR 40
#define MEMD_O_61_ACCEPT 48
#define MEMD_O_61_GETNAME 56
#define MEMD_O_61_POLL 64
#define MEMD_O_61_IOCTL 72
#define MEMD_O_61_LISTEN 96
#define MEMD_O_61_SHUT 104
#define MEMD_O_61_SETOPT 112
#define MEMD_O_61_GETOPT 120
#define MEMD_O_61_SEND 136
#define MEMD_O_61_RECV 144
#define MEMD_O_61_MMAP 152
#define MEMD_O_61_OWNER 8
#define MEMD_O_66_REL 16
#define MEMD_O_66_BIND 24
#define MEMD_O_66_CONN 32
#define MEMD_O_66_PAIR 40
#define MEMD_O_66_ACCEPT 48
#define MEMD_O_66_GETNAME 56
#define MEMD_O_66_POLL 64
#define MEMD_O_66_IOCTL 72
#define MEMD_O_66_LISTEN 96
#define MEMD_O_66_SHUT 104
#define MEMD_O_66_SETOPT 112
#define MEMD_O_66_GETOPT 120
#define MEMD_O_66_SEND 136
#define MEMD_O_66_RECV 144
#define MEMD_O_66_MMAP 152
#define MEMD_O_66_OWNER 8
#define MEMD_O_612_REL 16
#define MEMD_O_612_BIND 24
#define MEMD_O_612_CONN 32
#define MEMD_O_612_PAIR 40
#define MEMD_O_612_ACCEPT 48
#define MEMD_O_612_GETNAME 56
#define MEMD_O_612_POLL 64
#define MEMD_O_612_IOCTL 72
#define MEMD_O_612_LISTEN 96
#define MEMD_O_612_SHUT 104
#define MEMD_O_612_SETOPT 112
#define MEMD_O_612_GETOPT 120
#define MEMD_O_612_SEND 136
#define MEMD_O_612_RECV 144
#define MEMD_O_612_MMAP 152
#define MEMD_O_612_OWNER 8

struct memd_proto_off {
    short name;      /* char[32] */
    short owner;     /* struct module * (see has_owner) */
    short has_owner;
    short obj_size;  /* unsigned int */
    short slab;
};

struct memd_ops_off {
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

#define MEMD_MKPROTO(sfx) \
    { MEMD_P_##sfx##_NAME, MEMD_P_##sfx##_OWNER, MEMD_P_##sfx##_HAS_OWNER, \
      MEMD_P_##sfx##_OBJ, MEMD_P_##sfx##_SLAB }
#define MEMD_MKOPS(sfx) \
    { MEMD_O_##sfx##_REL, MEMD_O_##sfx##_BIND, MEMD_O_##sfx##_CONN, \
      MEMD_O_##sfx##_PAIR, MEMD_O_##sfx##_ACCEPT, MEMD_O_##sfx##_GETNAME, \
      MEMD_O_##sfx##_POLL, MEMD_O_##sfx##_IOCTL, MEMD_O_##sfx##_LISTEN, \
      MEMD_O_##sfx##_SHUT, MEMD_O_##sfx##_SETOPT, MEMD_O_##sfx##_GETOPT, \
      MEMD_O_##sfx##_SEND, MEMD_O_##sfx##_RECV, MEMD_O_##sfx##_MMAP, \
      MEMD_O_##sfx##_OWNER }

static const struct memd_proto_off memd_proto_offs[MEMD_GEN_N] = {
    MEMD_MKPROTO(54),
    MEMD_MKPROTO(510),
    MEMD_MKPROTO(515),
    MEMD_MKPROTO(61),
    MEMD_MKPROTO(66),
    MEMD_MKPROTO(612),
};

static const struct memd_ops_off memd_ops_offs[MEMD_GEN_N] = {
    MEMD_MKOPS(54),
    MEMD_MKOPS(510),
    MEMD_MKOPS(515),
    MEMD_MKOPS(61),
    MEMD_MKOPS(66),
    MEMD_MKOPS(612),
};

#undef MEMD_MKPROTO
#undef MEMD_MKOPS

/* Buffers cover the largest known layout plus slack. */
#define MEMD_PROTO_BUF 512
#define MEMD_OPS_BUF 256

/* Resolve the running kernel to a generation index, or -1. */
int memd_net_gen(void);

/* Safe accessor: identical to memd_net_gen() but named for call sites that
 * want an explicit "unknown -> refuse" contract. Never returns a value
 * outside [-1, MEMD_GEN_N). */
int memd_net_gen_safe(void);

/* Map a numeric (major, minor) kernel version to a generation index,
 * or MEMD_GEN_UNKNOWN when unsupported. Pure function of its args; does
 * not touch the running kernel. Safe to call from any context. */
int memd_net_gen_from_version(int major, int minor);

/* Parse a kernel release string ("5.15.0-...", "6.1.0-...-generic",
 * "5.4.147-android11-...", ...) into numeric components. Returns 0 on
 * success (major/minor found) and -1 otherwise. *patch is set to 0 when
 * no patch level is present. All output pointers may be NULL. */
int memd_net_parse_release(const char *release, int *major, int *minor,
                           int *patch);

/* True when the release string looks like an Android GKI build (contains
 * an "android" token). Informational only: generation mapping does not
 * depend on this. */
int memd_net_is_android_release(const char *release);

/* True when (major, minor) is one of the supported generations. */
int memd_net_version_supported(int major, int minor);

/* Human-readable name for a generation index ("5.4", "5.10", ...), or
 * "unknown" for MEMD_GEN_UNKNOWN/out of range. Returned string is a
 * compile-time literal (no allocation, safe to print). */
const char *memd_net_gen_name(int gen);

/* Copy the detected running-kernel release string into buf (NUL
 * terminated). Returns 0 on success, -1 if unavailable. */
int memd_net_release_str(char *buf, size_t cap);

/* Runtime-detected components of the running kernel release (0 when
 * unavailable). Each triggers detection on first use. */
int memd_net_cached_major(void);
int memd_net_cached_minor(void);
int memd_net_cached_patch(void);
/* True when the running kernel release contained an "android" token. */
int memd_net_cached_is_android(void);

/* Build registration structs into the internal static buffers.
 * Returns 0 ok, -1 unknown generation (caller refuses init). */
int memd_build_proto(void);
int memd_build_ops(void);
void memd_ops_set_family(int family);
struct proto_ops *memd_ops_ptr(void);
struct proto *memd_proto_ptr(void);

#endif /* MEMD_NETLAYOUT_H */
/* kmod/memd/net/memd_netlayout.h[∂] */
