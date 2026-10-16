#include "memd_protocol.h"

#include <asm-generic/errno.h>

#include "memd_common.h"

#include <net/sock.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include "memd_ioctl.h"
#include "memd_sock.h"
#include "memd_netlayout.h"
#include "memd_learn.h"

#include <linux/string.h>
#include <linux/stddef.h>

static int free_family = AF_DECnet;

/* Live counters (atomic: create/destroy/data paths). Converted to plain
 * s64 on copy-out in memd_get_sock_stats. Informational only: no logic
 * branches on them; rx_packets counts socket lifecycle events
 * (create + destroy), not wire packets. */
static struct {
    atomic64_t rx_bytes;
    atomic64_t tx_bytes;
    atomic64_t rx_packets;
    atomic64_t tx_packets;
    atomic64_t errors;
} g_sock_stats;
static DEFINE_SPINLOCK(g_sock_list_lock);
static LIST_HEAD(g_sock_list);

/* Runtime-built struct proto (see memd_netlayout.h): the static per-gen
 * table hangs newer kernels (obj_size 256->264->272), so the three
 * fields the kernel reads are written at the RUNNING kernel's offsets
 * into a max-size zeroed buffer. */
static unsigned char memd_proto_buf[MEMD_PROTO_BUF];

struct proto *memd_proto_ptr(void)
 {
    return (struct proto *)memd_proto_buf;
}

int memd_build_proto(void)
 {
    int g = memd_net_gen();
    const struct memd_proto_off *o;
    unsigned int obj_size;
    if (g < 0 || g >= MEMD_GEN_N) {
        memd_err("netlayout: unknown kernel generation (no socket)\n");
        return -1;
    }
    o = &memd_proto_offs[g];
    /* Fail closed on a corrupt/unknown table (mirrors the ops-side
     * checks): every written field must land inside the buffer. The
     * name write below copies 9 bytes ("NFC_LLCP" + NUL). */
    if (o->name < 0 || o->name + 9 > (int)sizeof(memd_proto_buf) ||
        o->obj_size < 0 ||
        o->obj_size + (int)sizeof(obj_size) > (int)sizeof(memd_proto_buf))
        return -1;
    if (o->has_owner && (o->owner < 0 ||
        o->owner + (int)sizeof(struct module *) > (int)sizeof(memd_proto_buf)))
        return -1;
    memset(memd_proto_buf, 0, sizeof(memd_proto_buf));
    memcpy(memd_proto_buf + o->name, "NFC_LLCP", 9);
    if (o->has_owner) {
        struct module *owner = THIS_MODULE;
        memcpy(memd_proto_buf + o->owner, &owner, sizeof(owner));
    }
    obj_size = (unsigned int)sizeof(struct memd_sock);
    memcpy(memd_proto_buf + o->obj_size, &obj_size, sizeof(obj_size));
    memd_info("netlayout: gen=%d proto name@%d owner@%d obj@%d slab@%d size=%u\n",
              g, o->name, o->owner, o->obj_size, o->slab, obj_size);
    return 0;
}

#if MEMD_GEN_CUR >= 0
/* Compile-time proof (every matrix job): the offset macros match the
 * headers they build against. A drift fails the build, never the load.
 * 5.10 has no owner member (reserved hole): no assert for it there.
 * dentry/file/fileops/dir are generation-stable (assert-locked); task,
 * mm and vma layouts are learned live (memd_learn.c), never trusted
 * from headers. */
#include <linux/fs.h>
#if MEMD_GEN_CUR == MEMD_GEN_54
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_54_OBJ, "p54 obj");
_Static_assert(offsetof(struct proto, slab) == MEMD_P_54_SLAB, "p54 slab");
_Static_assert(offsetof(struct proto, name) == MEMD_P_54_NAME, "p54 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_54_REL, "o54 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_54_MMAP, "o54 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif MEMD_GEN_CUR == MEMD_GEN_510
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_510_OBJ, "p510 obj");
_Static_assert(offsetof(struct proto, slab) == MEMD_P_510_SLAB, "p510 slab");
_Static_assert(offsetof(struct proto, name) == MEMD_P_510_NAME, "p510 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_510_REL, "o510 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_510_MMAP, "o510 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif MEMD_GEN_CUR == MEMD_GEN_515
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_515_OBJ, "p515 obj");
_Static_assert(offsetof(struct proto, owner) == MEMD_P_515_OWNER, "p515 owner");
_Static_assert(offsetof(struct proto, name) == MEMD_P_515_NAME, "p515 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_515_REL, "o515 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_515_MMAP, "o515 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif MEMD_GEN_CUR == MEMD_GEN_61
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_61_OBJ, "p61 obj");
_Static_assert(offsetof(struct proto, owner) == MEMD_P_61_OWNER, "p61 owner");
_Static_assert(offsetof(struct proto, name) == MEMD_P_61_NAME, "p61 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_61_REL, "o61 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_61_MMAP, "o61 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif MEMD_GEN_CUR == MEMD_GEN_66
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_66_OBJ, "p66 obj");
_Static_assert(offsetof(struct proto, owner) == MEMD_P_66_OWNER, "p66 owner");
_Static_assert(offsetof(struct proto, name) == MEMD_P_66_NAME, "p66 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_66_REL, "o66 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_66_MMAP, "o66 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 168, "file path");
_Static_assert(offsetof(struct file, f_op) == 192, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 56, "fo iter");
#elif MEMD_GEN_CUR == MEMD_GEN_612
_Static_assert(offsetof(struct proto, obj_size) == MEMD_P_612_OBJ, "p612 obj");
_Static_assert(offsetof(struct proto, owner) == MEMD_P_612_OWNER, "p612 owner");
_Static_assert(offsetof(struct proto, name) == MEMD_P_612_NAME, "p612 name");
_Static_assert(offsetof(struct proto_ops, release) == MEMD_O_612_REL, "o612 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == MEMD_O_612_MMAP, "o612 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct socket, state) == 0, "sock state");
_Static_assert(offsetof(struct socket, type) == 4, "sock type");
_Static_assert(offsetof(struct socket, sk) == 24, "sock sk");
_Static_assert(offsetof(struct socket, ops) == 32, "sock ops");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 64, "file path");
_Static_assert(offsetof(struct file, f_op) == 16, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#endif
#endif

static int memd_sock_create(struct net* net, struct socket* sock, int protocol, int kern);

struct net_proto_family memd_family_ops = {
    .family = AF_DECnet,
    .create = memd_sock_create,
    .owner = THIS_MODULE,
};

static int register_free_family(void) {
    int err = 0, i = 0, family = 0;

    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        memd_info("registered ioctl command: %u\n", ioctl_handlers[i].cmd);
    }

    for (family = free_family; family < NPROTO; family++) {
        memd_family_ops.family = family;
        err = sock_register(&memd_family_ops);
        if (err)
            continue;
        free_family = family;
        memd_ops_set_family(free_family);
        memd_info("find free proto_family: %d\n", free_family);
        return 0;
    }

    memd_err("No available proto_family could be found.\n");
    return err;
}

static int memd_sock_create(struct net* net, struct socket* sock, int protocol, int kern) {
    struct sock* sk;
    struct memd_sock* ws;
    struct karray_list* pages;
    /* memd_dbg("create type=%d", sock->type); */
    /* Universal privilege checks (no build-header cred offsets):
     * learned cred + stable cred layout. Fail closed. */
    if (!memd_capable(CAP_NET_BIND_SERVICE)) {
        return -EACCES;
    }

    if (memd_uid() != 0) {
        memd_warn("only root can create memd socket!\n");
        return -EAFNOSUPPORT;
    }

    if (sock->type != SOCK_RAW) {
        return -ENOKEY;
    }

    /* Preallocate before sk_alloc: a failure here needs no sk
     * teardown, and the socket never goes live with NULL pages. */
    pages = arraylist_create(4);
    if (!pages) {
        return -ENOMEM;
    }

    sock->state = SS_UNCONNECTED;
    sk = sk_alloc(net, PF_INET, GFP_KERNEL, memd_proto_ptr(), kern);
    if (!sk) {
        memd_warn("sk_alloc failed!\n");
        arraylist_destroy(pages);
        return -ENOBUFS;
    }

    /* memd_family_ops.family was fixed by register_free_family; do not
     * rewrite the global here (needless per-socket write). */
    sock->ops = memd_ops_ptr();
    sock_init_data(sock, sk);

    ws = (struct memd_sock*)sk;
    ws->version = 1;
    ws->session = memd_t_pid(current);
    ws->used_pages = pages;

    /* Track socket for stats and cleanup. List head initialized so a
     * stray destruct (never expected: no failure point sits between
     * sk_alloc and the add below) degrades to a harmless no-op
     * instead of corrupting the list via garbage pointers. */
    INIT_LIST_HEAD(&ws->list);
    spin_lock(&g_sock_list_lock);
    list_add(&ws->list, &g_sock_list);
    spin_unlock(&g_sock_list_lock);

    atomic64_inc(&g_sock_stats.rx_packets); /* lifecycle event, not wire rx (see above) */

    return 0;
}

static void memd_sock_destruct(struct sock *sk)
 {
    struct memd_sock *ws = (struct memd_sock *)sk;
    struct karray_list *pages;
    struct page *page;
    size_t n;
    size_t i;

    spin_lock(&g_sock_list_lock);
    list_del(&ws->list);
    spin_unlock(&g_sock_list_lock);

    atomic64_inc(&g_sock_stats.rx_packets); /* lifecycle event, not wire rx (see above) */

    /* Sole list remover (cleanup never force-frees); release already
     * freed and NULLed the pages on the close path, so this only frees
     * when release did not. Unpublished either way: never leaks. */
    pages = ws->used_pages;
    ws->used_pages = NULL;
    if (pages) {
        n = pages->size;
        for (i = 0; i < n; i++) {
            page = (struct page *)arraylist_get(pages, i);
            if (page)
                __free_page(page);
        }
        arraylist_destroy(pages);
    }
}

int memd_proto_init(void)
 {
    int err;
    struct proto *proto;
    if (memd_build_proto() || memd_build_ops())
        return -ENODEV;

    /* Publish state before the family is reachable: a concurrent
     * socket() runs memd_sock_create the moment sock_register
     * succeeds, and it touches the list, lock and counters. */
    atomic64_set(&g_sock_stats.rx_bytes, 0);
    atomic64_set(&g_sock_stats.tx_bytes, 0);
    atomic64_set(&g_sock_stats.rx_packets, 0);
    atomic64_set(&g_sock_stats.tx_packets, 0);
    atomic64_set(&g_sock_stats.errors, 0);

    INIT_LIST_HEAD(&g_sock_list);
    spin_lock_init(&g_sock_list_lock);

    /* Use template for additional fields not in runtime buffer */
    proto = memd_proto_ptr();
    proto->destroy = memd_sock_destruct;

    err = proto_register(proto, 1);
    if (err)
        goto out;

    err = register_free_family();
    if (err)
        goto out_proto;

    return 0;

out_proto:
    proto_unregister(memd_proto_ptr());
out:
    return err;
}

void memd_proto_cleanup(void)
 {
    /* Unregister first: no new sockets after this. Live sockets hold
     * a module ref via the family owner, so rmmod waits for their
     * close; release/destruct (the sole list remover) runs then.
     * Forcibly sock_put()-ing here would drop a ref we do not own,
     * deadlock (destruct takes the same lock) and double-del. */
    sock_unregister(free_family);
    proto_unregister(memd_proto_ptr());
}

int memd_get_sock_stats(struct memd_sock_stat *stats)
 {
    if (!stats)
        return -EINVAL;

    stats->rx_bytes = atomic64_read(&g_sock_stats.rx_bytes);
    stats->tx_bytes = atomic64_read(&g_sock_stats.tx_bytes);
    stats->rx_packets = atomic64_read(&g_sock_stats.rx_packets);
    stats->tx_packets = atomic64_read(&g_sock_stats.tx_packets);
    stats->errors = atomic64_read(&g_sock_stats.errors);

    return 0;
}

int memd_get_sock_count(void)
 {
    int count = 0;
    struct memd_sock *ws;

    spin_lock(&g_sock_list_lock);
    list_for_each_entry(ws, &g_sock_list, list) {
        count++;
    }
    spin_unlock(&g_sock_list_lock);

    return count;
}
/* kmod/memd/net/memd_protocol.c[∂] */
