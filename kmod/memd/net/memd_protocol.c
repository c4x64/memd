#include "memd_protocol.h"

#include <asm-generic/errno.h>

#include "memd_common.h"

#include <net/sock.h>

#include "memd_ioctl.h"
#include "memd_sock.h"
#include "memd_netlayout.h"
#include "memd_learn.h"

#include <linux/string.h>
#include <linux/stddef.h>

static int free_family = AF_DECnet;

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
    if (g < 0) {
        memd_err("netlayout: unknown kernel generation (no socket)\n");
        return -1;
    }
    o = &memd_proto_offs[g];
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
#if MEMD_GEN_CUR == MEMD_GEN_510
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

static int register_free_family(void) {
    int err = 0, i = 0;

    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        memd_info("registered ioctl command: %u\n", ioctl_handlers[i].cmd);
    }

    for (int family = free_family; family < NPROTO; family++) {
        memd_family_ops.family = family;
        err = sock_register(&memd_family_ops);
        if (err)
            continue;
        free_family = family;
        memd_ops_set_family(free_family);
        memd_info("find free proto_family: %d\n", free_family);
        return 0;
    }

    memd_err("can't find any free proto_family!\n");
    return err;
}

int memd_proto_init(void) {
    int err;
    if (memd_build_proto() || memd_build_ops())
        return -ENODEV;
    err = proto_register(memd_proto_ptr(), 1);
    if (err)
        goto out;

    err = register_free_family();
    if (err)
        goto out_proto;

    return 0;

    sock_unregister(free_family);
out_proto:
    proto_unregister(memd_proto_ptr());
out:
    return err;
}

void memd_proto_cleanup(void) {
    sock_unregister(free_family);
    proto_unregister(memd_proto_ptr());
}

static int memd_sock_create(struct net* net, struct socket* sock, int protocol, int kern) {
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

    sock->state = SS_UNCONNECTED;
    struct sock* sk = sk_alloc(net, PF_INET, GFP_KERNEL, memd_proto_ptr(), kern);
    if (!sk) {
        memd_warn("sk_alloc failed!\n");
        return -ENOBUFS;
    }

    memd_family_ops.family = free_family;
    sock->ops = memd_ops_ptr();
    sock_init_data(sock, sk);

    struct memd_sock* ws = (struct memd_sock*)sk;
    ws->version = 1;
    ws->session = memd_t_pid(current);
    ws->used_pages = arraylist_create(4);

    return 0;
}

struct net_proto_family memd_family_ops = {
    .family = PF_DECnet,
    .create = memd_sock_create,
    .owner = THIS_MODULE,
};
