#include "wuwa_protocol.h"

#include <asm-generic/errno.h>

#include "wuwa_common.h"

#include <net/sock.h>

#include "wuwa_ioctl.h"
#include "wuwa_sock.h"
#include "wuwa_netlayout.h"
#include "wuwa_learn.h"

#include <linux/string.h>
#include <linux/stddef.h>

static int free_family = AF_DECnet;

/* Runtime-built struct proto (see wuwa_netlayout.h): the static per-gen
 * table hangs newer kernels (obj_size 256->264->272), so the three
 * fields the kernel reads are written at the RUNNING kernel's offsets
 * into a max-size zeroed buffer. */
static unsigned char wuwa_proto_buf[WUWA_PROTO_BUF];

struct proto *wuwa_proto_ptr(void)
{
    return (struct proto *)wuwa_proto_buf;
}

int wuwa_build_proto(void)
{
    int g = wuwa_net_gen();
    const struct wuwa_proto_off *o;
    unsigned int obj_size;
    if (g < 0) {
        wuwa_err("netlayout: unknown kernel generation (no socket)\n");
        return -1;
    }
    o = &wuwa_proto_offs[g];
    memset(wuwa_proto_buf, 0, sizeof(wuwa_proto_buf));
    memcpy(wuwa_proto_buf + o->name, "NFC_LLCP", 9);
    if (o->has_owner) {
        struct module *owner = THIS_MODULE;
        memcpy(wuwa_proto_buf + o->owner, &owner, sizeof(owner));
    }
    obj_size = (unsigned int)sizeof(struct wuwa_sock);
    memcpy(wuwa_proto_buf + o->obj_size, &obj_size, sizeof(obj_size));
    return 0;
}

#if WUWA_GEN_CUR >= 0
/* Compile-time proof (every matrix job): the offset macros match the
 * headers they build against. A drift fails the build, never the load.
 * 5.10 has no owner member (reserved hole): no assert for it there.
 * dentry/file/fileops/dir are generation-stable (assert-locked); task,
 * mm and vma layouts are learned live (wuwa_learn.c), never trusted
 * from headers. */
#include <linux/fs.h>
#if WUWA_GEN_CUR == WUWA_GEN_510
_Static_assert(offsetof(struct proto, obj_size) == WUWA_P_510_OBJ, "p510 obj");
_Static_assert(offsetof(struct proto, slab) == WUWA_P_510_SLAB, "p510 slab");
_Static_assert(offsetof(struct proto, name) == WUWA_P_510_NAME, "p510 name");
_Static_assert(offsetof(struct proto_ops, release) == WUWA_O_510_REL, "o510 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == WUWA_O_510_MMAP, "o510 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif WUWA_GEN_CUR == WUWA_GEN_515
_Static_assert(offsetof(struct proto, obj_size) == WUWA_P_515_OBJ, "p515 obj");
_Static_assert(offsetof(struct proto, owner) == WUWA_P_515_OWNER, "p515 owner");
_Static_assert(offsetof(struct proto, name) == WUWA_P_515_NAME, "p515 name");
_Static_assert(offsetof(struct proto_ops, release) == WUWA_O_515_REL, "o515 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == WUWA_O_515_MMAP, "o515 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif WUWA_GEN_CUR == WUWA_GEN_61
_Static_assert(offsetof(struct proto, obj_size) == WUWA_P_61_OBJ, "p61 obj");
_Static_assert(offsetof(struct proto, owner) == WUWA_P_61_OWNER, "p61 owner");
_Static_assert(offsetof(struct proto, name) == WUWA_P_61_NAME, "p61 name");
_Static_assert(offsetof(struct proto_ops, release) == WUWA_O_61_REL, "o61 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == WUWA_O_61_MMAP, "o61 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#elif WUWA_GEN_CUR == WUWA_GEN_66
_Static_assert(offsetof(struct proto, obj_size) == WUWA_P_66_OBJ, "p66 obj");
_Static_assert(offsetof(struct proto, owner) == WUWA_P_66_OWNER, "p66 owner");
_Static_assert(offsetof(struct proto, name) == WUWA_P_66_NAME, "p66 name");
_Static_assert(offsetof(struct proto_ops, release) == WUWA_O_66_REL, "o66 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == WUWA_O_66_MMAP, "o66 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 56, "fo iter");
#elif WUWA_GEN_CUR == WUWA_GEN_612
_Static_assert(offsetof(struct proto, obj_size) == WUWA_P_612_OBJ, "p612 obj");
_Static_assert(offsetof(struct proto, owner) == WUWA_P_612_OWNER, "p612 owner");
_Static_assert(offsetof(struct proto, name) == WUWA_P_612_NAME, "p612 name");
_Static_assert(offsetof(struct proto_ops, release) == WUWA_O_612_REL, "o612 rel");
_Static_assert(offsetof(struct proto_ops, mmap) == WUWA_O_612_MMAP, "o612 mmap");
_Static_assert(offsetof(struct net_proto_family, create) == 8, "family create");
_Static_assert(offsetof(struct dir_context, pos) == 8, "dctx pos");
_Static_assert(sizeof(struct dir_context) == 16, "dctx size");
_Static_assert(offsetof(struct dentry, d_name) == 32, "dentry name");
_Static_assert(offsetof(struct file, f_path) == 16, "file path");
_Static_assert(offsetof(struct file, f_op) == 40, "file op");
_Static_assert(offsetof(struct file_operations, iterate_shared) == 64, "fo iter");
#endif
#endif

static int register_free_family(void) {
    int err = 0, i = 0;

    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        wuwa_info("registered ioctl command: %u\n", ioctl_handlers[i].cmd);
    }

    for (int family = free_family; family < NPROTO; family++) {
        wuwa_family_ops.family = family;
        err = sock_register(&wuwa_family_ops);
        if (err)
            continue;
        free_family = family;
        wuwa_ops_set_family(free_family);
        wuwa_info("find free proto_family: %d\n", free_family);
        return 0;
    }

    wuwa_err("can't find any free proto_family!\n");
    return err;
}

int wuwa_proto_init(void) {
    int err;
    if (wuwa_build_proto() || wuwa_build_ops())
        return -ENODEV;
    err = proto_register(wuwa_proto_ptr(), 1);
    wuwa_info("proto_register -> %d\n", err);
    if (err)
        goto out;

    err = register_free_family();
    wuwa_info("register_free_family -> %d\n", err);
    if (err)
        goto out_proto;

    return 0;

    sock_unregister(free_family);
out_proto:
    proto_unregister(wuwa_proto_ptr());
out:
    return err;
}

void wuwa_proto_cleanup(void) {
    sock_unregister(free_family);
    proto_unregister(wuwa_proto_ptr());
}

static int wuwa_sock_create(struct net* net, struct socket* sock, int protocol, int kern) {
    if (!capable(CAP_NET_BIND_SERVICE)) {
        return -EACCES;
    }

    uid_t caller_uid = *(uid_t*)&current_cred()->uid;
    if (caller_uid != 0) {
        wuwa_warn("only root can create wuwa socket!\n");
        return -EAFNOSUPPORT;
    }

    if (sock->type != SOCK_RAW) {
        wuwa_warn("socket must be SOCK_RAW!\n");
        return -ENOKEY;
    }

    sock->state = SS_UNCONNECTED;
    struct sock* sk = sk_alloc(net, PF_INET, GFP_KERNEL, wuwa_proto_ptr(), kern);
    if (!sk) {
        wuwa_warn("sk_alloc failed!\n");
        return -ENOBUFS;
    }

    wuwa_family_ops.family = free_family;
    sock->ops = wuwa_ops_ptr();
    sock_init_data(sock, sk);

    struct wuwa_sock* ws = (struct wuwa_sock*)sk;
    ws->version = 1;
    ws->session = wuwa_t_pid(current);
    ws->used_pages = arraylist_create(4);

    return 0;
}

struct net_proto_family wuwa_family_ops = {
    .family = PF_DECnet,
    .create = wuwa_sock_create,
    .owner = THIS_MODULE,
};
