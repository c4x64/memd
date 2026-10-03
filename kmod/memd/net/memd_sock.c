#include "memd_sock.h"
#include "memd_netlayout.h"

#include <linux/string.h>
#include "memd_region.h"
#include <asm/pgalloc.h>
#include <asm/pgtable-hwdef.h>
#include "memd_ioctl.h"
#include "memd_protocol.h"
#include "memd_utils.h"


static int memd_release(struct socket* sock) {
    struct sock* sk;
    struct memd_sock* ws;
    sk = sock->sk;
    if (!sk) {
        return 0;
    }

    ws = (struct memd_sock*)sk;
    ws->version = 0;

    if (ws->session) {
        memd_del_unsafe_region(ws->session);
        ws->session = 0;
    }

    if (ws->used_pages) {
        for (int i = 0; i < ws->used_pages->size; ++i) {
            struct page* page = (typeof(page))arraylist_get(ws->used_pages, i);
            if (page) {
                __free_page(page);
            }
        }
        arraylist_destroy(ws->used_pages);
    }
    /* TEST: skip sock_orphan (takes sk_callback_lock which panics on
     * foreign layout). Our socket has no callbacks/timers/packets —
     * nothing needs detaching. If close survives, orphan is the
     * confirmed killer and gets a layout-safe replacement. */
    sock_put(sk);
    return 0;
}

static int memd_ioctl(struct socket* sock, unsigned int cmd, unsigned long arg) {
    void __user* argp = (void __user*)arg;

    int i;
    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        if (cmd == ioctl_handlers[i].cmd) {
            if (ioctl_handlers[i].handler == NULL) {
                continue;
            }
            return ioctl_handlers[i].handler(sock, argp);
        }
    }

    memd_warn("unsupported ioctl command: %u\n", cmd);
    return -ENOTTY;
}

static __poll_t memd_poll(struct file* file, struct socket* sock, struct poll_table_struct* wait) { return 0; }

static int memd_setsockopt(struct socket* sock, int level, int optname, sockptr_t optval, unsigned int optlen) {
#if defined(BUILD_HIDE_SIGNAL)
    if (optname == SOCK_OPT_SET_MODULE_VISIBLE) {
        if (optval.user != NULL) {
            show_module();
        } else {
            hide_module();
        }
        return 0;
    }
#endif

    return -ENOPROTOOPT;
}

static int memd_getsockopt(struct socket* sock, int level, int optname, char __user* optval, int __user* optlen) {
    return 0;
}

static int memd_bind(struct socket* sock, struct sockaddr* saddr, int len) { return -EOPNOTSUPP; }

static int memd_connect(struct socket* sock, struct sockaddr* saddr, int len, int flags) { return -EOPNOTSUPP; }

// int (*)(struct socket *, struct sockaddr *, int)' with an expression of type 'int (struct socket *, struct  sockaddr *, int *, int)
#if  defined(MAGIC_MEMD_GETNAME)
static int memd_getname(struct socket* sock, struct sockaddr* saddr, int* len, int peer) { return -EOPNOTSUPP; }
#else
static int memd_getname(struct socket* sock, struct sockaddr* saddr, int peer) { return -EOPNOTSUPP; }
#endif

static int memd_recvmsg(struct socket* sock, struct msghdr* m, size_t len, int flags) { return -EOPNOTSUPP; }

static int memd_sendmsg(struct socket* sock, struct msghdr* m, size_t len) { return -EOPNOTSUPP; }

static int memd_socketpair(struct socket *sock1, struct socket *sock2)
{
	return -EOPNOTSUPP;
}

/* Old proto_ops.accept signature on all builds: this stub ignores its
 * args and returns -EOPNOTSUPP, so the 6.12 signature change (extra
 * wrapper struct) is behaviorally irrelevant — one image either way.
 * Stored as a raw pointer (no C-level conversion involved). */
static int memd_accept(struct socket *sock, struct socket *newsock, int flags,
		   bool kern)
{
	return -EOPNOTSUPP;
}

static int memd_listen(struct socket *sock, int backlog)
{
	return -EOPNOTSUPP;
}

static int memd_shutdown(struct socket *sock, int how)
{
	return -EOPNOTSUPP;
}

static int memd_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	/* Mirror missing mmap method error code */
	return -ENODEV;
}

/* Runtime-built struct proto_ops (see memd_netlayout.h): per-gen slot
 * layouts differ (5.10 lacks owner; 6.12 retypes accept), so the 15
 * callbacks + owner are stored at the RUNNING kernel's offsets into a
 * max-size zeroed buffer. family (offset 0 everywhere, asserted) is set
 * separately once the free family is known. */
static unsigned char memd_ops_buf[MEMD_OPS_BUF];

struct proto_ops *memd_ops_ptr(void)
{
    return (struct proto_ops *)memd_ops_buf;
}

static void memd_put64(int off, unsigned long v)
{
    unsigned long x = v;
    memcpy(memd_ops_buf + off, &x, 8);
}

int memd_build_ops(void)
{
    int g = memd_net_gen();
    const struct memd_ops_off *o;
    if (g < 0)
        return -1;
    o = &memd_ops_offs[g];
    memset(memd_ops_buf, 0, sizeof(memd_ops_buf));
    if (o->owner >= 0)
        memd_put64(o->owner, (unsigned long)THIS_MODULE);
    memd_put64(o->release, (unsigned long)memd_release);
    memd_put64(o->bind, (unsigned long)memd_bind);
    memd_put64(o->connect, (unsigned long)memd_connect);
    memd_put64(o->socketpair, (unsigned long)memd_socketpair);
    memd_put64(o->accept, (unsigned long)memd_accept);
    memd_put64(o->getname, (unsigned long)memd_getname);
    memd_put64(o->poll, (unsigned long)memd_poll);
    memd_put64(o->ioctl, (unsigned long)memd_ioctl);
    memd_put64(o->listen, (unsigned long)memd_listen);
    memd_put64(o->shutdown, (unsigned long)memd_shutdown);
    memd_put64(o->setsockopt, (unsigned long)memd_setsockopt);
    memd_put64(o->getsockopt, (unsigned long)memd_getsockopt);
    memd_put64(o->sendmsg, (unsigned long)memd_sendmsg);
    memd_put64(o->recvmsg, (unsigned long)memd_recvmsg);
    memd_put64(o->mmap, (unsigned long)memd_mmap);
    return 0;
}

void memd_ops_set_family(int family)
{
    int f = family;
    memcpy(memd_ops_buf, &f, 4);
}
