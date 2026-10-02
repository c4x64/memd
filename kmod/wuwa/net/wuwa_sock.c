#include "wuwa_sock.h"
#include "wuwa_netlayout.h"

#include <linux/string.h>
#include "wuwa_region.h"
#include <asm/pgalloc.h>
#include <asm/pgtable-hwdef.h>
#include "wuwa_ioctl.h"
#include "wuwa_protocol.h"
#include "wuwa_utils.h"


static int wuwa_release(struct socket* sock) {
    struct sock* sk;
    struct wuwa_sock* ws;
    wuwa_info("release enter\n");
    sk = sock->sk;
    wuwa_info("release sk=%px\n", sk);
    if (!sk) {
        return 0;
    }

    ws = (struct wuwa_sock*)sk;
    wuwa_info("release ws session=%d used=%px\n", ws->session,
              ws->used_pages);
    ws->version = 0;

    if (ws->session) {
        wuwa_info("release del region\n");
        wuwa_del_unsafe_region(ws->session);
        ws->session = 0;
    }

    if (ws->used_pages) {
        wuwa_info("release free pages n=%lu\n", (unsigned long)ws->used_pages->size);
        for (int i = 0; i < ws->used_pages->size; ++i) {
            struct page* page = (typeof(page))arraylist_get(ws->used_pages, i);
            if (page) {
                __free_page(page);
            }
        }
        wuwa_info("free %lu used pages\n", ws->used_pages->size);
        arraylist_destroy(ws->used_pages);
        wuwa_info("release pages done\n");
    }

    wuwa_info("release orphan\n");
    /* TEST: skip sock_orphan (takes sk_callback_lock which panics on
     * foreign layout). Our socket has no callbacks/timers/packets —
     * nothing needs detaching. If close survives, orphan is the
     * confirmed killer and gets a layout-safe replacement. */
    wuwa_info("release put\n");
    sock_put(sk);
    wuwa_info("release done\n");
    return 0;
}

static int wuwa_ioctl(struct socket* sock, unsigned int cmd, unsigned long arg) {
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

    wuwa_warn("unsupported ioctl command: %u\n", cmd);
    return -ENOTTY;
}

static __poll_t wuwa_poll(struct file* file, struct socket* sock, struct poll_table_struct* wait) { return 0; }

static int wuwa_setsockopt(struct socket* sock, int level, int optname, sockptr_t optval, unsigned int optlen) {
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

static int wuwa_getsockopt(struct socket* sock, int level, int optname, char __user* optval, int __user* optlen) {
    return 0;
}

static int wuwa_bind(struct socket* sock, struct sockaddr* saddr, int len) { return -EOPNOTSUPP; }

static int wuwa_connect(struct socket* sock, struct sockaddr* saddr, int len, int flags) { return -EOPNOTSUPP; }

// int (*)(struct socket *, struct sockaddr *, int)' with an expression of type 'int (struct socket *, struct  sockaddr *, int *, int)
#if  defined(MAGIC_WUWA_GETNAME)
static int wuwa_getname(struct socket* sock, struct sockaddr* saddr, int* len, int peer) { return -EOPNOTSUPP; }
#else
static int wuwa_getname(struct socket* sock, struct sockaddr* saddr, int peer) { return -EOPNOTSUPP; }
#endif

static int wuwa_recvmsg(struct socket* sock, struct msghdr* m, size_t len, int flags) { return -EOPNOTSUPP; }

static int wuwa_sendmsg(struct socket* sock, struct msghdr* m, size_t len) { return -EOPNOTSUPP; }

static int wuwa_socketpair(struct socket *sock1, struct socket *sock2)
{
	return -EOPNOTSUPP;
}

/* Old proto_ops.accept signature on all builds: this stub ignores its
 * args and returns -EOPNOTSUPP, so the 6.12 signature change (extra
 * wrapper struct) is behaviorally irrelevant — one image either way.
 * Stored as a raw pointer (no C-level conversion involved). */
static int wuwa_accept(struct socket *sock, struct socket *newsock, int flags,
		   bool kern)
{
	return -EOPNOTSUPP;
}

static int wuwa_listen(struct socket *sock, int backlog)
{
	return -EOPNOTSUPP;
}

static int wuwa_shutdown(struct socket *sock, int how)
{
	return -EOPNOTSUPP;
}

static int wuwa_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	/* Mirror missing mmap method error code */
	return -ENODEV;
}

/* Runtime-built struct proto_ops (see wuwa_netlayout.h): per-gen slot
 * layouts differ (5.10 lacks owner; 6.12 retypes accept), so the 15
 * callbacks + owner are stored at the RUNNING kernel's offsets into a
 * max-size zeroed buffer. family (offset 0 everywhere, asserted) is set
 * separately once the free family is known. */
static unsigned char wuwa_ops_buf[WUWA_OPS_BUF];

struct proto_ops *wuwa_ops_ptr(void)
{
    return (struct proto_ops *)wuwa_ops_buf;
}

static void wuwa_put64(int off, unsigned long v)
{
    unsigned long x = v;
    memcpy(wuwa_ops_buf + off, &x, 8);
}

int wuwa_build_ops(void)
{
    int g = wuwa_net_gen();
    const struct wuwa_ops_off *o;
    if (g < 0)
        return -1;
    o = &wuwa_ops_offs[g];
    memset(wuwa_ops_buf, 0, sizeof(wuwa_ops_buf));
    if (o->owner >= 0)
        wuwa_put64(o->owner, (unsigned long)THIS_MODULE);
    wuwa_put64(o->release, (unsigned long)wuwa_release);
    wuwa_put64(o->bind, (unsigned long)wuwa_bind);
    wuwa_put64(o->connect, (unsigned long)wuwa_connect);
    wuwa_put64(o->socketpair, (unsigned long)wuwa_socketpair);
    wuwa_put64(o->accept, (unsigned long)wuwa_accept);
    wuwa_put64(o->getname, (unsigned long)wuwa_getname);
    wuwa_put64(o->poll, (unsigned long)wuwa_poll);
    wuwa_put64(o->ioctl, (unsigned long)wuwa_ioctl);
    wuwa_put64(o->listen, (unsigned long)wuwa_listen);
    wuwa_put64(o->shutdown, (unsigned long)wuwa_shutdown);
    wuwa_put64(o->setsockopt, (unsigned long)wuwa_setsockopt);
    wuwa_put64(o->getsockopt, (unsigned long)wuwa_getsockopt);
    wuwa_put64(o->sendmsg, (unsigned long)wuwa_sendmsg);
    wuwa_put64(o->recvmsg, (unsigned long)wuwa_recvmsg);
    wuwa_put64(o->mmap, (unsigned long)wuwa_mmap);
    return 0;
}

void wuwa_ops_set_family(int family)
{
    int f = family;
    memcpy(wuwa_ops_buf, &f, 4);
}
