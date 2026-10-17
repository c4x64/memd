#ifndef MEMD_SOCK_H
#define MEMD_SOCK_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/sock.h>

struct memd_sock {
    struct sock sk;

    /* Slack: the running kernel's struct sock may exceed the build
     * baseline's (5.10 headers on newer targets — proven: total grows
     * per generation). Tail fields live past any plausible true size
     * (deltas are tens of bytes; this is 2K) and the slab, sized by
     * sizeof, covers everything. Without this, the slab object is
     * smaller than the kernel's sock (heap overflow on first socket)
     * and our tail overwrites live sock state. */
    char priv_pad[2048];

    int version;

    pid_t session;

    struct karray_list* used_pages;

    struct list_head list;
};

#define SOCK_OPT_SET_MODULE_VISIBLE 100

#endif // MEMD_SOCK_H
/* kmod/memd/net/memd_sock.h[∂] */
