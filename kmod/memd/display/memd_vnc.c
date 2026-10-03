#ifdef MEMD_DISP_TEST
/* memd_vnc — TEST-only kernel RFB (VNC) streamer for the display front.
 *
 * Why: dummy-virt has no panel/simplefb/DRM, so kernel pixels have no
 * guest-visible surface. This serves the stable core front as RAW RFB
 * over loopback TCP (port 5901); any VNC viewer shows LIVE kernel
 * pixels on a real monitor. The kernel still owns the frame (refresh
 * thread keeps presenting); the stream is a read-only tap.
 *
 * TEST ONLY (never ship): compiled under MEMD_DISP_TEST, started on
 * display install, stopped on uninstall/rmmod. Binds LOOPBACK only
 * (host reaches it via `adb forward tcp:5901 tcp:5901`). One client at
 * a time, RAW encoding only, unknown messages drop the client
 * (fail closed). All sockets are created, used and released by the
 * serving thread itself; stop is kthread_stop (no cross-thread close:
 * accept/recv poll with MSG_DONTWAIT + should_stop checks).
 *
 * Stable APIs only: sock_create_kern / kernel_{bind,listen,accept,
 * sendmsg,recvmsg} / sock_release (ancient, CI-verified 5.10-6.12).
 */
#include "disp_core.h"
#include "memd_display.h"

#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/overflow.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/byteorder/generic.h>
#include <net/sock.h>

#include "memd_common.h"

#define MEMD_VNC_PORT 5901
#define MEMD_VNC_NAME "memd"

static struct task_struct *g_vnc_task;

/* 16-byte server pixel format: 32bpp/24depth big-endian truecolor,
 * Rmax/Gmax/Bmax 255, shifts 16/8/0. Wire pixels are htonl(front). */
static const __u8 g_vnc_pixfmt[16] = {
    32, 24, 1, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0
};

static void memd_vnc_put16(__u8 *p, __u32 v)
{
    p[0] = (__u8)(v >> 8);
    p[1] = (__u8)v;
}

static void memd_vnc_put32(__u8 *p, __u32 v)
{
    p[0] = (__u8)(v >> 24);
    p[1] = (__u8)(v >> 16);
    p[2] = (__u8)(v >> 8);
    p[3] = (__u8)v;
}

static int memd_vnc_send_all(struct socket *s, const void *buf, size_t len)
{
    struct msghdr msg;
    struct kvec vec;
    size_t done = 0;
    memset(&msg, 0, sizeof(msg));
    while (done < len) {
        int rc;
        if (kthread_should_stop())
            return -EINTR;
        vec.iov_base = (void *)((const __u8 *)buf + done);
        vec.iov_len = len - done;
        rc = kernel_sendmsg(s, &msg, &vec, 1, vec.iov_len);
        if (rc <= 0)
            return rc ? rc : -EPIPE;
        done += (size_t)rc;
    }
    return 0;
}

/* Blocking-ish receive with stop checks (MSG_DONTWAIT + poll). >0 bytes,
 * 0 on orderly disconnect, negative errno (EINTR when stopping). */
static int memd_vnc_recv_all(struct socket *s, void *buf, size_t len)
{
    struct msghdr msg;
    struct kvec vec;
    size_t done = 0;
    memset(&msg, 0, sizeof(msg));
    while (done < len) {
        int rc;
        if (kthread_should_stop())
            return -EINTR;
        vec.iov_base = (void *)((__u8 *)buf + done);
        vec.iov_len = len - done;
        rc = kernel_recvmsg(s, &msg, &vec, 1, vec.iov_len,
                            MSG_DONTWAIT);
        if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
            msleep(10);
            continue;
        }
        if (rc <= 0)
            return rc ? rc : -EPIPE;
        done += (size_t)rc;
    }
    return 1;
}

/* Serve one connected viewer until disconnect/stop. 0 served cleanly. */
static int memd_vnc_serve(struct socket *cs, __u32 *wire)
{
    static const __u8 ver[] = "RFB 003.008\n";
    static const __u8 sec[] = { 1, 1 };
    __u8 tmp[32];
    __u32 w = 0, h = 0;
    size_t px = 0, i;
    int rc;

    rc = memd_vnc_send_all(cs, ver, 12);
    if (rc)
        return rc;
    rc = memd_vnc_recv_all(cs, tmp, 12);      /* client version */
    if (rc <= 0)
        return rc;
    rc = memd_vnc_send_all(cs, sec, 2);       /* one auth: None */
    if (rc)
        return rc;
    rc = memd_vnc_recv_all(cs, tmp, 1);       /* selected scheme */
    if (rc <= 0 || tmp[0] != 1)
        return -EPROTO;
    memd_vnc_put32(tmp, 0);                   /* SecurityResult OK */
    rc = memd_vnc_send_all(cs, tmp, 4);
    if (rc)
        return rc;
    rc = memd_vnc_recv_all(cs, tmp, 1);       /* ClientInit */
    if (rc <= 0)
        return rc;
    /* ServerInit carries the LIVE front dimensions (viewer reconnects
     * on change). Pixels follow per update request. */
    rc = memd_core_copy_front(wire, (MEMD_DISP_MAX_W *
                                     (size_t)MEMD_DISP_MAX_H) * 4, &w, &h);
    if (rc)
        return rc;
    memd_vnc_put16(tmp, w);
    memd_vnc_put16(tmp + 2, h);
    rc = memd_vnc_send_all(cs, tmp, 4);
    if (rc)
        return rc;
    rc = memd_vnc_send_all(cs, g_vnc_pixfmt, 16);
    if (rc)
        return rc;
    memd_vnc_put32(tmp, 4);
    rc = memd_vnc_send_all(cs, tmp, 4);
    if (rc)
        return rc;
    rc = memd_vnc_send_all(cs, MEMD_VNC_NAME, 4);
    if (rc)
        return rc;

    for (;;) {
        __u8 type;
        if (kthread_should_stop())
            return -EINTR;
        rc = memd_vnc_recv_all(cs, &type, 1);
        if (rc <= 0)
            return rc;
        if (type == 0) {                      /* SetPixelFormat */
            rc = memd_vnc_recv_all(cs, tmp, 19);
            if (rc <= 0)
                return rc;
            if (memcmp(tmp + 3, g_vnc_pixfmt, 16))
                return -EPROTO;               /* only our format */
        } else if (type == 2) {               /* SetEncodings */
            __u32 n;
            rc = memd_vnc_recv_all(cs, tmp, 3);
            if (rc <= 0)
                return rc;
            n = ((__u32)tmp[1] << 8) | tmp[2];
            if (n > 64)
                return -EPROTO;
            while (n--) {
                rc = memd_vnc_recv_all(cs, tmp, 4);
                if (rc <= 0)
                    return rc;
            }
        } else if (type == 3) {               /* FramebufferUpdateReq */
            __u8 hdr[16];
            rc = memd_vnc_recv_all(cs, tmp, 9);
            if (rc <= 0)
                return rc;
            rc = memd_core_copy_front(wire, (MEMD_DISP_MAX_W *
                                             (size_t)MEMD_DISP_MAX_H) * 4,
                                      &w, &h);
            if (rc)
                return rc;
            if (check_mul_overflow((size_t)w, (size_t)h, &px) ||
                px > (size_t)MEMD_DISP_MAX_W * MEMD_DISP_MAX_H)
                return -EINVAL;
            for (i = 0; i < px; i++)
                wire[i] = htonl(wire[i]);
            hdr[0] = 0;
            hdr[1] = 0;
            memd_vnc_put16(hdr + 2, 1);
            memd_vnc_put16(hdr + 4, 0);
            memd_vnc_put16(hdr + 6, 0);
            memd_vnc_put16(hdr + 8, (int)w);
            memd_vnc_put16(hdr + 10, (int)h);
            memd_vnc_put32(hdr + 12, 0);      /* RAW */
            rc = memd_vnc_send_all(cs, hdr, 16);
            if (rc)
                return rc;
            rc = memd_vnc_send_all(cs, wire, px * 4);
            if (rc)
                return rc;
        } else if (type == 4) {               /* KeyEvent */
            rc = memd_vnc_recv_all(cs, tmp, 7);
            if (rc <= 0)
                return rc;
        } else if (type == 5) {               /* PointerEvent */
            rc = memd_vnc_recv_all(cs, tmp, 5);
            if (rc <= 0)
                return rc;
        } else if (type == 6) {               /* ClientCutText */
            __u32 n;
            rc = memd_vnc_recv_all(cs, tmp, 7);
            if (rc <= 0)
                return rc;
            n = ((__u32)tmp[3] << 24) | ((__u32)tmp[4] << 16) |
                ((__u32)tmp[5] << 8) | tmp[6];
            if (n > (1u << 20))
                return -EPROTO;
            while (n) {
                __u32 c = n > sizeof(tmp) ? sizeof(tmp) : n;
                rc = memd_vnc_recv_all(cs, tmp, c);
                if (rc <= 0)
                    return rc;
                n -= c;
            }
        } else {
            return -EPROTO;                    /* unknown: drop */
        }
    }
}

static int memd_vnc_fn(void *data)
{
    struct socket *ls = NULL, *cs = NULL;
    struct sockaddr_in addr;
    __u32 *wire = NULL;
    size_t cap = 0;
    int rc;

    (void)data;
    if (check_mul_overflow((size_t)MEMD_DISP_MAX_W,
                           (size_t)MEMD_DISP_MAX_H, &cap) ||
        check_mul_overflow(cap, (size_t)4, &cap) || !cap)
        return -EINVAL;
    wire = vmalloc(cap);
    if (!wire)
        return -ENOMEM;

    rc = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                          &ls);
    if (rc) {
        vfree(wire);
        memd_err("vnc: socket failed (%d), display unaffected\n", rc);
        return rc;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MEMD_VNC_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rc = kernel_bind(ls, (struct sockaddr *)&addr, sizeof(addr));
    if (!rc)
        rc = kernel_listen(ls, 1);
    if (rc) {
        sock_release(ls);
        vfree(wire);
        memd_err("vnc: bind/listen failed (%d), display unaffected\n",
                 rc);
        return rc;
    }

    while (!kthread_should_stop()) {
        rc = kernel_accept(ls, &cs, O_NONBLOCK);
        if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
            msleep(100);
            continue;
        }
        if (rc) {
            if (!kthread_should_stop())
                msleep(500);
            continue;
        }
        memd_info("vnc: viewer connected\n");
        rc = memd_vnc_serve(cs, wire);
        sock_release(cs);
        cs = NULL;
        memd_info("vnc: viewer gone (%d)\n", rc);
    }
    sock_release(ls);
    vfree(wire);
    return 0;
}

/* Called with g_core_mu held (matches refresh thread discipline). */
void memd_vnc_start(void)
{
    if (g_vnc_task)
        return;
    g_vnc_task = kthread_run(memd_vnc_fn, NULL, "memd_vnc");
    if (IS_ERR(g_vnc_task))
        g_vnc_task = NULL;
}

/* Called WITHOUT g_core_mu held (kthread_stop sleeps). */
void memd_vnc_stop(void)
{
    struct task_struct *t = g_vnc_task;
    g_vnc_task = NULL;
    if (t)
        kthread_stop(t);
}

#endif /* MEMD_DISP_TEST */
