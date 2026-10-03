#ifndef MEMD_SOCK_H
#define MEMD_SOCK_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/sock.h>

struct memd_sock;

/* proto_ops is runtime-built (memd_netlayout.h); no static instance. */

#define SOCK_OPT_SET_MODULE_VISIBLE 100

#endif // MEMD_SOCK_H
