#ifndef MEMD_BINDPROC_H
#define MEMD_BINDPROC_H

#include <linux/socket.h>

int do_bind_proc(struct socket* sock, void __user* arg);

#endif // MEMD_BINDPROC_H