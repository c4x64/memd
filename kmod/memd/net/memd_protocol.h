#ifndef MEMD_PROTOCOL_H
#define MEMD_PROTOCOL_H

#include "memd_common.h"

/* Snapshot view: plain counters (the live ones are atomic64_t inside
 * memd_protocol.c; memd_get_sock_stats converts on copy-out). */
struct memd_sock_stat {
    s64 rx_bytes;
    s64 tx_bytes;
    s64 rx_packets;
    s64 tx_packets;
    s64 errors;
};

int memd_proto_init(void);
void memd_proto_cleanup(void);
int memd_get_sock_stats(struct memd_sock_stat *stats);
int memd_get_sock_count(void);

extern struct net_proto_family memd_family_ops;

#endif /* MEMD_PROTOCOL_H */
/* kmod/memd/net/memd_protocol.h[∂] */
