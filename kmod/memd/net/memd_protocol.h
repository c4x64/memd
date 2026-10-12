#ifndef MEMD_PROTOCOL_H
#define MEMD_PROTOCOL_H

#include "memd_common.h"

struct memd_sock_stat {
    atomic64_t rx_bytes;
    atomic64_t tx_bytes;
    atomic64_t rx_packets;
    atomic64_t tx_packets;
    atomic64_t errors;
};

int memd_proto_init(void);
void memd_proto_cleanup(void);
int memd_get_sock_stats(struct memd_sock_stat *stats);
int memd_get_sock_count(void);

extern struct net_proto_family memd_family_ops;

#endif /* MEMD_PROTOCOL_H */
