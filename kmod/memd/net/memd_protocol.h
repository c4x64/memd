#ifndef MEMD_PROTOCOL_H
#define MEMD_PROTOCOL_H

#include "memd_common.h"

int memd_proto_init(void);
void memd_proto_cleanup(void);

extern struct proto memd_proto;
extern struct net_proto_family memd_family_ops;

#endif /* MEMD_PROTOCOL_H */
