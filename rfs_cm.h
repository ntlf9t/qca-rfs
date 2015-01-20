/*
 * rfs_cm.h
 *	RFS connection manager - connection manager
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RFS_CM_H
#define __RFS_CM_H
struct rfs_cm_ipv4_connection {
        struct hlist_node conn_hlist;
        struct hlist_node snat_hlist;
        struct hlist_node dnat_hlist;
	struct rcu_head rcu;
        uint8_t protocol;
        __be32 orig_src_ip;
        __be32 orig_dest_ip;
        __be16 orig_src_port;
        __be16 orig_dest_port;
        __be32 reply_src_ip;
        __be32 reply_dest_ip;
        __be16 reply_src_port;
        __be16 reply_dest_port;
	uint32_t orig_rxhash;
	uint32_t reply_rxhash;
	uint32_t flag;
        uint16_t cpu;
};

#define RFS_CM_FLAG_SNAT 0x0001
#define RFS_CM_FLAG_DNAT 0x0002

int rfs_cm_update_rules(__be32 ipaddr, uint16_t cpu);
int rfs_cm_init(void);
void rfs_cm_exit(void);
#endif
