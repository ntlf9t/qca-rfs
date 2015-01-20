/*
 * rfs_nbr.h
 *	Receiving Flow Streering - Neighbor Manager
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RFS_NBR_H
#define __RFS_NBR_H
struct rfs_nbr_node {
        struct hlist_node ipaddr_hlist;
        struct hlist_node maddr_hlist;
	struct rcu_head rcu;
	int family;
	union {
		__be32 ip4addr;
		struct in6_addr ip6addr;
	} addr_u;
#define addr_in  addr_u
#define addr_in4 addr_u.ip4addr
#define addr_in6 addr_u.ip6addr
        char maddr[ETH_ALEN];
        uint16_t cpu;

};

uint16_t rfs_nbr_get_cpu_by_ipaddr(int family, int8_t *ipaddr);
int rfs_nbr_update_rules(int8_t *maddr, uint16_t cpu);
int rfs_nbr_init(void);
void rfs_nbr_exit(void);
#endif
