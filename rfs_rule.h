/*
 * rfs_rule.h
 *	Receiving Flow Streering - Rules
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RFS_RULE_H
#define __RFS_RULE_H

#define MAX_VLAN_PORT 6
struct rfs_rule_entry {
        struct hlist_node hlist;
	struct rcu_head rcu;
	uint32_t type;
	uint8_t mac[ETH_ALEN];
	union {
		__be32  ip4addr;
		struct in6_addr ip6addr;
	} u;
	uint32_t nvid;
	uint32_t vid[MAX_VLAN_PORT];
	uint8_t  vmac[MAX_VLAN_PORT *6];
	uint32_t is_static;
        uint16_t cpu;
};

#define RFS_RULE_TYPE_MAC_RULE 1
#define RFS_RULE_TYPE_IP4_RULE 2
#define RFS_RULE_TYPE_IP6_RULE 3

int rfs_rule_create_mac_rule(uint8_t *addr, uint16_t cpu, uint32_t is_static);
int rfs_rule_destroy_mac_rule(uint8_t *addr,  uint32_t is_static);
int rfs_rule_create_ip_rule(int family, uint8_t *ipaddr, uint8_t *maddr, uint32_t is_static);
int rfs_rule_destroy_ip_rule(int family, uint8_t *addr, uint32_t is_static);
uint16_t rfs_rule_get_cpu_by_ipaddr(__be32 ipaddr);
void rfs_rule_reset_all(void);

int rfs_rule_init(void);
void rfs_rule_exit(void);

#endif
