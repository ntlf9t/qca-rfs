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

int rfs_rule_create_mac_rule(uint8_t *addr, uint16_t cpu);
int rfs_rule_destroy_mac_rule(uint8_t *addr);
uint16_t rfs_rule_get_cpu_by_ipaddr(__be32 ipaddr);
uint16_t rfs_rule_get_cpu_by_imaddr(int family, uint8_t *ipaddr, uint8_t *maddr);

int rfs_rule_init(void);
void rfs_rule_exit(void);

#endif
