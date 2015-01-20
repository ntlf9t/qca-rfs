/*
 * rfs_ess.h
 *	Receiving Flow Streering - Ethernet Subsystem API
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RFS_ESS_H
#define __RFS_ESS_H

int rfs_ess_update_mac_rule(uint8_t *addr, uint16_t cpu);
int rfs_ess_update_ip_rule(int family, uint8_t *addr, uint16_t cpu);
int rfs_ess_update_tuple_rule(uint32_t orig_rxhash, uint32_t reply_rxhash, uint16_t cpu);
uint32_t rfs_ess_get_rxhash(__be32 sip, __be32 dip, __be16 sport, __be16 dport);

int rfs_ess_init(void);
void rfs_ess_exit(void);
#endif
