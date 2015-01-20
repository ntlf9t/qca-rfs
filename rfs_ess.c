/*
 * rfs_ess.c
 *	Receiving Flow Streering - Ethernet Subsystem API
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/inetdevice.h>
#include <linux/of.h>
#include <linux/bitops.h>
#include <net/route.h>
#include <net/sock.h>
#include <asm/byteorder.h>

#include "rfs.h"
#include "rfs_rule.h"
#include "rfs_nbr.h"
#include "rfs_cm.h"

/*
 * RSS key base address
 * It should be in a header file of EDMA driver or SOC
 */
#define RSS_KEY_BASE_ADDR 0x0898


#define BIT_OF_BYTE(nr)   (0x80 >> (nr))
#define BIT_OF_WORD(nr)   (0x80000000 >> (nr))

/*
 * Per-module structure.
 */
struct rfs_ess {
	uint32_t hashkey[10];
};

static struct rfs_ess __ess = {
	/*
	 * Default hash key, 0x6d is the left-most byte, and
	 * its most-significant bit is the left-most bit.
	 * This is for a little endian system.
	 * The key stored in ESS registers is in 10 words, they
	 * were stored in reversed order and big endian!
	 */
#ifdef __LITTLE_ENDIAN
	.hashkey = { 0xda565a6d, 0xc20e5b25, 0x3d256741, 0xb08fa343,
		     0xcb2bcad0, 0xb4307bae, 0xa32dcb77, 0x0cf23080,
		     0x3bb7426a, 0xfa01acbe },
#else
	.hashkey = { 0x6d5a56da, 0x255b0ec2, 0x4167253d, 0x43a38fb0,
		     0xd0ca2bcb, 0xae7b30b4, 0x77cb2da3, 0x8030f20c,
		     0x6a42b73b, 0xbeac01fa },
#endif
};


/*
 * rfs_ess_compute_hash
 *	It's same as Toeplitz algorithm
 */
static uint32_t rfs_ess_compute_hash(char *buf, int len, char *key)
{
	uint32_t tkey;
	uint32_t hash;
	int  byte, bit;
	int  kbyte, kbit;
	int  i, j;


	hash = 0;
	/*
	 * for each bit of input from left to right
	 */
	for (i = 0; i < len * BITS_PER_BYTE; i++) {
		byte = i/BITS_PER_BYTE;
		bit  = i%BITS_PER_BYTE;

		if ((buf[byte] & BIT_OF_BYTE(bit)) == 0)
			continue;

		/*
		 * get hash the key beginning with the ith bit
		 */
		tkey = 0;
		for ( j = i; j < i + 32; j ++) {
			kbyte = j/BITS_PER_BYTE;
			kbit  = j%BITS_PER_BYTE;
			if (key[kbyte] & BIT_OF_BYTE(kbit))
				tkey |= BIT_OF_WORD(j - i);
		}
		hash ^= tkey;

	}

	return hash;
}

/*
 * rfs_ess_get_rxhash
 *	calculate rxhash by 4-tuple
 */
uint32_t rfs_ess_get_rxhash(__be32 sip, __be32 dip,
			    __be16 sport, __be16 dport)
{
	char buf[64];
	char *pos;

	pos = buf;
	memcpy(pos, &sip, sizeof(sip));
	pos += sizeof(sip);
	memcpy(pos, &dip, sizeof(dip));
	pos += sizeof(dip);
	memcpy(pos, &sport, sizeof(sport));
	pos += sizeof(sport);
	memcpy(pos, &dport, sizeof(dport));
	pos += sizeof(dport);
	return rfs_ess_compute_hash(buf, pos - buf, (char *)__ess.hashkey);
}


/*
 * rfs_ess_update_mac_rule
 */
int rfs_ess_update_mac_rule(uint8_t *addr, uint16_t cpu)
{
	/*
	 * Set MAC rule
	 * Todo: add SSDK APIs
	 */
	RFS_INFO("Set MAC rule : address %pM cpu %d\n", addr, cpu);

	/*
	 * Apply the rule to layer 3(IP)
	 */

	rfs_nbr_update_rules(addr, cpu);
	return 0;
}


/*
 * rfs_ess_update_ip_rule
 */
int rfs_ess_update_ip_rule(int family, uint8_t *addr, uint16_t cpu)
{
	/*
	 * Set IP rule
	 * Todo: add SSDK APIs
	 */
	if (family == AF_INET)
		RFS_INFO("Set IP rule: IP: %pI4 cpu %d\n",
			   (__be32 *)addr, cpu);
	else
		RFS_INFO("Set IP rule: IP: %pI6 cpu %d\n",
			   (__be32 *)addr, cpu);

	/*
	 * Apply the rule to layer 4(TCP/UDP)
	 */
	if (family == AF_INET)
		rfs_cm_update_rules(*(__be32 *)addr, cpu);

	return 0;
}


/*
 * rfs_ess_update_tuple_rule_by_kernel
 */
static int rfs_ess_update_tuple_rule_by_kernel(uint32_t rxhash, uint16_t cpu)
{
	unsigned int index;
	struct rps_sock_flow_table *sock_flow_table;
	/*
	 * Set tuple rules through kernel RPS
	 */
	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	if (sock_flow_table) {
		index = rxhash & sock_flow_table->mask;
		if (sock_flow_table->ents[index] != cpu)
			sock_flow_table->ents[index] = cpu;
	}
	rcu_read_unlock();

	return 0;
}


/*
 * rfs_ess_update_tuple_rule
 */
int rfs_ess_update_tuple_rule(uint32_t orig_rxhash, uint32_t reply_rxhash, uint16_t cpu)
{
	if (orig_rxhash)
		rfs_ess_update_tuple_rule_by_kernel(orig_rxhash, cpu);

	if (reply_rxhash)
		rfs_ess_update_tuple_rule_by_kernel(reply_rxhash, cpu);

	return 0;
}


/*
 * rfs_ess_init()
 */
int rfs_ess_init(void)
{
	struct device_node *switch_node = NULL;
	const __be32 *reg_cfg;
	uint32_t reg_base_addr;
	uint32_t reg_size;
	uint8_t __iomem *virt_base_addr;
	uint32_t len = 0;
	int i;

	RFS_DEBUG("RFS ess init\n");

	/*
	 * Parse DT node of switch
	 */
	switch_node = of_find_node_by_name(NULL, "edma");
	if (!switch_node) {
		RFS_ERROR("Cannot find ess-switch\n");
		return -1;
	}

	reg_cfg = of_get_property(switch_node, "reg", &len);
	if (!reg_cfg) {
		RFS_ERROR("Cann't reg config\n");
		return -1;
	}

	reg_base_addr = be32_to_cpup(reg_cfg);
	reg_size = be32_to_cpup(reg_cfg + 1);

	virt_base_addr = ioremap_nocache(reg_base_addr, reg_size);
	if (!virt_base_addr) {
		RFS_ERROR("Iomap failed\n");
	}

	/*
	 * Get ESS RX hash key through EDMA registers
	 */
	for (i = 0; i < 10; i++) {
		uint32_t reg_val;
		reg_val = readl(virt_base_addr + RSS_KEY_BASE_ADDR + i * sizeof(uint32_t));
		/*
		 * Transform big endian to cpu byte order
		 */
		reg_val = __be32_to_cpu(reg_val);
		if (reg_val != __ess.hashkey[9-i]) {
			RFS_INFO("Not default RSS key %d : 0x%08x\n", i, reg_val);
		}
		__ess.hashkey[9- i] = reg_val;
	}

	iounmap(virt_base_addr);

	return 0;
}

/*
 * rfs_rule_exit()
 */
void rfs_ess_exit(void)
{
	RFS_DEBUG("RFS ess exit\n");
}


