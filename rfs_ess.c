/*
 * Copyright (c) 2014 - 2015, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * rfs_ess.c
 *	Receiving Flow Streering - Ethernet Subsystem API
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
#include "rfs_dev.h"

/*
 * RSS key base address
 * It should be in a header file of EDMA driver or SOC
 */
#define RSS_KEY_BASE_ADDR 0x0898


#define BIT_OF_BYTE(nr)   (0x80 >> (nr))
#define BIT_OF_WORD(nr)   (0x80000000 >> (nr))


struct rfs_vif {
	char ifname[IFNAMSIZ];
	uint8_t mac[ETH_ALEN];
	uint32_t vid;
	struct rfs_vif *next;
};

/*
 * Per-module structure.
 */
struct rfs_ess {
	uint32_t hashkey[10];
	struct rfs_vif *wan;
	struct rfs_vif *lan;
	spinlock_t vif_lock;
	struct proc_dir_entry *proc_vif;
	struct rfs_device *dev;
	spinlock_t dev_lock;
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

	hash = (uint16_t)hash;
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
 * rfs_ess_mac_rule_set
 */
static int rfs_ess_mac_rule_set(uint32_t vid, uint8_t *mac, uint16_t cpu)
{
	int ret;
	int is_set;
	struct rfs_device *dev;
	struct rfs_ess *ess = &__ess;

	rcu_read_lock();
	dev = rcu_dereference(ess->dev);

	if (!dev || !dev->mac_rule_cb) {
		rcu_read_unlock();
		return 0;
	}

	if (cpu == RPS_NO_CPU) {
		is_set = 0;
	} else {
		is_set = 1;
	}

	ret = dev->mac_rule_cb((uint16_t)vid, mac, (uint8_t)cpu, is_set);
	rcu_read_unlock();

	return ret;
}

/*
 * rfs_ess_ip4_rule_set
 */
static int rfs_ess_ip4_rule_set(uint32_t vid, __be32 ipaddr, uint8_t *mac, uint16_t cpu)
{
	int ret;
	int is_set;
	struct rfs_device *dev;
	struct rfs_ess *ess = &__ess;

	rcu_read_lock();
	dev = rcu_dereference(ess->dev);

	if (!dev || !dev->ip4_rule_cb) {
		rcu_read_unlock();
		return 0;
	}

	if (cpu == RPS_NO_CPU) {
		is_set = 0;
	} else {
		is_set = 1;
	}

	ret = dev->ip4_rule_cb((uint16_t)vid, __swab32(ipaddr), mac, (uint8_t)cpu, is_set);
	rcu_read_unlock();

	return ret;
}


/*
 * rfs_ess_ip6_rule_set
 */
static int rfs_ess_ip6_rule_set(uint32_t vid, struct in6_addr *ipaddr, uint8_t *mac, uint16_t cpu)
{
	int ret;
	int is_set;
	struct rfs_device *dev;
	struct rfs_ess *ess = &__ess;

	rcu_read_lock();
	dev = rcu_dereference(ess->dev);

	if (!dev || !dev->ip6_rule_cb) {
		rcu_read_unlock();
		return 0;
	}


	if (cpu == RPS_NO_CPU) {
		is_set = 0;
	} else {
		is_set = 1;
	}

	ret = dev->ip6_rule_cb((uint16_t)vid, (uint8_t *)ipaddr, mac, (uint8_t)cpu, is_set);
	rcu_read_unlock();

	return ret;
}


/*
 * rfs_ess_create_vif
 */
static int rfs_ess_create_vif(int iswan, char *ifname)
{
	struct rfs_ess *ess = &__ess;
	struct rfs_vif *vif;
	struct rfs_vif **hvif;
	char *pos;
	uint32_t vid;
	uint8_t mac[ETH_ALEN];
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, ifname);
	if (!dev || !dev->dev_addr) {
		RFS_WARN("Invalid ifname %s\n", ifname);
		return -1;
	}

	memcpy(mac, dev->dev_addr, ETH_ALEN);
	dev_put(dev);

	pos = strstr(ifname, ".");
	if (pos) {
		vid = simple_strtoul(pos+1, NULL, 10);
	} else {
		vid = 0;
	}

	if (iswan)
		hvif = &ess->wan;
	else
		hvif = &ess->lan;

	spin_lock_bh(&ess->vif_lock);
	vif = *hvif;
	while (vif) {
		if (strcmp(ifname, vif->ifname) == 0)
			break;
		vif = vif->next;
	}

	if (!vif) {
		vif = kzalloc(sizeof(struct rfs_vif), GFP_ATOMIC);
		vif->next = *hvif;
		*hvif = vif;
	}

	if (!vif) {
		spin_unlock_bh(&ess->vif_lock);
		return -EFAULT;
	}

	memcpy(vif->ifname, ifname, IFNAMSIZ);
	memcpy(vif->mac, mac, ETH_ALEN);
	vif->vid = vid;
	spin_unlock_bh(&ess->vif_lock);

	return 0;
}


/*
 * rfs_ess_destroy_vifs
 */
static int rfs_ess_destroy_vifs(void)
{
	struct rfs_ess *ess = &__ess;
	struct rfs_vif *vif, *next;

	spin_lock_bh(&ess->vif_lock);
	vif = ess->wan;
	ess->wan = NULL;
	while (vif) {
		next = vif->next;
		kfree(vif);
		vif = next;
	}

	vif = ess->lan;
	ess->lan = NULL;
	while (vif) {
		next = vif->next;
		kfree(vif);
		vif = next;
	}

	spin_unlock_bh(&ess->vif_lock);
	return 0;
}


/*
 * rfs_ess_get_vid_wan
 */
static int rfs_ess_get_ifvid_wan(uint32_t *ifvid, uint8_t *ifmac, uint32_t *ifnum)
{
	struct rfs_vif *vif;
	struct rfs_ess *ess = &__ess;
	int array_size = *ifnum;

	*ifnum = 0;
	vif = ess->wan;

	spin_lock_bh(&ess->vif_lock);
	while (vif) {
		if (*ifnum + 1 > array_size) {
			break;
		}
		ifvid[*ifnum] = vif->vid;
		memcpy(ifmac, vif->mac, ETH_ALEN);
		ifmac += ETH_ALEN;
		*ifnum = *ifnum +1;
		vif = vif->next;
	}
	spin_unlock_bh(&ess->vif_lock);

	return 0;
}


/*
 * rfs_ess_get_vid_lan
 */
static int rfs_ess_get_ifvid_lan(uint32_t hvid, uint32_t *ifvid, uint32_t *ifnum)
{
	struct rfs_vif *vif;
	struct rfs_ess *ess = &__ess;
	int array_size = *ifnum;

	*ifnum = 0;
	vif = ess->lan;

	spin_lock_bh(&ess->vif_lock);
	while (vif) {
		if (hvid == vif->vid) {
			vif = vif->next;
			continue;
		}

		if (*ifnum + 1 > array_size) {
			break;
		}
		ifvid[*ifnum] = vif->vid;
		*ifnum = *ifnum +1;
		vif = vif->next;
	}

	spin_unlock_bh(&ess->vif_lock);

	return 0;
}


/*
 * rfs_ess_update_mac_rule
 *	The parameter 'cpu' may differ from re->cpu
 *	re->cpu          cpu
 *	RPS_NO_CPU       cpuid              new rule
 *	cpuid	         RPS_NO_CPU         clear rule
 *	cpuid            cpuid              reset rule(vid change)
 */
int rfs_ess_update_mac_rule(struct rfs_rule_entry *re, uint16_t cpu)
{
	int i;
	uint32_t nvif;
	uint32_t ifvid[MAX_VLAN_PORT];


	/*
	 * Get VLAN ID of LAN
	 */
	nvif = MAX_VLAN_PORT;
	rfs_ess_get_ifvid_lan(re->hvid, ifvid, &nvif);


	/*
	 * Clear old  MAC rule
	 */
	if (re->cpu != RPS_NO_CPU && re->nvif > 0) {
		if (re->cpu == cpu &&
			nvif == re->nvif &&
			!memcmp(ifvid, re->ifvid, sizeof(uint32_t) * nvif)) {
			return 0;
		}

		RFS_DEBUG("Clear old MAC rule : address %pM cpu %d\n", re->mac, re->cpu);
		/*for each vid*/
		for (i = 0; i < re->nvif; i++) {
			if (rfs_ess_mac_rule_set(re->ifvid[i], re->mac, RPS_NO_CPU) < 0) {
				RFS_INFO("Failed to set ssdk rule: vid %d addr %pM cpu %d\n",
					re->ifvid[i], re->mac, re->cpu);
			}
		}
	}


	re->nvif = nvif;
	if (nvif == 0) {
		return 0;
	}
	memcpy(re->ifvid, ifvid, sizeof(uint32_t) * nvif);

	if (cpu == RPS_NO_CPU) {
		return 0;
	}

	/*
	 * Set MAC rule
	 */
	RFS_DEBUG("Set MAC rule : address %pM cpu %d\n", re->mac, cpu);
	/*for each vid*/
	for (i = 0; i < nvif; i++) {
		if (rfs_ess_mac_rule_set(re->ifvid[i], re->mac, cpu) < 0) {
			RFS_INFO("Failed to set ssdk rule: vid %d addr %pM cpu %d\n",
				re->ifvid[i], re->mac, cpu);
		}
	}

	return 0;
}


/*
 * rfs_ess_update_ip_rule
 *	The parameter 'cpu' may differ from re->cpu
 *	re->cpu          cpu
 *	RPS_NO_CPU       cpuid              new rule
 *	cpuid	         RPS_NO_CPU         clear rule
 *	cpuid            cpuid              reset rule(vid change)
 */
int rfs_ess_update_ip_rule(struct rfs_rule_entry *re, uint16_t cpu)
{
	int i;
	uint32_t nvif = 0;
	uint32_t ifvid[MAX_VLAN_PORT];
	uint8_t  ifmac[MAX_VLAN_PORT * ETH_ALEN];
	int ret;

	/*
	 * Get VLAN ID of WAN
	 */
	nvif = MAX_VLAN_PORT;
	rfs_ess_get_ifvid_wan(ifvid, ifmac, &nvif);


	/*
	 * Clear old  IP rule
	 */
	if (re->cpu != RPS_NO_CPU && re->nvif > 0) {
		if (re->cpu == cpu &&
			nvif == re->nvif &&
			!memcmp(ifvid, re->ifvid, sizeof(uint32_t) * nvif)) {
			return 0;
		}

		if (re->type == RFS_RULE_TYPE_IP4_RULE)
			RFS_DEBUG("Clear old IP rule : address %pI4 cpu %d\n", (__be32 *)&re->u.ip4addr, re->cpu);
		else
			RFS_DEBUG("Clear old IP rule : address %pI6 cpu %d\n", (__be32 *)&re->u.ip6addr, re->cpu);

		/*for each vid*/
		for (i = 0; i < re->nvif; i++) {
			if (re->type == RFS_RULE_TYPE_IP4_RULE) {
				ret = rfs_ess_ip4_rule_set(re->ifvid[i], re->u.ip4addr,
					&re->ifmac[i * ETH_ALEN], RPS_NO_CPU);
				if (ret < 0) {
					RFS_INFO("Failed to clear ssdk rule: vid %d addr %pI4 cpu %d\n",
						re->ifvid[i], &re->u.ip4addr, re->cpu);
				}
			} else {
				ret = rfs_ess_ip6_rule_set(re->ifvid[i], &re->u.ip6addr,
					&re->ifmac[i * ETH_ALEN], RPS_NO_CPU);
				if (ret < 0) {
					RFS_INFO("Failed to clear ssdk rule: vid %d addr %pI6 cpu %d\n",
						re->ifvid[i], &re->u.ip6addr, re->cpu);
				}
			}

		}

	}

	re->nvif = nvif;
	if (nvif == 0) {
		goto l4update;
	}
	memcpy(re->ifvid, ifvid, sizeof(uint32_t) * nvif);
	memcpy(re->ifmac, ifmac, ETH_ALEN * nvif);


	/*
	 * The caller just wants to clear the SSDK rule, no new rules will be set
	 */
	if (cpu == RPS_NO_CPU) {
		goto l4update;
	}
	/*
	 * Set IP rule
	 */
	if (re->type == RFS_RULE_TYPE_IP4_RULE)
		RFS_DEBUG("Set IP rule: IP: %pI4 cpu %d\n",
			   (__be32 *)&re->u.ip4addr, cpu);
	else
		RFS_DEBUG("Set IP rule: IP: %pI6 cpu %d\n",
			   (__be32 *)&re->u.ip6addr, cpu);

	/*for each vid*/
	for (i = 0; i < re->nvif; i++) {
		if (re->type == RFS_RULE_TYPE_IP4_RULE) {
			ret = rfs_ess_ip4_rule_set(re->ifvid[i], re->u.ip4addr,
				&re->ifmac[i * ETH_ALEN], cpu);
			if (ret < 0) {
				RFS_INFO("Failed to set ssdk rule: vid %d addr %pI4 ifaddr %pM cpu %d\n",
						re->ifvid[i], &re->u.ip4addr, &re->ifmac[i * ETH_ALEN], cpu);
			}
		} else {
			ret = rfs_ess_ip6_rule_set(re->ifvid[i], &re->u.ip6addr,
				&re->ifmac[i * ETH_ALEN], cpu);
			if (ret < 0) {
				RFS_INFO("Failed to set ssdk rule: vid %d addr %pI6 ifaddr %pM cpu %d\n",
						re->ifvid[i], &re->u.ip6addr, &re->ifmac[i * ETH_ALEN], cpu);
			}
		}
	}


l4update:
	/*
	 * Apply the rule to layer 4(TCP/UDP)
	 */
	if (re->type == RFS_RULE_TYPE_IP4_RULE && re->cpu != cpu)
		rfs_cm_update_rules(re->u.ip4addr, cpu);

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
 * rfs_ess_device_register
 */
int rfs_ess_device_register(struct rfs_device *dev)
{
	struct rfs_ess *ess = &__ess;
	struct rfs_device *odev;

	spin_lock_bh(&ess->dev_lock);
	odev = rcu_dereference(ess->dev);
	if (odev) {
		RFS_WARN("ESS dev[%s] has registered\n", odev->name);
		spin_unlock_bh(&ess->dev_lock);
		return -1;
	}

	rcu_assign_pointer(ess->dev, dev);
	spin_unlock_bh(&ess->dev_lock);
	return 0;
}
EXPORT_SYMBOL(rfs_ess_device_register);

/*
 * rfs_ess_device_unregister
 */
int rfs_ess_device_unregister(struct rfs_device *dev)
{
	struct rfs_ess *ess = &__ess;
	struct rfs_device *odev;

	spin_lock_bh(&ess->dev_lock);
	odev = rcu_dereference(ess->dev);
	if (odev != dev) {
		RFS_WARN("ESS dev[%s] has not registered\n", dev->name);
		spin_unlock_bh(&ess->dev_lock);
		return -1;
	}

	rcu_assign_pointer(ess->dev, NULL);
	spin_unlock_bh(&ess->dev_lock);

	return 0;
}
EXPORT_SYMBOL(rfs_ess_device_unregister);


/*
 * rfs_ess_proc_show
 *	show RFS rules in proc
 */
static int rfs_ess_vif_proc_show(struct seq_file *m, void *v)
{
	struct rfs_ess *ess = &__ess;
	struct rfs_vif *vif;
	seq_printf(m, "ESS VLAN configuration:\n");

	spin_lock_bh(&ess->vif_lock);

	vif = ess->wan;
	while (vif) {
		seq_printf(m, "WAN %16s %4d    %pM\n", vif->ifname, vif->vid, vif->mac);
		vif = vif->next;
	}


	vif = ess->lan;
	while (vif) {
		seq_printf(m, "LAN %16s %4d    %pM\n", vif->ifname, vif->vid, vif->mac);
		vif = vif->next;
	}

	seq_putc(m, '\n');
	spin_unlock_bh(&ess->vif_lock);
	return 0;
}


/*
 * rfs_ess_proc_write
 *	get ESS vlan configuration
 */
static ssize_t rfs_ess_vif_proc_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char buf[64];
	char ifname[IFNAMSIZ];
	char cmd[8];
	int nvar;

	count = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';

	memset(ifname, 0, sizeof(ifname));
	memset(cmd, 0, sizeof(cmd));
	nvar = sscanf(buf, "%8s %16s", cmd, ifname);

	if (!strcmp(cmd, "wan") && nvar == 2) {
		rfs_ess_create_vif(1, ifname);
	} else if (!strcmp(cmd, "lan") && nvar == 2) {
		rfs_ess_create_vif(0, ifname);
	} else if (!strcmp(cmd, "reset") && nvar == 1) {
		rfs_ess_destroy_vifs();
	} else {
		RFS_WARN("Unknown configuration\n");
		return count;
	}

	rfs_rule_reset_all();
	return count;

}


/*
 * rfs_ess_proc_open
 */
static int rfs_ess_vif_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, rfs_ess_vif_proc_show, NULL);
}


/*
 * struct file_operations ess_proc_fops
 */
static const struct file_operations ess_vif_proc_fops = {
	.owner = THIS_MODULE,
	.open  = rfs_ess_vif_proc_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.write  = rfs_ess_vif_proc_write,
	.release = single_release,
};


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

	spin_lock_init(&__ess.vif_lock);
	spin_lock_init(&__ess.dev_lock);
	__ess.proc_vif = proc_create("vif", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
				    rfs_proc_entry, &ess_vif_proc_fops);

	return 0;
}

/*
 * rfs_rule_exit()
 */
void rfs_ess_exit(void)
{
	RFS_DEBUG("RFS ess exit\n");
	if (__ess.proc_vif);
		remove_proc_entry("vif", rfs_proc_entry);
}


