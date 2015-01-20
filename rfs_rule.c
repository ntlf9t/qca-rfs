/*
 * rfs_rule.c
 *	Receiving Flow Streering - Rules
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>

#include "rfs.h"
#include "rfs_rule.h"
#include "rfs_ess.h"
#include "rfs_nbr.h"

struct rfs_rule_entry {
        struct hlist_node hlist;
	struct rcu_head rcu;
	uint32_t type;
	union {
		uint8_t mac[ETH_ALEN];
		__be32  ip4addr;
	} u;
	uint32_t flag;
        uint16_t cpu;
};

#define RFS_RULE_TYPE_MAC_RULE 1
#define RFS_RULE_TYPE_IP4_RULE 2


#define RFS_RULE_HASH_SHIFT 8
#define RFS_RULE_HASH_SIZE (1 << RFS_RULE_HASH_SHIFT)
#define RFS_RULE_HASH_MASK (RFS_RULE_HASH_SIZE - 1)


/*
 * Per-module structure.
 */
struct rfs_rule {
	spinlock_t hash_lock;
	struct hlist_head hash[RFS_RULE_HASH_SIZE];
	struct proc_dir_entry *proc_rule;
};

static struct rfs_rule __rr;


/*
 * rfs_rule_hash
 */
unsigned int rfs_rule_hash(uint32_t type, uint8_t *data)
{
	switch (type) {
	case RFS_RULE_TYPE_MAC_RULE:
		return jhash(data, ETH_ALEN, 0) & RFS_RULE_HASH_MASK;
	case RFS_RULE_TYPE_IP4_RULE:
		return jhash(data, 4, 0) & RFS_RULE_HASH_MASK;
	default:
		return 0;
	}
}


/*
 * rfs_rule_rcu_free
 */
static void rfs_rule_rcu_free(struct rcu_head *head)
{
	struct rfs_rule_entry *re
		= container_of(head, struct rfs_rule_entry, rcu);
	kfree(re);
}


/*
 * rfs_rule_create_mac_rule
 */
int rfs_rule_create_mac_rule(uint8_t *addr, uint16_t cpu)
{
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;
	uint32_t type = RFS_RULE_TYPE_MAC_RULE;

	head = &rr->hash[rfs_rule_hash(type, addr)];

	spin_lock_bh(&rr->hash_lock);
	hlist_for_each_entry_rcu(re, head, hlist) {
		if (type != re->type)
			continue;

		if (memcmp(re->u.mac, addr, ETH_ALEN) == 0) {
			break;
		}
	}

	if (re) {
		spin_unlock_bh(&rr->hash_lock);
		return 0;
	}

	/*
	 * Create a rule entry if it doesn't exist
	 */
	re = kzalloc(sizeof(struct rfs_rule_entry), GFP_ATOMIC);
	if (!re ) {
		spin_unlock_bh(&rr->hash_lock);
		return -1;
	}

	memcpy(re->u.mac, addr, ETH_ALEN);
	re->type = type;
	re->cpu = cpu;
	hlist_add_head_rcu(&re->hlist, head);


	RFS_INFO("New MAC rule %pM, cpu %d\n", addr, cpu);
	if (rfs_ess_update_mac_rule(addr, cpu) < 0) {
		RFS_WARN("Failed to update MAC rule %pM, cpu %d\n", addr, cpu);
	}

	spin_unlock_bh(&rr->hash_lock);
	return 0;
}


/*
 * rfs_rule_destroy_mac_rule
 */
int rfs_rule_destroy_mac_rule(uint8_t *addr)
{
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;
	uint16_t cpu;
	uint32_t type = RFS_RULE_TYPE_MAC_RULE;

	head = &rr->hash[rfs_rule_hash(type, addr)];

	spin_lock_bh(&rr->hash_lock);
	hlist_for_each_entry_rcu(re, head, hlist) {
		if (type != re->type)
			continue;

		if (memcmp(re->u.mac, addr, ETH_ALEN) == 0) {
			break;
		}
	}

	if (!re) {
		spin_unlock_bh(&rr->hash_lock);
		return 0;
	}

	hlist_del_rcu(&re->hlist);
	cpu = re->cpu;
	re->cpu = RPS_NO_CPU;

	RFS_INFO("Remove rules: %pM, cpu %d\n", addr, cpu);
	if (rfs_ess_update_mac_rule(addr, RPS_NO_CPU) < 0) {
		RFS_WARN("Failed to update mac rules: %pM, cpu %d\n", addr, cpu);
	}

	call_rcu(&re->rcu, rfs_rule_rcu_free);
	spin_unlock_bh(&rr->hash_lock);

	return 0;
}


/*
 * rfs_rule_create_ip_rule
 */
int rfs_rule_create_ip_rule(uint8_t *addr, uint16_t cpu)
{
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;
	uint32_t type = RFS_RULE_TYPE_IP4_RULE;

	head = &rr->hash[rfs_rule_hash(type, addr)];

	spin_lock_bh(&rr->hash_lock);
	hlist_for_each_entry_rcu(re, head, hlist) {
		if (type != re->type)
			continue;

		if (re->u.ip4addr ==  *(__be32*)addr) {
			break;
		}
	}

	if (re) {
		spin_unlock_bh(&rr->hash_lock);
		return 0;
	}

	/*
	 * Create a rule entry if it doesn't exist
	 */
	re = kzalloc(sizeof(struct rfs_rule_entry), GFP_ATOMIC);
	if (!re ) {
		spin_unlock_bh(&rr->hash_lock);
		return -1;
	}

	re->u.ip4addr =  *(__be32*)addr;
	re->type = type;
	re->cpu = cpu;
	hlist_add_head_rcu(&re->hlist, head);


	RFS_INFO("New IP rule %pI4, cpu %d\n", addr, cpu);
	if (rfs_ess_update_ip_rule(AF_INET, addr, cpu) < 0) {
		RFS_WARN("Failed to update IP rule %pI4, cpu %d\n", addr, cpu);
	}

	spin_unlock_bh(&rr->hash_lock);
	return 0;
}


/*
 * rfs_rule_destroy_ip_rule
 */
int rfs_rule_destroy_ip_rule(uint8_t *addr)
{
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;
	uint32_t type = RFS_RULE_TYPE_IP4_RULE;
	uint16_t cpu;

	head = &rr->hash[rfs_rule_hash(type, addr)];

	spin_lock_bh(&rr->hash_lock);
	hlist_for_each_entry_rcu(re, head, hlist) {
		if (type != re->type)
			continue;

		if (re->u.ip4addr ==  *(__be32*)addr) {
			break;
		}
	}

	if (!re) {
		spin_unlock_bh(&rr->hash_lock);
		return 0;
	}

	hlist_del_rcu(&re->hlist);
	cpu = re->cpu;
	re->cpu = RPS_NO_CPU;

	RFS_INFO("Remove rules: %pI4, cpu %d\n", addr, cpu);
	if (rfs_ess_update_ip_rule(AF_INET, addr, RPS_NO_CPU) < 0) {
		RFS_WARN("Failed to update ip rules: %pI4, cpu %d\n", addr, cpu);
	}

	call_rcu(&re->rcu, rfs_rule_rcu_free);
	spin_unlock_bh(&rr->hash_lock);

	return 0;
}


/*
 * rfs_rule_destroy_all
 */
static void rfs_rule_destroy_all(void)
{
	int index;
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;

	spin_lock_bh(&rr->hash_lock);
	for ( index = 0; index < RFS_RULE_HASH_SIZE; index++) {
		struct hlist_node *n;
		head = &rr->hash[index];
		hlist_for_each_entry_safe(re, n, head, hlist) {
			hlist_del_rcu(&re->hlist);
			rfs_rule_rcu_free(&re->rcu);

		}
	}
	spin_unlock_bh(&rr->hash_lock);
}


/*
 * rfs_rule_get_cpu
 */
static uint16_t rfs_rule_get_cpu(uint32_t type, uint8_t *addr)
{
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;
	uint16_t cpu = RPS_NO_CPU;

	head = &rr->hash[rfs_rule_hash(RFS_RULE_TYPE_MAC_RULE, addr)];
	rcu_read_lock();
	hlist_for_each_entry_rcu(re, head, hlist) {
		if (type != re->type)
			continue;

		if (type == RFS_RULE_TYPE_MAC_RULE) {
			if (memcmp(re->u.mac, addr, ETH_ALEN) == 0) {
				break;
			}
		}
		else if (type == RFS_RULE_TYPE_IP4_RULE) {
			if (re->u.ip4addr ==  *(__be32*)addr) {
				break;
			}
		}
	}

	if (re)
		cpu = re->cpu;

	rcu_read_unlock();
	return cpu;
}


/*
 * rfs_rule_get_cpu_by_ipaddr
 */
uint16_t rfs_rule_get_cpu_by_ipaddr(__be32 ipaddr)
{
	uint16_t cpu = RPS_NO_CPU;
	uint32_t type = RFS_RULE_TYPE_IP4_RULE;
	/*
	 * Static IP rules firstly
	 */
	cpu = rfs_rule_get_cpu(type, (uint8_t *)&ipaddr);

	if (cpu != RPS_NO_CPU)
		return cpu;

	/*
	 * Look up the neighbor who has the dynamic rule
	 */
	cpu = rfs_nbr_get_cpu_by_ipaddr(AF_INET, (uint8_t *)&ipaddr);
	return cpu;
}


/*
 * rfs_rule_get_cpu_by_imaddr
 */
uint16_t rfs_rule_get_cpu_by_imaddr(int family, uint8_t *ipaddr, uint8_t *maddr)
{
	uint16_t cpu = RPS_NO_CPU;
	uint32_t type;

	/*
	 * IP rules have more priority than MAC rules
	 */
	if (family == AF_INET) {
		type = RFS_RULE_TYPE_IP4_RULE;
		cpu = rfs_rule_get_cpu(type, ipaddr);
	}

	if (cpu != RPS_NO_CPU)
		return cpu;

	type = RFS_RULE_TYPE_MAC_RULE;
	cpu = rfs_rule_get_cpu(type, maddr);
	return cpu;
}


/*
 * rfs_rule_proc_show
 *	show RFS rules in proc
 */
static int rfs_rule_proc_show(struct seq_file *m, void *v)
{
	int index;
	int count = 0;
	struct hlist_head *head;
	struct rfs_rule_entry *re;
	struct rfs_rule *rr = &__rr;

	seq_printf(m, "RFS rule table:\n");

	rcu_read_lock();
	for ( index = 0; index < RFS_RULE_HASH_SIZE; index++) {
		head = &rr->hash[index];
		hlist_for_each_entry_rcu(re, head, hlist) {
			seq_printf(m, "%03d hash %08x", ++count, index);
			if (re->type == RFS_RULE_TYPE_MAC_RULE)
				seq_printf(m, " MAC: %pM cpu %d\n", re->u.mac, re->cpu);
			else
				seq_printf(m, " IP: %pI4 cpu %d\n", &re->u.ip4addr, re->cpu);

		}
	}
	seq_putc(m, '\n');
	rcu_read_unlock();
	return 0;
}


/*
 * rfs_rule_proc_write
 *	get user configuration from proc
 */
static ssize_t rfs_rule_proc_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	char buf[64];
	unsigned int addr[6];
	int nvar;
	int cpu;

	count = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';

	nvar = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x %d",
			&addr[0], &addr[1], &addr[2], &addr[3],
			&addr[4], &addr[5], &cpu);

	if (nvar == 7) {
		uint8_t mac[6];
		mac[0] = addr[0];
		mac[1] = addr[1];
		mac[2] = addr[2];
		mac[3] = addr[3];
		mac[4] = addr[4];
		mac[5] = addr[5];
		if ((uint16_t)cpu != RPS_NO_CPU)
			rfs_rule_create_mac_rule(mac, (uint16_t)cpu);
		else
			rfs_rule_destroy_mac_rule(mac);
		return count;
	}

	nvar = sscanf(buf, "%u.%u.%u.%u %d", &addr[0], &addr[1],
			&addr[2], &addr[3], &cpu);
	if (nvar == 5) {
		uint8_t  ip[4];
		ip[0] = addr[0];
		ip[1] = addr[1];
		ip[2] = addr[2];
		ip[3] = addr[3];
		if ((uint16_t)cpu != RPS_NO_CPU)
			rfs_rule_create_ip_rule(ip, (uint16_t)cpu);
		else
			rfs_rule_destroy_ip_rule(ip);
		return count;
	}

	return -EFAULT;

}


/*
 * rfs_rule_proc_open
 */
static int rfs_rule_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, rfs_rule_proc_show, NULL);
}


/*
 * struct file_operations rule_proc_fops
 */
static const struct file_operations rule_proc_fops = {
	.owner = THIS_MODULE,
	.open  = rfs_rule_proc_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.write  = rfs_rule_proc_write,
	.release = single_release,
};


/*
 * rfs_rule_init()
 */
int rfs_rule_init(void)
{
	struct rfs_rule *rr = &__rr;

	RFS_DEBUG("RFS Rule init\n");
	spin_lock_init(&rr->hash_lock);
	memset(&rr->hash, 0, RFS_RULE_HASH_SIZE);

	rr->proc_rule = proc_create("rule", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
				    rfs_proc_entry, &rule_proc_fops);
	return 0;
}

/*
 * rfs_rule_exit()
 */
void rfs_rule_exit(void)
{
	struct rfs_rule *rr = &__rr;

	RFS_DEBUG("RFS Rule exit\n");
	if (rr->proc_rule);
		remove_proc_entry("rule", rfs_proc_entry);
	rfs_rule_destroy_all();
}


