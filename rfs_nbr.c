/*
 * rfs_nbr.c
 *	Receiving Flow Streering - Neighbor Manager
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netevent.h>
#include <net/route.h>

#include "rfs.h"
#include "rfs_nbr.h"
#include "rfs_rule.h"
#include "rfs_ess.h"

#define RFS_NBR_HASH_SHIFT 10
#define RFS_NBR_HASH_SIZE (1 << RFS_NBR_HASH_SHIFT)
#define RFS_NBR_HASH_MASK (RFS_NBR_HASH_SIZE - 1)

/*
 * Per-module structure.
 */
struct rfs_nbr {
	spinlock_t hash_lock;
	struct hlist_head ip_hash[RFS_NBR_HASH_SIZE];
	struct hlist_head mac_hash[RFS_NBR_HASH_SIZE];
	struct proc_dir_entry *proc_nbr;
};

static struct rfs_nbr __nbr;


/*
 * rfs_nbr_mac_hash
 */
static unsigned int rfs_nbr_mac_hash(uint8_t *maddr)
{
        return jhash(maddr, ETH_ALEN, 0) & RFS_NBR_HASH_MASK;
}


/*
 * rfs_nbr_ip_hash
 */
static unsigned int rfs_nbr_ip_hash(int family, uint8_t *ipaddr)
{
	uint32_t length;

	if (family == AF_INET)
		length = 4;
	else
		length = sizeof(struct in6_addr);
        return jhash(ipaddr, length,  0) & RFS_NBR_HASH_MASK;
}


/*
 * rfs_nbr_ip_equal
 */
static int rfs_nbr_ip_equal(struct rfs_nbr_node *nn, int family, uint8_t *ipaddr)
{
	if (family ==AF_INET)
		return (nn->addr_in4 == *(__be32*)ipaddr);
	else
		return memcmp(&nn->addr_in6, ipaddr, sizeof(struct in6_addr))?0:1;
}

/*
 * rfs_nbr_node_rcu_free
 */
static void rfs_nbr_node_rcu_free(struct rcu_head *head)
{
	struct rfs_nbr_node *nn;
	nn = container_of(head, struct rfs_nbr_node, rcu);
	kfree(nn);
}


/*
 * rfs_nbr_create
 */
static int rfs_nbr_create(int family, uint8_t *maddr, uint8_t *ipaddr)
{
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	struct rfs_nbr *nbr;
	uint16_t cpu;

	nbr = &__nbr;

	spin_lock_bh(&nbr->hash_lock);

	/*
	 *  Look up the mac hash
	 */
	head = &nbr->mac_hash[rfs_nbr_mac_hash(maddr)];
	hlist_for_each_entry_rcu(nn, head, maddr_hlist) {
		if (memcmp(nn->maddr, maddr, ETH_ALEN) == 0 &&
			rfs_nbr_ip_equal(nn, family, ipaddr))
			break;
	}

	if (nn) {
		spin_unlock_bh(&nbr->hash_lock);
		return 0;
	}

	/*
	 * Create a neighbor node if it doesn't exist
	 */
	nn = kzalloc(sizeof(struct rfs_nbr_node), GFP_ATOMIC);
	if (!nn) {
		spin_unlock_bh(&nbr->hash_lock);
		return -1;
	}

	memcpy(nn->maddr, maddr, ETH_ALEN);
	nn->family = family;
	if (family == AF_INET)
		nn->addr_in4 = *(__be32*)ipaddr;
	else
		memcpy(&nn->addr_in6, ipaddr, sizeof(struct in6_addr));
	nn->cpu = RPS_NO_CPU;

	/*
	 * Add to MAC hash
	 */
	hlist_add_head_rcu(&nn->maddr_hlist, head);

	/*
	 * Add to IP hash
	 */
	head = &nbr->ip_hash[rfs_nbr_ip_hash(family, ipaddr)];
	hlist_add_head_rcu(&nn->ipaddr_hlist, head);

	/*
	 * Add IP rule (including IP connection rules)
	 */

	if (family == AF_INET)
		RFS_DEBUG("new neigh: mac: %pM IP: %pI4\n",
			   nn->maddr, (__be32 *)&nn->addr_in4);
	else
		RFS_DEBUG("new neigh: mac: %pM IP: %pI6\n",
			    nn->maddr, (__be32 *)&nn->addr_in6);

	cpu = rfs_rule_get_cpu_by_imaddr(family, ipaddr, maddr);
	if (cpu != RPS_NO_CPU &&
	    rfs_ess_update_ip_rule(family, (uint8_t*)&nn->addr_in, cpu) >= 0) {
		nn->cpu = cpu;
	}

	spin_unlock_bh(&nbr->hash_lock);


	return 0;
}


/*
 * rfs_nbr_destory
 */
static void rfs_nbr_destory(int family, uint8_t *maddr, uint8_t *ipaddr)
{
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	struct rfs_nbr *nbr;

	nbr = &__nbr;
	spin_lock_bh(&nbr->hash_lock);

	/*
	 *  Look up the MAC hash
	 */
	head = &nbr->mac_hash[rfs_nbr_mac_hash(maddr)];
	hlist_for_each_entry_rcu(nn, head, maddr_hlist) {
		if (memcmp(nn->maddr, maddr, ETH_ALEN) == 0 &&
			rfs_nbr_ip_equal(nn, family, ipaddr))
			break;
	}

	if (!nn) {
		spin_unlock_bh(&nbr->hash_lock);
		return;
	}

	/* Remove from IP hash*/
	hlist_del_rcu(&nn->ipaddr_hlist);

	/* Remove from MAC hash*/
	hlist_del_rcu(&nn->maddr_hlist);

	/*
	 * Remove IP rule(including IP conneciton rules)
	 */

	if (family == AF_INET)
		RFS_DEBUG("remove neigh: mac: %pM IP: %pI4\n",
			   nn->maddr, (__be32 *)&nn->addr_in4);
	else
		RFS_DEBUG("remove neigh: mac: %pM IP: %pI6\n",
			    nn->maddr, (__be32 *)&nn->addr_in6);

	if (nn->cpu != RPS_NO_CPU) {
		rfs_ess_update_ip_rule(family, (uint8_t*)&nn->addr_in, RPS_NO_CPU);
		nn->cpu = RPS_NO_CPU;
	}
	call_rcu(&nn->rcu, rfs_nbr_node_rcu_free);
	spin_unlock_bh(&nbr->hash_lock);
}


/*
 * rfs_nbr_destory_all
 */
static void rfs_nbr_destory_all(void)
{
	int index;
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	struct rfs_nbr *nbr;

	nbr = &__nbr;

	spin_lock_bh(&nbr->hash_lock);
	for ( index = 0; index < RFS_NBR_HASH_SIZE; index++) {
		struct hlist_node *n;
		head = &nbr->ip_hash[index];
		hlist_for_each_entry_safe(nn, n, head, ipaddr_hlist) {
			/* Remove from IP hash*/
			hlist_del_rcu(&nn->ipaddr_hlist);

			/* Remove from MAC hash*/
			hlist_del_rcu(&nn->maddr_hlist);

			rfs_nbr_node_rcu_free(&nn->rcu);

		}
	}

	spin_unlock_bh(&nbr->hash_lock);

}


/*
 * rfs_nbr_get_cpu_by_ipaddr
 */
uint16_t rfs_nbr_get_cpu_by_ipaddr(int family, int8_t *ipaddr)
{
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	uint16_t cpu = RPS_NO_CPU;
	struct rfs_nbr *nbr;

	nbr = &__nbr;
	head = &nbr->ip_hash[rfs_nbr_ip_hash(family, ipaddr)];

	rcu_read_lock();
	hlist_for_each_entry_rcu(nn, head, ipaddr_hlist) {
		if (rfs_nbr_ip_equal(nn, family, ipaddr))
			 break;
	}

	if (nn)
		cpu = nn->cpu;
	rcu_read_unlock();

	return cpu;
}


/*
 * rfs_nbr_update_rules
 */
int rfs_nbr_update_rules(int8_t *maddr, uint16_t cpu)
{
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	struct rfs_nbr *nbr;

	nbr = &__nbr;
	head = &nbr->mac_hash[rfs_nbr_mac_hash(maddr)];
	spin_lock_bh(&nbr->hash_lock);
	hlist_for_each_entry_rcu(nn, head, maddr_hlist) {
		if (memcmp(nn->maddr, maddr, ETH_ALEN))
			continue;

		if (cpu == nn->cpu)
			continue;

		RFS_INFO("Update neighbor cpu %d --> %d\n", nn->cpu, cpu);
		if (rfs_ess_update_ip_rule(nn->family, (uint8_t*)&nn->addr_in, cpu) >= 0)
			nn->cpu = cpu;
	}
	spin_unlock_bh(&nbr->hash_lock);

	return 0;
}


/*
 * rfs_nbr_proc_show
 *	show neighbor information in proc file system
 */
static int rfs_nbr_proc_show(struct seq_file *m, void *v)
{
	int index;
	int count = 0;
	struct hlist_head *head;
	struct rfs_nbr_node *nn;
	struct rfs_nbr *nbr;

	seq_printf(m, "RFS neighbor table:\n");
	nbr = &__nbr;

	rcu_read_lock();
	for ( index = 0; index < RFS_NBR_HASH_SIZE; index++) {
		head = &nbr->ip_hash[index];
		hlist_for_each_entry_rcu(nn, head, ipaddr_hlist) {
			seq_printf(m, "%03d hash %08x MAC :%pM", ++count, index, nn->maddr);
			if (nn->family == AF_INET)
				seq_printf(m, " IP: %pI4", &nn->addr_in4);
			else
				seq_printf(m, " IP: %pI6", &nn->addr_in6);
			seq_printf(m, " cpu %d\n", nn->cpu);

		}
	}
	seq_putc(m, '\n');
	rcu_read_unlock();
	return 0;
}


/*
 * rfs_nbr_proc_open
 */
static int rfs_nbr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, rfs_nbr_proc_show, NULL);
}


/*
 * struct file_operations nbr_proc_fops
 */
static const struct file_operations nbr_proc_fops = {
	.owner = THIS_MODULE,
	.open  = rfs_nbr_proc_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/*
 * nbr_netevent_callback
 */
static int nbr_netevent_callback(struct notifier_block *notifier, unsigned long event, void *ctx)
{
	struct neigh_table *tbl;
	struct neighbour *neigh;
	int family;
	int key_len;

	if (event != NETEVENT_NEIGH_UPDATE)
		return NOTIFY_DONE;

	neigh = ctx;
	tbl   = neigh->tbl;
	key_len = tbl->key_len;
	family  = tbl->family;

	if (family != AF_INET && family != AF_INET6)
		return NOTIFY_DONE;

	if (neigh->nud_state & NUD_VALID) {
		rfs_nbr_create(family, neigh->ha, neigh->primary_key);

	} else {
		rfs_nbr_destory(family, neigh->ha, neigh->primary_key);
	}

	return NOTIFY_DONE;
}

static struct notifier_block nbr_notifier = {
	.notifier_call = nbr_netevent_callback,
};



/*
 * rfs_nbr_init
 */
int rfs_nbr_init(void)
{
	static struct rfs_nbr *nbr = &__nbr;

	RFS_DEBUG("RFS nbr init\n");
	spin_lock_init(&nbr->hash_lock);
	memset(nbr->ip_hash, 0, RFS_NBR_HASH_SIZE);
	memset(nbr->mac_hash, 0, RFS_NBR_HASH_SIZE);
	register_netevent_notifier(&nbr_notifier);
	nbr->proc_nbr = proc_create("neighbor", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
				    rfs_proc_entry, &nbr_proc_fops);
	return 0;
}


/*
 * rfs_nbr_exit
 */
void rfs_nbr_exit(void)
{
	static struct rfs_nbr *nbr = &__nbr;

	RFS_DEBUG("RFS nbr exit\n");
	if (nbr->proc_nbr)
		remove_proc_entry("neighbor", rfs_proc_entry);
	unregister_netevent_notifier(&nbr_notifier);
	rfs_nbr_destory_all();
}

