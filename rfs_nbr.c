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
		rfs_rule_create_ip_rule(family, neigh->primary_key, neigh->ha, 0);

	} else {
		rfs_rule_destroy_ip_rule(family, neigh->primary_key, 0);
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
	RFS_DEBUG("RFS nbr init\n");
	register_netevent_notifier(&nbr_notifier);
	return 0;
}


/*
 * rfs_nbr_exit
 */
void rfs_nbr_exit(void)
{
	RFS_DEBUG("RFS nbr exit\n");
	unregister_netevent_notifier(&nbr_notifier);
}

