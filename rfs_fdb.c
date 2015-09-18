/*
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
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
 * rfs_fdb.c
 *	Receiving Flow Streering - FDB Manager
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <net/netevent.h>
#include <net/route.h>

#include "rfs.h"
#include "rfs_wxt.h"
#include "rfs_rule.h"

/*
 * Per-module structure.
 */
struct rfs_fdb {
	int is_running;
};


static struct rfs_fdb __fdb;


/*
 * fdb_event_callback
 */
static int fdb_event_callback(struct notifier_block *notifier, unsigned long event, void *ctx)
{
	struct br_fdb_event *fe;
        struct net_device *dev;
	int cpu;

	fe = (struct br_fdb_event*)ctx;
	dev = fe->dev;

	if (!dev || !dev->wireless_handlers)
		return NOTIFY_DONE;

	if (fe->is_local)
		return NOTIFY_DONE;

	switch (event) {
	case BR_FDB_EVENT_ADD:
		cpu = rfs_wxt_get_cpu(dev->ifindex);
		if (cpu < 0 )
			break;
		RFS_DEBUG("STA %pM joining\n", (unsigned char*) fe->addr);
		rfs_rule_create_mac_rule((unsigned char*) fe->addr, (uint16_t)cpu, 0, 0);
		break;
	case BR_FDB_EVENT_DEL:
		RFS_DEBUG("STA %pM leaving\n", (unsigned char*) fe->addr);
		rfs_rule_destroy_mac_rule((unsigned char*) fe->addr, 0);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block fdb_notifier = {
	.notifier_call = fdb_event_callback,
};


/*
 * rfs_fdb_start
 */
int rfs_fdb_start(void)
{
	struct rfs_fdb *fdb = &__fdb;

	if (fdb->is_running)
		return 0;

	RFS_DEBUG("RFS fdb start\n");
	br_fdb_register_notify(&fdb_notifier);
	fdb->is_running = 1;
	return 0;
}


/*
 * rfs_fdb_stop
 */
int rfs_fdb_stop(void)
{
	struct rfs_fdb *fdb = &__fdb;

	if (!fdb->is_running)
		return 0;

	RFS_DEBUG("RFS fdb stop\n");
	br_fdb_unregister_notify(&fdb_notifier);
	fdb->is_running = 0;
	return 0;
}


/*
 * rfs_fdb_init
 */
int rfs_fdb_init(void)
{
	struct rfs_fdb *fdb = &__fdb;

	RFS_DEBUG("RFS fdb init\n");
	fdb->is_running = 0;
	return 0;
}


/*
 * rfs_fdb_exit
 */
void rfs_fdb_exit(void)
{
	RFS_DEBUG("RFS fdb exit\n");
	rfs_fdb_stop();
}

