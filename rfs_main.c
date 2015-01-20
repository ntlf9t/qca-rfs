/*
 * rfs_main.c
 *	Receiving Flow Steering
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/if_bridge.h>

#include "rfs.h"
#include "rfs_cm.h"
#include "rfs_nbr.h"
#include "rfs_wxt.h"
#include "rfs_rule.h"
#include "rfs_ess.h"

/*
 * debug level
 */
int rfs_dbg_level = DBG_LVL_DEFAULT;


/*
 * rfs_proc_entry, root proc entry of RFS module
 */
struct proc_dir_entry *rfs_proc_entry;


/*
 * rfs_debug_entry, debug entry in proc file system
 */
static struct proc_dir_entry *rfs_debug_entry;


/*
 * rfs_debug_proc_show
 *	Show debug level in proc file system
 */
static int rfs_debug_proc_show(struct seq_file *m, void *v)
{
	return seq_printf(m, "%d\n", rfs_dbg_level);
}


/*
 * rfs_debug_proc_write
 *	Change debug level through proc file system
 */
static ssize_t rfs_debug_proc_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *ppos)
{
	unsigned long val;
	int err = kstrtoul_from_user(buffer, count, 0, &val);
	if (err)
		return err;

	rfs_dbg_level = val;
	return count;

}


/*
 * rfs_debug_proc_open
 */
static int rfs_debug_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, rfs_debug_proc_show, NULL);
}


/*
 * struct file_operations debug_proc_fops
 */
static const struct file_operations debug_proc_fops = {
	.owner = THIS_MODULE,
	.open  = rfs_debug_proc_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.write  = rfs_debug_proc_write,
	.release = single_release,
};


/*
 * rfs_proc_init
 */
static int rfs_proc_init(void)
{
	/*
	 * Create /proc/qrfs
	 */
	rfs_proc_entry = proc_mkdir("qrfs", NULL);
	if (!rfs_proc_entry) {
		RFS_ERROR("failed to register qrfs proc entry\n");
		return -1;
	}

	rfs_debug_entry = proc_create("debug",
				S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
				rfs_proc_entry, &debug_proc_fops);


	return 0;
}


/*
 * rfs_proc_exit
 */
static void rfs_proc_exit(void)
{
	if (rfs_debug_entry)
		remove_proc_entry("debug", rfs_proc_entry);

	if (rfs_proc_entry) {
		remove_proc_entry("qrfs", NULL);
		rfs_proc_entry = NULL;
	}
}


/*
 * rfs_init()
 */
static int __init rfs_init(void)
{
	RFS_DEBUG("RFS init\n");

	/*
	 * proc file system
	 */
	if (rfs_proc_init() < 0)
		return -1;

	/*
	 * Ethernet sub-system
	 */
	if (rfs_ess_init() < 0) {
		goto exit1;
	}

	/*
	 * IPv4 connection management
	 */
	if (rfs_cm_init() < 0) {
		goto exit2;
	}

	/*
	 * IP neighbor management
	 */
	if (rfs_nbr_init() < 0) {
		goto exit3;
	}

	/*
	 * RFS rules
	 */
	if ( rfs_rule_init() < 0) {
		goto exit4;
	}

	/*
	 * wireless extension
	 */
	if (rfs_wxt_init() < 0) {
		goto exit5;
	}

	return 0;

exit5:
	rfs_rule_exit();
exit4:
	rfs_nbr_exit();
exit3:
	rfs_cm_exit();
exit2:
	rfs_ess_exit();
exit1:
	rfs_proc_exit();

	return -1;
}


/*
 * rfs_exit()
 */
static void __exit rfs_exit(void)
{
	RFS_DEBUG("RFS exit\n");

	rfs_wxt_exit();

	rfs_rule_exit();

	rfs_nbr_exit();

	rfs_cm_exit();

	rfs_ess_exit();

	rfs_proc_exit();
}


module_init(rfs_init)
module_exit(rfs_exit)

MODULE_AUTHOR("Qualcomm Atheros Inc.");
MODULE_DESCRIPTION("Receiving Flow Steering");
MODULE_LICENSE("GPL v2");

