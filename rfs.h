/*
 * rfs.h
 *	Receiving Flow Streering
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RFS_H
#define __RFS_H
#define DBG_LVL_ERROR    0
#define DBG_LVL_WARN     1
#define DBG_LVL_INFO     2
#define DBG_LVL_DEBUG    3
#define DBG_LVL_TRACE    4
#define DBG_LVL_DEFAULT  DBG_LVL_INFO

extern int rfs_dbg_level;
extern struct proc_dir_entry *rfs_proc_entry;

#define __DBG_FUN(xyz, fmt, ...) \
	do { \
		if (DBG_LVL_##xyz <= rfs_dbg_level) { \
			printk("%s[%u]:"#xyz":", __FUNCTION__, __LINE__); \
			printk(fmt, ##__VA_ARGS__); \
		} \
	} while(0)

#define RFS_ERROR(fmt, ...) __DBG_FUN(ERROR, fmt, ##__VA_ARGS__)
#define RFS_WARN(fmt, ...)  __DBG_FUN(WARN, fmt, ##__VA_ARGS__)
#define RFS_INFO(fmt, ...)  __DBG_FUN(INFO, fmt, ##__VA_ARGS__)
#define RFS_DEBUG(fmt, ...) __DBG_FUN(DEBUG, fmt, ##__VA_ARGS__)
#define RFS_TRACE(fmt, ...) __DBG_FUN(TRACE, fmt, ##__VA_ARGS__)
#endif
