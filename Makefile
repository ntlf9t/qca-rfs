#
# Copyright (c) 2015 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# Makefile for QCA Receiving Flow Steering.
#

obj-m += qrfs.o

qrfs-objs := \
	rfs_main.o \
	rfs_cm.o \
	rfs_nbr.o \
	rfs_wxt.o \
	rfs_rule.o \
	rfs_ess.o
