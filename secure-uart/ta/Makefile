# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024, Secure UART Project

# TA UUID
TA_UUID := a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d

# TA Development Kit directory (set by Yocto)
TA_DEV_KIT_DIR ?= /usr/include/optee/export-user_ta

# Cross compiler prefix (set by Yocto)
CROSS_COMPILE ?= arm-oe-linux-gnueabi-

# Binary name
BINARY = $(TA_UUID)

# Source directories
SRC_DIR = src
INC_DIR = include

# Include TA development kit Makefile
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
$(error TA_DEV_KIT_DIR is not correctly defined or OP-TEE dev kit is not installed)
endif
