# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024, Secure UART Project

# Include directories
global-incdirs-y += ../include
global-incdirs-y += .

# Source files
srcs-y += src/entry.c
srcs-y += src/session.c
srcs-y += src/crypto.c
srcs-y += src/filter.c
