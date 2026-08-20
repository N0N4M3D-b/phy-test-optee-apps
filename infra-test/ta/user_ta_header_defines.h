/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <test_ta.h>

#define TA_UUID				TEST_TA_UUID

/*
 * TA flags:
 * - TA_FLAG_SINGLE_INSTANCE: Only one instance of TA
 * - TA_FLAG_MULTI_SESSION: Support multiple concurrent sessions
 */
#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION)

/*
 * Stack size: 8KB (sufficient for test operations)
 */
#define TA_STACK_SIZE			(8 * 1024)

/*
 * Heap size: 16KB (for crypto objects and buffers)
 */
#define TA_DATA_SIZE			(16 * 1024)

/*
 * TA version
 */
#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
		"OP-TEE Infrastructure Test TA" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /* USER_TA_HEADER_DEFINES_H */
