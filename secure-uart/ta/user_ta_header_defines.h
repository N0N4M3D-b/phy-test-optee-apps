/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <secure_uart_ta.h>

#define TA_UUID				SECURE_UART_TA_UUID

/*
 * TA flags:
 * - TA_FLAG_SINGLE_INSTANCE: Only one instance of TA
 * - TA_FLAG_MULTI_SESSION: Support multiple concurrent sessions
 * - TA_FLAG_INSTANCE_KEEP_ALIVE: Keep TA loaded in memory
 */
#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION | \
					 TA_FLAG_INSTANCE_KEEP_ALIVE)

/*
 * Stack size: 16KB
 * - Crypto operations require significant stack
 * - HKDF, HMAC, AES operations
 */
#define TA_STACK_SIZE			(16 * 1024)

/*
 * Heap size: 32KB
 * - Session management structures
 * - Packet buffers
 * - Whitelist filter data
 */
#define TA_DATA_SIZE			(32 * 1024)

/*
 * TA version
 */
#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
		"Secure UART Trusted Application" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /* USER_TA_HEADER_DEFINES_H */
