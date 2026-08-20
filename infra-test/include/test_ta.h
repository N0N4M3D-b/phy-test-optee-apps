/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Test TA - Header for OP-TEE infrastructure testing
 */

#ifndef TEST_TA_H
#define TEST_TA_H

#include <stdint.h>
#include <stddef.h>

/*
 * Test TA UUID: b2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e
 */
#define TEST_TA_UUID \
	{ 0xb2c3d4e5, 0x6f7a, 0x8b9c, \
	  { 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e } }

/*
 * Test Commands
 */

/* Echo: Send data, receive same data back */
#define CMD_TEST_ECHO		0x01

/* RNG: Request random bytes */
#define CMD_TEST_RNG		0x02

/* AES: Encrypt then decrypt, verify round-trip */
#define CMD_TEST_AES		0x03

/* HMAC: Compute HMAC-SHA256 */
#define CMD_TEST_HMAC		0x04

/* Storage: Write and read back from Secure Storage */
#define CMD_TEST_STORAGE	0x05

/*
 * Constants
 */
#define TEST_AES_KEY_SIZE	32	/* AES-256 */
#define TEST_AES_IV_SIZE	16
#define TEST_HMAC_KEY_SIZE	32
#define TEST_HMAC_TAG_SIZE	32	/* SHA-256 output */
#define TEST_STORAGE_ID		"test_ta_storage_obj"
#define TEST_MAX_DATA_SIZE	4096

#endif /* TEST_TA_H */
