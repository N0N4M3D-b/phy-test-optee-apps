/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#ifndef SECURE_UART_TA_H
#define SECURE_UART_TA_H

#include <stdint.h>
#include <stddef.h>

/*
 * Secure UART TA UUID: a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
 */
#define SECURE_UART_TA_UUID \
	{ 0xa1b2c3d4, 0x5e6f, 0x7a8b, \
	  { 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d } }

/*
 * TA Commands
 */

/* Phase 1: Nonce Generation */
#define CMD_GENERATE_CHALLENGE		0x01

/* Phase 2: Authentication and Session Key Derivation */
#define CMD_VERIFY_FINAL_AUTH		0x02

/* Phase 3: Secure Tunneling */
#define CMD_DECRYPT_AND_FILTER		0x03  /* User -> Shell (decrypt + filter) */
#define CMD_ENCRYPT_OUTPUT		0x04  /* Shell -> User (encrypt) */

/* Session Management */
#define CMD_DESTROY_SESSION		0x05
#define CMD_GET_SESSION_STATUS		0x06

/*
 * Constants
 */
#define SESSION_ID_SIZE			16
#define NONCE_SIZE			16
#define MASTER_KEY_SIZE			32
#define SESSION_KEY_SIZE		32
#define HMAC_KEY_SIZE			32
#define HMAC_TAG_SIZE			32
#define AES_IV_SIZE			16
#define AES_BLOCK_SIZE			16

#define MAX_PACKET_SIZE			4096
#define MAX_COMMAND_LENGTH		256

/* Session timeout: 5 minutes */
#define SESSION_TIMEOUT_SEC		300

/* Anti-hammering */
#define MAX_AUTH_ATTEMPTS		3
#define LOCKOUT_DURATION_SEC		300

/*
 * Packet structures (shared with REE)
 */

/* Challenge packet (TA -> C0) */
struct challenge_packet {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t iv[AES_IV_SIZE];
	uint8_t enc_payload[64];  /* Encrypted: Nonce || Timestamp || Counter */
	uint8_t hmac_tag[HMAC_TAG_SIZE];
} __attribute__((packed));

/* Auth response (C0 -> TA) */
struct auth_packet {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t iv[AES_IV_SIZE];
	uint8_t enc_data[64];     /* Encrypted: User auth response */
	uint8_t hmac_tag[HMAC_TAG_SIZE];
} __attribute__((packed));

/* Data packet (bidirectional) */
struct data_packet {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t iv[AES_IV_SIZE];
	uint16_t data_len;
	uint8_t enc_data[MAX_PACKET_SIZE];
	uint8_t hmac_tag[HMAC_TAG_SIZE];
} __attribute__((packed));

/*
 * Session state
 */
enum session_state {
	SESSION_STATE_IDLE = 0,
	SESSION_STATE_CHALLENGE_SENT,
	SESSION_STATE_AUTHENTICATED,
	SESSION_STATE_ACTIVE,
	SESSION_STATE_CLOSED
};

/*
 * Error codes (in addition to TEE_Result)
 */
#define TA_ERROR_SESSION_TIMEOUT	0xF0000001
#define TA_ERROR_REPLAY_DETECTED	0xF0000002
#define TA_ERROR_AUTH_FAILED		0xF0000003
#define TA_ERROR_LOCKED_OUT		0xF0000004
#define TA_ERROR_COMMAND_BLOCKED	0xF0000005

#endif /* SECURE_UART_TA_H */
