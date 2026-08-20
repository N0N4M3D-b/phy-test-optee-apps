/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#ifndef TEE_CLIENT_H
#define TEE_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <tee_client_api.h>
#include <secure_uart_ta.h>

/* Buffer sizes */
#define CHALLENGE_PKT_SIZE		sizeof(struct challenge_packet)
#define AUTH_PKT_SIZE			sizeof(struct auth_packet)
#define DATA_PKT_SIZE			sizeof(struct data_packet)

/**
 * tee_client_init - Initialize TEE client context and session
 *
 * Returns: 0 on success, -1 on error
 */
int tee_client_init(void);

/**
 * tee_client_cleanup - Cleanup TEE client session and context
 */
void tee_client_cleanup(void);

/**
 * tee_generate_challenge - Request challenge from TA
 * @challenge: Output buffer for encrypted challenge
 * @challenge_len: Size of challenge buffer (in/out)
 *
 * Returns: 0 on success, -1 on error
 */
int tee_generate_challenge(uint8_t *challenge, size_t *challenge_len);

/**
 * tee_verify_auth - Verify authentication response
 * @auth_data: Authentication response data
 * @auth_len: Length of auth data
 *
 * Returns: 0 on success, -1 on error
 */
int tee_verify_auth(const uint8_t *auth_data, size_t auth_len);

/**
 * tee_decrypt_and_filter - Decrypt and filter input command
 * @enc_data: Encrypted data packet
 * @enc_len: Length of encrypted data
 * @plaintext: Output buffer for decrypted data
 * @plaintext_len: Size of output buffer (in/out)
 *
 * Returns: 0 on success, -1 on error
 */
int tee_decrypt_and_filter(const uint8_t *enc_data, size_t enc_len,
			    uint8_t *plaintext, size_t *plaintext_len);

/**
 * tee_encrypt_output - Encrypt shell output
 * @plaintext: Plaintext data
 * @plaintext_len: Length of plaintext
 * @enc_data: Output buffer for encrypted data
 * @enc_len: Size of output buffer (in/out)
 *
 * Returns: 0 on success, -1 on error
 */
int tee_encrypt_output(const uint8_t *plaintext, size_t plaintext_len,
			uint8_t *enc_data, size_t *enc_len);

/**
 * tee_destroy_session - Destroy current session
 *
 * Returns: 0 on success, -1 on error
 */
int tee_destroy_session(void);

/**
 * tee_get_session_status - Get current session status
 * @status: Output session status
 *
 * Returns: 0 on success, -1 on error
 */
int tee_get_session_status(uint32_t *status);

#endif /* TEE_CLIENT_H */
