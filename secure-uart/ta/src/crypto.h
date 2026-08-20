/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SECURE_UART_CRYPTO_H
#define SECURE_UART_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>
#include <secure_uart_ta.h>

TEE_Result crypto_encrypt_challenge(const uint8_t *master_key,
				    const uint8_t *plaintext, size_t pt_len,
				    struct challenge_packet *out_pkt);
TEE_Result crypto_verify_auth(const struct auth_packet *auth_pkt);
TEE_Result crypto_decrypt_and_verify(const struct data_packet *pkt,
				     const uint8_t *session_key,
				     const uint8_t *hmac_key,
				     uint8_t *plaintext, size_t *pt_len);
TEE_Result crypto_encrypt_and_sign(const uint8_t *plaintext, size_t pt_len,
				   const uint8_t *session_key,
				   const uint8_t *hmac_key,
				   const uint8_t *session_id,
				   const uint8_t *iv,
				   struct data_packet *out_pkt);

#endif /* SECURE_UART_CRYPTO_H */
