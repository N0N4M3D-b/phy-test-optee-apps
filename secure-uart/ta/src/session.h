/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SECURE_UART_SESSION_H
#define SECURE_UART_SESSION_H

#include <stdint.h>
#include <tee_internal_api.h>
#include <secure_uart_ta.h>

void session_init(void);
TEE_Result session_generate_challenge(struct challenge_packet *out_pkt);
TEE_Result session_verify_auth(const struct auth_packet *auth_pkt);
TEE_Result session_validate(const uint8_t *session_id);
TEE_Result session_get_keys(const uint8_t **session_key,
			    const uint8_t **hmac_key,
			    uint32_t *counter);
TEE_Result session_verify_counter(uint32_t received_counter);
uint32_t session_get_next_counter(void);
void session_destroy(void);
enum session_state session_get_state(void);

#endif /* SECURE_UART_SESSION_H */
