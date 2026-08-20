// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Main TA entry points and command dispatcher
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <secure_uart_ta.h>
#include "session.h"
#include "crypto.h"
#include "filter.h"

/*
 * TA_CreateEntryPoint - Called when TA is loaded
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("Secure UART TA CreateEntryPoint");

	/* Initialize modules */
	session_init();
	filter_init();

	return TEE_SUCCESS;
}

/*
 * TA_DestroyEntryPoint - Called when TA is unloaded
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("Secure UART TA DestroyEntryPoint");

	/* Cleanup session */
	session_destroy();
}

/*
 * TA_OpenSessionEntryPoint - Called when client opens session
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **session_ctx __unused)
{
	DMSG("Secure UART TA OpenSession");

	/* No per-session context needed (single instance TA) */
	*session_ctx = NULL;

	return TEE_SUCCESS;
}

/*
 * TA_CloseSessionEntryPoint - Called when client closes session
 */
void TA_CloseSessionEntryPoint(void *session_ctx __unused)
{
	DMSG("Secure UART TA CloseSession");

	/* Destroy session if active */
	session_destroy();
}

/*
 * CMD_GENERATE_CHALLENGE handler
 */
static TEE_Result cmd_generate_challenge(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	struct challenge_packet *out_pkt;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct challenge_packet)) {
		params[0].memref.size = sizeof(struct challenge_packet);
		return TEE_ERROR_SHORT_BUFFER;
	}

	out_pkt = (struct challenge_packet *)params[0].memref.buffer;

	res = session_generate_challenge(out_pkt);
	if (res == TEE_SUCCESS)
		params[0].memref.size = sizeof(struct challenge_packet);

	return res;
}

/*
 * CMD_VERIFY_FINAL_AUTH handler
 */
static TEE_Result cmd_verify_final_auth(uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	struct auth_packet *auth_pkt;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct auth_packet)) {
		EMSG("Auth packet too small");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	auth_pkt = (struct auth_packet *)params[0].memref.buffer;

	res = session_verify_auth(auth_pkt);

	return res;
}

/*
 * CMD_DECRYPT_AND_FILTER handler
 */
static TEE_Result cmd_decrypt_and_filter(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	struct data_packet *in_pkt;
	uint8_t *plaintext;
	size_t pt_len;
	const uint8_t *session_key, *hmac_key;
	uint32_t counter;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	in_pkt = (struct data_packet *)params[0].memref.buffer;

	/* Validate session */
	res = session_validate(in_pkt->session_id);
	if (res != TEE_SUCCESS) {
		EMSG("Session validation failed: 0x%x", res);
		return res;
	}

	/* Get session keys */
	res = session_get_keys(&session_key, &hmac_key, &counter);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get session keys: 0x%x", res);
		return res;
	}

	/* Extract counter from IV (bytes 8-11) */
	uint32_t pkt_counter;
	memcpy(&pkt_counter, in_pkt->iv + 8, sizeof(pkt_counter));

	/* Verify counter (replay protection) */
	res = session_verify_counter(pkt_counter);
	if (res != TEE_SUCCESS) {
		EMSG("Counter verification failed: 0x%x", res);
		return res;
	}

	/* Allocate plaintext buffer */
	plaintext = TEE_Malloc(in_pkt->data_len, TEE_MALLOC_FILL_ZERO);
	if (!plaintext) {
		EMSG("Out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Decrypt and verify */
	pt_len = in_pkt->data_len;
	res = crypto_decrypt_and_verify(in_pkt, session_key, hmac_key,
					plaintext, &pt_len);
	if (res != TEE_SUCCESS) {
		EMSG("Decrypt and verify failed: 0x%x", res);
		goto cleanup;
	}

	/* Null-terminate for string operations */
	if (pt_len < in_pkt->data_len)
		plaintext[pt_len] = '\0';
	else
		plaintext[in_pkt->data_len - 1] = '\0';

	/* Filter command */
	res = filter_check_command((const char *)plaintext, pt_len);
	if (res != TEE_SUCCESS) {
		EMSG("Command filtered: %s", (char *)plaintext);
		goto cleanup;
	}

	/* Copy to output */
	if (params[1].memref.size < pt_len) {
		params[1].memref.size = pt_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto cleanup;
	}

	memcpy(params[1].memref.buffer, plaintext, pt_len);
	params[1].memref.size = pt_len;

	DMSG("Command decrypted and filtered: %zu bytes", pt_len);
	res = TEE_SUCCESS;

cleanup:
	TEE_MemFill(plaintext, 0, in_pkt->data_len);
	TEE_Free(plaintext);
	return res;
}

/*
 * CMD_ENCRYPT_OUTPUT handler
 */
static TEE_Result cmd_encrypt_output(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint8_t *plaintext;
	size_t pt_len;
	struct data_packet *out_pkt;
	const uint8_t *session_key, *hmac_key;
	uint32_t counter;
	uint8_t iv[AES_IV_SIZE];
	uint8_t session_id[SESSION_ID_SIZE];
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plaintext = params[0].memref.buffer;
	pt_len = params[0].memref.size;

	/* Validate session (use session_id from input or global session) */
	/* For simplicity, use global session */
	if (session_get_state() != SESSION_STATE_ACTIVE &&
	    session_get_state() != SESSION_STATE_AUTHENTICATED) {
		EMSG("No active session");
		return TEE_ERROR_BAD_STATE;
	}

	/* Get session keys */
	res = session_get_keys(&session_key, &hmac_key, &counter);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get session keys: 0x%x", res);
		return res;
	}

	/* Generate IV: Nonce(8) || Counter(4) || Random(4) */
	counter = session_get_next_counter();
	TEE_GenerateRandom(iv, 8);  /* Random nonce part */
	memcpy(iv + 8, &counter, 4);
	TEE_GenerateRandom(iv + 12, 4);  /* Random part */

	/* Allocate output packet */
	if (params[1].memref.size < sizeof(struct data_packet)) {
		params[1].memref.size = sizeof(struct data_packet);
		return TEE_ERROR_SHORT_BUFFER;
	}

	out_pkt = (struct data_packet *)params[1].memref.buffer;

	/* Get session ID (from global session for now) */
	/* TODO: Pass session_id explicitly if needed */
	memset(session_id, 0, SESSION_ID_SIZE);  /* Placeholder */

	/* Encrypt and sign */
	res = crypto_encrypt_and_sign(plaintext, pt_len,
				      session_key, hmac_key,
				      session_id, iv, out_pkt);
	if (res != TEE_SUCCESS) {
		EMSG("Encrypt and sign failed: 0x%x", res);
		return res;
	}

	params[1].memref.size = sizeof(struct data_packet);

	DMSG("Output encrypted: %zu bytes", pt_len);
	return TEE_SUCCESS;
}

/*
 * CMD_DESTROY_SESSION handler
 */
static TEE_Result cmd_destroy_session(uint32_t param_types __unused,
				      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	DMSG("Destroying session");
	session_destroy();
	return TEE_SUCCESS;
}

/*
 * CMD_GET_SESSION_STATUS handler
 */
static TEE_Result cmd_get_session_status(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	enum session_state state;
	uint32_t *out_state;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
					TEE_PARAM_TYPE_VALUE_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = session_get_state();
	out_state = &params[0].value.a;
	*out_state = (uint32_t)state;

	DMSG("Session state: %u", state);
	return TEE_SUCCESS;
}

/*
 * TA_InvokeCommandEntryPoint - Command dispatcher
 */
TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx __unused,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("Invoked command: 0x%x", cmd_id);

	switch (cmd_id) {
	case CMD_GENERATE_CHALLENGE:
		return cmd_generate_challenge(param_types, params);

	case CMD_VERIFY_FINAL_AUTH:
		return cmd_verify_final_auth(param_types, params);

	case CMD_DECRYPT_AND_FILTER:
		return cmd_decrypt_and_filter(param_types, params);

	case CMD_ENCRYPT_OUTPUT:
		return cmd_encrypt_output(param_types, params);

	case CMD_DESTROY_SESSION:
		return cmd_destroy_session(param_types, params);

	case CMD_GET_SESSION_STATUS:
		return cmd_get_session_status(param_types, params);

	default:
		EMSG("Command ID 0x%x not supported", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
