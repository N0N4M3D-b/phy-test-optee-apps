// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <string_ext.h>
#include <secure_uart_ta.h>
#include "session.h"
#include "crypto.h"

/*
 * Session context structure
 */
struct secure_session {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t session_key[SESSION_KEY_SIZE];
	uint8_t hmac_key[HMAC_KEY_SIZE];

	uint64_t created_time;
	uint64_t last_activity;
	uint32_t packet_counter;

	enum session_state state;
	bool active;

	/* Anti-hammering */
	uint32_t failed_attempts;
	uint64_t lockout_until;
};

/* Master key stored in Secure Storage */
#define MASTER_KEY_OBJ_ID	"secure_uart_master_key"

/* Global session (single instance TA) */
static struct secure_session g_session;

/*
 * Helper: Get current time in seconds
 */
static uint64_t get_current_time_sec(void)
{
	TEE_Time time;
	TEE_GetSystemTime(&time);
	return (uint64_t)time.seconds;
}

/*
 * Helper: Load or generate Master Key from Secure Storage
 */
static TEE_Result get_master_key(uint8_t *master_key, size_t key_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	uint32_t obj_data_size __maybe_unused = MASTER_KEY_SIZE;
	uint8_t obj_id[] = MASTER_KEY_OBJ_ID;
	size_t obj_id_len = strlen(MASTER_KEY_OBJ_ID);

	if (key_len != MASTER_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Try to open existing key */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_len,
					flags, &obj);

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		/* Generate new master key */
		DMSG("Generating new master key");
		TEE_GenerateRandom(master_key, MASTER_KEY_SIZE);

		/* Store in Secure Storage */
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj_id, obj_id_len,
						 flags,
						 TEE_HANDLE_NULL,
						 master_key, MASTER_KEY_SIZE,
						 &obj);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create master key: 0x%x", res);
			goto cleanup;
		}
	} else if (res == TEE_SUCCESS) {
		/* Read existing key */
		uint32_t read_bytes;
		res = TEE_ReadObjectData(obj, master_key, MASTER_KEY_SIZE,
					 &read_bytes);
		if (res != TEE_SUCCESS || read_bytes != MASTER_KEY_SIZE) {
			EMSG("Failed to read master key: 0x%x", res);
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto cleanup;
		}
	} else {
		EMSG("Failed to open master key: 0x%x", res);
		goto cleanup;
	}

	res = TEE_SUCCESS;

cleanup:
	if (obj != TEE_HANDLE_NULL)
		TEE_CloseObject(obj);

	return res;
}

/*
 * HKDF-Extract: PRK = HMAC(salt, IKM)
 */
static TEE_Result hkdf_extract(const uint8_t *salt, size_t salt_len,
			       const uint8_t *ikm, size_t ikm_len,
			       uint8_t *prk, size_t *prk_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, 256);
	if (res != TEE_SUCCESS)
		return res;

	/* Use salt as HMAC key */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)salt, salt_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	/* HMAC(salt, ikm) */
	TEE_MACInit(op, NULL, 0);
	res = TEE_MACComputeFinal(op, (void *)ikm, ikm_len, prk, prk_len);

cleanup:
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * HKDF-Expand: OKM = HMAC(PRK, info || 0x01)
 */
static TEE_Result hkdf_expand(const uint8_t *prk, size_t prk_len,
			      const uint8_t *info, size_t info_len,
			      uint8_t *okm, size_t okm_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;
	uint8_t t[32] = {0};  /* SHA256 output */
	size_t t_len = 0;
	uint8_t counter = 1;
	size_t offset = 0;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, 256);
	if (res != TEE_SUCCESS)
		return res;

	/* Use PRK as HMAC key */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)prk, prk_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	/* Expand loop: T(i) = HMAC(PRK, T(i-1) || info || i) */
	while (offset < okm_len) {
		size_t copy_len;

		TEE_MACInit(op, NULL, 0);

		/* T(i-1) */
		if (t_len > 0)
			TEE_MACUpdate(op, t, t_len);

		/* info */
		if (info && info_len > 0)
			TEE_MACUpdate(op, (void *)info, info_len);

		/* counter */
		t_len = sizeof(t);
		res = TEE_MACComputeFinal(op, &counter, 1, t, &t_len);
		if (res != TEE_SUCCESS)
			goto cleanup;

		/* Copy to output */
		copy_len = (okm_len - offset < t_len) ?
			   (okm_len - offset) : t_len;
		memcpy(okm + offset, t, copy_len);
		offset += copy_len;
		counter++;
	}

	res = TEE_SUCCESS;

cleanup:
	TEE_MemFill(t, 0, sizeof(t));
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * Derive session keys using HKDF
 */
static TEE_Result derive_session_keys(const uint8_t *master_key,
				      const uint8_t *nonce,
				      uint8_t *session_key,
				      uint8_t *hmac_key)
{
	TEE_Result res;
	uint8_t prk[32];
	size_t prk_len = sizeof(prk);
	const uint8_t info_sess[] = "stm32mp1-uart-session-v1";
	const uint8_t info_mac[] = "stm32mp1-uart-mac-v1";

	/* HKDF-Extract: PRK = HMAC(salt=nonce, IKM=master_key) */
	res = hkdf_extract(nonce, NONCE_SIZE,
			   master_key, MASTER_KEY_SIZE,
			   prk, &prk_len);
	if (res != TEE_SUCCESS) {
		EMSG("HKDF-Extract failed: 0x%x", res);
		goto cleanup;
	}

	/* HKDF-Expand for session key */
	res = hkdf_expand(prk, prk_len,
			  info_sess, sizeof(info_sess) - 1,
			  session_key, SESSION_KEY_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("HKDF-Expand (session) failed: 0x%x", res);
		goto cleanup;
	}

	/* HKDF-Expand for HMAC key */
	res = hkdf_expand(prk, prk_len,
			  info_mac, sizeof(info_mac) - 1,
			  hmac_key, HMAC_KEY_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("HKDF-Expand (mac) failed: 0x%x", res);
		goto cleanup;
	}

	res = TEE_SUCCESS;

cleanup:
	TEE_MemFill(prk, 0, sizeof(prk));
	return res;
}

/*
 * Initialize session module
 */
void session_init(void)
{
	memset(&g_session, 0, sizeof(g_session));
	g_session.state = SESSION_STATE_IDLE;
	g_session.active = false;
}

/*
 * Generate challenge (Nonce + Timestamp + Counter)
 * Returns encrypted challenge packet
 */
TEE_Result session_generate_challenge(struct challenge_packet *out_pkt)
{
	TEE_Result res;
	uint8_t master_key[MASTER_KEY_SIZE];
	uint8_t plaintext[64];
	uint64_t timestamp;
	uint32_t counter;

	if (!out_pkt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check lockout */
	timestamp = get_current_time_sec();
	if (timestamp < g_session.lockout_until) {
		EMSG("Session locked out");
		return TA_ERROR_LOCKED_OUT;
	}

	/* Load master key */
	res = get_master_key(master_key, sizeof(master_key));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get master key: 0x%x", res);
		return res;
	}

	/* Generate session ID and nonce */
	TEE_GenerateRandom(g_session.session_id, SESSION_ID_SIZE);
	TEE_GenerateRandom(g_session.nonce, NONCE_SIZE);

	/* Prepare plaintext: Nonce || Timestamp || Counter */
	memcpy(plaintext, g_session.nonce, NONCE_SIZE);
	memcpy(plaintext + NONCE_SIZE, &timestamp, sizeof(timestamp));

	counter = 0;
	memcpy(plaintext + NONCE_SIZE + sizeof(timestamp), &counter,
	       sizeof(counter));

	/* Encrypt with master key (will be implemented in crypto.c) */
	res = crypto_encrypt_challenge(master_key, plaintext,
					NONCE_SIZE + sizeof(timestamp) +
					sizeof(counter),
					out_pkt);

	if (res == TEE_SUCCESS) {
		g_session.created_time = timestamp;
		g_session.last_activity = timestamp;
		g_session.packet_counter = 0;
		g_session.state = SESSION_STATE_CHALLENGE_SENT;
		g_session.active = true;

		/* Copy session ID to output */
		memcpy(out_pkt->session_id, g_session.session_id,
		       SESSION_ID_SIZE);

		DMSG("Challenge generated, session_id: %02x%02x...",
		     g_session.session_id[0], g_session.session_id[1]);
	}

	TEE_MemFill(master_key, 0, sizeof(master_key));
	TEE_MemFill(plaintext, 0, sizeof(plaintext));

	return res;
}

/*
 * Verify auth and derive session keys
 */
TEE_Result session_verify_auth(const struct auth_packet *auth_pkt)
{
	TEE_Result res;
	uint8_t master_key[MASTER_KEY_SIZE];
	uint64_t current_time = 0;

	if (!auth_pkt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get current time early for lockout checks */
	current_time = get_current_time_sec();

	/* Verify session state */
	if (g_session.state != SESSION_STATE_CHALLENGE_SENT) {
		EMSG("Invalid session state: %d", g_session.state);
		return TEE_ERROR_BAD_STATE;
	}

	/* Verify session ID */
	if (memcmp(auth_pkt->session_id, g_session.session_id,
		   SESSION_ID_SIZE) != 0) {
		EMSG("Session ID mismatch");
		g_session.failed_attempts++;
		goto auth_failed;
	}

	/* Check lockout */
	if (current_time < g_session.lockout_until) {
		EMSG("Session locked out");
		return TA_ERROR_LOCKED_OUT;
	}

	/* Verify auth packet (decrypt and validate) */
	res = crypto_verify_auth(auth_pkt);
	if (res != TEE_SUCCESS) {
		EMSG("Auth verification failed: 0x%x", res);
		g_session.failed_attempts++;
		goto auth_failed;
	}

	/* Load master key */
	res = get_master_key(master_key, sizeof(master_key));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get master key: 0x%x", res);
		return res;
	}

	/* Derive session keys using HKDF */
	res = derive_session_keys(master_key,
				  g_session.nonce,
				  g_session.session_key,
				  g_session.hmac_key);

	TEE_MemFill(master_key, 0, sizeof(master_key));

	if (res != TEE_SUCCESS) {
		EMSG("Key derivation failed: 0x%x", res);
		g_session.failed_attempts++;
		goto auth_failed;
	}

	/* Auth successful */
	g_session.state = SESSION_STATE_AUTHENTICATED;
	g_session.last_activity = current_time;
	g_session.failed_attempts = 0;

	DMSG("Authentication successful");
	return TEE_SUCCESS;

auth_failed:
	if (g_session.failed_attempts >= MAX_AUTH_ATTEMPTS) {
		g_session.lockout_until = current_time + LOCKOUT_DURATION_SEC;
		EMSG("Too many failed attempts, locked out for %d seconds",
		     LOCKOUT_DURATION_SEC);
		return TA_ERROR_LOCKED_OUT;
	}

	return TA_ERROR_AUTH_FAILED;
}

/*
 * Validate session (check timeout, update activity)
 */
TEE_Result session_validate(const uint8_t *session_id)
{
	uint64_t current_time;

	if (!session_id)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_session.active)
		return TEE_ERROR_BAD_STATE;

	/* Verify session ID */
	if (memcmp(session_id, g_session.session_id, SESSION_ID_SIZE) != 0) {
		EMSG("Session ID mismatch in validation");
		return TEE_ERROR_BAD_STATE;
	}

	/* Check state */
	if (g_session.state != SESSION_STATE_AUTHENTICATED &&
	    g_session.state != SESSION_STATE_ACTIVE) {
		EMSG("Invalid session state: %d", g_session.state);
		return TEE_ERROR_BAD_STATE;
	}

	/* Check timeout */
	current_time = get_current_time_sec();
	if ((current_time - g_session.last_activity) > SESSION_TIMEOUT_SEC) {
		EMSG("Session timeout");
		session_destroy();
		return TA_ERROR_SESSION_TIMEOUT;
	}

	/* Update activity timestamp */
	g_session.last_activity = current_time;
	g_session.state = SESSION_STATE_ACTIVE;

	return TEE_SUCCESS;
}

/*
 * Get session keys
 */
TEE_Result session_get_keys(const uint8_t **session_key,
			    const uint8_t **hmac_key,
			    uint32_t *counter)
{
	if (!session_key || !hmac_key || !counter)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_session.active ||
	    (g_session.state != SESSION_STATE_AUTHENTICATED &&
	     g_session.state != SESSION_STATE_ACTIVE)) {
		return TEE_ERROR_BAD_STATE;
	}

	*session_key = g_session.session_key;
	*hmac_key = g_session.hmac_key;
	*counter = g_session.packet_counter;

	return TEE_SUCCESS;
}

/*
 * Increment and verify packet counter (replay protection)
 */
TEE_Result session_verify_counter(uint32_t received_counter)
{
	if (!g_session.active)
		return TEE_ERROR_BAD_STATE;

	/* Counter must be monotonically increasing */
	if (received_counter <= g_session.packet_counter) {
		EMSG("Replay detected: received %u, expected > %u",
		     received_counter, g_session.packet_counter);
		return TA_ERROR_REPLAY_DETECTED;
	}

	g_session.packet_counter = received_counter;
	return TEE_SUCCESS;
}

/*
 * Get next counter value
 */
uint32_t session_get_next_counter(void)
{
	return ++g_session.packet_counter;
}

/*
 * Destroy session
 */
void session_destroy(void)
{
	if (g_session.active) {
		DMSG("Destroying session");

		/* Zeroize sensitive data */
		TEE_MemFill(g_session.session_key, 0,
				 sizeof(g_session.session_key));
		TEE_MemFill(g_session.hmac_key, 0,
				 sizeof(g_session.hmac_key));
		TEE_MemFill(g_session.nonce, 0, sizeof(g_session.nonce));

		memset(&g_session, 0, sizeof(g_session));
		g_session.state = SESSION_STATE_CLOSED;
		g_session.active = false;
	}
}

/*
 * Get session status
 */
enum session_state session_get_state(void)
{
	return g_session.state;
}
