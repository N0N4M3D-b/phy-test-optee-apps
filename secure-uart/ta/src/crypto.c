// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <string_ext.h>
#include <secure_uart_ta.h>
#include "crypto.h"

/*
 * Constant-time memory comparison
 */
static bool secure_memcmp(const void *a, const void *b, size_t len)
{
	const uint8_t *a_bytes = a;
	const uint8_t *b_bytes = b;
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= a_bytes[i] ^ b_bytes[i];

	return (diff == 0);
}

/*
 * HMAC-SHA256 computation
 */
static TEE_Result compute_hmac(const uint8_t *key, size_t key_len,
			       const uint8_t *data, size_t data_len,
			       uint8_t *mac, size_t *mac_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, key_len * 8);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_len * 8,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)key, key_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_MACInit(op, NULL, 0);
	res = TEE_MACComputeFinal(op, (void *)data, data_len, mac, mac_len);

cleanup:
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * AES-CBC encryption (used for challenge)
 */
static TEE_Result aes_cbc_encrypt(const uint8_t *key, size_t key_len,
				  const uint8_t *iv, size_t iv_len,
				  const uint8_t *plaintext, size_t pt_len,
				  uint8_t *ciphertext, size_t *ct_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, key_len * 8);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_len * 8,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)key, key_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_CipherInit(op, (void *)iv, iv_len);
	res = TEE_CipherDoFinal(op, (void *)plaintext, pt_len,
				ciphertext, ct_len);

cleanup:
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * AES-CBC decryption (used for challenge verification)
 */
static TEE_Result __maybe_unused aes_cbc_decrypt(const uint8_t *key, size_t key_len,
				  const uint8_t *iv, size_t iv_len,
				  const uint8_t *ciphertext, size_t ct_len,
				  uint8_t *plaintext, size_t *pt_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_DECRYPT, key_len * 8);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_len * 8,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)key, key_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_CipherInit(op, (void *)iv, iv_len);
	res = TEE_CipherDoFinal(op, (void *)ciphertext, ct_len,
				plaintext, pt_len);

cleanup:
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * AES-CTR encryption/decryption (symmetric operation)
 */
static TEE_Result aes_ctr_crypt(const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *input, size_t input_len,
				uint8_t *output, size_t *output_len)
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute attr;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR,
				    TEE_MODE_ENCRYPT, key_len * 8);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_len * 8,
					  &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     (void *)key, key_len);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_CipherInit(op, (void *)iv, iv_len);
	res = TEE_CipherDoFinal(op, (void *)input, input_len,
				output, output_len);

cleanup:
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);

	return res;
}

/*
 * Encrypt challenge packet (AES-CBC + HMAC)
 */
TEE_Result crypto_encrypt_challenge(const uint8_t *master_key,
				    const uint8_t *plaintext, size_t pt_len,
				    struct challenge_packet *out_pkt)
{
	TEE_Result res;
	uint8_t iv[AES_IV_SIZE];
	size_t ct_len = sizeof(out_pkt->enc_payload);
	size_t mac_len = HMAC_TAG_SIZE;
	uint8_t mac_input[SESSION_ID_SIZE + AES_IV_SIZE + 64];
	size_t mac_input_len;

	if (!master_key || !plaintext || !out_pkt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pt_len > sizeof(out_pkt->enc_payload))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Generate random IV */
	TEE_GenerateRandom(iv, AES_IV_SIZE);
	memcpy(out_pkt->iv, iv, AES_IV_SIZE);

	/* AES-CBC encrypt */
	res = aes_cbc_encrypt(master_key, MASTER_KEY_SIZE,
			      iv, AES_IV_SIZE,
			      plaintext, pt_len,
			      out_pkt->enc_payload, &ct_len);
	if (res != TEE_SUCCESS) {
		EMSG("AES-CBC encryption failed: 0x%x", res);
		return res;
	}

	/* Compute HMAC(master_key, session_id || iv || ciphertext) */
	mac_input_len = 0;
	memcpy(mac_input + mac_input_len, out_pkt->session_id,
	       SESSION_ID_SIZE);
	mac_input_len += SESSION_ID_SIZE;

	memcpy(mac_input + mac_input_len, out_pkt->iv, AES_IV_SIZE);
	mac_input_len += AES_IV_SIZE;

	memcpy(mac_input + mac_input_len, out_pkt->enc_payload, ct_len);
	mac_input_len += ct_len;

	res = compute_hmac(master_key, MASTER_KEY_SIZE,
			   mac_input, mac_input_len,
			   out_pkt->hmac_tag, &mac_len);
	TEE_MemFill(mac_input, 0, sizeof(mac_input));
	if (res != TEE_SUCCESS) {
		EMSG("Challenge HMAC failed: 0x%x", res);
		return res;
	}

	return TEE_SUCCESS;
}

/*
 * Verify authentication packet.
 *
 * The peer-authentication payload format is intentionally kept compatible
 * with the original implementation. Cryptographic verification must replace
 * this development stub before the protocol is used in production.
 */
TEE_Result crypto_verify_auth(const struct auth_packet *auth_pkt)
{
	/* Placeholder - actual verification logic would go here */
	/* For now, just accept any auth packet */
	/* In real implementation, decrypt and verify user response */

	if (!auth_pkt)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Auth packet verification (placeholder)");
	return TEE_SUCCESS;
}

/*
 * Decrypt and verify data packet (AES-CTR + HMAC)
 */
TEE_Result crypto_decrypt_and_verify(const struct data_packet *pkt,
				     const uint8_t *session_key,
				     const uint8_t *hmac_key,
				     uint8_t *plaintext, size_t *pt_len)
{
	TEE_Result res;
	uint8_t computed_mac[HMAC_TAG_SIZE];
	size_t mac_len = HMAC_TAG_SIZE;
	uint8_t mac_input[SESSION_ID_SIZE + AES_IV_SIZE + 2 + MAX_PACKET_SIZE];
	size_t mac_input_len;

	if (!pkt || !session_key || !hmac_key || !plaintext || !pt_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pkt->data_len > MAX_PACKET_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Compute HMAC(hmac_key, session_id || iv || data_len || ciphertext) */
	mac_input_len = 0;
	memcpy(mac_input + mac_input_len, pkt->session_id, SESSION_ID_SIZE);
	mac_input_len += SESSION_ID_SIZE;

	memcpy(mac_input + mac_input_len, pkt->iv, AES_IV_SIZE);
	mac_input_len += AES_IV_SIZE;

	memcpy(mac_input + mac_input_len, &pkt->data_len, 2);
	mac_input_len += 2;

	memcpy(mac_input + mac_input_len, pkt->enc_data, pkt->data_len);
	mac_input_len += pkt->data_len;

	res = compute_hmac(hmac_key, HMAC_KEY_SIZE,
			   mac_input, mac_input_len,
			   computed_mac, &mac_len);

	TEE_MemFill(mac_input, 0, sizeof(mac_input));

	if (res != TEE_SUCCESS) {
		EMSG("HMAC computation failed: 0x%x", res);
		return res;
	}

	/* Constant-time MAC comparison */
	if (!secure_memcmp(computed_mac, pkt->hmac_tag, HMAC_TAG_SIZE)) {
		EMSG("HMAC verification failed");
		return TEE_ERROR_MAC_INVALID;
	}

	/* AES-CTR decrypt */
	*pt_len = pkt->data_len;
	res = aes_ctr_crypt(session_key, SESSION_KEY_SIZE,
			    pkt->iv, AES_IV_SIZE,
			    pkt->enc_data, pkt->data_len,
			    plaintext, pt_len);

	if (res != TEE_SUCCESS) {
		EMSG("AES-CTR decryption failed: 0x%x", res);
		return res;
	}

	return TEE_SUCCESS;
}

/*
 * Encrypt data packet (AES-CTR + HMAC)
 */
TEE_Result crypto_encrypt_and_sign(const uint8_t *plaintext, size_t pt_len,
				   const uint8_t *session_key,
				   const uint8_t *hmac_key,
				   const uint8_t *session_id,
				   const uint8_t *iv,
				   struct data_packet *out_pkt)
{
	TEE_Result res;
	size_t ct_len = pt_len;
	size_t mac_len = HMAC_TAG_SIZE;
	uint8_t mac_input[SESSION_ID_SIZE + AES_IV_SIZE + 2 + MAX_PACKET_SIZE];
	size_t mac_input_len;

	if (!plaintext || !session_key || !hmac_key || !session_id ||
	    !iv || !out_pkt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (pt_len > MAX_PACKET_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Copy session ID and IV */
	memcpy(out_pkt->session_id, session_id, SESSION_ID_SIZE);
	memcpy(out_pkt->iv, iv, AES_IV_SIZE);
	out_pkt->data_len = pt_len;

	/* AES-CTR encrypt */
	res = aes_ctr_crypt(session_key, SESSION_KEY_SIZE,
			    iv, AES_IV_SIZE,
			    plaintext, pt_len,
			    out_pkt->enc_data, &ct_len);

	if (res != TEE_SUCCESS) {
		EMSG("AES-CTR encryption failed: 0x%x", res);
		return res;
	}

	/* Compute HMAC(hmac_key, session_id || iv || data_len || ciphertext) */
	mac_input_len = 0;
	memcpy(mac_input + mac_input_len, out_pkt->session_id,
	       SESSION_ID_SIZE);
	mac_input_len += SESSION_ID_SIZE;

	memcpy(mac_input + mac_input_len, out_pkt->iv, AES_IV_SIZE);
	mac_input_len += AES_IV_SIZE;

	memcpy(mac_input + mac_input_len, &out_pkt->data_len, 2);
	mac_input_len += 2;

	memcpy(mac_input + mac_input_len, out_pkt->enc_data, ct_len);
	mac_input_len += ct_len;

	res = compute_hmac(hmac_key, HMAC_KEY_SIZE,
			   mac_input, mac_input_len,
			   out_pkt->hmac_tag, &mac_len);

	TEE_MemFill(mac_input, 0, sizeof(mac_input));

	if (res != TEE_SUCCESS) {
		EMSG("HMAC computation failed: 0x%x", res);
		return res;
	}

	return TEE_SUCCESS;
}
