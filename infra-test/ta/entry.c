// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Test TA - Validates OP-TEE infrastructure: TEE communication,
 * RNG, AES-CTR, HMAC-SHA256, and Secure Storage.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <test_ta.h>

/*
 * TA_CreateEntryPoint - Called when TA is loaded
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("Test TA CreateEntryPoint");
	return TEE_SUCCESS;
}

/*
 * TA_DestroyEntryPoint - Called when TA is unloaded
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("Test TA DestroyEntryPoint");
}

/*
 * TA_OpenSessionEntryPoint - Called when client opens session
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **session_ctx __unused)
{
	DMSG("Test TA OpenSession");
	*session_ctx = NULL;
	return TEE_SUCCESS;
}

/*
 * TA_CloseSessionEntryPoint - Called when client closes session
 */
void TA_CloseSessionEntryPoint(void *session_ctx __unused)
{
	DMSG("Test TA CloseSession");
}

/* ----------------------------------------------------------------
 * CMD_TEST_ECHO: memcpy input to output — TEE communication test
 * ---------------------------------------------------------------- */
static TEE_Result cmd_test_echo(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp) {
		EMSG("Echo: bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t in_len = params[0].memref.size;

	if (params[1].memref.size < in_len) {
		params[1].memref.size = in_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	memcpy(params[1].memref.buffer, params[0].memref.buffer, in_len);
	params[1].memref.size = in_len;

	DMSG("Echo: %zu bytes", in_len);
	return TEE_SUCCESS;
}

/* ----------------------------------------------------------------
 * CMD_TEST_RNG: Fill output buffer with random bytes
 * ---------------------------------------------------------------- */
static TEE_Result cmd_test_rng(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp) {
		EMSG("RNG: bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	uint32_t req_size = params[0].value.a;

	if (req_size == 0 || req_size > TEST_MAX_DATA_SIZE) {
		EMSG("RNG: invalid size %u", req_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < req_size) {
		params[1].memref.size = req_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_GenerateRandom(params[1].memref.buffer, req_size);
	params[1].memref.size = req_size;

	DMSG("RNG: generated %u bytes", req_size);
	return TEE_SUCCESS;
}

/* ----------------------------------------------------------------
 * CMD_TEST_AES: AES-CTR encrypt then decrypt, return decrypted
 * Params[0]: MEMREF_INPUT  — plaintext
 * Params[1]: MEMREF_OUTPUT — decrypted (should match plaintext)
 * ---------------------------------------------------------------- */
static TEE_Result cmd_test_aes(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle enc_op = TEE_HANDLE_NULL;
	TEE_OperationHandle dec_op = TEE_HANDLE_NULL;
	TEE_Attribute attr;
	uint8_t key_data[TEST_AES_KEY_SIZE];
	uint8_t iv[TEST_AES_IV_SIZE];
	uint8_t *ciphertext = NULL;
	size_t ct_len, pt_len;

	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp) {
		EMSG("AES: bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t in_len = params[0].memref.size;

	if (in_len == 0 || in_len > TEST_MAX_DATA_SIZE) {
		EMSG("AES: invalid input size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < in_len) {
		params[1].memref.size = in_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Generate random key and IV */
	TEE_GenerateRandom(key_data, sizeof(key_data));
	TEE_GenerateRandom(iv, sizeof(iv));

	/* Allocate transient key object */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AES: AllocateTransientObject failed: 0x%x", res);
		goto cleanup;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     key_data, sizeof(key_data));
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("AES: PopulateTransientObject failed: 0x%x", res);
		goto cleanup;
	}

	/* Allocate ciphertext buffer */
	ciphertext = TEE_Malloc(in_len, TEE_MALLOC_FILL_ZERO);
	if (!ciphertext) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* --- Encrypt --- */
	res = TEE_AllocateOperation(&enc_op, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT,
				    256);
	if (res != TEE_SUCCESS) {
		EMSG("AES: AllocateOperation(enc) failed: 0x%x", res);
		goto cleanup;
	}

	res = TEE_SetOperationKey(enc_op, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AES: SetOperationKey(enc) failed: 0x%x", res);
		goto cleanup;
	}

	TEE_CipherInit(enc_op, iv, sizeof(iv));

	ct_len = in_len;
	res = TEE_CipherDoFinal(enc_op, params[0].memref.buffer, in_len,
				ciphertext, &ct_len);
	if (res != TEE_SUCCESS) {
		EMSG("AES: CipherDoFinal(enc) failed: 0x%x", res);
		goto cleanup;
	}

	/* --- Decrypt with same key and IV --- */
	res = TEE_AllocateOperation(&dec_op, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT,
				    256);
	if (res != TEE_SUCCESS) {
		EMSG("AES: AllocateOperation(dec) failed: 0x%x", res);
		goto cleanup;
	}

	res = TEE_SetOperationKey(dec_op, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("AES: SetOperationKey(dec) failed: 0x%x", res);
		goto cleanup;
	}

	TEE_CipherInit(dec_op, iv, sizeof(iv));

	pt_len = in_len;
	res = TEE_CipherDoFinal(dec_op, ciphertext, ct_len,
				params[1].memref.buffer, &pt_len);
	if (res != TEE_SUCCESS) {
		EMSG("AES: CipherDoFinal(dec) failed: 0x%x", res);
		goto cleanup;
	}

	params[1].memref.size = pt_len;
	DMSG("AES: round-trip %zu bytes", pt_len);

cleanup:
	if (enc_op)
		TEE_FreeOperation(enc_op);
	if (dec_op)
		TEE_FreeOperation(dec_op);
	if (key_handle)
		TEE_FreeTransientObject(key_handle);
	if (ciphertext) {
		TEE_MemFill(ciphertext, 0, in_len);
		TEE_Free(ciphertext);
	}
	TEE_MemFill(key_data, 0, sizeof(key_data));
	return res;
}

/* ----------------------------------------------------------------
 * CMD_TEST_HMAC: Compute HMAC-SHA256 over input data
 * Params[0]: MEMREF_INPUT  — data to MAC
 * Params[1]: MEMREF_OUTPUT — 32-byte HMAC tag
 * ---------------------------------------------------------------- */
static TEE_Result cmd_test_hmac(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle mac_op = TEE_HANDLE_NULL;
	TEE_Attribute attr;
	uint8_t key_data[TEST_HMAC_KEY_SIZE];
	size_t mac_len = TEST_HMAC_TAG_SIZE;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.size ||
	    params[0].memref.size > TEST_MAX_DATA_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < TEST_HMAC_TAG_SIZE) {
		params[1].memref.size = TEST_HMAC_TAG_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_GenerateRandom(key_data, sizeof(key_data));
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
					  sizeof(key_data) * 8, &key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     key_data, sizeof(key_data));
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_AllocateOperation(&mac_op, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, sizeof(key_data) * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(mac_op, key_handle);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_MACInit(mac_op, NULL, 0);
	res = TEE_MACComputeFinal(mac_op, params[0].memref.buffer,
				  params[0].memref.size,
				  params[1].memref.buffer, &mac_len);
	if (res == TEE_SUCCESS)
		params[1].memref.size = mac_len;

cleanup:
	if (mac_op != TEE_HANDLE_NULL)
		TEE_FreeOperation(mac_op);
	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);
	TEE_MemFill(key_data, 0, sizeof(key_data));
	return res;
}

/* ----------------------------------------------------------------
 * CMD_TEST_STORAGE: Write data to Secure Storage, read back, compare
 * ---------------------------------------------------------------- */
static TEE_Result cmd_test_storage(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t read_bytes = 0;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_OVERWRITE;
	const char object_id[] = TEST_STORAGE_ID;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp || !params[0].memref.size ||
	    params[0].memref.size > TEST_MAX_DATA_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < params[0].memref.size) {
		params[1].memref.size = params[0].memref.size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 object_id, sizeof(object_id) - 1,
					 flags, TEE_HANDLE_NULL,
					 params[0].memref.buffer,
					 params[0].memref.size, &obj);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);
	if (res == TEE_SUCCESS)
		res = TEE_ReadObjectData(obj, params[1].memref.buffer,
					 params[1].memref.size, &read_bytes);

	TEE_CloseAndDeletePersistentObject1(obj);
	if (res == TEE_SUCCESS)
		params[1].memref.size = read_bytes;
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx __unused,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case CMD_TEST_ECHO:
		return cmd_test_echo(param_types, params);
	case CMD_TEST_RNG:
		return cmd_test_rng(param_types, params);
	case CMD_TEST_AES:
		return cmd_test_aes(param_types, params);
	case CMD_TEST_HMAC:
		return cmd_test_hmac(param_types, params);
	case CMD_TEST_STORAGE:
		return cmd_test_storage(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
