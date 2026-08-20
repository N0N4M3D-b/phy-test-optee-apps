/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "tee_client.h"

/* Global TEE context and session */
static TEEC_Context ctx;
static TEEC_Session sess;
static bool initialized = false;

/* Shared memory for zero-copy transfers */
static TEEC_SharedMemory shm_in;
static TEEC_SharedMemory shm_out;

#define SHM_SIZE	sizeof(struct data_packet)

/*
 * Initialize TEE client
 */
int tee_client_init(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = SECURE_UART_TA_UUID;
	uint32_t err_origin;

	if (initialized) {
		fprintf(stderr, "TEE client already initialized\n");
		return -1;
	}

	/* Initialize context */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext failed: 0x%x\n", res);
		return -1;
	}

	/* Allocate shared memory for input */
	shm_in.size = SHM_SIZE;
	shm_in.flags = TEEC_MEM_INPUT;
	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "Failed to allocate input shared memory: 0x%x\n",
			res);
		goto err_ctx;
	}

	/* Allocate shared memory for output */
	shm_out.size = SHM_SIZE;
	shm_out.flags = TEEC_MEM_OUTPUT;
	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "Failed to allocate output shared memory: 0x%x\n",
			res);
		goto err_shm_in;
	}

	/* Open session with TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_OpenSession failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		goto err_shm_out;
	}

	initialized = true;
	printf("TEE client initialized successfully\n");
	return 0;

err_shm_out:
	TEEC_ReleaseSharedMemory(&shm_out);
err_shm_in:
	TEEC_ReleaseSharedMemory(&shm_in);
err_ctx:
	TEEC_FinalizeContext(&ctx);
	return -1;
}

/*
 * Cleanup TEE client
 */
void tee_client_cleanup(void)
{
	if (!initialized)
		return;

	TEEC_CloseSession(&sess);
	TEEC_ReleaseSharedMemory(&shm_out);
	TEEC_ReleaseSharedMemory(&shm_in);
	TEEC_FinalizeContext(&ctx);

	initialized = false;
	printf("TEE client cleaned up\n");
}

/*
 * Generate challenge
 */
int tee_generate_challenge(uint8_t *challenge, size_t *challenge_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	if (!challenge || !challenge_len) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	/* Prepare operation */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = challenge;
	op.params[0].tmpref.size = *challenge_len;

	/* Invoke command */
	res = TEEC_InvokeCommand(&sess, CMD_GENERATE_CHALLENGE, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "CMD_GENERATE_CHALLENGE failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	*challenge_len = op.params[0].tmpref.size;

	printf("Challenge generated: %zu bytes\n", *challenge_len);
	return 0;
}

/*
 * Verify authentication
 */
int tee_verify_auth(const uint8_t *auth_data, size_t auth_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	if (!auth_data || auth_len == 0) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	/* Prepare operation */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)auth_data;
	op.params[0].tmpref.size = auth_len;

	/* Invoke command */
	res = TEEC_InvokeCommand(&sess, CMD_VERIFY_FINAL_AUTH, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "CMD_VERIFY_FINAL_AUTH failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	printf("Authentication verified successfully\n");
	return 0;
}

/*
 * Decrypt and filter input
 */
int tee_decrypt_and_filter(const uint8_t *enc_data, size_t enc_len,
			    uint8_t *plaintext, size_t *plaintext_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	if (!enc_data || !plaintext || !plaintext_len) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	if (enc_len > shm_in.size) {
		fprintf(stderr, "Input too large: %zu bytes (max %zu)\n",
			enc_len, shm_in.size);
		return -1;
	}

	/* Copy to shared memory */
	memcpy(shm_in.buffer, enc_data, enc_len);

	/* Prepare operation */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = enc_len;

	op.params[1].memref.parent = &shm_out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_out.size;

	/* Invoke command */
	res = TEEC_InvokeCommand(&sess, CMD_DECRYPT_AND_FILTER, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "CMD_DECRYPT_AND_FILTER failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	/* Copy from shared memory */
	if (op.params[1].memref.size > *plaintext_len) {
		fprintf(stderr, "Output buffer too small: need %u bytes\n",
			op.params[1].memref.size);
		return -1;
	}

	memcpy(plaintext, shm_out.buffer, op.params[1].memref.size);
	*plaintext_len = op.params[1].memref.size;

	printf("Decrypted and filtered: %zu bytes\n", *plaintext_len);
	return 0;
}

/*
 * Encrypt output
 */
int tee_encrypt_output(const uint8_t *plaintext, size_t plaintext_len,
			uint8_t *enc_data, size_t *enc_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	if (!plaintext || !enc_data || !enc_len) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	if (plaintext_len > shm_in.size) {
		fprintf(stderr, "Input too large: %zu bytes (max %zu)\n",
			plaintext_len, shm_in.size);
		return -1;
	}

	/* Copy to shared memory */
	memcpy(shm_in.buffer, plaintext, plaintext_len);

	/* Prepare operation */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = plaintext_len;

	op.params[1].memref.parent = &shm_out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_out.size;

	/* Invoke command */
	res = TEEC_InvokeCommand(&sess, CMD_ENCRYPT_OUTPUT, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "CMD_ENCRYPT_OUTPUT failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	/* Copy from shared memory */
	if (op.params[1].memref.size > *enc_len) {
		fprintf(stderr, "Output buffer too small: need %u bytes\n",
			op.params[1].memref.size);
		return -1;
	}

	memcpy(enc_data, shm_out.buffer, op.params[1].memref.size);
	*enc_len = op.params[1].memref.size;

	printf("Encrypted output: %zu bytes\n", *enc_len);
	return 0;
}

/*
 * Destroy session
 */
int tee_destroy_session(void)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	/* Prepare operation */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	/* Invoke command */
	res = TEEC_InvokeCommand(&sess, CMD_DESTROY_SESSION, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "CMD_DESTROY_SESSION failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	printf("Session destroyed\n");
	return 0;
}

/*
 * Get session status
 */
int tee_get_session_status(uint32_t *status)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	if (!initialized) {
		fprintf(stderr, "TEE client not initialized\n");
		return -1;
	}

	if (!status) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, CMD_GET_SESSION_STATUS, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"CMD_GET_SESSION_STATUS failed: 0x%x (origin: 0x%x)\n",
			res, err_origin);
		return -1;
	}

	*status = op.params[0].value.a;
	return 0;
}
