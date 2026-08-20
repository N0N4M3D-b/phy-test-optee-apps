/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Secure UART TA tests: session lifecycle and crypto verification
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <tee_client_api.h>

#include "test_secure_uart.h"
#include <secure_uart_ta.h>

/* Test result tracking */
static int passed;
static int failed;
static bool verbose_mode;

static void print_result(const char *name, bool success)
{
	printf("[SecUART] %-25s %s\n", name,
	       success ? "PASS" : "FAIL");
}

static void verbose_hex(const char *label, const uint8_t *data, size_t len)
{
	if (!verbose_mode)
		return;

	printf("  %s (%zu bytes): ", label, len);
	for (size_t i = 0; i < len && i < 32; i++)
		printf("%02x", data[i]);
	if (len > 32)
		printf("...");
	printf("\n");
}

/* ----------------------------------------------------------------
 * Get session status helper
 * ---------------------------------------------------------------- */
static int get_status(TEEC_Session *sess, uint32_t *status)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, CMD_GET_SESSION_STATUS, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  GET_SESSION_STATUS failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		return -1;
	}

	*status = op.params[0].value.a;
	return 0;
}

/* ----------------------------------------------------------------
 * Test 1: Session status should be IDLE initially
 * ---------------------------------------------------------------- */
static void test_status_idle(TEEC_Session *sess)
{
	uint32_t status;
	bool success = false;

	if (get_status(sess, &status) < 0)
		goto done;

	if (status != SESSION_STATE_IDLE) {
		if (verbose_mode)
			printf("  Expected state %d (IDLE), got %u\n",
			       SESSION_STATE_IDLE, status);
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  Session state: %u (IDLE)\n", status);

done:
	print_result("Session status (idle)", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Test 2: Generate challenge
 * ---------------------------------------------------------------- */
static void test_generate_challenge(TEEC_Session *sess, uint8_t *challenge_buf,
				    size_t *challenge_len)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	bool success = false;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = challenge_buf;
	op.params[0].tmpref.size = *challenge_len;

	res = TEEC_InvokeCommand(sess, CMD_GENERATE_CHALLENGE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  GENERATE_CHALLENGE failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		*challenge_len = 0;
		goto done;
	}

	*challenge_len = op.params[0].tmpref.size;

	if (*challenge_len == 0) {
		if (verbose_mode)
			printf("  Challenge returned zero bytes\n");
		goto done;
	}

	success = true;
	if (verbose_mode) {
		printf("  Challenge size: %zu bytes\n", *challenge_len);
		verbose_hex("challenge", challenge_buf, *challenge_len);
	}

done:
	print_result("Generate challenge", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Test 3: Verify auth (uses placeholder auth — TA currently accepts any)
 * ---------------------------------------------------------------- */
static void test_verify_auth(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t auth_pkt[sizeof(struct auth_packet)];
	bool success = false;

	/* Fill auth packet with dummy data.
	 * The current TA crypto_verify_auth() is a placeholder that
	 * accepts any auth, so this should succeed. */
	memset(auth_pkt, 0, sizeof(auth_pkt));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = auth_pkt;
	op.params[0].tmpref.size = sizeof(auth_pkt);

	res = TEEC_InvokeCommand(sess, CMD_VERIFY_FINAL_AUTH, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  VERIFY_FINAL_AUTH failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  Authentication verified\n");

done:
	print_result("Verify auth", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Test 4: Session status should be AUTHENTICATED after auth
 * ---------------------------------------------------------------- */
static void test_status_authenticated(TEEC_Session *sess)
{
	uint32_t status;
	bool success = false;

	if (get_status(sess, &status) < 0)
		goto done;

	if (status != SESSION_STATE_AUTHENTICATED) {
		if (verbose_mode)
			printf("  Expected state %d (AUTHENTICATED), got %u\n",
			       SESSION_STATE_AUTHENTICATED, status);
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  Session state: %u (AUTHENTICATED)\n", status);

done:
	print_result("Session status (auth)", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Test 5: Destroy session
 * ---------------------------------------------------------------- */
static void test_destroy_session(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	bool success = false;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, CMD_DESTROY_SESSION, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  DESTROY_SESSION failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  Session destroyed\n");

done:
	print_result("Destroy session", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */
int run_secure_uart_tests(bool verbose)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = SECURE_UART_TA_UUID;
	uint32_t err_origin;
	uint8_t challenge_buf[sizeof(struct challenge_packet)];
	size_t challenge_len = sizeof(challenge_buf);

	passed = 0;
	failed = 0;
	verbose_mode = verbose;

	/* Initialize context */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("[SecUART] Failed to initialize context: 0x%x\n", res);
		return 5;
	}

	/* Open session with Secure UART TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("[SecUART] Failed to open session: 0x%x (origin 0x%x)\n",
		       res, err_origin);
		TEEC_FinalizeContext(&ctx);
		return 5;
	}

	if (verbose)
		printf("[SecUART] Session opened, running tests...\n");

	/* Run session lifecycle tests in order */
	test_status_idle(&sess);
	test_generate_challenge(&sess, challenge_buf, &challenge_len);
	test_verify_auth(&sess);
	test_status_authenticated(&sess);
	test_destroy_session(&sess);

	/* Cleanup */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return failed;
}
