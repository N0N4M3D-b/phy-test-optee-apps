/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Test TA basic tests: echo, RNG, AES round-trip, HMAC, Secure Storage
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <tee_client_api.h>

#include "test_basic.h"
#include <test_ta.h>

#define TEST_DATA_SIZE		256
#define TEST_RNG_SIZE		32
#define TEST_HMAC_TAG_SIZE	32
#define TEST_STORAGE_SIZE	64

/* Test result tracking */
static int passed;
static int failed;
static bool verbose_mode;

static void print_result(const char *name, bool success)
{
	printf("[Test TA] %-25s %s\n", name,
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
 * Echo test: send 256 bytes, verify identical return
 * ---------------------------------------------------------------- */
static void test_echo(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t in_buf[TEST_DATA_SIZE];
	uint8_t out_buf[TEST_DATA_SIZE];
	bool success = false;

	/* Fill with pattern */
	for (int i = 0; i < TEST_DATA_SIZE; i++)
		in_buf[i] = (uint8_t)(i & 0xff);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in_buf;
	op.params[0].tmpref.size = TEST_DATA_SIZE;
	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = TEST_DATA_SIZE;

	res = TEEC_InvokeCommand(sess, CMD_TEST_ECHO, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  TEEC_InvokeCommand failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	if (op.params[1].tmpref.size != TEST_DATA_SIZE) {
		if (verbose_mode)
			printf("  Size mismatch: got %u, expected %d\n",
			       (unsigned)op.params[1].tmpref.size,
			       TEST_DATA_SIZE);
		goto done;
	}

	if (memcmp(in_buf, out_buf, TEST_DATA_SIZE) != 0) {
		if (verbose_mode)
			printf("  Data mismatch\n");
		goto done;
	}

	success = true;
	if (verbose_mode)
		verbose_hex("echo data", out_buf, 16);

done:
	print_result("Echo test", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * RNG test: request 32 bytes, verify not all-zero
 * ---------------------------------------------------------------- */
static void test_rng(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t out_buf[TEST_RNG_SIZE];
	bool success = false;
	bool has_nonzero = false;

	memset(out_buf, 0, sizeof(out_buf));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = TEST_RNG_SIZE;
	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = TEST_RNG_SIZE;

	res = TEEC_InvokeCommand(sess, CMD_TEST_RNG, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  TEEC_InvokeCommand failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	/* Check at least one byte is non-zero */
	for (int i = 0; i < TEST_RNG_SIZE; i++) {
		if (out_buf[i] != 0) {
			has_nonzero = true;
			break;
		}
	}

	if (!has_nonzero) {
		if (verbose_mode)
			printf("  All bytes are zero\n");
		goto done;
	}

	success = true;
	if (verbose_mode)
		verbose_hex("random data", out_buf, TEST_RNG_SIZE);

done:
	print_result("RNG test", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * AES round-trip test: encrypt+decrypt in TA, verify plaintext == result
 * ---------------------------------------------------------------- */
static void test_aes(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t plaintext[TEST_DATA_SIZE];
	uint8_t result[TEST_DATA_SIZE];
	bool success = false;

	/* Fill with known pattern */
	for (int i = 0; i < TEST_DATA_SIZE; i++)
		plaintext[i] = (uint8_t)((i * 7 + 3) & 0xff);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = TEST_DATA_SIZE;
	op.params[1].tmpref.buffer = result;
	op.params[1].tmpref.size = TEST_DATA_SIZE;

	res = TEEC_InvokeCommand(sess, CMD_TEST_AES, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  TEEC_InvokeCommand failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	if (op.params[1].tmpref.size != TEST_DATA_SIZE) {
		if (verbose_mode)
			printf("  Size mismatch: got %u, expected %d\n",
			       (unsigned)op.params[1].tmpref.size,
			       TEST_DATA_SIZE);
		goto done;
	}

	if (memcmp(plaintext, result, TEST_DATA_SIZE) != 0) {
		if (verbose_mode) {
			printf("  Round-trip data mismatch\n");
			verbose_hex("original", plaintext, 16);
			verbose_hex("result  ", result, 16);
		}
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  AES-CTR round-trip verified: %d bytes\n",
		       TEST_DATA_SIZE);

done:
	print_result("AES round-trip test", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * HMAC test: compute HMAC-SHA256, verify tag length == 32
 * ---------------------------------------------------------------- */
static void test_hmac(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t data[] = "HMAC test data for OP-TEE infrastructure validation";
	uint8_t mac[TEST_HMAC_TAG_SIZE];
	bool success = false;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = sizeof(data) - 1;  /* exclude null terminator */
	op.params[1].tmpref.buffer = mac;
	op.params[1].tmpref.size = TEST_HMAC_TAG_SIZE;

	res = TEEC_InvokeCommand(sess, CMD_TEST_HMAC, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  TEEC_InvokeCommand failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	if (op.params[1].tmpref.size != TEST_HMAC_TAG_SIZE) {
		if (verbose_mode)
			printf("  MAC length mismatch: got %u, expected %d\n",
			       (unsigned)op.params[1].tmpref.size,
			       TEST_HMAC_TAG_SIZE);
		goto done;
	}

	success = true;
	if (verbose_mode)
		verbose_hex("HMAC tag", mac, TEST_HMAC_TAG_SIZE);

done:
	print_result("HMAC test", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Secure Storage test: write data, read back, compare
 * ---------------------------------------------------------------- */
static void test_storage(TEEC_Session *sess)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t write_data[TEST_STORAGE_SIZE];
	uint8_t read_data[TEST_STORAGE_SIZE];
	bool success = false;

	/* Fill with test pattern */
	for (int i = 0; i < TEST_STORAGE_SIZE; i++)
		write_data[i] = (uint8_t)((i * 13 + 42) & 0xff);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = write_data;
	op.params[0].tmpref.size = TEST_STORAGE_SIZE;
	op.params[1].tmpref.buffer = read_data;
	op.params[1].tmpref.size = TEST_STORAGE_SIZE;

	res = TEEC_InvokeCommand(sess, CMD_TEST_STORAGE, &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		if (verbose_mode)
			printf("  TEEC_InvokeCommand failed: 0x%x (origin 0x%x)\n",
			       res, err_origin);
		goto done;
	}

	if (op.params[1].tmpref.size != TEST_STORAGE_SIZE) {
		if (verbose_mode)
			printf("  Read size mismatch: got %u, expected %d\n",
			       (unsigned)op.params[1].tmpref.size,
			       TEST_STORAGE_SIZE);
		goto done;
	}

	if (memcmp(write_data, read_data, TEST_STORAGE_SIZE) != 0) {
		if (verbose_mode) {
			printf("  Data mismatch\n");
			verbose_hex("written", write_data, 16);
			verbose_hex("read   ", read_data, 16);
		}
		goto done;
	}

	success = true;
	if (verbose_mode)
		printf("  Secure Storage verified: %d bytes\n",
		       TEST_STORAGE_SIZE);

done:
	print_result("Secure Storage test", success);
	if (success)
		passed++;
	else
		failed++;
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */
int run_basic_tests(bool verbose)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TEST_TA_UUID;
	uint32_t err_origin;

	passed = 0;
	failed = 0;
	verbose_mode = verbose;

	/* Initialize context */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("[Test TA] Failed to initialize context: 0x%x\n", res);
		return 5;  /* All 5 tests failed */
	}

	/* Open session with Test TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("[Test TA] Failed to open session: 0x%x (origin 0x%x)\n",
		       res, err_origin);
		TEEC_FinalizeContext(&ctx);
		return 5;
	}

	if (verbose)
		printf("[Test TA] Session opened, running tests...\n");

	/* Run all tests */
	test_echo(&sess);
	test_rng(&sess);
	test_aes(&sess);
	test_hmac(&sess);
	test_storage(&sess);

	/* Cleanup */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return failed;
}
