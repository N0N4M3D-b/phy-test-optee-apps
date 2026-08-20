/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * secure-uart-test - CLI tool for testing OP-TEE infrastructure
 * and Secure UART TA on STM32MP target board.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include <test_basic.h>
#include "test_secure_uart.h"

static void print_usage(const char *prog)
{
	printf("Usage: %s [options]\n\n", prog);
	printf("OP-TEE infrastructure and Secure UART TA test tool\n\n");
	printf("Options:\n");
	printf("  --test-basic     Test TA basic tests (echo, RNG, AES, HMAC, storage)\n");
	printf("  --test-session   Secure UART TA session lifecycle tests\n");
	printf("  --test-crypto    Alias for --test-session (crypto is tested via session)\n");
	printf("  --test-all       Run all tests (default)\n");
	printf("  --verbose        Enable verbose output\n");
	printf("  --help           Show this help\n");
}

enum {
	OPT_TEST_BASIC = 256,
	OPT_TEST_SESSION,
	OPT_TEST_CRYPTO,
	OPT_TEST_ALL,
	OPT_VERBOSE,
	OPT_HELP,
};

static const struct option long_options[] = {
	{ "test-basic",   no_argument, NULL, OPT_TEST_BASIC },
	{ "test-session", no_argument, NULL, OPT_TEST_SESSION },
	{ "test-crypto",  no_argument, NULL, OPT_TEST_CRYPTO },
	{ "test-all",     no_argument, NULL, OPT_TEST_ALL },
	{ "verbose",      no_argument, NULL, OPT_VERBOSE },
	{ "help",         no_argument, NULL, OPT_HELP },
	{ NULL, 0, NULL, 0 },
};

int main(int argc, char *argv[])
{
	bool do_basic = false;
	bool do_session = false;
	bool verbose = false;
	bool explicit_test = false;
	int opt;
	int total_passed = 0;
	int total_failed = 0;
	int total_tests = 0;

	while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (opt) {
		case OPT_TEST_BASIC:
			do_basic = true;
			explicit_test = true;
			break;
		case OPT_TEST_SESSION:
		case OPT_TEST_CRYPTO:
			do_session = true;
			explicit_test = true;
			break;
		case OPT_TEST_ALL:
			do_basic = true;
			do_session = true;
			explicit_test = true;
			break;
		case OPT_VERBOSE:
			verbose = true;
			break;
		case OPT_HELP:
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Default: run all tests */
	if (!explicit_test) {
		do_basic = true;
		do_session = true;
	}

	printf("=== Secure UART Test Suite ===\n\n");

	/* Run Test TA basic tests */
	if (do_basic) {
		int basic_failed = run_basic_tests(verbose);
		int basic_total = 5;

		total_failed += basic_failed;
		total_passed += basic_total - basic_failed;
		total_tests += basic_total;

		if (do_session)
			printf("\n");
	}

	/* Run Secure UART TA session tests */
	if (do_session) {
		int session_failed = run_secure_uart_tests(verbose);
		int session_total = 5;

		total_failed += session_failed;
		total_passed += session_total - session_failed;
		total_tests += session_total;
	}

	/* Summary */
	printf("\nResults: %d/%d passed, %d failed\n",
	       total_passed, total_tests, total_failed);

	return total_failed > 0 ? 1 : 0;
}
