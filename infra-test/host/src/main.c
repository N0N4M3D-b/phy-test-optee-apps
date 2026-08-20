/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "test_basic.h"

static void print_usage(const char *program)
{
	printf("Usage: %s [--verbose]\n", program);
}

int main(int argc, char *argv[])
{
	bool verbose = false;
	int failed;

	if (argc == 2 && strcmp(argv[1], "--verbose") == 0) {
		verbose = true;
	} else if (argc == 2 && (strcmp(argv[1], "--help") == 0 ||
				 strcmp(argv[1], "-h") == 0)) {
		print_usage(argv[0]);
		return 0;
	} else if (argc != 1) {
		print_usage(argv[0]);
		return 1;
	}

	failed = run_basic_tests(verbose);
	printf("\nInfrastructure TA: %d/5 passed, %d failed\n",
	       5 - failed, failed);

	return failed ? 1 : 0;
}
