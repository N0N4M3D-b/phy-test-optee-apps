/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Test TA basic tests - header
 */

#ifndef TEST_BASIC_H
#define TEST_BASIC_H

#include <stdbool.h>

/**
 * run_basic_tests - Run all Test TA tests (echo, RNG, AES, HMAC, storage)
 * @verbose: Enable verbose output
 *
 * Returns: Number of failed tests (0 = all passed)
 */
int run_basic_tests(bool verbose);

#endif /* TEST_BASIC_H */
