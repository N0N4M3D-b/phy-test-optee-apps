/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Secure UART TA tests - header
 */

#ifndef TEST_SECURE_UART_H
#define TEST_SECURE_UART_H

#include <stdbool.h>

/**
 * run_secure_uart_tests - Run Secure UART TA session lifecycle tests
 * @verbose: Enable verbose output
 *
 * Returns: Number of failed tests (0 = all passed)
 */
int run_secure_uart_tests(bool verbose);

#endif /* TEST_SECURE_UART_H */
