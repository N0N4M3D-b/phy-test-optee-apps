/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SECURE_UART_FILTER_H
#define SECURE_UART_FILTER_H

#include <stddef.h>
#include <tee_internal_api.h>

void filter_init(void);
TEE_Result filter_check_command(const char *input, size_t input_len);
TEE_Result filter_add_whitelist_entry(const char *cmd);
TEE_Result filter_get_whitelist(char *buf, size_t buf_size, size_t *out_len);

#endif /* SECURE_UART_FILTER_H */
