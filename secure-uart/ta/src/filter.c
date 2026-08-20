// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <tee_internal_api.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <secure_uart_ta.h>
#include "filter.h"

/*
 * Whitelist: Allowed commands
 * Configured at TA initialization
 */
static const char *whitelist[] = {
	"ls",
	"pwd",
	"cd",
	"cat",
	"echo",
	"date",
	"uptime",
	"uname",
	"whoami",
	"id",
	"df",
	"du",
	"free",
	"ps",
	"top",
	"kill",
	"clear",
	"exit",
	"help",
	NULL  /* Sentinel */
};

/*
 * Dangerous patterns to block
 */
static const char *blocked_patterns[] = {
	";",       /* Command chaining */
	"&&",      /* Conditional execution */
	"||",      /* Conditional execution */
	"|",       /* Pipe */
	"`",       /* Command substitution */
	"$(",      /* Command substitution */
	">",       /* Redirection */
	"<",       /* Redirection */
	"&",       /* Background execution */
	"\n",      /* Newline injection */
	"\r",      /* Carriage return injection */
	"sudo",    /* Privilege escalation */
	"su",      /* Privilege escalation */
	"rm",      /* Dangerous file operations */
	"mv",      /* Dangerous file operations */
	"cp",      /* Dangerous file operations */
	"chmod",   /* Permission changes */
	"chown",   /* Ownership changes */
	NULL
};

/*
 * Helper: Skip leading whitespace
 */
static const char *skip_whitespace(const char *str)
{
	while (*str && isspace((unsigned char)*str))
		str++;
	return str;
}

/*
 * Helper: Extract first word (command) from input
 */
static size_t extract_command(const char *input, char *cmd, size_t cmd_size)
{
	const char *start = skip_whitespace(input);
	const char *end = start;
	size_t len;

	/* Find end of command (whitespace or special char) */
	while (*end && !isspace((unsigned char)*end) &&
	       *end != ';' && *end != '&' && *end != '|' &&
	       *end != '>' && *end != '<')
		end++;

	len = end - start;
	if (len >= cmd_size)
		len = cmd_size - 1;

	if (len > 0) {
		memcpy(cmd, start, len);
		cmd[len] = '\0';
	} else {
		cmd[0] = '\0';
	}

	return len;
}

/*
 * Check if string contains blocked pattern
 */
static bool contains_blocked_pattern(const char *input)
{
	size_t i;

	for (i = 0; blocked_patterns[i] != NULL; i++) {
		if (strstr(input, blocked_patterns[i]) != NULL) {
			DMSG("Blocked pattern detected: %s",
			     blocked_patterns[i]);
			return true;
		}
	}

	return false;
}

/*
 * Check if command is in whitelist
 */
static bool is_whitelisted_command(const char *cmd)
{
	size_t i;

	if (!cmd || cmd[0] == '\0')
		return false;

	for (i = 0; whitelist[i] != NULL; i++) {
		if (strcmp(cmd, whitelist[i]) == 0) {
			DMSG("Command whitelisted: %s", cmd);
			return true;
		}
	}

	DMSG("Command NOT whitelisted: %s", cmd);
	return false;
}

/*
 * Initialize filter module
 */
void filter_init(void)
{
	DMSG("Filter initialized with %zu whitelist entries",
	     sizeof(whitelist) / sizeof(whitelist[0]) - 1);
}

/*
 * Filter input command
 * Returns TEE_SUCCESS if allowed, error otherwise
 */
TEE_Result filter_check_command(const char *input, size_t input_len)
{
	char cmd[MAX_COMMAND_LENGTH];
	size_t cmd_len;

	if (!input || input_len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Sanity check: input must be null-terminated or within bounds */
	if (input_len > MAX_COMMAND_LENGTH) {
		EMSG("Input too long: %zu bytes", input_len);
		return TA_ERROR_COMMAND_BLOCKED;
	}

	/* Check for blocked patterns first */
	if (contains_blocked_pattern(input)) {
		EMSG("Command contains blocked pattern");
		return TA_ERROR_COMMAND_BLOCKED;
	}

	/* Extract command */
	cmd_len = extract_command(input, cmd, sizeof(cmd));
	if (cmd_len == 0) {
		/* Empty command - allow (no-op) */
		return TEE_SUCCESS;
	}

	/* Check whitelist */
	if (!is_whitelisted_command(cmd)) {
		EMSG("Command not in whitelist: %s", cmd);
		return TA_ERROR_COMMAND_BLOCKED;
	}

	DMSG("Command allowed: %s", cmd);
	return TEE_SUCCESS;
}

/*
 * Filter configuration: Add command to whitelist (optional)
 * For future extension - allow dynamic whitelist updates
 */
TEE_Result filter_add_whitelist_entry(const char *cmd)
{
	/* TODO: Implement dynamic whitelist management */
	/* For now, whitelist is static */
	(void)cmd;
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * Get whitelist (for debugging/status)
 */
TEE_Result filter_get_whitelist(char *buf, size_t buf_size, size_t *out_len)
{
	size_t i;
	size_t offset = 0;
	int ret;

	if (!buf || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; whitelist[i] != NULL && offset < buf_size; i++) {
		ret = snprintf(buf + offset, buf_size - offset,
			       "%s\n", whitelist[i]);
		if (ret < 0 || (size_t)ret >= (buf_size - offset))
			break;
		offset += ret;
	}

	*out_len = offset;
	return TEE_SUCCESS;
}
