/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 *
 * Main daemon for Secure UART
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include "packet.h"
#include "tee_client.h"
#include "uart_handler.h"
#include "pty_manager.h"

#define MAX_EVENTS		10
#define EPOLL_TIMEOUT_MS	1000

/* Global state */
static volatile sig_atomic_t g_running = 1;
static int g_uart_fd = -1;
static int g_pty_master_fd = -1;
static pid_t g_shell_pid = -1;

/* State machine */
typedef enum {
	STATE_IDLE,
	STATE_CHALLENGE_SENT,
	STATE_AUTHENTICATED,
	STATE_ACTIVE,
	STATE_ERROR
} daemon_state_t;

static daemon_state_t g_state = STATE_IDLE;

/*
 * Signal handler
 */
static void signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		printf("\nReceived signal %d, shutting down...\n", sig);
		g_running = 0;
	}
}

/*
 * Cleanup resources
 */
static void cleanup(void)
{
	printf("Cleaning up...\n");

	if (g_pty_master_fd >= 0 || g_shell_pid > 0)
		pty_cleanup(g_pty_master_fd, g_shell_pid);

	if (g_uart_fd >= 0)
		uart_close(g_uart_fd);

	tee_client_cleanup();
}

/*
 * Handle UART packet
 */
static int handle_uart_packet(const struct packet *pkt)
{
	printf("Received %s packet\n", packet_type_str(pkt->hdr.type));

	switch (pkt->hdr.type) {
	case PKT_TYPE_NONCE_REQ: {
		/* Generate challenge via TA */
		uint8_t challenge[CHALLENGE_PKT_SIZE];
		size_t challenge_len = sizeof(challenge);
		struct packet rsp_pkt;

		if (tee_generate_challenge(challenge, &challenge_len) < 0) {
			fprintf(stderr, "Failed to generate challenge\n");
			return -1;
		}

		/* Send response */
		if (packet_create(&rsp_pkt, PKT_TYPE_NONCE_RSP,
				  challenge, challenge_len) < 0) {
			fprintf(stderr, "Failed to create response packet\n");
			return -1;
		}

		if (uart_send_packet(g_uart_fd, &rsp_pkt) < 0) {
			fprintf(stderr, "Failed to send response\n");
			return -1;
		}

		g_state = STATE_CHALLENGE_SENT;
		printf("Challenge sent\n");
		break;
	}

	case PKT_TYPE_AUTH_SUCCESS: {
		/* Verify auth via TA */
		uint16_t payload_len = ntohs(pkt->hdr.payload_len);

		if (tee_verify_auth(pkt->payload, payload_len) < 0) {
			fprintf(stderr, "Authentication failed\n");
			g_state = STATE_ERROR;
			return -1;
		}

		/* Spawn shell */
		if (pty_spawn_shell(&g_pty_master_fd, &g_shell_pid) < 0) {
			fprintf(stderr, "Failed to spawn shell\n");
			g_state = STATE_ERROR;
			return -1;
		}

		g_state = STATE_ACTIVE;
		printf("Authentication successful, shell spawned\n");
		break;
	}

	case PKT_TYPE_DATA_IN: {
		/* Decrypt and filter input */
		uint8_t plaintext[MAX_PAYLOAD_SIZE];
		size_t plaintext_len = sizeof(plaintext);
		uint16_t payload_len = ntohs(pkt->hdr.payload_len);

		if (g_state != STATE_ACTIVE) {
			fprintf(stderr, "Not in active state\n");
			return -1;
		}

		if (tee_decrypt_and_filter(pkt->payload, payload_len,
					    plaintext, &plaintext_len) < 0) {
			fprintf(stderr, "Decrypt/filter failed\n");
			return -1;
		}

		/* Write to shell */
		if (pty_write(g_pty_master_fd, plaintext, plaintext_len) < 0) {
			fprintf(stderr, "Failed to write to shell\n");
			return -1;
		}

		printf("Forwarded %zu bytes to shell\n", plaintext_len);
		break;
	}

	case PKT_TYPE_SESSION_CLOSE:
		printf("Session close requested\n");
		tee_destroy_session();
		g_running = 0;
		break;

	default:
		fprintf(stderr, "Unhandled packet type: %u\n", pkt->hdr.type);
		break;
	}

	return 0;
}

/*
 * Handle shell output
 */
static int handle_shell_output(void)
{
	uint8_t buf[4096];
	int n;
	uint8_t enc_data[DATA_PKT_SIZE];
	size_t enc_len = sizeof(enc_data);
	struct packet pkt;

	if (g_state != STATE_ACTIVE) {
		fprintf(stderr, "Not in active state\n");
		return -1;
	}

	/* Read from shell */
	n = pty_read(g_pty_master_fd, buf, sizeof(buf));
	if (n < 0) {
		fprintf(stderr, "Failed to read from shell\n");
		return -1;
	}

	if (n == 0)
		return 0;

	printf("Shell output: %d bytes\n", n);

	/* Encrypt output via TA */
	if (tee_encrypt_output(buf, n, enc_data, &enc_len) < 0) {
		fprintf(stderr, "Failed to encrypt output\n");
		return -1;
	}

	/* Send to UART */
	if (packet_create(&pkt, PKT_TYPE_DATA_OUT, enc_data, enc_len) < 0) {
		fprintf(stderr, "Failed to create packet\n");
		return -1;
	}

	if (uart_send_packet(g_uart_fd, &pkt) < 0) {
		fprintf(stderr, "Failed to send packet\n");
		return -1;
	}

	printf("Sent %zu bytes to UART\n", enc_len);
	return 0;
}

/*
 * Main loop
 */
static int main_loop(void)
{
	int epfd;
	struct epoll_event ev, events[MAX_EVENTS];
	int nfds, i;

	/* Create epoll instance */
	epfd = epoll_create1(0);
	if (epfd < 0) {
		fprintf(stderr, "epoll_create1 failed: %s\n", strerror(errno));
		return -1;
	}

	/* Add UART fd */
	ev.events = EPOLLIN;
	ev.data.fd = g_uart_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_uart_fd, &ev) < 0) {
		fprintf(stderr, "Failed to add UART fd to epoll: %s\n",
			strerror(errno));
		close(epfd);
		return -1;
	}

	printf("Main loop started\n");

	/* Event loop */
	while (g_running) {
		nfds = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT_MS);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "epoll_wait failed: %s\n",
				strerror(errno));
			break;
		}

		for (i = 0; i < nfds; i++) {
			if (events[i].data.fd == g_uart_fd) {
				/* UART event */
				struct packet pkt;
				int ret = uart_recv_packet(g_uart_fd, &pkt, 0);
				if (ret < 0) {
					fprintf(stderr, "UART receive failed\n");
					g_running = 0;
					break;
				}

				if (ret > 0) {
					if (handle_uart_packet(&pkt) < 0)
						fprintf(stderr, "Packet handling failed\n");
				}
			} else if (events[i].data.fd == g_pty_master_fd) {
				/* PTY event */
				if (handle_shell_output() < 0)
					fprintf(stderr, "Shell output handling failed\n");
			}
		}

		/* Add PTY to epoll if shell is active */
		if (g_state == STATE_ACTIVE && g_pty_master_fd >= 0) {
			static int pty_added = 0;
			if (!pty_added) {
				ev.events = EPOLLIN;
				ev.data.fd = g_pty_master_fd;
				if (epoll_ctl(epfd, EPOLL_CTL_ADD,
					      g_pty_master_fd, &ev) == 0) {
					pty_added = 1;
					printf("PTY added to epoll\n");
				}
			}
		}
	}

	close(epfd);
	printf("Main loop exited\n");
	return 0;
}

/*
 * Main entry point
 */
int main(int argc, char *argv[])
{
	const char *uart_dev = "/dev/ttySTM1";
	int baudrate = 115200;

	printf("Secure UART Daemon v1.0\n");

	/* Parse arguments */
	if (argc >= 2)
		uart_dev = argv[1];
	if (argc >= 3)
		baudrate = atoi(argv[2]);

	/* Setup signal handler */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	/* Initialize TEE client */
	if (tee_client_init() < 0) {
		fprintf(stderr, "Failed to initialize TEE client\n");
		return 1;
	}

	/* Open UART */
	g_uart_fd = uart_open(uart_dev, baudrate);
	if (g_uart_fd < 0) {
		fprintf(stderr, "Failed to open UART\n");
		tee_client_cleanup();
		return 1;
	}

	printf("Starting main loop...\n");

	/* Run main loop */
	main_loop();

	/* Cleanup */
	cleanup();

	printf("Secure UART Daemon exited\n");
	return 0;
}
