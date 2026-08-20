/* SPDX-License-Identifier: MIT */
#ifndef UART_HANDLER_H
#define UART_HANDLER_H

#include "packet.h"

int uart_open(const char *device, int baudrate);
void uart_close(int fd);
int uart_send_packet(int fd, const struct packet *pkt);
int uart_recv_packet(int fd, struct packet *pkt, int timeout_ms);

#endif /* UART_HANDLER_H */
