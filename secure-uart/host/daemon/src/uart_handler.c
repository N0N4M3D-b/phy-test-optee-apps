/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "uart_handler.h"

static speed_t baud_to_speed(int baudrate)
{
	switch (baudrate) {
	case 9600:
		return B9600;
	case 19200:
		return B19200;
	case 38400:
		return B38400;
	case 57600:
		return B57600;
	case 115200:
		return B115200;
	default:
		return 0;
	}
}

static int read_exact(int fd, void *buffer, size_t length, int timeout_ms)
{
	uint8_t *cursor = buffer;
	size_t offset = 0;

	while (offset < length) {
		struct pollfd pollfd = { .fd = fd, .events = POLLIN };
		int ready = poll(&pollfd, 1, timeout_ms);
		ssize_t count;

		if (ready == 0)
			return offset ? -1 : 0;
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		count = read(fd, cursor + offset, length - offset);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!count)
			return -1;
		offset += count;
	}

	return 1;
}

static int write_all(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor = buffer;
	size_t offset = 0;

	while (offset < length) {
		ssize_t count = write(fd, cursor + offset, length - offset);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		offset += count;
	}
	return 0;
}

int uart_open(const char *device, int baudrate)
{
	struct termios options;
	speed_t speed = baud_to_speed(baudrate);
	int fd;

	if (!device || !speed) {
		errno = EINVAL;
		return -1;
	}

	fd = open(device, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", device,
			strerror(errno));
		return -1;
	}

	if (tcgetattr(fd, &options) < 0) {
		close(fd);
		return -1;
	}

	cfmakeraw(&options);
	cfsetispeed(&options, speed);
	cfsetospeed(&options, speed);
	options.c_cflag |= CLOCAL | CREAD;
	options.c_cflag &= ~CRTSCTS;
	options.c_cc[VMIN] = 0;
	options.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSANOW, &options) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

void uart_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

int uart_send_packet(int fd, const struct packet *pkt)
{
	uint8_t buffer[sizeof(struct packet_header) + MAX_PAYLOAD_SIZE];
	size_t length;

	if (packet_serialize(pkt, buffer, sizeof(buffer), &length) < 0)
		return -1;
	return write_all(fd, buffer, length);
}

int uart_recv_packet(int fd, struct packet *pkt, int timeout_ms)
{
	uint8_t buffer[sizeof(struct packet_header) + MAX_PAYLOAD_SIZE];
	struct packet_header header;
	uint16_t payload_len;
	int ret;

	ret = read_exact(fd, &header, sizeof(header), timeout_ms);
	if (ret <= 0)
		return ret;

	payload_len = ntohs(header.payload_len);
	if (payload_len > MAX_PAYLOAD_SIZE)
		return -1;

	memcpy(buffer, &header, sizeof(header));
	ret = read_exact(fd, buffer + sizeof(header), payload_len, timeout_ms);
	if (ret <= 0 && payload_len)
		return -1;

	if (packet_deserialize(buffer, sizeof(header) + payload_len, pkt) < 0)
		return -1;
	return 1;
}
