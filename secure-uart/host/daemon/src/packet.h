/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <secure_uart_ta.h>

/* Packet magic number */
#define PACKET_MAGIC		0x5355  /* "SU" - Secure UART */

/* Packet types */
typedef enum {
	PKT_TYPE_NONCE_REQ		= 0x01,
	PKT_TYPE_NONCE_RSP		= 0x02,
	PKT_TYPE_AUTH_SUCCESS		= 0x03,
	PKT_TYPE_AUTH_FAILED		= 0x04,
	PKT_TYPE_DATA_IN		= 0x10,  /* C0 -> REE (user input) */
	PKT_TYPE_DATA_OUT		= 0x11,  /* REE -> C0 (shell output) */
	PKT_TYPE_SESSION_CLOSE		= 0x20,
	PKT_TYPE_ERROR			= 0xFF,
} packet_type_t;

/* Packet header (fixed size) */
struct packet_header {
	uint16_t magic;			/* PACKET_MAGIC */
	uint8_t type;			/* packet_type_t */
	uint8_t reserved;
	uint16_t payload_len;		/* Length of payload */
	uint16_t checksum;		/* Simple checksum of header */
} __attribute__((packed));

/* Maximum packet payload size */
#define MAX_PAYLOAD_SIZE	(sizeof(struct data_packet))

/* Complete packet structure */
struct packet {
	struct packet_header hdr;
	uint8_t payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed));

/* Packet protocol functions */

/**
 * packet_create - Create a packet
 * @pkt: Output packet structure
 * @type: Packet type
 * @payload: Payload data (can be NULL if payload_len is 0)
 * @payload_len: Length of payload
 *
 * Returns: 0 on success, -1 on error
 */
int packet_create(struct packet *pkt, packet_type_t type,
		  const void *payload, size_t payload_len);

/**
 * packet_serialize - Serialize packet to buffer
 * @pkt: Packet to serialize
 * @buf: Output buffer
 * @buf_size: Size of output buffer
 * @out_len: Actual length of serialized data (output)
 *
 * Returns: 0 on success, -1 on error
 */
int packet_serialize(const struct packet *pkt, uint8_t *buf,
		     size_t buf_size, size_t *out_len);

/**
 * packet_deserialize - Deserialize buffer to packet
 * @buf: Input buffer
 * @buf_len: Length of input buffer
 * @pkt: Output packet structure
 *
 * Returns: 0 on success, -1 on error
 */
int packet_deserialize(const uint8_t *buf, size_t buf_len,
		       struct packet *pkt);

/**
 * packet_validate - Validate packet integrity
 * @pkt: Packet to validate
 *
 * Returns: true if valid, false otherwise
 */
bool packet_validate(const struct packet *pkt);

/**
 * packet_type_str - Get string representation of packet type
 * @type: Packet type
 *
 * Returns: String representation
 */
const char *packet_type_str(packet_type_t type);

#endif /* PACKET_H */
