/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2024, Secure UART Project
 */

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet.h"

/*
 * Calculate simple checksum for header
 */
static uint16_t calculate_checksum(const struct packet_header *hdr)
{
	uint16_t sum = 0;
	const uint8_t *bytes = (const uint8_t *)hdr;
	size_t i;

	/* Sum all bytes except checksum field */
	for (i = 0; i < offsetof(struct packet_header, checksum); i++)
		sum += bytes[i];

	return sum;
}

/*
 * Create a packet
 */
int packet_create(struct packet *pkt, packet_type_t type,
		  const void *payload, size_t payload_len)
{
	if (!pkt)
		return -1;

	if (payload_len > MAX_PAYLOAD_SIZE)
		return -1;

	if (payload_len > 0 && !payload)
		return -1;

	/* Clear packet */
	memset(pkt, 0, sizeof(*pkt));

	/* Fill header */
	pkt->hdr.magic = htons(PACKET_MAGIC);
	pkt->hdr.type = type;
	pkt->hdr.reserved = 0;
	pkt->hdr.payload_len = htons(payload_len);

	/* Copy payload */
	if (payload && payload_len > 0)
		memcpy(pkt->payload, payload, payload_len);

	/* Calculate and set checksum */
	pkt->hdr.checksum = htons(calculate_checksum(&pkt->hdr));

	return 0;
}

/*
 * Serialize packet to buffer
 */
int packet_serialize(const struct packet *pkt, uint8_t *buf,
		     size_t buf_size, size_t *out_len)
{
	size_t total_len;
	uint16_t payload_len;

	if (!pkt || !buf || !out_len)
		return -1;

	payload_len = ntohs(pkt->hdr.payload_len);
	total_len = sizeof(struct packet_header) + payload_len;

	if (buf_size < total_len) {
		*out_len = total_len;
		return -1;
	}

	/* Copy header */
	memcpy(buf, &pkt->hdr, sizeof(struct packet_header));

	/* Copy payload */
	if (payload_len > 0)
		memcpy(buf + sizeof(struct packet_header),
		       pkt->payload, payload_len);

	*out_len = total_len;
	return 0;
}

/*
 * Deserialize buffer to packet
 */
int packet_deserialize(const uint8_t *buf, size_t buf_len,
		       struct packet *pkt)
{
	struct packet_header hdr;
	uint16_t payload_len;
	uint16_t expected_checksum, actual_checksum;

	if (!buf || !pkt)
		return -1;

	if (buf_len < sizeof(struct packet_header))
		return -1;

	/* Copy and validate header */
	memcpy(&hdr, buf, sizeof(hdr));

	/* Check magic */
	if (ntohs(hdr.magic) != PACKET_MAGIC) {
		fprintf(stderr, "Invalid packet magic: 0x%04x\n",
			ntohs(hdr.magic));
		return -1;
	}

	/* Verify checksum */
	expected_checksum = ntohs(hdr.checksum);
	hdr.checksum = 0;  /* Clear for calculation */
	actual_checksum = calculate_checksum(&hdr);

	if (expected_checksum != actual_checksum) {
		fprintf(stderr, "Checksum mismatch: expected 0x%04x, got 0x%04x\n",
			expected_checksum, actual_checksum);
		return -1;
	}

	/* Restore checksum */
	hdr.checksum = htons(expected_checksum);

	/* Check payload length */
	payload_len = ntohs(hdr.payload_len);
	if (payload_len > MAX_PAYLOAD_SIZE) {
		fprintf(stderr, "Payload too large: %u bytes\n", payload_len);
		return -1;
	}

	if (buf_len < sizeof(struct packet_header) + payload_len) {
		fprintf(stderr, "Buffer too small for payload\n");
		return -1;
	}

	/* Copy to output packet */
	memset(pkt, 0, sizeof(*pkt));
	memcpy(&pkt->hdr, &hdr, sizeof(hdr));

	if (payload_len > 0)
		memcpy(pkt->payload, buf + sizeof(struct packet_header),
		       payload_len);

	return 0;
}

/*
 * Validate packet integrity
 */
bool packet_validate(const struct packet *pkt)
{
	uint16_t expected_checksum, actual_checksum;
	struct packet_header hdr;
	uint16_t payload_len;

	if (!pkt)
		return false;

	/* Check magic */
	if (ntohs(pkt->hdr.magic) != PACKET_MAGIC)
		return false;

	/* Verify checksum */
	memcpy(&hdr, &pkt->hdr, sizeof(hdr));
	expected_checksum = ntohs(hdr.checksum);
	hdr.checksum = 0;
	actual_checksum = calculate_checksum(&hdr);

	if (expected_checksum != actual_checksum)
		return false;

	/* Check payload length */
	payload_len = ntohs(pkt->hdr.payload_len);
	if (payload_len > MAX_PAYLOAD_SIZE)
		return false;

	return true;
}

/*
 * Get string representation of packet type
 */
const char *packet_type_str(packet_type_t type)
{
	switch (type) {
	case PKT_TYPE_NONCE_REQ:
		return "NONCE_REQ";
	case PKT_TYPE_NONCE_RSP:
		return "NONCE_RSP";
	case PKT_TYPE_AUTH_SUCCESS:
		return "AUTH_SUCCESS";
	case PKT_TYPE_AUTH_FAILED:
		return "AUTH_FAILED";
	case PKT_TYPE_DATA_IN:
		return "DATA_IN";
	case PKT_TYPE_DATA_OUT:
		return "DATA_OUT";
	case PKT_TYPE_SESSION_CLOSE:
		return "SESSION_CLOSE";
	case PKT_TYPE_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}
