/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef NATCAP_CODEC_H
#define NATCAP_CODEC_H

#include <stddef.h>
#include <stdint.h>

#define NC_PACKET_MAX 65535
#define NC_DATAGRAM_MAX 65507
#define NC_TCP_MAGIC UINT32_C(0xffff0099)
#define NC_TCP_V1_MAGIC UINT32_C(0xfff70099)
#define NC_UDP_MAGIC UINT32_C(0xfffe0099)
#define NC_UDP_AUTH_MAGIC UINT32_C(0xfffd0099)
#define NC_UDP_CFM UINT32_C(0xfffe009a)

enum { NC_OK = 0, NC_CONTROL = 1, NC_INVALID = -1, NC_SPACE = -2,
       NC_UNSUPPORTED = -3, NC_FLOW = -4 };

/* IP addresses are network-order bytes; integer fields are host order. */
struct nc_config {
    uint32_t user_hash;
    uint8_t mac[6];
    uint8_t seed;
    uint8_t encryption;
    uint8_t udp_auth; /* Linux default_protocol=1: 24-byte UDP header. */
    uint8_t sproxy;
};

struct nc_key {
    uint8_t src[4], dst[4];
    uint16_t sport, dport;
    uint8_t protocol;
};

struct nc_packet {
    struct nc_key key;
    size_t ip_len, header_len, transport_len;
    uint8_t tcp_flags;
};

struct nc_flow {
    struct nc_key key;
    uint8_t udp_confirmed;
};

struct nc_output {
    uint8_t data[NC_PACKET_MAX];
    size_t len;
    /* Option-space fallback: send this control SYN BEFORE data. */
    uint8_t pioneer[64];
    size_t pioneer_len;
};

int nc_parse(const uint8_t *packet, size_t len, struct nc_packet *parsed);
int nc_key_equal(const struct nc_key *a, const struct nc_key *b);
/* Input and output buffers must not overlap. No allocations or socket I/O. */
int nc_encode(const struct nc_config *config, const struct nc_flow *flow,
              const uint8_t *packet, size_t len, struct nc_output *output);
/* NC_CONTROL consumes a UDP confirmation without creating an IP packet. */
int nc_decode(const struct nc_config *config, struct nc_flow *flow,
              const uint8_t *datagram, size_t len, uint8_t *packet,
              size_t capacity, size_t *packet_len);

#endif
