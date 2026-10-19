/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "natcap_codec.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct nc_output output;
static uint8_t packet[NC_PACKET_MAX], result[NC_PACKET_MAX], wire[NC_PACKET_MAX];
static const uint8_t src[] = {198, 18, 99, 1}, dst[] = {203, 0, 113, 9};
static const struct nc_config config = {
    .user_hash = 0x12345678, .mac = {2, 0x11, 0x22, 0x33, 0x44, 0x55}, .udp_auth = 1
};

static unsigned get16(const uint8_t *p) { return (unsigned)p[0] * 256 + p[1]; }
static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static unsigned checksum(const uint8_t *p, size_t n, unsigned sum)
{
    while (n >= 2) { sum += (unsigned)p[0] * 256 + p[1]; p += 2; n -= 2; }
    if (n) sum += (unsigned)*p * 256;
    while (sum > 65535) sum = sum / 65536 + sum % 65536;
    return sum ^ 65535;
}

static size_t make_packet(unsigned protocol, unsigned options, size_t payload,
                          unsigned flags, struct nc_flow *flow)
{
    size_t header = protocol == 6 ? 20 + options : 8;
    size_t n = 20 + header + payload, i;
    struct nc_packet parsed;
    assert(n <= sizeof(packet));
    memset(packet, 0, n);
    packet[0] = 0x45;
    put16(packet + 2, (unsigned)n);
    packet[8] = 64;
    packet[9] = (uint8_t)protocol;
    memcpy(packet + 12, src, 4);
    memcpy(packet + 16, dst, 4);
    put16(packet + 20, 12345);
    put16(packet + 22, protocol == 6 ? 443 : 53);
    if (protocol == 6) {
        packet[24] = 1; packet[25] = 2; packet[26] = 3; packet[27] = 4;
        packet[32] = (uint8_t)(header / 4 * 16);
        packet[33] = (uint8_t)flags;
        packet[34] = 0x40;
        memset(packet + 40, 1, options); /* NOPs. */
    } else {
        put16(packet + 24, (unsigned)(header + payload));
    }
    for (i = 0; i < payload; i++) packet[20 + header + i] = (uint8_t)i;
    memset(flow, 0, sizeof(*flow));
    assert(nc_parse(packet, n, &parsed) == NC_OK);
    flow->key = parsed.key;
    return n;
}

static void verify_reply(size_t n, unsigned protocol, unsigned header, size_t payload)
{
    size_t i;
    unsigned sum;
    struct nc_packet parsed;
    assert(n == 20 + header + payload);
    assert(nc_parse(result, n, &parsed) == NC_OK);
    assert(parsed.key.protocol == protocol);
    assert(!memcmp(result + 12, dst, 4));
    assert(!memcmp(result + 16, src, 4));
    assert(get16(result + 20) == (protocol == 6 ? 443 : 53));
    assert(get16(result + 22) == 12345);
    assert(checksum(result, 20, 0) == 0);
    sum = checksum(result + 20, n - 20,
                   ((checksum(result + 12, 8, 0) ^ 65535) + (unsigned)n - 20 + protocol));
    assert(sum == 0);
    for (i = 0; i < payload; i++) assert(result[20 + header + i] == (uint8_t)i);
}

static void tcp_golden(void)
{
    struct nc_flow flow;
    size_t n = make_packet(6, 0, 0, 2, &flow), reply;
    /* Exactly the packed ALL option in natcap.h. u_hash is network order. */
    const uint8_t expected[] = {
        0xff,0xff,0,0x99, 1,2,3,4, 0,0,0,0, 0xa0,2,0x40,0, 0,0,0,0,
        0x99,20,1,0, 0x12,0x34,0x56,0x78, 2,0x11,0x22,0x33,0x44,0x55,
        1,0xbb, 203,0,113,9
    };
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK);
    assert(!output.pioneer_len && output.len == sizeof(expected));
    assert(!memcmp(output.data, expected, sizeof(expected)));
    /* Handcrafted server SYN+ACK: magic replaces ports, no NATCAP option. */
    const uint8_t response[] = {
        0xff,0xff,0,0x99, 0x11,0x22,0x33,0x44, 1,2,3,5,
        0x50,0x12,0x20,0, 0,0,0,0
    };
    assert(nc_decode(&config, &flow, response, sizeof(response), result, sizeof(result), &reply) == NC_OK);
    verify_reply(reply, 6, 20, 0);
    assert(!memcmp(result + 24, response + 4, 12));
}

static void udp_golden(void)
{
    struct nc_flow flow;
    struct nc_config legacy = config;
    size_t n = make_packet(17, 0, 3, 0, &flow), reply;
    const uint8_t auth[] = {
        0xff,0xfd,0,0x99, 203,0,113,9, 0,53, 0,2,
        0x12,0x34,0x56,0x78, 2,0x11,0x22,0x33,0x44,0x55, 0,0, 0,1,2
    };
    const uint8_t cfm[] = {0xff,0xfe,0,0x9a};
    const uint8_t old[] = {0xff,0xfe,0,0x99, 203,0,113,9, 0,53, 0,2, 0,1,2};
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK);
    assert(output.len == sizeof(auth) && !memcmp(output.data, auth, sizeof(auth)));
    legacy.udp_auth = 0;
    assert(nc_encode(&legacy, &flow, packet, n, &output) == NC_OK);
    assert(output.len == sizeof(old) && !memcmp(output.data, old, sizeof(old)));
    assert(nc_decode(&config, &flow, cfm, sizeof(cfm), result, sizeof(result), &reply) == NC_CONTROL);
    assert(flow.udp_confirmed && reply == 0);
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK);
    assert(output.len == 3 && !memcmp(output.data, "\0\1\2", 3));
    assert(nc_decode(&config, &flow, output.data, output.len, result, sizeof(result), &reply) == NC_OK);
    verify_reply(reply, 17, 8, 3);
}

static void payload_encoding(void)
{
    struct nc_config enc = config;
    struct nc_flow flow;
    unsigned protocol, seed;
    size_t n, reply;
    enc.encryption = 1;
    for (protocol = 6; protocol <= 17; protocol += 11) {
        for (seed = 0; seed < 256; seed++) {
            enc.seed = (uint8_t)seed;
            n = make_packet(protocol, 0, 256, protocol == 6 ? 0x18 : 0, &flow);
            if (protocol == 17) flow.udp_confirmed = 1;
            assert(nc_encode(&enc, &flow, packet, n, &output) == NC_OK);
            assert(output.data[protocol == 6 ? 20 : 0] == (uint8_t)(152 + seed));
            assert(output.data[protocol == 6 ? 21 : 1] == (uint8_t)(151 + seed));
            assert(nc_decode(&enc, &flow, output.data, output.len, result, sizeof(result), &reply) == NC_OK);
            verify_reply(reply, protocol, protocol == 6 ? 20 : 8, 256);
        }
    }
    n = make_packet(17, 0, 3, 0, &flow);
    enc.seed = 0;
    assert(nc_encode(&enc, &flow, packet, n, &output) == NC_OK);
    assert(output.data[10] == 1 && output.data[11] == 2);
    assert(!memcmp(output.data + 24, "\230\227\152", 3));
}

static void options_and_fallback(void)
{
    struct nc_flow flow;
    struct nc_config proxy = config;
    size_t n, reply;
    unsigned opt;
    proxy.sproxy = 1;
    for (opt = 0; opt <= 40; opt += 4) {
        n = make_packet(6, opt, 7, 2, &flow);
        assert(nc_encode(&proxy, &flow, packet, n, &output) == NC_OK);
        if (opt <= 20) {
            assert(!output.pioneer_len && output.data[22] == 0x21);
            assert(nc_decode(&proxy, &flow, output.data, output.len, result, sizeof(result), &reply) == NC_OK);
            verify_reply(reply, 6, 20 + opt, 7);
            assert(!memcmp(result + 40, packet + 40, opt + 7));
        } else {
            assert(output.pioneer_len == 44);
            assert(output.pioneer[22] == 0xa1);
            assert(output.pioneer[40] == 2 && output.pioneer[41] == 4);
            assert(get16(output.pioneer + 42) == 536);
            assert(output.len == n - 20);
            assert(!memcmp(output.data + 20, packet + 40, opt + 7));
        }
    }
    /* Preserve original MSS in the metadata SYN. */
    n = make_packet(6, 40, 0, 2, &flow);
    packet[40] = 2; packet[41] = 4; put16(packet + 42, 1160);
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK);
    assert(get16(output.pioneer + 42) == 1160);
    /* Server-side v1 marker can be received without enabling multipath. */
    memcpy(wire, output.data, output.len);
    wire[1] = 0xf7;
    assert(nc_decode(&config, &flow, wire, output.len, result, sizeof(result), &reply) == NC_OK);
}

static void boundaries(void)
{
    struct nc_flow flow, other;
    struct nc_packet parsed;
    size_t n = make_packet(6, 0, 10, 2, &flow), reply, i;
    for (i = 0; i < n; i++) assert(nc_parse(packet, i, &parsed) != NC_OK);
    other = flow;
    other.key.dport++;
    assert(nc_encode(&config, &other, packet, n, &output) == NC_FLOW);
    packet[6] = 0x20;
    assert(nc_parse(packet, n, &parsed) == NC_UNSUPPORTED);
    packet[6] = 0;
    packet[32] = 0x40;
    assert(nc_parse(packet, n, &parsed) == NC_INVALID);
    n = make_packet(6, 4, 0, 2, &flow);
    packet[40] = 2; packet[41] = 0;
    assert(nc_parse(packet, n, &parsed) == NC_INVALID);
    n = make_packet(17, 0, 0, 0, &flow);
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK && output.len == 24);
    flow.udp_confirmed = 1;
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK && output.len == 0);
    assert(nc_decode(&config, &flow, output.data, 0, result, sizeof(result), &reply) == NC_OK);
    verify_reply(reply, 17, 8, 0);
    n = make_packet(17, 0, 65507, 0, &flow);
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_SPACE);
    flow.udp_confirmed = 1;
    assert(nc_encode(&config, &flow, packet, n, &output) == NC_OK);
    assert(nc_decode(&config, &flow, output.data, output.len, result, sizeof(result), &reply) == NC_OK);
    verify_reply(reply, 17, 8, 65507);
    assert(nc_decode(&config, &flow, output.data, output.len, result, 100, &reply) == NC_SPACE && !reply);
    assert(nc_decode(&config, &flow, output.data, 65508, result, sizeof(result), &reply) == NC_INVALID);
}

static uint32_t rng = 0x12345678;
static uint8_t random_byte(void)
{
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return (uint8_t)rng;
}

static void malformed_inputs(void)
{
    unsigned iteration;
    struct nc_flow flow;
    struct nc_packet parsed;
    size_t i, n, reply;
    for (iteration = 0; iteration < 30000; iteration++) {
        n = ((unsigned)random_byte() << 2) + random_byte();
        for (i = 0; i < n; i++) wire[i] = random_byte();
        make_packet(6, 0, 0, 2, &flow);
        (void)nc_parse(wire, n, &parsed);
        (void)nc_encode(&config, &flow, wire, n, &output);
        if (n >= 4 && iteration % 2) {
            wire[0] = wire[1] = 255; wire[2] = 0; wire[3] = 0x99;
        }
        assert(nc_decode(&config, &flow, wire, n, result, iteration % 300,
                          &reply) != NC_CONTROL);
    }
}

int main(void)
{
    tcp_golden();
    udp_golden();
    payload_encoding();
    options_and_fallback();
    boundaries();
    malformed_inputs();
    puts("codec: golden wire vectors, 256 seeds, checksums, option fallback, limits and 30000 malformed inputs passed");
    return 0;
}
