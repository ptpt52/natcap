/* SPDX-License-Identifier: GPL-3.0-or-later
 * Optional Linux-only test, run in a private user/network namespace. Feed a
 * decoded macOS-layout SYN to a real TCP listener and inspect its SYN-ACK.
 * Unlike the UDP mock test, this validates TCP negotiation/checksums against
 * the kernel rather than constructing the expected response ourselves.
 */
#define _POSIX_C_SOURCE 200809L
#include "natcap_codec.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static struct nc_output output;
static unsigned read16(const uint8_t *p) { return (unsigned)p[0] * 256 + p[1]; }
static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)read16(p) << 16 | read16(p + 2);
}
static void write16(uint8_t *p, unsigned n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }

int main(void)
{
    static const uint8_t options[] = {
        2,4,4,0x88, 1,3,3,6, 1,1,8,10, 0x1c,0x2d,0xb7,0xaf,
        0,0,0,0, 4,2,0,0
    };
    uint8_t original[64] = {0}, decoded[80], incoming[65535];
    struct nc_config config = {.mac = {2,0,0,0,0,1}, .encryption = 1};
    struct nc_packet parsed;
    struct nc_flow client = {0}, reverse = {0};
    struct sockaddr_in address = {0};
    socklen_t address_len = sizeof(address);
    size_t decoded_len;
    int listener, capture, sender, one = 1, found = 0;
    assert(getenv("NATCAP_TEST_ISOLATED"));
    alarm(10);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(getsockname(listener, (struct sockaddr *)&address, &address_len) == 0);
    assert(listen(listener, 1) == 0);
    capture = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    sender = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    assert(capture >= 0 && sender >= 0);
    assert(setsockopt(sender, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == 0);
    original[0] = 0x45;
    write16(original + 2, sizeof(original));
    original[8] = 64; original[9] = 6;
    memcpy(original + 12, "\x7f\x00\x00\x02", 4);
    memcpy(original + 16, "\x7f\x00\x00\x01", 4);
    write16(original + 20, 40000);
    memcpy(original + 22, &address.sin_port, 2);
    memcpy(original + 24, "\xb6\x50\xba\x3d", 4);
    original[32] = 0xb0; original[33] = 0xc2;
    original[34] = original[35] = 255;
    memcpy(original + 40, options, sizeof(options));
    assert(nc_parse(original, sizeof(original), &parsed) == NC_OK);
    client.key = parsed.key;
    assert(nc_encode(&config, &client, original, sizeof(original), &output) == NC_OK);
    assert(output.len == 60 && output.data[22] == 1);
    /* Normal server decoding strips the ALL option without changing sequence.
     * Reverse the mapping to use nc_decode() in the client->server direction.
     */
    reverse.key.protocol = 6;
    memcpy(reverse.key.src, client.key.dst, 4);
    memcpy(reverse.key.dst, client.key.src, 4);
    reverse.key.sport = client.key.dport;
    reverse.key.dport = client.key.sport;
    assert(nc_decode(&config, &reverse, output.data, output.len, decoded,
                     sizeof(decoded), &decoded_len) == NC_OK);
    assert(decoded_len == 60 && read32(decoded + 24) == UINT32_C(0xb650ba3d));
    assert(sendto(sender, decoded, decoded_len, 0, (struct sockaddr *)&address,
                   sizeof(address)) == (ssize_t)decoded_len);
    while (!found) {
        struct pollfd p = {.fd = capture, .events = POLLIN};
        ssize_t len;
        size_t ip_len, tcp_len, at;
        const uint8_t *tcp;
        int timestamp = 0;
        assert(poll(&p, 1, 3000) == 1);
        len = recv(capture, incoming, sizeof(incoming), 0);
        assert(len >= 40);
        ip_len = (size_t)(incoming[0] & 15) * 4;
        tcp = incoming + ip_len;
        if (read16(tcp) != ntohs(address.sin_port) || read16(tcp + 2) != 40000 ||
            (tcp[13] & 0x12) != 0x12) continue;
        assert(read32(tcp + 8) == UINT32_C(0xb650ba3e));
        tcp_len = (size_t)(tcp[12] >> 4) * 4;
        for (at = 20; at < tcp_len && tcp[at];) {
            if (tcp[at] == 1) { at++; continue; }
            assert(at + 2 <= tcp_len && tcp[at + 1] >= 2 && at + tcp[at + 1] <= tcp_len);
            if (tcp[at] == 8 && tcp[at + 1] == 10) {
                assert(read32(tcp + at + 6) == UINT32_C(0x1c2db7af));
                timestamp = 1;
            }
            at += tcp[at + 1];
        }
        assert(timestamp);
        found = 1;
    }
    close(sender); close(capture); close(listener);
    puts("kernel TCP: compacted macOS SYN accepted, correct SYN-ACK acknowledgement and timestamp echo received");
    return 0;
}
