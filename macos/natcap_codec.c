/* SPDX-License-Identifier: GPL-3.0-or-later
 * Wire format: ../natcap.h, ../natcap_common.c, ../natcap_{client,server}.c.
 * This deliberately includes no Linux networking headers or C bitfields.
 */
#include "natcap_codec.h"
#include <string.h>

static const uint8_t substitution[256] = {
    152,151,106,224,13,90,137,200,178,138,212,156,238,54,44,237,
    101,42,97,91,163,191,119,157,123,102,124,125,197,35,15,26,
    40,179,129,229,38,221,71,175,95,77,245,153,31,56,253,107,
    109,243,67,225,167,133,19,32,150,180,160,203,110,131,169,16,
    130,210,183,24,12,79,114,118,215,250,10,165,164,27,112,233,
    213,49,204,139,65,98,34,115,173,228,207,47,59,143,135,219,
    199,66,76,113,33,186,187,134,105,155,190,249,181,21,201,88,
    9,70,89,62,241,220,236,148,227,116,214,41,185,244,211,184,
    166,18,140,63,3,222,136,248,84,93,121,120,132,171,108,73,
    55,30,83,1,68,117,128,87,209,231,239,5,223,172,17,246,
    39,254,170,94,48,182,196,58,149,86,216,22,202,20,159,53,
    78,174,141,189,252,4,25,69,8,64,147,37,60,111,74,11,
    192,146,198,255,240,61,36,51,247,226,57,154,194,6,80,50,
    208,72,144,234,158,217,23,82,242,122,195,177,193,205,7,232,
    96,206,145,103,43,45,162,176,104,126,100,188,81,218,161,92,
    46,251,52,75,0,142,28,14,2,168,235,127,230,85,99,29
};

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static void write16(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void write32(uint8_t *p, uint32_t v)
{
    write16(p, v >> 16);
    write16(p + 2, v & 65535);
}

static uint32_t sum_bytes(const uint8_t *p, size_t len, uint32_t sum)
{
    while (len >= 2) {
        sum += read16(p);
        p += 2;
        len -= 2;
    }
    if (len) sum += (unsigned)*p << 8;
    return sum;
}

static uint16_t finish_sum(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Reject malformed option lengths before any mutation or payload decoding. */
static int valid_tcp(const uint8_t *tcp, size_t len, size_t *header)
{
    size_t at;
    if (len < 20) return NC_INVALID;
    *header = (size_t)(tcp[12] >> 4) * 4;
    if (*header < 20 || *header > len) return NC_INVALID;
    for (at = 20; at < *header;) {
        unsigned kind = tcp[at], size;
        if (!kind) break;
        if (kind == 1) { at++; continue; }
        if (at + 2 > *header) return NC_INVALID;
        size = tcp[at + 1];
        if (size < 2 || size > *header - at) return NC_INVALID;
        if (kind == 2 && size != 4) return NC_INVALID;
        at += size;
    }
    return NC_OK;
}

int nc_key_equal(const struct nc_key *a, const struct nc_key *b)
{
    return a->protocol == b->protocol && a->sport == b->sport &&
           a->dport == b->dport && !memcmp(a->src, b->src, 4) &&
           !memcmp(a->dst, b->dst, 4);
}

int nc_parse(const uint8_t *packet, size_t len, struct nc_packet *parsed)
{
    size_t ip, total, transport, header;
    const uint8_t *p;
    if (len < 20) return NC_INVALID;
    if (packet[0] >> 4 != 4) return NC_UNSUPPORTED;
    ip = (size_t)(packet[0] & 15) * 4;
    total = read16(packet + 2);
    if (ip < 20 || ip > len || total != len || total < ip)
        return NC_INVALID;
    if (read16(packet + 6) & 0x3fff) return NC_UNSUPPORTED;
    transport = total - ip;
    p = packet + ip;
    if (packet[9] == 6) {
        if (valid_tcp(p, transport, &header)) return NC_INVALID;
    } else if (packet[9] == 17) {
        if (transport < 8 || read16(p + 4) != transport) return NC_INVALID;
        header = 8;
    } else {
        return NC_UNSUPPORTED;
    }
    memset(parsed, 0, sizeof(*parsed));
    memcpy(parsed->key.src, packet + 12, 4);
    memcpy(parsed->key.dst, packet + 16, 4);
    parsed->key.protocol = packet[9];
    parsed->key.sport = read16(p);
    parsed->key.dport = read16(p + 2);
    if (!parsed->key.sport || !parsed->key.dport) return NC_UNSUPPORTED;
    parsed->ip_len = ip;
    parsed->header_len = header;
    parsed->transport_len = transport;
    parsed->tcp_flags = packet[9] == 6 ? p[13] : 0;
    return NC_OK;
}

static void encode_bytes(uint8_t *p, size_t len, uint8_t seed)
{
    size_t i;
    for (i = 0; i < len; i++) p[i] = (uint8_t)(substitution[p[i]] + seed);
}

static void decode_bytes(uint8_t *p, size_t len, uint8_t seed)
{
    uint8_t inverse[256];
    unsigned i;
    size_t j;
    for (i = 0; i < 256; i++) inverse[(uint8_t)(substitution[i] + seed)] = (uint8_t)i;
    for (j = 0; j < len; j++) p[j] = inverse[p[j]];
}

static void all_option(uint8_t *out, const struct nc_config *config,
                       const struct nc_key *key, unsigned pioneer)
{
    memset(out, 0, 20);
    out[0] = 0x99;
    out[1] = 20;
    out[2] = (uint8_t)(1 | (pioneer ? 0x80 : 0) | (config->sproxy ? 0x20 : 0));
    out[3] = !!config->encryption;
    write32(out + 4, config->user_hash);
    memcpy(out + 8, config->mac, 6);
    write16(out + 14, key->dport);
    memcpy(out + 16, key->dst, 4);
}

int nc_encode(const struct nc_config *config, const struct nc_flow *flow,
              const uint8_t *packet, size_t len, struct nc_output *output)
{
    struct nc_packet parsed;
    const uint8_t *p;
    size_t header, add = 0, payload, at;
    int ret;
    output->len = output->pioneer_len = 0;
    ret = nc_parse(packet, len, &parsed);
    if (ret) return ret;
    if (!nc_key_equal(&parsed.key, &flow->key)) return NC_FLOW;
    p = packet + parsed.ip_len;
    header = parsed.header_len;
    payload = parsed.transport_len - header;
    if (parsed.key.protocol == 17) {
        if (!flow->udp_confirmed) add = config->udp_auth ? 24 : 12;
        if (payload + add > NC_DATAGRAM_MAX) return NC_SPACE;
        if (add) {
            memset(output->data, 0, add);
            write32(output->data, config->udp_auth ? NC_UDP_AUTH_MAGIC : NC_UDP_MAGIC);
            memcpy(output->data + 4, flow->key.dst, 4);
            write16(output->data + 8, flow->key.dport);
            write16(output->data + 10, 2 | (config->encryption ? 0x100 : 0));
            if (config->udp_auth) {
                write32(output->data + 12, config->user_hash);
                memcpy(output->data + 16, config->mac, 6);
            }
        }
        memcpy(output->data + add, p + 8, payload);
        if (config->encryption) encode_bytes(output->data + add, payload, config->seed);
        output->len = payload + add;
        return NC_OK;
    }
    /* A UDP payload is magic[4] + TCP bytes starting at sequence number.
     * The outer UDP source/destination ports replace the TCP ports on wire.
     * The Linux receiver reconstructs and checksums the TCP segment.
     */
    if ((parsed.tcp_flags & 0x12) == 0x02) {
        if (header <= 40) {
            add = 20;
        } else {
            uint8_t *ctrl = output->pioneer;
            unsigned mss = 536;
            for (at = 20; at < header;) {
                if (!p[at]) break;
                if (p[at] == 1) { at++; continue; }
                if (p[at] == 2) mss = read16(p + at + 2);
                at += p[at + 1];
            }
            memset(ctrl, 0, 44);
            write32(ctrl, NC_TCP_MAGIC);
            memcpy(ctrl + 4, p + 4, 16);
            ctrl[12] = (uint8_t)((11 << 4) | (p[12] & 15));
            ctrl[16] = ctrl[17] = 0;
            all_option(ctrl + 20, config, &flow->key, 1);
            ctrl[40] = 2;
            ctrl[41] = 4;
            write16(ctrl + 42, mss);
            output->pioneer_len = 44;
        }
    }
    if (parsed.transport_len + add > NC_DATAGRAM_MAX) {
        output->pioneer_len = 0;
        return NC_SPACE;
    }
    write32(output->data, NC_TCP_MAGIC);
    memcpy(output->data + 4, p + 4, 16);
    if (add) all_option(output->data + 20, config, &flow->key, 0);
    memcpy(output->data + 20 + add, p + 20, parsed.transport_len - 20);
    output->data[12] = (uint8_t)(((header + add) / 4 << 4) | (p[12] & 15));
    output->data[16] = output->data[17] = 0;
    if (config->encryption)
        encode_bytes(output->data + header + add, payload, config->seed);
    output->len = parsed.transport_len + add;
    return NC_OK;
}

static void ip_header(uint8_t *ip, size_t total, const struct nc_key *key)
{
    memset(ip, 0, 20);
    ip[0] = 0x45;
    write16(ip + 2, (unsigned)total);
    ip[8] = 64;
    ip[9] = key->protocol;
    memcpy(ip + 12, key->dst, 4);
    memcpy(ip + 16, key->src, 4);
    write16(ip + 10, finish_sum(sum_bytes(ip, 20, 0)));
}

int nc_decode(const struct nc_config *config, struct nc_flow *flow,
              const uint8_t *datagram, size_t len, uint8_t *packet,
              size_t capacity, size_t *packet_len)
{
    uint8_t *p;
    size_t transport, header = 8, remove = 0;
    uint32_t sum;
    *packet_len = 0;
    if (len > NC_DATAGRAM_MAX) return NC_INVALID;
    if (flow->key.protocol == 17) {
        if (len == 4 && read32(datagram) == NC_UDP_CFM) {
            flow->udp_confirmed = 1;
            return NC_CONTROL;
        }
        transport = len + 8;
    } else if (flow->key.protocol == 6) {
        uint8_t fixed[60];
        if (len < 20 || (read32(datagram) != NC_TCP_MAGIC &&
                         read32(datagram) != NC_TCP_V1_MAGIC)) return NC_INVALID;
        header = (size_t)(datagram[12] >> 4) * 4;
        if (header < 20 || header > len) return NC_INVALID;
        /* valid_tcp only reads the header; provide the real segment length. */
        memcpy(fixed, datagram, header);
        if (valid_tcp(fixed, len, &header)) return NC_INVALID;
        if (header > 20 && datagram[20] == 0x99) {
            unsigned type;
            if (header < 24) return NC_INVALID;
            remove = datagram[21];
            if (remove < 4 || remove % 4 || remove > header - 20) return NC_INVALID;
            type = datagram[22] & 15;
            if ((datagram[22] & 0xd0) || (datagram[23] >> 1) ||
                type == 4 || (type == 1 && remove != 20) ||
                (type == 2 && remove != 12) || (type == 3 && remove != 16) ||
                (type == 5 && remove != 4) || type > 5 || !type)
                return NC_UNSUPPORTED;
        }
        transport = len - remove;
    } else {
        return NC_UNSUPPORTED;
    }
    if (transport + 20 > capacity || transport + 20 > NC_PACKET_MAX)
        return NC_SPACE;
    p = packet + 20;
    if (flow->key.protocol == 17) {
        write16(p + 4, (unsigned)transport);
        p[6] = p[7] = 0;
        memcpy(p + 8, datagram, len);
        if (config->encryption) decode_bytes(p + 8, len, config->seed);
    } else {
        memcpy(p + 4, datagram + 4, 16);
        memcpy(p + 20, datagram + 20 + remove, len - 20 - remove);
        p[12] = (uint8_t)(((header - remove) / 4 << 4) | (p[12] & 15));
        p[16] = p[17] = 0;
        if (config->encryption)
            decode_bytes(p + header - remove, len - header, config->seed);
    }
    write16(p, flow->key.dport);
    write16(p + 2, flow->key.sport);
    ip_header(packet, transport + 20, &flow->key);
    sum = sum_bytes(packet + 12, 8, (uint32_t)transport + flow->key.protocol);
    sum = finish_sum(sum_bytes(p, transport, sum));
    if (flow->key.protocol == 17 && !sum) sum = 65535;
    write16(p + (flow->key.protocol == 17 ? 6 : 16), sum);
    *packet_len = transport + 20;
    return NC_OK;
}
