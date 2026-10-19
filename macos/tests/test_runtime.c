/* SPDX-License-Identifier: GPL-3.0-or-later
 * Exercise the real packet loop with a datagram socketpair in place of utun
 * and loopback UDP in place of a Linux natcap server. No route changes/root.
 */
#define main natcap_cli_main
#include "../natcap_macos.c"
#undef main
#include <assert.h>

static void ready_to_read(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    assert(poll(&p, 1, 3000) == 1 && (p.revents & POLLIN));
}

int main(void)
{
    int pair[2], remote, status;
    pid_t child;
    struct sockaddr_in server = {0}, first, second;
    socklen_t address_len = sizeof(server);
    uint8_t frame[512] = {0}, datagram[512], reply[512];
    struct nc_config cfg = {.mac = {2,0,0,0,0,1}, .udp_auth = 1};
    struct nc_packet parsed;
    uint32_t family = htonl(AF_INET);
    ssize_t n;
#ifdef __linux__
    if (access("/sys/module/natcap", F_OK) == 0 && !getenv("NATCAP_TEST_ISOLATED")) {
        puts("SKIP runtime: host already loads natcap, which can intercept protocol packets on loopback; use a clean network namespace or macOS");
        return 0;
    }
#endif
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
    assert(fcntl(pair[1], F_SETFL, O_NONBLOCK) == 0);
    remote = socket(AF_INET, SOCK_DGRAM, 0);
    assert(remote >= 0);
    server.sin_family = AF_INET;
#ifdef __APPLE__
    server.sin_len = sizeof(server);
#endif
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(remote, (struct sockaddr *)&server, sizeof(server)) == 0);
    assert(getsockname(remote, (struct sockaddr *)&server, &address_len) == 0);
    child = fork();
    assert(child >= 0);
    if (!child) {
        close(pair[0]); close(remote);
        signal(SIGTERM, stop_signal);
        _exit(event_loop(pair[1], &cfg, server.sin_addr, ntohs(server.sin_port)) ? 1 : 0);
    }
    close(pair[1]);
    memcpy(frame, &family, 4);
    frame[4] = 0x45; frame[7] = 40; frame[12] = 64; frame[13] = 6;
    frame[16] = 198; frame[17] = 18; frame[18] = 99; frame[19] = 1;
    frame[20] = 203; frame[22] = 113; frame[23] = 9;
    frame[24] = 0x30; frame[25] = 0x39; /* original TCP source 12345 */
    frame[26] = 1; frame[27] = 0xbb;
    frame[36] = 0x50; frame[37] = 2;
    assert(send(pair[0], frame, 44, 0) == 44);
    ready_to_read(remote);
    address_len = sizeof(first);
    n = recvfrom(remote, datagram, sizeof(datagram), 0, (struct sockaddr *)&first, &address_len);
    assert(n == 40 && !memcmp(datagram, "\xff\xff\x00\x99", 4));
    assert(datagram[20] == 0x99 && datagram[21] == 20 && datagram[22] == 1);
    assert(datagram[34] == 1 && datagram[35] == 0xbb);
    assert(!memcmp(datagram + 36, frame + 20, 4));
    /* The outer port may differ from 12345; return demultiplexing restores it. */
    datagram[12] = 0x50; datagram[13] = 0x12;
    assert(sendto(remote, datagram, 20, 0, (struct sockaddr *)&first, sizeof(first)) == 20);
    ready_to_read(pair[0]);
    n = recv(pair[0], reply, sizeof(reply), 0);
    assert(n == 44 && !memcmp(reply, &family, 4));
    assert(nc_parse(reply + 4, (size_t)n - 4, &parsed) == NC_OK);
    assert(parsed.key.sport == 443 && parsed.key.dport == 12345);
    assert(parsed.tcp_flags == 0x12 && !memcmp(parsed.key.src, frame + 20, 4));
    /* Same original source port, different destination: distinct outer socket. */
    frame[23] = 10;
    assert(send(pair[0], frame, 44, 0) == 44);
    ready_to_read(remote);
    address_len = sizeof(second);
    assert(recvfrom(remote, datagram, sizeof(datagram), 0, (struct sockaddr *)&second, &address_len) == 40);
    assert(second.sin_port != first.sin_port && datagram[39] == 10);
    /* Native UDP: consume confirmation, then stop including setup headers. */
    frame[7] = 31; frame[13] = 17;
    frame[26] = 0; frame[27] = 53; frame[28] = 0; frame[29] = 11;
    frame[30] = frame[31] = 0;
    memcpy(frame + 32, "abc", 3);
    assert(send(pair[0], frame, 35, 0) == 35);
    ready_to_read(remote);
    address_len = sizeof(first);
    assert(recvfrom(remote, datagram, sizeof(datagram), 0, (struct sockaddr *)&first, &address_len) == 27);
    assert(!memcmp(datagram, "\xff\xfd\x00\x99", 4) && !memcmp(datagram + 24, "abc", 3));
    assert(sendto(remote, "\xff\xfe\x00\x9a", 4, 0, (struct sockaddr *)&first, sizeof(first)) == 4);
    assert(sendto(remote, "xyz", 3, 0, (struct sockaddr *)&first, sizeof(first)) == 3);
    ready_to_read(pair[0]);
    assert(recv(pair[0], reply, sizeof(reply), 0) == 35);
    assert(!memcmp(reply + 32, "xyz", 3));
    assert(nc_parse(reply + 4, 31, &parsed) == NC_OK && parsed.key.protocol == 17);
    assert(send(pair[0], frame, 35, 0) == 35);
    ready_to_read(remote);
    assert(recv(remote, datagram, sizeof(datagram), 0) == 3 && !memcmp(datagram, "abc", 3));
    assert(kill(child, SIGTERM) == 0);
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(pair[0]); close(remote);
    puts("runtime: UDP sockets, TCP/UDP return injection, tuple isolation and UDP confirmation passed");
    return 0;
}
