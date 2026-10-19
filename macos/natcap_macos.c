/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "natcap_codec.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#endif

#define MAX_ROUTES 128
#define MAX_FLOWS 512
struct route_entry { char cidr[32]; uint32_t network, mask; int added; };
struct connection {
    struct nc_flow flow;
    int fd;
    double touched;
    double retire_after;
};
static struct route_entry routes[MAX_ROUTES];
static size_t route_count;
static struct connection connections[MAX_FLOWS];
static struct nc_output output;
static uint8_t input[NC_PACKET_MAX + 4], decoded[NC_PACKET_MAX + 4];
static volatile sig_atomic_t stopping;
static char ifname[IF_NAMESIZE], gateway[INET_ADDRSTRLEN], uplink[IF_NAMESIZE];
static char server_text[INET_ADDRSTRLEN];
static int pin_added, lock_fd = -1;
static unsigned long long tx_packets, rx_packets, drops;

static void stop_signal(int sig) { (void)sig; stopping = 1; }

static double now_seconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) abort();
    return (double)value.tv_sec + (double)value.tv_nsec / 1e9;
}

static void usage(FILE *to)
{
    fprintf(to,
        "Usage: natcap-macos --server IPv4 --mac XX:XX:XX:XX:XX:XX\n"
        "                    --route CIDR [--route CIDR ...] [options]\n"
        "  --port N             1..65534 fixed; 0 original; 65535 random (default)\n"
        "  --user-hash N        Authentication/user mark, default 0\n"
        "  --seed N             Server payload substitution seed, 0..255\n"
        "  --no-encryption      Disable the existing natcap payload encoding\n"
        "  --udp-protocol N     0: 12-byte header; 1: 24-byte auth header (default)\n"
        "  --sproxy             Request server-side natcapd TCP proxy\n"
        "  --mtu N              utun MTU, 576..1400, default 1200\n"
        "  --check-config       Validate options without changing networking\n"
        "  --help               Show this help\n"
        "Requires root on macOS. IPv4 only; both TCP and UDP use outer UDP.\n"
        "Only specified IPv4 routes are installed. DNS settings are not changed.\n");
}

static int number(const char *s, unsigned long maximum, unsigned long *out)
{
    char *end;
    unsigned long value;
    if (!s[0] || s[0] < '0' || s[0] > '9') return -1;
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno || *end || value > maximum) return -1;
    *out = value;
    return 0;
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned i;
    if (strlen(s) != 17) return -1;
    for (i = 0; i < 6; i++) {
        char pair[3] = { s[i * 3], s[i * 3 + 1], 0 }, *end;
        unsigned long value;
        if ((i < 5 && s[i * 3 + 2] != ':') ||
            !strchr("0123456789abcdefABCDEF", pair[0]) ||
            !strchr("0123456789abcdefABCDEF", pair[1])) return -1;
        value = strtoul(pair, &end, 16);
        if (*end || value > 255) return -1;
        mac[i] = (uint8_t)value;
    }
    return (mac[0] & 1) || !memcmp(mac, "\0\0\0\0\0\0", 6) ? -1 : 0;
}

static int add_route_argument(const char *s)
{
    char address[INET_ADDRSTRLEN], *slash;
    struct in_addr ip;
    unsigned long prefix;
    struct route_entry *r;
    size_t i;
    if (route_count == MAX_ROUTES || strlen(s) >= sizeof(routes[0].cidr)) return -1;
    r = &routes[route_count];
    strcpy(r->cidr, s);
    slash = strchr(r->cidr, '/');
    if (!slash) return -1;
    *slash++ = 0;
    if (inet_pton(AF_INET, r->cidr, &ip) != 1 || number(slash, 32, &prefix)) return -1;
    r->mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    r->network = ntohl(ip.s_addr);
    if (r->network & ~r->mask) return -1;
    inet_ntop(AF_INET, &ip, address, sizeof(address));
    snprintf(r->cidr, sizeof(r->cidr), "%s/%lu", address, prefix);
    for (i = 0; i < route_count; i++)
        if (!strcmp(routes[i].cidr, r->cidr)) return -1;
    route_count++;
    return 0;
}

/* Fixed executable paths and argv, with no shell and no inherited PATH lookup. */
static int command(char *const argv[], char *capture, size_t capacity)
{
    int pipefd[2] = {-1, -1}, status;
    pid_t child, waited;
    size_t used = 0;
    if (capture && pipe(pipefd)) return -1;
    child = fork();
    if (child < 0) {
        if (capture) { close(pipefd[0]); close(pipefd[1]); }
        return -1;
    }
    if (!child) {
        /* Finish each short route mutation even if the terminal interrupts the
         * parent, so it can record the result and undo successful additions. */
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        if (capture) {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
            close(pipefd[1]);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    if (capture) {
        char discard[512];
        ssize_t count;
        close(pipefd[1]);
        while ((count = read(pipefd[0], discard, sizeof(discard))) != 0) {
            size_t copy;
            if (count < 0) { if (errno == EINTR) continue; break; }
            copy = (size_t)count;
            if (copy > capacity - 1 - used) copy = capacity - 1 - used;
            memcpy(capture + used, discard, copy);
            used += copy;
        }
        capture[used] = 0;
        close(pipefd[0]);
    }
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -1;
}

static int utun_open(void)
{
#ifdef __APPLE__
    struct ctl_info info = {0};
    struct sockaddr_ctl address = {0};
    socklen_t name_len = sizeof(ifname);
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    snprintf(info.ctl_name, sizeof(info.ctl_name), "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) goto failed;
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    address.sc_unit = 0; /* Let the kernel allocate an unused utun interface. */
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &name_len) < 0)
        goto failed;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto failed;
    return fd;
failed:
    close(fd);
    return -1;
#else
    errno = ENOTSUP;
    return -1;
#endif
}

static int discover_uplink(int *existing_host)
{
    char text[8192], *line, flags[256] = "";
    char *argv[] = {"/sbin/route", "-n", "get", server_text, NULL};
    struct in_addr parsed;
    if (command(argv, text, sizeof(text))) return -1;
    for (line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        char key[64], value[256];
        if (sscanf(line, " %63[^:]: %255s", key, value) != 2) continue;
        if (!strcmp(key, "gateway") && inet_pton(AF_INET, value, &parsed) == 1)
            snprintf(gateway, sizeof(gateway), "%s", inet_ntoa(parsed));
        if (!strcmp(key, "interface") && strlen(value) < sizeof(uplink))
            memcpy(uplink, value, strlen(value) + 1);
        if (!strcmp(key, "flags")) memcpy(flags, value, strlen(value) + 1);
    }
    *existing_host = strstr(flags, "HOST") != NULL;
    if (!uplink[0] || !strncmp(uplink, "utun", 4) || !strcmp(uplink, "lo0")) return -1;
    return 0;
}

static int pin_server(const char *action)
{
    char *via_gateway[] = {"/sbin/route", "-n", (char *)action,
                          "-host", server_text, gateway, NULL};
    char *on_link[] = {"/sbin/route", "-n", (char *)action,
                      "-host", server_text, "-interface", uplink, NULL};
    return command(gateway[0] ? via_gateway : on_link, NULL, 0);
}

static int tunnel_route(const char *action, char *cidr)
{
    char *argv[] = {"/sbin/route", "-n", (char *)action,
                    "-net", cidr, "-interface", ifname, NULL};
    return command(argv, NULL, 0);
}

static void cleanup(void)
{
    size_t i = route_count;
    while (i--) if (routes[i].added) {
        if (tunnel_route("delete", routes[i].cidr))
            fprintf(stderr, "Could not remove route %s via %s\n", routes[i].cidr, ifname);
        routes[i].added = 0;
    }
    if (pin_added) {
        if (pin_server("delete")) fprintf(stderr, "Could not remove server host route\n");
        pin_added = 0;
    }
    if (lock_fd >= 0) { close(lock_fd); lock_fd = -1; }
}

static int acquire_lock(void)
{
    struct flock lock = {0};
    struct stat st;
    lock_fd = open("/var/run/natcap-macos.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (lock_fd < 0) return -1;
    if (fstat(lock_fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || (st.st_mode & 0022)) return -1;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(lock_fd, F_SETLK, &lock) || fcntl(lock_fd, F_SETFD, FD_CLOEXEC)) return -1;
    /* Keep the inode: unlinking a live lock allows two processes to own locks. */
    return 0;
}

static void close_connection(size_t at)
{
    if (connections[at].fd >= 0) close(connections[at].fd);
    connections[at].fd = -1;
}

static void observe_close(struct connection *c, unsigned flags, double now)
{
    double deadline;
    if (c->flow.key.protocol != 6 || !(flags & 5)) return;
    deadline = now + ((flags & 4) ? 10 : 120);
    if (!c->retire_after || deadline < c->retire_after) c->retire_after = deadline;
}

static int connection_for(const struct nc_packet *packet, struct in_addr server,
                           unsigned port, double now)
{
    size_t i;
    int free_slot = -1, fd;
    struct sockaddr_in address = {0};
    for (i = 0; i < MAX_FLOWS; i++) {
        struct connection *c = &connections[i];
        if (c->fd < 0) { if (free_slot < 0) free_slot = (int)i; continue; }
        if (nc_key_equal(&c->flow.key, &packet->key)) {
            if (c->retire_after && (packet->tcp_flags & 0x12) == 0x02) {
                close_connection(i);
                free_slot = (int)i;
                break;
            }
            return (int)i;
        }
    }
    if (free_slot < 0) return -1;
    /* Do not manufacture a new server-side TCP connection from a stray ACK. */
    if (packet->key.protocol == 6 && (packet->tcp_flags & 0x12) != 0x02) return -1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) < 0) goto failed;
    address.sin_family = AF_INET;
#ifdef __APPLE__
    address.sin_len = sizeof(address);
#endif
    address.sin_addr = server;
    if (!port) port = packet->key.dport;
    else if (port == 65535) {
#ifdef __APPLE__
        port = 1024 + arc4random_uniform(65535 - 1024);
#else
        port = 1024; /* The Linux build only supports offline configuration checks. */
#endif
    }
    address.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) goto failed;
    memset(&connections[free_slot], 0, sizeof(connections[free_slot]));
    connections[free_slot].flow.key = packet->key;
    connections[free_slot].fd = fd;
    connections[free_slot].touched = now;
    return free_slot;
failed:
    close(fd);
    return -1;
}

static int send_datagram(int fd, const uint8_t *p, size_t len)
{
    ssize_t sent;
    do { sent = send(fd, p, len, 0); } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)len) { drops++; return -1; }
    tx_packets++;
    return 0;
}

static int event_loop(int tun, const struct nc_config *config,
                       struct in_addr server, unsigned port)
{
    struct pollfd descriptors[MAX_FLOWS + 1];
    double last_report = now_seconds();
    uint32_t family = htonl(AF_INET);
    size_t i;
    for (i = 0; i < MAX_FLOWS; i++) connections[i].fd = -1;
    memcpy(decoded, &family, 4);
    while (!stopping) {
        double now = now_seconds();
        int ready;
        descriptors[0] = (struct pollfd){.fd = tun, .events = POLLIN};
        for (i = 0; i < MAX_FLOWS; i++) {
            struct connection *c = &connections[i];
            double lifetime = c->flow.key.protocol == 17 ? 20 : 7200;
            if (c->fd >= 0 && (now - c->touched > lifetime ||
                (c->retire_after && now >= c->retire_after))) close_connection(i);
            descriptors[i + 1] = (struct pollfd){.fd = c->fd, .events = POLLIN};
        }
        ready = poll(descriptors, MAX_FLOWS + 1, 1000);
        if (ready < 0) { if (errno == EINTR) continue; return -1; }
        if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = EIO; return -1; }
        /* Drain bounded batches so an active socket cannot starve others. */
        for (i = 0; i < MAX_FLOWS; i++) if (descriptors[i + 1].revents) {
            struct connection *c = &connections[i];
            unsigned batch;
            for (batch = 0; batch < 32; batch++) {
                ssize_t count = recv(c->fd, input, sizeof(input), 0);
                size_t len;
                int ret;
                if (count < 0) {
                    if (errno == EINTR) continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK) close_connection(i);
                    break;
                }
                ret = nc_decode(config, &c->flow, input, (size_t)count,
                                decoded + 4, NC_PACKET_MAX, &len);
                if (ret == NC_CONTROL) { c->touched = now; continue; }
                if (ret) { drops++; continue; }
                c->touched = now;
                if (c->flow.key.protocol == 6) observe_close(c, decoded[4 + 20 + 13], now);
                if (write(tun, decoded, len + 4) != (ssize_t)(len + 4)) drops++;
                else rx_packets++;
            }
        }
        if (descriptors[0].revents & POLLIN) {
            unsigned batch;
            for (batch = 0; batch < 32; batch++) {
                struct nc_packet packet;
                ssize_t count = read(tun, input, sizeof(input));
                int index, ret;
                if (count < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    return -1;
                }
                if (!count) return -1;
                if (count < 4 || memcmp(input, &family, 4) ||
                    nc_parse(input + 4, (size_t)count - 4, &packet)) { drops++; continue; }
                index = connection_for(&packet, server, port, now);
                if (index < 0) { drops++; continue; }
                ret = nc_encode(config, &connections[index].flow, input + 4,
                                (size_t)count - 4, &output);
                if (ret) {
                    if (ret == NC_OPTIONS) {
                        fprintf(stderr, "TCP SYN options exceed the 20-byte budget after removing padding; connection unsupported.\n");
                        close_connection((size_t)index);
                    }
                    drops++;
                    continue;
                }
                connections[index].touched = now;
                observe_close(&connections[index], packet.tcp_flags, now);
                send_datagram(connections[index].fd, output.data, output.len);
            }
        }
        if (now - last_report >= 30) {
            unsigned active = 0;
            for (i = 0; i < MAX_FLOWS; i++) active += connections[i].fd >= 0;
            fprintf(stderr, "flows=%u tx=%llu rx=%llu dropped=%llu\n",
                    active, tx_packets, rx_packets, drops);
            last_report = now;
        }
    }
    for (i = 0; i < MAX_FLOWS; i++) close_connection(i);
    return 0;
}

int main(int argc, char **argv)
{
    enum { OPT_HASH = 256, OPT_SEED, OPT_CLEAR, OPT_UDP, OPT_SPROXY, OPT_MTU, OPT_CHECK };
    static const struct option options[] = {
        {"server", required_argument, NULL, 's'}, {"port", required_argument, NULL, 'p'},
        {"mac", required_argument, NULL, 'm'}, {"route", required_argument, NULL, 'r'},
        {"user-hash", required_argument, NULL, OPT_HASH}, {"seed", required_argument, NULL, OPT_SEED},
        {"no-encryption", no_argument, NULL, OPT_CLEAR}, {"udp-protocol", required_argument, NULL, OPT_UDP},
        {"sproxy", no_argument, NULL, OPT_SPROXY}, {"mtu", required_argument, NULL, OPT_MTU},
        {"check-config", no_argument, NULL, OPT_CHECK}, {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}
    };
    struct nc_config config = {.encryption = 1, .udp_auth = 1};
    struct in_addr server = {0};
    unsigned long port = 65535, mtu = 1200, value;
    int option, have_mac = 0, check = 0, tun, existing_host = 0, ret = 1;
    size_t i;
    struct sigaction action = {0};
    while ((option = getopt_long(argc, argv, "s:p:m:r:h", options, NULL)) != -1) {
        switch (option) {
        case 's':
            if (inet_pton(AF_INET, optarg, &server) != 1) goto invalid;
            break;
        case 'p': if (number(optarg, 65535, &port)) goto invalid; break;
        case 'm': if (parse_mac(optarg, config.mac)) goto invalid; have_mac = 1; break;
        case 'r':
            if (!strcmp(optarg, "0.0.0.0/0")) {
                if (add_route_argument("0.0.0.0/1") || add_route_argument("128.0.0.0/1")) goto invalid;
            } else if (add_route_argument(optarg)) goto invalid;
            break;
        case OPT_HASH: if (number(optarg, UINT32_MAX, &value)) goto invalid; config.user_hash = (uint32_t)value; break;
        case OPT_SEED: if (number(optarg, 255, &value)) goto invalid; config.seed = (uint8_t)value; break;
        case OPT_CLEAR: config.encryption = 0; break;
        case OPT_UDP: if (number(optarg, 1, &value)) goto invalid; config.udp_auth = (uint8_t)value; break;
        case OPT_SPROXY: config.sproxy = 1; break;
        case OPT_MTU: if (number(optarg, 1400, &mtu) || mtu < 576) goto invalid; break;
        case OPT_CHECK: check = 1; break;
        case 'h': usage(stdout); return 0;
        default: goto invalid;
        }
    }
    value = ntohl(server.s_addr);
    if (optind != argc || !value || value >> 24 == 0 || value >> 24 == 127 || value >> 28 >= 14 ||
        (value & 0xfffffffc) == 0xc6126300 || !have_mac || !route_count) goto invalid;
    for (i = 0; i < route_count; i++)
        if (routes[i].mask == UINT32_MAX && routes[i].network == value) goto invalid;
    inet_ntop(AF_INET, &server, server_text, sizeof(server_text));
    if (check) {
        printf("Valid: server=%s port=%lu routes=%zu mtu=%lu TCP->UDP UDP->UDP\n",
                server_text, port, route_count, mtu);
        return 0;
    }
#ifndef __APPLE__
    fprintf(stderr, "This client requires macOS; only --check-config and --help work here.\n");
    return 1;
#endif
    if (geteuid()) { fprintf(stderr, "Run this client with sudo.\n"); return 1; }
    if (acquire_lock()) { fprintf(stderr, "Cannot acquire /var/run/natcap-macos.lock; another instance may be running.\n"); return 1; }
    atexit(cleanup);
    action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    if (discover_uplink(&existing_host)) {
        fprintf(stderr, "Cannot find a physical route to %s; disconnect other tunnels first.\n", server_text);
        return 1;
    }
    if (!existing_host) {
        if (pin_server("add")) return 1;
        pin_added = 1;
    }
    if (stopping) return 1;
    tun = utun_open();
    if (tun < 0) { perror("utun"); return 1; }
    {
        char mtu_text[16];
        char *ifconfig[] = {"/sbin/ifconfig", ifname, "inet", "198.18.99.1",
                            "198.18.99.2", "netmask", "255.255.255.255",
                            "mtu", mtu_text, "up", NULL};
        snprintf(mtu_text, sizeof(mtu_text), "%lu", mtu);
        if (command(ifconfig, NULL, 0)) goto finished;
    }
    for (i = 0; i < route_count; i++) {
        if (stopping || tunnel_route("add", routes[i].cidr)) goto finished;
        routes[i].added = 1;
    }
    fprintf(stderr, "%s: TCP->UDP, UDP->UDP via %s. Ctrl-C stops and removes installed routes.\n",
            ifname, server_text);
    fprintf(stderr, "IPv6 and system DNS configuration are unchanged. ICMP and IP fragments are unsupported.\n");
    if (event_loop(tun, &config, server, (unsigned)port)) perror("packet loop");
    else ret = 0;
finished:
    /* Remove routes while the utun still exists. Only successful adds are undone. */
    cleanup();
    close(tun);
    return ret;
invalid:
    fprintf(stderr, "Invalid configuration. CIDRs must use network addresses; MAC must be unicast.\n");
    usage(stderr);
    return 2;
}
