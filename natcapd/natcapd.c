#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>

#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/un.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netfilter_ipv4.h>
#include "natcapd.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef MAXCONN
#define MAXCONN 1024
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

static remote_t *new_remote(int fd);
static server_t *new_server(int fd, listen_ctx_t *listener);
static remote_t *connect_to_remote(EV_P_ struct addrinfo *res, server_t *server);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

int verbose = 0;
int reuse_port = 0;

static int set_reuseport(int socket)
{
	int opt = 1;
	return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

static int remote_conn = 0;
static int server_conn = 0;

uint64_t tx                  = 0;
uint64_t rx                  = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

int setnonblocking(int fd)
{
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_and_bind(const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp, *ipv4v6bindall;
	int s, listen_sock;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
	hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
	hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
	hints.ai_protocol = IPPROTO_TCP;

	result = NULL;

	for (int i = 1; i < 8; i++) {
		s = getaddrinfo(host, port, &hints, &result);
		if (s == 0) {
			break;
		} else {
			sleep(pow(2, i));
			printf("failed to resolve server name, wait %.0f seconds\n", pow(2, i));
		}
	}

	if (s != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	if (result == NULL) {
		printf("Could not bind\n");
		return -1;
	}

	rp = result;

	/*
	 * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
	 * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
	 * return a list of addresses to listen on, but it is impossible to listen on
	 * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
	 */
	if (!host) {
		ipv4v6bindall = result;

		/* Loop over all address infos found until a IPV6 address is found. */
		while (ipv4v6bindall) {
			if (ipv4v6bindall->ai_family == AF_INET6) {
				rp = ipv4v6bindall; /* Take first IPV6 address available */
				break;
			}
			ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
		}
	}

	for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
		listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (listen_sock == -1) {
			continue;
		}

		if (rp->ai_family == AF_INET6) {
			int ipv6only = host ? 1 : 0;
			setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
		}

		int opt = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
		setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
		if (reuse_port) {
			int err = set_reuseport(listen_sock);
			if (err == 0) {
				printf("tcp port reuse enabled\n");
			}
		}

		s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		} else {
			perror("bind");
		}

		close(listen_sock);
		listen_sock = -1;
	}

	freeaddrinfo(result);

	return listen_sock;
}

static remote_t *connect_to_remote(EV_P_ struct addrinfo *res, server_t *server)
{
	int sockfd;

	// initialize remote socks
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1) {
		perror("socket");
		close(sockfd);
		return NULL;
	}

	int opt = 1;
	setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
	setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	// setup remote socks

	if (setnonblocking(sockfd) == -1)
		perror("setnonblocking");

	remote_t *remote = new_remote(sockfd);

	int r = connect(sockfd, res->ai_addr, res->ai_addrlen);

	if (r == -1 && errno != EINPROGRESS) {
		perror("connect");
		close_and_free_remote(EV_A_ remote);
		return NULL;
	}

	return remote;
}

#ifdef NATCAP_CLIENT_MODE
int getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t socklen = sizeof(*destaddr);
    int error = 0;

	error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
	if (error) {
		return -1;
	}
	return 0;
}
#else
static int getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error = 0;

	error = getsockopt(fd, SOL_IP, SO_NATCAP_DST, destaddr, &socklen);
	if (error) {
		return -1;
	}
	return 0;
}
#endif

static void server_recv_cb(EV_P_ ev_io *w, int revents)
{
	server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
	server_t *server              = server_recv_ctx->server;
	remote_t *remote              = server->remote;

	if (remote == NULL) {
		printf("invalid remote\n");
		close_and_free_server(EV_A_ server);
		return;
	}

	ssize_t r = recv(server->fd, remote->buf->data, BUF_SIZE, 0);
	if (r == 0) {
		// connection closed
		if (verbose) {
			printf("server_recv close the connection\n");
		}
		close_and_free_remote(EV_A_ remote);
		close_and_free_server(EV_A_ server);
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// no data
			// continue to wait for recv
			return;
		} else {
			//perror("server recv");
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	}
	tx += r;
	remote->buf->len = r;

	if (server->stage == STAGE_STREAM) {
		ev_timer_again(EV_A_ & server->recv_ctx->watcher);

		int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
		if (s == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// no data, wait for send
				remote->buf->idx = 0;
				ev_io_stop(EV_A_ & server_recv_ctx->io);
				ev_io_start(EV_A_ & remote->send_ctx->io);
			} else {
				perror("server_recv_send");
				close_and_free_remote(EV_A_ remote);
				close_and_free_server(EV_A_ server);
			}
		} else if (s < remote->buf->len) {
			remote->buf->len -= s;
			remote->buf->idx  = s;
			ev_io_stop(EV_A_ & server_recv_ctx->io);
			ev_io_start(EV_A_ & remote->send_ctx->io);
		}
		return;
	} else if (server->stage == STAGE_INIT) {
		// waiting on remote connected event
		ev_io_stop(EV_A_ & server_recv_ctx->io);
		ev_io_start(EV_A_ & remote->send_ctx->io);
		return;
	}
}

static void server_send_cb(EV_P_ ev_io *w, int revents)
{
	server_ctx_t *server_send_ctx = (server_ctx_t *)w;
	server_t *server              = server_send_ctx->server;
	remote_t *remote              = server->remote;

	if (remote == NULL) {
		printf("invalid server\n");
		close_and_free_server(EV_A_ server);
		return;
	}

	if (server->buf->len == 0) {
		// close and free
		if (verbose) {
			printf("server_send close the connection\n");
		}
		close_and_free_remote(EV_A_ remote);
		close_and_free_server(EV_A_ server);
		return;
	} else {
		// has data to send
		ssize_t s = send(server->fd, server->buf->data + server->buf->idx, server->buf->len, 0);
		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("server_send_send");
				close_and_free_remote(EV_A_ remote);
				close_and_free_server(EV_A_ server);
			}
			return;
		} else if (s < server->buf->len) {
			// partly sent, move memory, wait for the next time to send
			server->buf->len -= s;
			server->buf->idx += s;
			return;
		} else {
			// all sent out, wait for reading
			server->buf->len = 0;
			server->buf->idx = 0;
			ev_io_stop(EV_A_ & server_send_ctx->io);
			ev_io_start(EV_A_ & remote->recv_ctx->io);
		}
	}
}

static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
	server_ctx_t *server_ctx = container_of(watcher, server_ctx_t, watcher);
	server_t *server = server_ctx->server;
	remote_t *remote = server->remote;

	if (verbose) {
		printf("TCP connection timeout\n");
	}

	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
	remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
	remote_t *remote              = remote_recv_ctx->remote;
	server_t *server              = remote->server;

	if (server == NULL) {
		printf("invalid server\n");
		close_and_free_remote(EV_A_ remote);
		return;
	}

	ev_timer_again(EV_A_ & server->recv_ctx->watcher);

	ssize_t r = recv(remote->fd, server->buf->data, BUF_SIZE, 0);
	if (r == 0) {
		// connection closed
		if (verbose) {
			printf("remote_recv close the connection\n");
		}
		close_and_free_remote(EV_A_ remote);
		close_and_free_server(EV_A_ server);
		return;
	} else if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// no data
			// continue to wait for recv
			return;
		} else {
			//perror("remote recv");
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	}
	rx += r;
	server->buf->len = r;

	int s = send(server->fd, server->buf->data, server->buf->len, 0);
	if (s == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			// no data, wait for send
			server->buf->idx = 0;
			ev_io_stop(EV_A_ & remote_recv_ctx->io);
			ev_io_start(EV_A_ & server->send_ctx->io);
		} else {
			perror("remote_recv_send");
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	} else if (s < server->buf->len) {
		server->buf->len -= s;
		server->buf->idx  = s;
		ev_io_stop(EV_A_ & remote_recv_ctx->io);
		ev_io_start(EV_A_ & server->send_ctx->io);
	}

	// Disable TCP_NODELAY after the first response are sent
	if (!remote->recv_ctx->connected) {
		int opt = 0;
		setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
		setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
		remote->recv_ctx->connected = 1;
	}
}

static void remote_send_cb(EV_P_ ev_io *w, int revents)
{
	remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
	remote_t *remote              = remote_send_ctx->remote;
	server_t *server              = remote->server;

	if (server == NULL) {
		printf("invalid server\n");
		close_and_free_remote(EV_A_ remote);
		return;
	}

	if (!remote_send_ctx->connected) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(struct sockaddr_storage);
		memset(&addr, 0, len);
		int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
		if (r == 0) {
			if (verbose) {
				printf("remote connected\n");
			}
			remote_send_ctx->connected = 1;
			if (server->stage != STAGE_STREAM) {
				server->stage = STAGE_STREAM;
				ev_io_start(EV_A_ & remote->recv_ctx->io);
			}

			if (remote->buf->len == 0) {
				ev_io_stop(EV_A_ & remote_send_ctx->io);
				ev_io_start(EV_A_ & server->recv_ctx->io);
				return;
			}
		} else {
			perror("remote_send_getpeername");
			// not connected
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	}

	if (remote->buf->len == 0) {
		// close and free
		if (verbose) {
			printf("remote_send close the connection\n");
		}
		close_and_free_remote(EV_A_ remote);
		close_and_free_server(EV_A_ server);
		return;
	} else {
		// has data to send
		ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx, remote->buf->len, 0);
		if (s == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("remote_send_send");
				// close and free
				close_and_free_remote(EV_A_ remote);
				close_and_free_server(EV_A_ server);
				return;
			}
		} else if (s < remote->buf->len) {
			// partly sent, move memory, wait for the next time to send
			remote->buf->len -= s;
			remote->buf->idx += s;
		} else {
			// all sent out, wait for reading
			remote->buf->len = 0;
			remote->buf->idx = 0;
			ev_io_stop(EV_A_ & remote_send_ctx->io);
			ev_io_start(EV_A_ & server->recv_ctx->io);
		}
		if (server->stage != STAGE_STREAM) {
			server->stage = STAGE_STREAM;
			ev_io_start(EV_A_ & remote->recv_ctx->io);
		}
	}
}

static remote_t *new_remote(int fd)
{
	if (verbose) {
		remote_conn++;
	}

	remote_t *remote = malloc(sizeof(remote_t));
	memset(remote, 0, sizeof(remote_t));

	remote->recv_ctx = malloc(sizeof(remote_ctx_t));
	remote->send_ctx = malloc(sizeof(remote_ctx_t));
	remote->buf = malloc(sizeof(buffer_t));
	remote->buf->len = 0;
	remote->buf->idx = 0;
	memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
	memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
	remote->fd                  = fd;
	remote->recv_ctx->remote    = remote;
	remote->recv_ctx->connected = 0;
	remote->send_ctx->remote    = remote;
	remote->send_ctx->connected = 0;
	remote->server              = NULL;

	ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
	ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

	return remote;
}

static void free_remote(remote_t *remote)
{
	if (remote->server != NULL) {
		remote->server->remote = NULL;
	}
	if (remote->buf != NULL) {
		free(remote->buf);
	}
	free(remote->recv_ctx);
	free(remote->send_ctx);
	free(remote);
}

static void close_and_free_remote(EV_P_ remote_t *remote)
{
	if (remote != NULL) {
		ev_io_stop(EV_A_ & remote->send_ctx->io);
		ev_io_stop(EV_A_ & remote->recv_ctx->io);
		close(remote->fd);
		free_remote(remote);
		if (verbose) {
			remote_conn--;
			printf("current remote connection: %d\n", remote_conn);
		}
	}
}

static server_t *new_server(int fd, listen_ctx_t *listener)
{
	if (verbose) {
		server_conn++;
	}

	server_t *server;
	server = malloc(sizeof(server_t));

	memset(server, 0, sizeof(server_t));

	server->recv_ctx   = malloc(sizeof(server_ctx_t));
	server->send_ctx   = malloc(sizeof(server_ctx_t));
	memset(server->recv_ctx, 0, sizeof(server_ctx_t));
	memset(server->send_ctx, 0, sizeof(server_ctx_t));
	server->buf = malloc(sizeof(buffer_t));
	server->buf->len = 0;
	server->buf->idx = 0;
	server->fd                  = fd;
	server->recv_ctx->server    = server;
	server->recv_ctx->connected = 0;
	server->send_ctx->server    = server;
	server->send_ctx->connected = 0;
	server->stage               = STAGE_INIT;
	server->listen_ctx          = listener;
	server->remote              = NULL;

	int request_timeout = min(MAX_REQUEST_TIMEOUT, listener->timeout)
	                      + rand() % MAX_REQUEST_TIMEOUT;

	ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
	ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
	ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
	              request_timeout, listener->timeout);

	return server;
}

static void free_server(server_t *server)
{
	if (server->remote != NULL) {
		server->remote->server = NULL;
	}
	if (server->buf != NULL) {
		free(server->buf);
	}

	free(server->recv_ctx);
	free(server->send_ctx);
	free(server);
}

static void close_and_free_server(EV_P_ server_t *server)
{
	if (server != NULL) {
		ev_io_stop(EV_A_ & server->send_ctx->io);
		ev_io_stop(EV_A_ & server->recv_ctx->io);
		ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
		close(server->fd);
		free_server(server);
		if (verbose) {
			server_conn--;
			printf("current server connection: %d\n", server_conn);
		}
	}
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
	if (revents & EV_SIGNAL) {
		switch (w->signum) {
		case SIGCHLD:
			return;
		case SIGINT:
		case SIGTERM:
			ev_signal_stop(EV_DEFAULT, &sigint_watcher);
			ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
			ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
			ev_unloop(EV_A_ EVUNLOOP_ALL);
		}
	}
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	listen_ctx_t *listener = (listen_ctx_t *)w;
	int serverfd           = accept(listener->fd, NULL, NULL);
	if (serverfd == -1) {
		perror("accept");
		return;
	}

	int opt = 1;
	setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
	setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
	setnonblocking(serverfd);

	if (verbose) {
		printf("accept a connection\n");
	}

	server_t *server = new_server(serverfd, listener);
	//ev_io_start(EV_A_ & server->recv_ctx->io);
	ev_timer_start(EV_A_ & server->recv_ctx->watcher);

	if (server->stage == STAGE_INIT) {
		struct sockaddr_in *addr;
		struct addrinfo info;
		struct sockaddr_storage storage;
		memset(&info, 0, sizeof(struct addrinfo));
		memset(&storage, 0, sizeof(struct sockaddr_storage));

		if (getdestaddr(server->fd, &storage) != 0) {
			perror("getdestaddr");
			close_and_free_server(EV_A_ server);
			return;
		}

		addr = (struct sockaddr_in *)&storage;
		info.ai_family   = AF_INET;
		info.ai_socktype = SOCK_STREAM;
		info.ai_protocol = IPPROTO_TCP;
		info.ai_addrlen  = sizeof(struct sockaddr_in);
		info.ai_addr     = (struct sockaddr *)addr;

		remote_t *remote = connect_to_remote(EV_A_ & info, server);
		if (remote == NULL) {
			printf("connect error\n");
			close_and_free_server(EV_A_ server);
			return;
		} else {
			server->remote = remote;
			remote->server = server;
			//ev_io_start(EV_A_ & remote->recv_ctx->io);
			ev_io_start(EV_A_ & remote->send_ctx->io);
		}
	}
}

void usage()
{
	printf("\n");
	printf("natcapd %s\n\n", "1.0");
	printf("  Chen Minqiang <ptpt52@gmail.com>\n\n");
	printf("  usage:\n\n");
	printf("       [-l <local_port>]          Port number of your local server.\n");
	printf("       [-t <timeout>]             Socket timeout in seconds.\n");
	printf("       [-v]                       Verbose mode.\n");
	printf("       [-h, --help]               Print this message.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	int c;
	char *timeout   = NULL;
	char *server_port = "1080";

	int server_num = 0;
	const char *server_host[MAX_REMOTE_NUM];

	opterr = 0;

	while ((c = getopt_long(argc, argv, "l:t:hv", NULL, NULL)) != -1) {
		switch (c) {
			case 'l':
				server_port = optarg;
				break;
			case 't':
				timeout = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case '?':
				// The option character is not recognized.
				opterr = 1;
				break;
		}
	}

	if (opterr) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (server_num == 0) {
		server_host[server_num++] = "0.0.0.0";
	}

	if (timeout == NULL) {
		timeout = "60";
	}

	// ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);
	signal(SIGABRT, SIG_IGN);

	ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
	ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
	ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
	ev_signal_start(EV_DEFAULT, &sigint_watcher);
	ev_signal_start(EV_DEFAULT, &sigterm_watcher);
	ev_signal_start(EV_DEFAULT, &sigchld_watcher);

	// initialize ev loop
	struct ev_loop *loop = EV_DEFAULT;

	// initialize listen context
	listen_ctx_t listen_ctx_list[server_num];

	// bind to each interface
	for (int i = 0; i < server_num; i++) {
		const char *host = server_host[i];

		// Bind to port
		int listenfd;
		listenfd = create_and_bind(host, server_port);
		if (listenfd == -1) {
			FATAL("bind() error");
		}
		if (listen(listenfd, MAXCONN) == -1) {
			FATAL("listen() error");
		}
		setnonblocking(listenfd);
		listen_ctx_t *listen_ctx = &listen_ctx_list[i];

		// Setup proxy context
		listen_ctx->timeout = atoi(timeout);
		listen_ctx->fd      = listenfd;
		listen_ctx->loop    = loop;

		ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
		ev_io_start(loop, &listen_ctx->io);

		if (host && strcmp(host, ":") > 0)
			printf("tcp server listening at [%s]:%s\n", host, server_port);
		else
			printf("tcp server listening at %s:%s\n", host ? host : "0.0.0.0", server_port);
	}


	if (geteuid() == 0) {
		printf("running from root user\n");
	}

	// start ev loop
	ev_run(loop, 0);

	if (verbose) {
		printf("closed gracefully\n");
	}

	// Clean up
	for (int i = 0; i < server_num; i++) {
		listen_ctx_t *listen_ctx = &listen_ctx_list[i];
		ev_io_stop(loop, &listen_ctx->io);
		close(listen_ctx->fd);
	}

	return 0;
}
