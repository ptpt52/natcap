#ifndef _NATCAPD_H
#define _NATCAPD_H

#include <stddef.h>
#include <time.h>
#include <ev.h>
#include "natcap.h"

typedef struct {
	int idx;
	int len;
#define BUF_SIZE 2048
	unsigned char data[BUF_SIZE];
} buffer_t;

typedef struct listen_ctx {
	ev_io io;
	int fd;
	int timeout;
	struct ev_loop *loop;
} listen_ctx_t;

typedef struct server_ctx {
	ev_io io;
	ev_timer watcher;
	int connected;
	struct server *server;
} server_ctx_t;

typedef struct server {
	int fd;
	int stage;

	buffer_t *buf;

	struct server_ctx *recv_ctx;
	struct server_ctx *send_ctx;
	struct listen_ctx *listen_ctx;
	struct remote *remote;
} server_t;

typedef struct remote_ctx {
	ev_io io;
	int connected;
	struct remote *remote;
} remote_ctx_t;

typedef struct remote {
	int fd;

	buffer_t *buf;

	struct remote_ctx *recv_ctx;
	struct remote_ctx *send_ctx;
	struct server *server;
} remote_t;

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_PARSE      2  /* Parse the header                 */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_WAIT       5  /* Wait for more data               */
#define STAGE_STREAM     6  /* Stream between client and server */

#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define MAX_REQUEST_TIMEOUT 30
#define MAX_REMOTE_NUM 10

void
FATAL(const char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(-1);
}

#endif // _NATCAPD_H
