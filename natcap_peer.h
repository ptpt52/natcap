/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Thu, 30 Aug 2018 11:25:35 +0800
 *
 * This file is part of the natcap.
 *
 * natcap is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * natcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with natcap; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _NATCAP_PEER_H_
#define _NATCAP_PEER_H_

#define __ALIGN_64BITS 8

struct port_tuple {
	__be16 sport;
	__be16 dport;
};

struct peer_server_node {
	__be32 ip;
	unsigned short mss;
#define MAX_PEER_SERVER_PORT 8
	struct port_tuple port_map[MAX_PEER_SERVER_PORT];
};

struct fakeuser_expect {
	unsigned int pi;
	unsigned int local_seq;
	unsigned int remote_seq;
};

static inline struct fakeuser_expect *peer_fakeuser_expect(struct nf_conn *ct)
{
	return (void *)ct->ext + ct->ext->len;
}

struct peer_tuple {
	__be32 sip;
	__be32 dip;
	__be16 sport;
	__be16 dport;
	unsigned long last_active;
};

struct user_expect {
	unsigned long last_active;
	__be32 ip;
	__be16 map_port;
#define MAX_PEER_TUPLE 8
	struct peer_tuple tuple[MAX_PEER_TUPLE];
};

static inline struct user_expect *peer_user_expect(struct nf_conn *ct)
{
	return (void *)ct->ext + ct->ext->len;
}

int natcap_peer_init(void);
void natcap_peer_exit(void);

#endif /* _NATCAP_PEER_H_ */