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
	unsigned int local_seq;
	unsigned int remote_seq;
	unsigned int connected;
	unsigned long last_active;
};

struct peer_server_node {
	__be32 ip;
	__be16 map_port;
	unsigned short mss;
	unsigned int max_port_idx;
#define MAX_PEER_SERVER_PORT 8
	struct port_tuple port_map[MAX_PEER_SERVER_PORT];
};

struct fakeuser_expect {
	unsigned int pmi;
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
	unsigned int local_seq;
	unsigned int remote_seq;
	unsigned int connected;
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

static inline struct natcap_TCPOPT *natcap_peer_decode_header(struct tcphdr *tcph)
{
	struct natcap_TCPOPT *opt;

	opt = (struct natcap_TCPOPT *)((void *)tcph + sizeof(struct tcphdr));
	if (
			!(
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_PEER &&
				 (opt->header.type == NATCAP_TCPOPT_TYPE_PEER_SYN || opt->header.type == NATCAP_TCPOPT_TYPE_PEER_ACK) &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer_synack), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_PEER &&
				 opt->header.type == NATCAP_TCPOPT_TYPE_PEER_SYNACK &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer_synack), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_PEER &&
				 (opt->header.type == NATCAP_TCPOPT_TYPE_PEER_FSYN || opt->header.type == NATCAP_TCPOPT_TYPE_PEER_FACK) &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)))
			 )
	   )
	{
		return NULL;
	}

	return opt;
}

int natcap_peer_init(void);
void natcap_peer_exit(void);

#endif /* _NATCAP_PEER_H_ */
