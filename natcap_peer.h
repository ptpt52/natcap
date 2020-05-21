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

struct peer_server_node {
	spinlock_t  lock;
#define PEER_SUBTYPE_SSYN_BIT 0
#define PEER_SUBTYPE_SSYN (1 << PEER_SUBTYPE_SSYN_BIT)
#define PEER_SUBTYPE_SYN_BIT 1
#define PEER_SUBTYPE_SYN (1 << PEER_SUBTYPE_SYN_BIT)
#define PEER_SUBTYPE_PUB_BIT 2
#define PEER_SUBTYPE_PUB (1 << PEER_SUBTYPE_PUB_BIT)
	unsigned short status;
	__be32 ip;
	__be16 map_port;
	unsigned short conn;
	unsigned int last_active;
	unsigned int last_inuse;
#define MAX_PEER_CONN 8
	struct nf_conn *port_map[MAX_PEER_CONN];
};

struct natcap_route {
	/* max L2 len supoorted
	 * mac + vlan + pppoe (=14 + 4 + 8)
	 */
#define NF_L2_MAX_LEN (14 + 4 + 8)
	unsigned char l2_head[NF_L2_MAX_LEN];
	unsigned short l2_head_len;
	struct net_device *outdev;
};

struct fakeuser_expect {
#define FUE_STATE_INIT 0
#define FUE_STATE_CONNECTED 1
	unsigned char state;
#define FUE_MODE_TCP 0
#define FUE_MODE_UDP 1
	unsigned char mode;
	unsigned short mss;
	unsigned int pmi;
	unsigned int local_seq;
	unsigned int remote_seq;
	unsigned int last_active;
	struct natcap_route rt_out;
};

static inline struct fakeuser_expect *peer_fakeuser_expect(struct nf_conn *ct)
{
	return (void *)ct->ext + ct->ext->len;
}

struct peer_tuple {
	unsigned int local_seq;
	unsigned int remote_seq;
	__be32 sip;
	__be32 dip;
	__be16 sport;
	__be16 dport;
	unsigned short mss;
	unsigned char connected:7,
	         sni_ban:1;
#define PT_MODE_TCP 0
#define PT_MODE_UDP 1
	unsigned char mode;
	unsigned int last_active;
};

struct user_expect {
	spinlock_t lock;
	unsigned int last_active;
	unsigned int last_active_peer;
	__be32 local_ip;
	__be32 ip;
	__be16 map_port;
	unsigned short status;
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
	         (opt->header.opcode == TCPOPT_PEER || opt->header.opcode == TCPOPT_PEER_V2) &&
	         (opt->header.subtype == SUBTYPE_PEER_SYN ||
	          opt->header.subtype == SUBTYPE_PEER_SSYN ||
	          opt->header.subtype == SUBTYPE_PEER_SYNACK ||
	          opt->header.subtype == SUBTYPE_PEER_ACK ||
	          opt->header.subtype == SUBTYPE_PEER_FSYNACK) &&
	         opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int))) ||
	        (tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)) &&
	         (opt->header.opcode == TCPOPT_PEER || opt->header.opcode == TCPOPT_PEER_V2) &&
	         (opt->header.subtype == SUBTYPE_PEER_FSYN || opt->header.subtype == SUBTYPE_PEER_FACK) &&
	         opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int))) ||
	        (tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int)) &&
	         (opt->header.opcode == TCPOPT_PEER || opt->header.opcode == TCPOPT_PEER_V2) &&
	         opt->header.subtype == SUBTYPE_PEER_XSYN &&
	         opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int)))
	    )
	)
	{
		return NULL;
	}

	return opt;
}

int natcap_peer_init(void);
void natcap_peer_exit(void);

#define PEER_XSYN_MASK_ADDR __constant_htonl(0xffffffff)
extern __be32 peer_xsyn_enumerate_addr(void);

#define PEER_PUB_NUM 256
extern __be32 peer_pub_ip[PEER_PUB_NUM];

extern __be16 peer_knock_local_port;

#endif /* _NATCAP_PEER_H_ */
