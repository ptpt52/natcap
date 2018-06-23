/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
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
#ifndef _NATCAP_H_
#define _NATCAP_H_

#define MODULE_NAME "natcap"
#define NATCAP_VERSION "5.0.0"

#ifdef __KERNEL__
#include <linux/ctype.h>
#include <asm/types.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#pragma pack(push)
#pragma pack(1)

#define NATCAP_CLIENT_MODE (1<<0)
#define NATCAP_NEED_ENC    (1<<1)

struct natcap_TCPOPT_header {
	u8 opcode;
#define TCPOPT_NATCAP 0x99
	u8 opsize;
	u8 type;
	u8 encryption;
};

struct natcap_TCPOPT_data {
	u32 u_hash;
	u8 mac_addr[ETH_ALEN];
	__be16 port;
	__be32 ip;
};

struct natcap_TCPOPT_dst {
	__be32 ip;
	__be16 port;
};

struct natcap_TCPOPT_user {
	u32 u_hash;
	u8 mac_addr[ETH_ALEN];
};

#define NATCAP_TCPOPT_SYN (1<<7)
#define NATCAP_TCPOPT_TARGET (1<<6)
#define NATCAP_TCPOPT_SPROXY (1<<5)
#define NATCAP_TCPOPT_CONFUSION (1<<4)

#define NATCAP_TCPOPT_TYPE_MASK (0x0F)
#define NTCAP_TCPOPT_TYPE(t) ((t) & NATCAP_TCPOPT_TYPE_MASK)

struct natcap_TCPOPT {
#define NATCAP_TCPOPT_TYPE_NONE 0
	struct natcap_TCPOPT_header header;
	union {
		struct {
#define NATCAP_TCPOPT_TYPE_ALL 1
			struct natcap_TCPOPT_data data;
		} all;
		struct {
#define NATCAP_TCPOPT_TYPE_DST 2
			struct natcap_TCPOPT_dst data;
		} dst;
		struct {
#define NATCAP_TCPOPT_TYPE_USER 3
			struct natcap_TCPOPT_user data;
		} user;
	};
#define NATCAP_TCPOPT_TYPE_CONFUSION 4
	char pad[4];
#define NATCAP_TCPOPT_TYPE_ADD 5
};

struct cone_nat_session {
	__be32 ip;
	__be16 port;
};

#pragma pack(pop)

struct tuple {
	u16 encryption;
	__be16 port;
	__be32 ip;
};

struct natcap_session {
	unsigned int magic;
	__be16 new_source;
	struct tuple tup;
	int tcp_seq_offset;
	int tcp_ack_offset;
	unsigned int foreign_seq;
	unsigned int current_seq;
};

#define NATCAP_MAGIC 0x43415099

/*XXX refer to drivers/nos/src/nos.h */
#define IPS_NOS_TRACK_INIT_BIT 15
#define IPS_NOS_TRACK_INIT (1 << IPS_NOS_TRACK_INIT_BIT)
#define IPS_NATFLOW_STOP_BIT 18
#define IPS_NATFLOW_STOP (1 << IPS_NATFLOW_STOP_BIT)

#define IPS_NATFLOW_FF_BIT 14
#define IPS_NATFLOW_FF (1 << IPS_NATFLOW_FF_BIT)

// test t1 < t2 return 1
static inline int tuple_lt(const struct tuple *t1, const struct tuple *t2)
{
	if (ntohl(t1->ip) < ntohl(t2->ip))
		return 1;
	else if (ntohl(t1->ip) > ntohl(t2->ip))
		return 0;
	else if (ntohs(t1->port) < ntohl(t2->port))
		return 1;
	else if (ntohs(t1->port) > ntohl(t2->port))
		return 0;
	else if (t1->encryption < t2->encryption)
		return 1;
	else
		return 0;
}
// test t1 == t2
static inline int tuple_eq(const struct tuple *t1, const struct tuple *t2)
{
	return (t1->ip == t2->ip &&
			t1->port == t2->port &&
			t1->encryption == t2->encryption);
}

static inline void tuple_copy(struct tuple *to, const struct tuple *from)
{
	to->encryption = from->encryption;
	to->port = from->port;
	to->ip = from->ip;
}

#define XT_MARK_NATCAP 0x99
#define XT_MARK_NATCAP_MASK 0xFF
#define xt_mark_natcap_set(mark, at) *(unsigned int *)(at) = ((*(unsigned int *)(at)) & (~XT_MARK_NATCAP_MASK)) | ((mark) & XT_MARK_NATCAP_MASK)

/* @linux/netfilter/nf_conntrack_common.h */
/* ct->status use bits:[31-24] for ecap status */
#define IPS_NATCAP_BIT 24
#define IPS_NATCAP (1 << IPS_NATCAP_BIT)
#define IPS_NATCAP_BYPASS_BIT 25
#define IPS_NATCAP_BYPASS (1 << IPS_NATCAP_BYPASS_BIT)
#define IPS_NATCAP_ENC_BIT 26
#define IPS_NATCAP_ENC (1 << IPS_NATCAP_ENC_BIT)
#define IPS_NATCAP_AUTH_BIT 27
#define IPS_NATCAP_AUTH (1 << IPS_NATCAP_AUTH_BIT)
#define IPS_NATCAP_DROP_BIT 28 /* only use in server */
#define IPS_NATCAP_DROP (1 << IPS_NATCAP_DROP_BIT)
#define IPS_NATCAP_MASTER_BIT 28 /* only use in client: overlay with IPS_NATCAP_DROP_BIT is okay */
#define IPS_NATCAP_MASTER (1 << IPS_NATCAP_MASTER_BIT)
#define IPS_NATCAP_SYN1_BIT 29
#define IPS_NATCAP_SYN1 (1 << IPS_NATCAP_SYN1_BIT)
#define IPS_NATCAP_SYN2_BIT 30
#define IPS_NATCAP_SYN2 (1 << IPS_NATCAP_SYN2_BIT)
#define IPS_NATCAP_UDPENC_BIT 31
#define IPS_NATCAP_UDPENC (1 << IPS_NATCAP_UDPENC_BIT)
#define IPS_NATCAP_TCPENC_BIT IPS_NATCAP_UDPENC_BIT
#define IPS_NATCAP_TCPENC IPS_NATCAP_UDPENC

#define IPS_NATCAP_ACK_BIT 23
#define IPS_NATCAP_ACK (1 << IPS_NATCAP_ACK_BIT)
#define IPS_NATCAP_SYN_BIT 22 /* only use in client */
#define IPS_NATCAP_SYN (1 << IPS_NATCAP_SYN_BIT)
#define IPS_NATCAP_DST_BIT 22 /* only use in server */
#define IPS_NATCAP_DST (1 << IPS_NATCAP_DST_BIT)
#define IPS_NATCAP_CFM_BIT 21
#define IPS_NATCAP_CFM (1 << IPS_NATCAP_CFM_BIT)
#define IPS_NATCAP_SERVER_BIT 20
#define IPS_NATCAP_SERVER (1 << IPS_NATCAP_SERVER_BIT)

#define IPS_NATCAP_CONFUSION_BIT 19
#define IPS_NATCAP_CONFUSION (1 << IPS_NATCAP_CONFUSION_BIT)

#define IPS_NATCAP_NEED_REPLY_FINACK_BIT 18
#define IPS_NATCAP_NEED_REPLY_FINACK (1 << IPS_NATCAP_NEED_REPLY_FINACK_BIT)

#define NATCAP_UDP_GET_TYPE(x) (0xFF & ntohs(x))
#define NATCAP_UDP_GET_ENC(x) ((0xFF00 & ntohs(x)) >> 8)

enum {
	E_NATCAP_OK = 0,
	E_NATCAP_AUTH_FAIL,
	E_NATCAP_INVAL,
};
#endif /* __KERNEL__ */

#define SO_NATCAP_DST 153

#endif /* _NATCAP_H_ */
