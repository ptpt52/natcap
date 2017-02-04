/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#ifndef _NATCAP_H_
#define _NATCAP_H_

#define MODULE_NAME "natcap"
#define NATCAP_VERSION "5.0.0"

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

#define NATCAP_TCPOPT_SYN_BIT (1<<7)
#define NATCAP_TCPOPT_TARGET_BIT (1<<6)

#define NATCAP_TCPOPT_TYPE_MASK (0x0F)
#define NTCAP_TCPOPT_TYPE(t) ((t) & NATCAP_TCPOPT_TYPE_MASK)

struct natcap_TCPOPT {
#define NATCAP_TCPOPT_NONE 0
	struct natcap_TCPOPT_header header;
	union {
		struct {
#define NATCAP_TCPOPT_ALL 1
			struct natcap_TCPOPT_data data;
		} all;
		struct {
#define NATCAP_TCPOPT_DST 2
			struct natcap_TCPOPT_dst data;
		} dst;
		struct {
#define NATCAP_TCPOPT_USER 3
			struct natcap_TCPOPT_user data;
		} user;
	};
};

#pragma pack(pop)

struct tuple {
	u16 encryption;
	__be16 port;
	__be32 ip;
};

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

/* @linux/netfilter/nf_conntrack_common.h */
/* ct->status use bits:[31-24] for ecap status */
#define IPS_NATCAP_BIT 24
#define IPS_NATCAP (1 << IPS_NATCAP_BIT)
#define IPS_NATCAP_BYPASS_BIT 25
#define IPS_NATCAP_BYPASS (1 << IPS_NATCAP_BYPASS_BIT)
#define IPS_NATCAP_ENC_BIT 26
#define IPS_NATCAP_ENC (1 << IPS_NATCAP_ENC_BIT)
#define IPS_NATCAP_SYN1_BIT 27
#define IPS_NATCAP_SYN1 (1 << IPS_NATCAP_SYN1_BIT)
#define IPS_NATCAP_SYN2_BIT 28
#define IPS_NATCAP_SYN2 (1 << IPS_NATCAP_SYN2_BIT)
#define IPS_NATCAP_SYN3_BIT 29
#define IPS_NATCAP_SYN3 (1 << IPS_NATCAP_SYN3_BIT)
#define IPS_NATCAP_AUTH_BIT 30
#define IPS_NATCAP_AUTH (1 << IPS_NATCAP_AUTH_BIT)

#define IPS_NATCAP_DROP_BIT 31
#define IPS_NATCAP_DROP (1 << IPS_NATCAP_DROP_BIT)
#define IPS_NATCAP_IPSET_BIT 31
#define IPS_NATCAP_IPSET (1 << IPS_NATCAP_IPSET_BIT)

#define IPS_NATCAP_UDP_BIT 23
#define IPS_NATCAP_UDP (1 << IPS_NATCAP_UDP_BIT)
#define IPS_NATCAP_UDPENC_BIT 22
#define IPS_NATCAP_UDPENC (1 << IPS_NATCAP_UDPENC_BIT)
#define IPS_NATCAP_ACK_BIT 21
#define IPS_NATCAP_ACK (1 << IPS_NATCAP_ACK_BIT)
#define IPS_NATCAP_SYN_BIT 20
#define IPS_NATCAP_SYN (1 << IPS_NATCAP_SYN_BIT)
#define IPS_NATCAP_CFM_BIT 19
#define IPS_NATCAP_CFM (1 << IPS_NATCAP_CFM_BIT)

enum {
	E_NATCAP_OK = 0,
	E_NATCAP_AUTH_FAIL,
	E_NATCAP_INVAL,
};

#endif /* _NATCAP_H_ */
