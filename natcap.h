/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#ifndef _NATCAP_H_
#define _NATCAP_H_

#define MODULE_NAME "natcap"
#define NATCAP_VERSION "4.0.0"

#include <linux/ctype.h>
#include <asm/types.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#pragma pack(push)
#pragma pack(1)

#define NATCAP_CLIENT_MODE (1<<0)
#define NATCAP_NEED_ENC    (1<<1)

struct natcap_tcp_tcpopt {
	u8 opcode;
#define TCPOPT_NATCAP 0x99
	u8 opsize;
	__be16 port;
	__be32 ip;
	u32 u_hash;
	u8 mac_addr[ETH_ALEN];
	u16 encryption;
};

struct natcap_udp_tcpopt {
	u8 opcode;
#define TCPOPT_NATCAP_UDP 0x9A
	u8 opsize;
	__be16 port;
	__be32 ip;
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

#define IPS_NATCAP_UDP_BIT 23
#define IPS_NATCAP_UDP (1 << IPS_NATCAP_UDP_BIT)

#endif /* _NATCAP_H_ */
