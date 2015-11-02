/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#ifndef _NATCAP_H_
#define _NATCAP_H_

#define NATCAP_VERSION "2.0.0"

#include <linux/ctype.h>
#include <asm/types.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#pragma pack(push)
#pragma pack(1)
struct natcap_data {
	__be16 server_port;
	__be32 server_ip;
};

struct natcap_tcp_option {
	u8 opcode;
#define TCPOPT_NATCAP 0x99

	u8 opsize;
	struct natcap_data data;
};
#pragma pack(pop)

#define XT_MARK_NATCAP 0x99
#define NATCAP_WHITELIST_TID 0x99

struct natcap_session {
	__be32 server_ip;
};

/* @linux/netfilter/nf_conntrack_common.h */
/* ct->status use bits:[18-16] for ecap status */
#define IPS_NATCAP_BIT 16
#define IPS_NATCAP (1 << IPS_NATCAP_BIT)
#define IPS_NATCAP_SERVER_BIT 17
#define IPS_NATCAP_SERVER (1 << IPS_NATCAP_SERVER_BIT)
#define IPS_NATCAP_SESSION_BIT 19
#define IPS_NATCAP_SESSION (1 << IPS_NATCAP_SESSION_BIT)
#define IPS_NATCAP_BYPASS_BIT 20
#define IPS_NATCAP_BYPASS (1 << IPS_NATCAP_BYPASS_BIT)

#endif /* _NATCAP_H_ */
