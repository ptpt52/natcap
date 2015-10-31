/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#ifndef _NATCAP_H_
#define _NATCAP_H_

#include <linux/ctype.h>
#include <asm/types.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#pragma pack(push)
#pragma pack(1)
struct natcap_data {
	unsigned int type;
	__be32 server_ip;
	__u16 gso_size;
	u16 payload_crc;
};
#pragma pack(pop)

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
