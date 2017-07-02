/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:31 +0800
 */
#ifndef _NATCAP_CLIENT_H_
#define _NATCAP_CLIENT_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include "natcap.h"

extern unsigned int macfilter;
enum {
	NATCAP_ACL_NONE,
	NATCAP_ACL_ALLOW,
	NATCAP_ACL_DENY,
	NATCAP_ACL_MAX
};

extern const char *macfilter_acl_str[NATCAP_ACL_MAX];

extern unsigned int server_persist_timeout;
extern unsigned int http_confusion;
extern unsigned int shadowsocks;
extern unsigned int sproxy;
extern unsigned int enable_hosts;

extern unsigned int dns_server;
extern unsigned short dns_port;

extern u32 default_u_hash;
extern unsigned char default_mac_addr[ETH_ALEN];

void natcap_server_info_cleanup(void);
int natcap_server_info_add(const struct tuple *dst);
int natcap_server_info_delete(const struct tuple *dst);
void *natcap_server_info_get(loff_t idx);
void natcap_server_info_select(__be32 ip, __be16 port, struct tuple *dst);

int natcap_client_init(void);
void natcap_client_exit(void);

#endif /* _NATCAP_CLIENT_H_ */
