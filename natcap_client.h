/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:31 +0800
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
#ifndef _NATCAP_CLIENT_H_
#define _NATCAP_CLIENT_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include "natcap.h"

extern unsigned int cnipwhitelist_mode;

enum {
	NATCAP_ACL_NONE,
	NATCAP_ACL_ALLOW,
	NATCAP_ACL_DENY,
	NATCAP_ACL_MAX
};

extern unsigned int macfilter;
extern const char *macfilter_acl_str[NATCAP_ACL_MAX];

extern unsigned int ipfilter;
extern const char *ipfilter_acl_str[NATCAP_ACL_MAX];

extern unsigned int server_persist_lock;
extern unsigned int server_persist_timeout;
extern unsigned int encode_http_only;
extern unsigned int http_confusion;
extern unsigned int sproxy;

extern unsigned int dns_server;
extern unsigned short dns_port;

extern u32 default_u_hash;
extern unsigned char default_mac_addr[ETH_ALEN];
void default_mac_addr_init(void);

void natcap_server_info_change(int change);
void natcap_server_info_cleanup(void);
int natcap_server_info_add(const struct tuple *dst);
int natcap_server_info_delete(const struct tuple *dst);
void *natcap_server_info_get(loff_t idx);
void natcap_server_in_touch(__be32 ip);
void natcap_server_info_select(__be32 ip, __be16 port, struct tuple *dst);

const struct tuple *natcap_server_info_current(void);

int natcap_client_init(void);
void natcap_client_exit(void);

struct natcap_token_ctrl {
	int tokens;
	int tokens_per_jiffy;
	unsigned long jiffies;
	spinlock_t lock;
};

extern int tx_pkts_threshold;
extern int rx_pkts_threshold;

extern void natcap_tx_speed_set(int speed);
extern void natcap_rx_speed_set(int speed);

extern int natcap_tx_speed_get(void);
extern int natcap_rx_speed_get(void);

#endif /* _NATCAP_CLIENT_H_ */
