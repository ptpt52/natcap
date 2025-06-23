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
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "net/netfilter/nf_conntrack_seqadj.h"
#include "natcap_common.h"
#include "natcap_peer.h"
#include "natcap_client.h"
#include "natcap_knock.h"

static unsigned int peer_open_portmap = 0;
static unsigned int peer_mode = 0;
static unsigned int peer_max_pmtu = 1420;
static unsigned int peer_sni_ban = 0;

static struct in6_addr peer_local_ip6_addr;

struct peer_cache_node {
	struct nf_conn *user;
	struct sk_buff *skb;
	unsigned long jiffies;
};

DEFINE_SPINLOCK(peer_cache_lock);
#if defined(CONFIG_64BIT) || defined(CONFIG_X86) || defined(CONFIG_X86_64) || defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#define MAX_PEER_CACHE 1024
#else
#define MAX_PEER_CACHE 64
#endif
static unsigned short peer_cache_next_to_clean = 0;
static unsigned short peer_cache_next_to_use = 0;
static struct peer_cache_node peer_cache[MAX_PEER_CACHE];
#define PEER_CACHE_TIMEOUT 4

__be32 peer_pub_ip[PEER_PUB_NUM];
unsigned int peer_pub_active[PEER_PUB_NUM];
unsigned int peer_pub_idx = 0;

static unsigned int rt_out_magic = 0;

static struct natcap_fastpath_route peer_fastpath_route[MAX_PEER_NUM];
struct natcap_fastpath_route *natcap_pfr = peer_fastpath_route;

int is_fastpath_route_ready(struct natcap_fastpath_route *pfr)
{
	return (!pfr->is_dead &&
	        pfr->rt_out_magic == rt_out_magic &&
	        pfr->rt_out.outdev != NULL);
}

static inline void peer_cache_init(void)
{
	spin_lock_bh(&peer_cache_lock);
	memset(peer_cache, 0, sizeof(struct peer_cache_node) * MAX_PEER_CACHE);
	spin_unlock_bh(&peer_cache_lock);
}

static inline int peer_cache_attach(struct nf_conn *ct, struct sk_buff *skb)
{
	struct natcap_session *ns = natcap_session_get(ct);
	//XXX we use p.cache_index - 1 as index
	if (ns == NULL || ns->p.cache_index != 0) {
		return -EINVAL;
	}
	spin_lock_bh(&peer_cache_lock);
	if ((peer_cache_next_to_use + 1) % MAX_PEER_CACHE == peer_cache_next_to_clean) {
		spin_unlock_bh(&peer_cache_lock);
		return -ENOSPC;
	}
	nf_conntrack_get(&ct->ct_general);
	peer_cache[peer_cache_next_to_use].jiffies = jiffies;
	peer_cache[peer_cache_next_to_use].user = ct;
	peer_cache[peer_cache_next_to_use].skb = skb;
	ns->p.cache_index = peer_cache_next_to_use + 1;
	peer_cache_next_to_use = (peer_cache_next_to_use + 1) % MAX_PEER_CACHE;
	spin_unlock_bh(&peer_cache_lock);
	return 0;
}

static inline struct sk_buff *peer_cache_detach(struct nf_conn *ct)
{
	unsigned short i;
	struct sk_buff *skb = NULL;
	struct natcap_session *ns = natcap_session_get(ct);

	if (ns == NULL)
		return NULL;
	i = ns->p.cache_index;
	if (i == 0 || i > MAX_PEER_CACHE)
		return NULL;
	i = i - 1;
	spin_lock_bh(&peer_cache_lock);
	if (peer_cache[i].user == ct) {
		ns->p.cache_index = 0;
		nf_ct_put(peer_cache[i].user);
		peer_cache[i].user = NULL;
		if (peer_cache[i].skb != NULL) {
			skb = peer_cache[i].skb;
			peer_cache[i].skb = NULL;
		}
	}
	spin_unlock_bh(&peer_cache_lock);
	return skb;
}

static inline void peer_cache_cleaner(void)
{
	unsigned short i;
	struct natcap_session *ns;
	if (peer_cache[peer_cache_next_to_clean].user != NULL &&
	        !time_after(jiffies, peer_cache[peer_cache_next_to_clean].jiffies + PEER_CACHE_TIMEOUT * HZ))
		return;
	spin_lock_bh(&peer_cache_lock);
	i = peer_cache_next_to_clean;
	while (i != peer_cache_next_to_use) {
		if (peer_cache[i].user == NULL) {
			i = (i + 1) % MAX_PEER_CACHE;
			continue;
		}
		if (!time_after(jiffies, peer_cache[i].jiffies + PEER_CACHE_TIMEOUT * HZ))
			break;
		ns = natcap_session_get(peer_cache[i].user);
		ns->p.cache_index = 0;
		nf_ct_put(peer_cache[i].user);
		peer_cache[i].user = NULL;
		if (peer_cache[i].skb != NULL) {
			consume_skb(peer_cache[i].skb);
			peer_cache[i].skb = NULL;
		}
		i = (i + 1) % MAX_PEER_CACHE;
	}
	peer_cache_next_to_clean = i;
	spin_unlock_bh(&peer_cache_lock);
}

static inline void peer_cache_cleanup(void)
{
	unsigned short i;
	struct natcap_session *ns;
	spin_lock_bh(&peer_cache_lock);
	for (i = 0; i < MAX_PEER_CACHE; i++) {
		if (peer_cache[i].user == NULL)
			continue;
		ns = natcap_session_get(peer_cache[i].user);
		//BUG_ON(ns == NULL);
		ns->p.cache_index = 0;
		nf_ct_put(peer_cache[i].user);
		peer_cache[i].user = NULL;
		if (peer_cache[i].skb != NULL) {
			consume_skb(peer_cache[i].skb);
			peer_cache[i].skb = NULL;
		}
	}
	spin_unlock_bh(&peer_cache_lock);
}

struct peer_sni_cache_node {
	unsigned long active_jiffies;
	__be32 src_ip;
	__be16 src_port;
	unsigned short add_data_len;
	struct sk_buff *skb;
};

#define MAX_PEER_SNI_CACHE_NODE 64
static struct peer_sni_cache_node peer_sni_cache[NR_CPUS][MAX_PEER_SNI_CACHE_NODE];

static inline void peer_sni_cache_init(void)
{
	int i, j;
	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < MAX_PEER_SNI_CACHE_NODE; j++) {
			peer_sni_cache[i][j].skb = NULL;
		}
	}
}

static inline void peer_sni_cache_cleanup(void)
{
	int i, j;
	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < MAX_PEER_SNI_CACHE_NODE; j++) {
			if (peer_sni_cache[i][j].skb != NULL) {
				consume_skb(peer_sni_cache[i][j].skb);
				peer_sni_cache[i][j].skb = NULL;
			}
		}
	}
}

static inline int peer_sni_cache_attach(__be32 src_ip, __be16 src_port, struct sk_buff *skb, unsigned short add_data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_PEER_SNI_CACHE_NODE;
	for (j = 0; j < MAX_PEER_SNI_CACHE_NODE; j++) {
		if (peer_sni_cache[i][j].src_ip == src_ip) {
			if (peer_sni_cache[i][j].src_port == src_port) {
				return -EEXIST;
			}
		} else if (next_to_use == MAX_PEER_SNI_CACHE_NODE && peer_sni_cache[i][j].skb == NULL) {
			next_to_use = j;
		}
	}
	if (next_to_use == MAX_PEER_SNI_CACHE_NODE) {
		return -ENOMEM;
	}

	peer_sni_cache[i][next_to_use].src_ip = src_ip;
	peer_sni_cache[i][next_to_use].src_port = src_port;
	peer_sni_cache[i][next_to_use].add_data_len = add_data_len;
	peer_sni_cache[i][next_to_use].skb = skb;
	peer_sni_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

static inline struct sk_buff *peer_sni_cache_detach(__be32 src_ip, __be16 src_port, unsigned short *add_data_len)
{
	int i = smp_processor_id();
	int j = 0;
	struct sk_buff *skb = NULL;
	for (j = 0; j < MAX_PEER_SNI_CACHE_NODE; j++) {
		if (peer_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, peer_sni_cache[i][j].active_jiffies + PEER_CACHE_TIMEOUT * HZ)) {
				consume_skb(peer_sni_cache[i][j].skb);
				peer_sni_cache[i][j].skb = NULL;
			} else if (peer_sni_cache[i][j].src_ip == src_ip) {
				if (peer_sni_cache[i][j].src_port == src_port) {
					skb = peer_sni_cache[i][j].skb;
					*add_data_len = peer_sni_cache[i][j].add_data_len;
					peer_sni_cache[i][j].skb = NULL;
					break;
				}
			}
		}
	}
	for (; j < MAX_PEER_SNI_CACHE_NODE; j++) {
		if (peer_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, peer_sni_cache[i][j].active_jiffies + PEER_CACHE_TIMEOUT * HZ)) {
				consume_skb(peer_sni_cache[i][j].skb);
				peer_sni_cache[i][j].skb = NULL;
			}
		}
	}

	return skb;
}

int peer_sni_cache_used_nodes(void)
{
	int used = 0;
	int i, j = 0;
	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < MAX_PEER_SNI_CACHE_NODE; j++) {
			if (peer_sni_cache[i][j].skb != NULL) {
				used++;
			}
		}
	}
	return used;
}

static int peer_dns_server = 0;

static int peer_stop = 1;

static int peer_subtype = 0;

static unsigned int peer_sni_auth = 0;

static __be32 peer_sni_ip = __constant_htonl(0);
__be16 peer_sni_port = __constant_htons(991);

static void *peer_xsyn_last_dev = NULL;
__be32 peer_xsyn_enumerate_addr(void)
{
	__be32 ip;
	struct net_device *dev;
	struct net_device *last_dev;
	struct in_device *indev;
	struct in_ifaddr *ifa;

	last_dev = peer_xsyn_last_dev;
	rcu_read_lock();

	for(dev = first_net_device(&init_net); dev != NULL && dev != last_dev; dev = next_net_device(dev));
	if (dev == peer_xsyn_last_dev && peer_xsyn_last_dev != NULL) {
		dev = next_net_device(dev);
	}
	if (dev == NULL) {
		dev = first_net_device(&init_net);
	}

	last_dev = dev;

	for (; dev != NULL; dev = next_net_device(dev)) {
		indev = __in_dev_get_rcu(dev);
		if (indev && indev->ifa_list) {
			ifa = indev->ifa_list;
			ip = ifa->ifa_local;
			if (!ipv4_is_loopback(ip)) {
				peer_xsyn_last_dev = dev;
				rcu_read_unlock();
				return ip;
			}
		}
	}

	for (dev = first_net_device(&init_net); dev != NULL && dev != last_dev; dev = next_net_device(dev)) {
		indev = __in_dev_get_rcu(dev);
		if (indev && indev->ifa_list) {
			ifa = indev->ifa_list;
			ip = ifa->ifa_local;
			if (!ipv4_is_loopback(ip)) {
				peer_xsyn_last_dev = dev;
				rcu_read_unlock();
				return ip;
			}
		}
	}

	peer_xsyn_last_dev = last_dev;
	rcu_read_unlock();
	return 0;
}

static __be32 peer_knock_ip = __constant_htonl(0);
static __be16 peer_knock_port = __constant_htons(22);
static unsigned char peer_knock_mac[ETH_ALEN] = { };
__be16 peer_knock_local_port = __constant_htons(997);

static inline __be32 gen_seq_number(void)
{
	__be32 s;
	do {
		s = get_random_u32();
	} while (s == 0);
	return s;
}

static __be32 peer_local_ip = __constant_htonl(0);
static __be16 peer_local_port = __constant_htons(443);

#define ICMP_PAYLOAD_LIMIT 1024

#define MAX_PEER_SERVER 8
struct peer_server_node peer_server[MAX_PEER_SERVER];

static inline __be16 peer_fakeuser_sport(struct nf_conn *user)
{
	if (!user)
		return 0;
	return user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
}
static inline __be16 peer_fakeuser_dport(struct nf_conn *user)
{
	if (!user)
		return 0;
	return user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
}

#define MAX_PEER_PORT_MAP 65536
static struct nf_conn **peer_port_map = NULL;
DEFINE_SPINLOCK(peer_port_map_lock);
static struct timer_list peer_timer;

#define NATCAP_PEER_EXPECT_TIMEOUT 5
#define NATCAP_PEER_USER_TIMEOUT_DEFAULT 180

unsigned int peer_port_map_timeout = NATCAP_PEER_USER_TIMEOUT_DEFAULT;

#define NATCAP_PEER_CONN_TIMEOUT_DEFAULT 180
unsigned int peer_conn_timeout = NATCAP_PEER_CONN_TIMEOUT_DEFAULT;

#define PEER_PORT_MAP_FLUSH_STEP 256

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
static void peer_timer_flush(unsigned long ignore)
#else
static void peer_timer_flush(struct timer_list *ignore)
#endif
{
	static unsigned short flush_idx = 0;
	unsigned int i, j = 0;
	struct nf_conn *user;
	for (i = 0; i < PEER_PORT_MAP_FLUSH_STEP; i++) {
		if (peer_port_map[flush_idx] == NULL) {
			flush_idx++;
			continue;
		}
		spin_lock_bh(&peer_port_map_lock);
		user = peer_port_map[flush_idx];
		if (user != NULL) {
			unsigned char client_mac[ETH_ALEN];
			struct user_expect *ue = peer_user_expect(user);
			if (after(jiffies, ue->last_active + peer_port_map_timeout * HZ)) {
				set_byte4(client_mac, get_byte4((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip));
				set_byte2(client_mac + 4, get_byte2((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all));
				NATCAP_INFO(DEBUG_FMT_PREFIX "C[%02x:%02x:%02x:%02x:%02x:%02x,%pI4,%pI4] P=%u [AS %ds] timeout drop\n", DEBUG_ARG_PREFIX,
				            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
				            &ue->local_ip, &ue->ip, ntohs(ue->map_port), ue->last_active != 0 ? (uintmindiff(ue->last_active, jiffies) + HZ / 2) / HZ : (-1)
				           );
				peer_port_map[flush_idx] = NULL;
				nf_ct_put(user);
				j++;
			}
		}
		spin_unlock_bh(&peer_port_map_lock);
		flush_idx++;
	}

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		struct peer_server_node *ps = &peer_server[i];
		spin_lock_bh(&ps->lock);
		for (j = 0; j < MAX_PEER_CONN; j++) {
			user = ps->port_map[j];
			if (user != NULL) {
				struct fakeuser_expect *fue = peer_fakeuser_expect(user);
				if (after(jiffies, fue->last_active + peer_conn_timeout * HZ)) {
					NATCAP_INFO(DEBUG_FMT_PREFIX "conn[%u:%u] @N[[%pI4:%u] [AS %ds] timeout drop\n", DEBUG_ARG_PREFIX,
					            ntohs(peer_fakeuser_sport(user)), ntohs(peer_fakeuser_dport(user)),
					            &ps->ip, ntohs(ps->map_port), fue->last_active != 0 ?(uintmindiff(fue->last_active, jiffies) + HZ / 2) / HZ : (-1)
					           );
					peer_server[i].port_map[j] = NULL;
					nf_ct_put(user);
				}
			}
		}
		spin_unlock_bh(&ps->lock);
	}

	peer_cache_cleaner();

	if (peer_stop) {
		return;
	}
	mod_timer(&peer_timer, jiffies + HZ / 2);
}

static inline void peer_port_map_kill(unsigned short idx)
{
	struct nf_conn *user;
	spin_lock_bh(&peer_port_map_lock);
	user = peer_port_map[idx];
	if (user != NULL) {
		unsigned char client_mac[ETH_ALEN];
		struct user_expect *ue = peer_user_expect(user);
		set_byte4(client_mac, get_byte4((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip));
		set_byte2(client_mac + 4, get_byte2((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all));
		NATCAP_INFO(DEBUG_FMT_PREFIX "C[%02x:%02x:%02x:%02x:%02x:%02x,%pI4,%pI4] P=%u [AS %ds] killed\n", DEBUG_ARG_PREFIX,
		            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
		            &ue->local_ip, &ue->ip, ntohs(ue->map_port), ue->last_active != 0 ? (uintmindiff(ue->last_active, jiffies) + HZ / 2) / HZ : (-1)
		           );
		peer_port_map[idx] = NULL;
		nf_ct_put(user);
	}
	spin_unlock_bh(&peer_port_map_lock);
}

static int peer_timer_init(void)
{
	struct timer_list *timer = &peer_timer;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
	init_timer(timer);
	timer->data = 0;
	timer->function = peer_timer_flush;
#else
	timer_setup(timer, peer_timer_flush, 0);
#endif
	return 0;
}

static void peer_timer_start(void)
{
	struct timer_list *timer = &peer_timer;
	mod_timer(timer, jiffies + 8 * HZ);
}

static void peer_timer_exit(void)
{
	del_timer(&peer_timer);
}

static inline struct nf_conn *get_peer_user(unsigned int port)
{
	struct nf_conn *user;
	if (port >= MAX_PEER_PORT_MAP || peer_port_map[port] == NULL)
		return NULL;

	spin_lock_bh(&peer_port_map_lock);
	user = peer_port_map[port];
	if (user) {
		nf_conntrack_get(&user->ct_general);
	}
	spin_unlock_bh(&peer_port_map_lock);
	return user;
}

static inline void put_peer_user(struct nf_conn *user)
{
	nf_ct_put(user);
}

static __be16 alloc_peer_port(struct nf_conn *user, const unsigned char *mac)
{
	static unsigned int seed_rnd;
	unsigned short port;
	unsigned int hash;
	unsigned int data = get_byte4(mac);

	get_random_once(&seed_rnd, sizeof(seed_rnd));

	hash = jhash2(&data, 1, get_byte2(mac + 4)^seed_rnd);

	port = 1024 + hash % (MAX_PEER_PORT_MAP - 1024);

	for (; port < MAX_PEER_PORT_MAP - 1; port++) {
		if (peer_port_map[port] == NULL) {
			spin_lock_bh(&peer_port_map_lock);
			//re-check-in-lock
			if (peer_port_map[port] == NULL) {
				peer_port_map[port] = user;
				nf_conntrack_get(&user->ct_general);
				spin_unlock_bh(&peer_port_map_lock);
				return htons(port);
			}
			spin_unlock_bh(&peer_port_map_lock);
		}
	}

	for (port = 1024; port < 1024 + hash % (MAX_PEER_PORT_MAP - 1024); port++) {
		if (peer_port_map[port] == NULL) {
			spin_lock_bh(&peer_port_map_lock);
			//re-check-in-lock
			if (peer_port_map[port] == NULL) {
				peer_port_map[port] = user;
				nf_conntrack_get(&user->ct_general);
				spin_unlock_bh(&peer_port_map_lock);
				return htons(port);
			}
			spin_unlock_bh(&peer_port_map_lock);
		}
	}

	return 0;
}

static struct peer_server_node *peer_server_node_in(__be32 ip, unsigned short conn, int new)
{
	unsigned int i;
	unsigned long maxdiff = 0;
	unsigned long last_jiffies = jiffies;
	struct peer_server_node *ps = NULL;

	if (conn <= 0)
		conn = 1;
	if (ip == 0)
		return NULL;

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		if (peer_server[i].ip == ip) {
			spin_lock_bh(&peer_server[i].lock);
			//re-check-in-lock
			if (peer_server[i].ip == ip) {
				if (new == 1 && peer_server[i].conn != conn) {
					peer_server[i].conn = conn;
				}
				spin_unlock_bh(&peer_server[i].lock);
				return &peer_server[i];
			}
			spin_unlock_bh(&peer_server[i].lock);
			break;
		}
	}
	if (new == 0)
		return NULL;

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		if (peer_server[i].ip == 0) {
			spin_lock_bh(&peer_server[i].lock);
			if (peer_server[i].ip == 0) {
				ps = &peer_server[i];
				goto init_out;
			}
			spin_unlock_bh(&peer_server[i].lock);
		}
		if (maxdiff < uintmindiff(peer_server[i].last_active, last_jiffies)) {
			maxdiff = uintmindiff(peer_server[i].last_active, last_jiffies);
			ps = &peer_server[i];
		}
	}

	if (ps) {
		spin_lock_bh(&ps->lock);
init_out:
		if (ps->ip != 0) {
			NATCAP_WARN(DEBUG_FMT_PREFIX "drop the old server %pI4 map_port=%u replace new=%pI4\n",
			            DEBUG_ARG_PREFIX, &ps->ip, ntohs(ps->map_port), &ip);
		}
		for (i = 0; i < MAX_PEER_CONN; i++) {
			if (ps->port_map[i] != NULL) {
				nf_ct_put(ps->port_map[i]);
				ps->port_map[i] = NULL;
			}
		}
		ps->ip = ip;
		ps->map_port = 0;
		ps->conn = conn;
		ps->last_active = 0;
		ps->last_inuse = 0;

		spin_unlock_bh(&ps->lock);
	}

	return ps;
}

static void natcap_user_timeout_touch(struct nf_conn *ct, unsigned long timeout)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	unsigned long newtimeout = jiffies + timeout * HZ;
	if (newtimeout - ct->timeout.expires > HZ) {
		mod_timer_pending(&ct->timeout, newtimeout);
	}
#else
	ct->timeout = jiffies + timeout * HZ;
#endif
}

static struct nf_conn *peer_fakeuser_expect_new(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, int pmi)
{
	struct fakeuser_expect *fue;
	struct nf_conn *user;
	struct nf_ct_ext *new = NULL;
	enum ip_conntrack_info ctinfo;
	unsigned int newoff = 0;
	int ret;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;

	uskb = uskb_of_this_cpu();
	if (uskb == NULL) {
		return NULL;
	}
	skb_reset_transport_header(uskb);
	skb_reset_network_header(uskb);
	skb_reset_mac_len(uskb);

	uskb->protocol = __constant_htons(ETH_P_IP);
	skb_set_tail_pointer(uskb, PEER_USKB_SIZE);
	uskb->len = PEER_USKB_SIZE;
	uskb->pkt_type = PACKET_HOST;
	uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

	iph = ip_hdr(uskb);
	iph->version = 4;
	iph->ihl = 5;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->tos = 0;
	iph->tot_len = htons(PEER_USKB_SIZE);
	iph->ttl=255;
	iph->protocol = IPPROTO_UDP;
	iph->id = __constant_htons(0xdead);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = sport;
	udph->dest = dport;
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
	if (ret != NF_ACCEPT) {
		return NULL;
	}
	user = nf_ct_get(uskb, &ctinfo);

	if (!user) {
		NATCAP_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u] failed\n", &saddr, ntohs(sport), &daddr, ntohs(dport));
		return NULL;
	}

	if (!user->ext) {
		NATCAP_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u] failed, user->ext is NULL\n", &saddr, ntohs(sport), &daddr, ntohs(dport));
		skb_nfct_reset(uskb);
		return NULL;
	}
	if (nf_ct_is_confirmed(user)) {
		skb_nfct_reset(uskb);
		NATCAP_WARN("fakeuser create for ct[%pI4:%u->%pI4:%u] failed, user nf_ct_is_confirmed\n", &saddr, ntohs(sport), &daddr, ntohs(dport));
		return NULL;
	}
	if (!(IPS_NATCAP_PEER & user->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &user->status)) {
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
		new = __krealloc(user->ext, newoff + sizeof(struct fakeuser_expect), GFP_ATOMIC);
#else
		new = krealloc(user->ext, newoff + sizeof(struct fakeuser_expect), GFP_ATOMIC);
#endif
		if (!new) {
			NATCAP_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u] failed, realloc user->ext failed\n", &saddr, ntohs(sport), &daddr, ntohs(dport));
			skb_nfct_reset(uskb);
			return NULL;
		}

		if (user->ext != new) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
			kfree_rcu(user->ext, rcu);
			user->ext = new;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
#else
			user->ext = new;
#endif
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, sizeof(struct fakeuser_expect));

		fue = peer_fakeuser_expect(user);
		fue->pmi = pmi;
		fue->local_seq = ntohl(gen_seq_number());
		fue->remote_seq = 0;
		fue->last_active = jiffies;
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return NULL;
	}
	user = nf_ct_get(uskb, &ctinfo);

	nf_conntrack_get(&user->ct_general);
	skb_nfct_reset(uskb);
	natcap_user_timeout_touch(user, peer_conn_timeout);

	fue = peer_fakeuser_expect(user);
	NATCAP_DEBUG("fakeuser create user[%pI4:%u->%pI4:%u] pmi=%d upmi=%d\n", &saddr, ntohs(sport), &daddr, ntohs(dport), pmi, fue->pmi);

	return user;
}

static struct nf_conn *peer_user_expect_in(int ttl, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, __be32 client_ip, const unsigned char *client_mac, struct peer_tuple **ppt)
{
	int ret;
	unsigned int i;
	struct peer_tuple *pt = NULL;
	struct user_expect *ue;
	struct nf_conn *user;
	struct nf_ct_ext *new;
	enum ip_conntrack_info ctinfo;
	unsigned int newoff;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned long last_jiffies = jiffies;

	uskb = uskb_of_this_cpu();
	if (uskb == NULL) {
		return NULL;
	}
	skb_reset_transport_header(uskb);
	skb_reset_network_header(uskb);
	skb_reset_mac_len(uskb);

	uskb->protocol = __constant_htons(ETH_P_IP);
	skb_set_tail_pointer(uskb, PEER_USKB_SIZE);
	uskb->len = PEER_USKB_SIZE;
	uskb->pkt_type = PACKET_HOST;
	uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

	iph = ip_hdr(uskb);
	iph->version = 4;
	iph->ihl = 5;
	iph->saddr = get_byte4(client_mac);
	iph->daddr = PEER_FAKEUSER_DADDR;
	iph->tos = 0;
	iph->tot_len = htons(PEER_USKB_SIZE);
	iph->ttl=255;
	iph->protocol = IPPROTO_UDP;
	iph->id = __constant_htons(0xdead);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = get_byte2(client_mac + 4);
	udph->dest = __constant_htons(65535);
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
	if (ret != NF_ACCEPT) {
		return NULL;
	}
	user = nf_ct_get(uskb, &ctinfo);

	if (!user) {
		NATCAP_ERROR("user [%02x:%02x:%02x:%02x:%02x:%02x] ct[%pI4:%u->%pI4:%u] failed\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
		             &saddr, ntohs(sport), &daddr, ntohs(dport));
		return NULL;
	}

	if (!user->ext) {
		NATCAP_ERROR("user [%02x:%02x:%02x:%02x:%02x:%02x] ct[%pI4:%u->%pI4:%u] failed, user->ext is NULL\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
		             &saddr, ntohs(sport), &daddr, ntohs(dport));
		skb_nfct_reset(uskb);
		return NULL;
	}
	if (!nf_ct_is_confirmed(user) && !(IPS_NATCAP_PEER & user->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &user->status)) {
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
		new = __krealloc(user->ext, newoff + sizeof(struct user_expect), GFP_ATOMIC);
#else
		new = krealloc(user->ext, newoff + sizeof(struct user_expect), GFP_ATOMIC);
#endif
		if (!new) {
			NATCAP_ERROR("user [%02x:%02x:%02x:%02x:%02x:%02x] ct[%pI4:%u->%pI4:%u] failed, realloc user->ext failed\n",
			             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
			             &saddr, ntohs(sport), &daddr, ntohs(dport));
			skb_nfct_reset(uskb);
			return NULL;
		}

		if (user->ext != new) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
			kfree_rcu(user->ext, rcu);
			user->ext = new;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
#else
			user->ext = new;
#endif
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, sizeof(struct user_expect));

		//Repeated initialization cannot happen, it is safe.
		ue = peer_user_expect(user);
		spin_lock_init(&ue->lock);

		spin_lock_bh(&ue->lock);
		ue->ip = saddr;
		ue->local_ip = client_ip;
		ue->map_port = alloc_peer_port(user, client_mac);
		spin_unlock_bh(&ue->lock);

		user->mark = ntohl(saddr);
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return NULL;
	}
	user = nf_ct_get(uskb, &ctinfo);

	ue = peer_user_expect(user);

	if (user != peer_port_map[ntohs(ue->map_port)]) {
		//XXX this can only happen when alloc_peer_port get 0 or old user got timeout.
		//    so we re-alloc it
		spin_lock_bh(&ue->lock);
		//re-check-in-lock
		if (user != peer_port_map[ntohs(ue->map_port)]) {
			//re-alloc-map_port
			ue->map_port = alloc_peer_port(user, client_mac);
		}
		spin_unlock_bh(&ue->lock);

		if (user != peer_port_map[ntohs(ue->map_port)]) {
			NATCAP_WARN("user [%02x:%02x:%02x:%02x:%02x:%02x] ct[%pI4:%u->%pI4:%u] alloc map_port fail\n",
			            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
			            &saddr, ntohs(sport), &daddr, ntohs(dport));
			/* alloc_peer_port fail: portmap would not work, but sni should work */
		}
	}

	if (ntohl(saddr) != user->mark) {
		__be32 old_ip = htonl(user->mark);
		NATCAP_WARN("user [%02x:%02x:%02x:%02x:%02x:%02x] ct[%pI4:%u->%pI4:%u] change ip from %pI4(ttl=%u) to %pI4(ttl=%u) P=%u AS=%d\n",
		            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
		            &saddr, ntohs(sport), &daddr, ntohs(dport),
		            &old_ip, (unsigned int)((user->status & 0xff000000) >> 24), &saddr, ttl, ntohs(ue->map_port),
		            ue->last_active != 0 ? (uintmindiff(ue->last_active, jiffies) + HZ / 2) / HZ : (-1));
		user->mark = ntohl(saddr);
		user->status &= ~(0xff << 24);
		user->status |= ((ttl & 0xff) << 24);
	}
	natcap_user_timeout_touch(user, peer_port_map_timeout);

	if (ue->ip != saddr) {
		ue->ip = saddr;
		short_clear_bit(PEER_SUBTYPE_PUB_BIT, &ue->status);
	}
	if (ue->local_ip != client_ip) {
		ue->local_ip = client_ip;
		short_clear_bit(PEER_SUBTYPE_PUB_BIT, &ue->status);
	}

	for (i = 0; i < MAX_PEER_TUPLE; i++) {
		if (ue->tuple[i].sip == saddr && ue->tuple[i].dip == daddr && ue->tuple[i].sport == sport && ue->tuple[i].dport) {
			spin_lock_bh(&ue->lock);
			//re-check-in-lock
			if (ue->tuple[i].sip == saddr && ue->tuple[i].dip == daddr && ue->tuple[i].sport == sport && ue->tuple[i].dport) {
				pt = &ue->tuple[i];
				spin_unlock_bh(&ue->lock);
				break;
			}
			spin_unlock_bh(&ue->lock);
		}
	}
	if (pt == NULL) {
		unsigned long maxdiff = 0;
		for (i = 0; i < MAX_PEER_TUPLE; i++) {
			if (maxdiff < uintmindiff(last_jiffies, ue->tuple[i].last_active)) {
				maxdiff = uintmindiff(last_jiffies, ue->tuple[i].last_active);
				pt = &ue->tuple[i];
			}
			if (ue->tuple[i].sip == 0) {
				pt = &ue->tuple[i];
				break;
			}
		}
		if (pt) {
			spin_lock_bh(&ue->lock);
			NATCAP_INFO("user [%02x:%02x:%02x:%02x:%02x:%02x] @map_port=%u use new-ct[%pI4:%u->%pI4:%u] replace old-ct[%pI4:%u->%pI4:%u] time=%u,%u\n",
			            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
			            ntohs(ue->map_port), &saddr, ntohs(sport), &daddr, ntohs(dport),
			            &pt->sip, ntohs(pt->sport), &pt->dip, ntohs(pt->dport), pt->last_active, (unsigned int)last_jiffies);
			pt->sip = saddr;
			pt->dip = daddr;
			pt->sport = sport;
			pt->dport = dport;
			pt->local_seq = 0;
			pt->remote_seq = 0;
			pt->connected = 0;
			pt->mode = 0;
			pt->last_active = 0;
			spin_unlock_bh(&ue->lock);
		}
	}
	if (ppt && pt) {
		*ppt = pt;
	}

	nf_conntrack_get(&user->ct_general);
	skb_nfct_reset(uskb);

	return user;
}

static __be32 peer_upstream_auth_ip = 0;

static void natcap_auth_request_upstream(const unsigned char *client_mac, __be32 client_ip)
{
	struct nf_conn *user;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_TCPOPT *tcpopt;
	struct peer_server_node *ps = NULL;
	struct fakeuser_expect *fue;
	u8 protocol = IPPROTO_TCP;
	int opt_header_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	int nlen;

	ps = peer_server_node_in(peer_upstream_auth_ip, 0, 0);
	if (ps == NULL) {
		return;
	}

	spin_lock_bh(&ps->lock);

	user = ps->port_map[0];
	if (user == NULL) {
		spin_unlock_bh(&ps->lock);
		return;
	}
	nf_conntrack_get(&user->ct_general);

	fue = peer_fakeuser_expect(user);
	if (fue->pmi != 0 || fue->state != FUE_STATE_CONNECTED || fue->rt_out_magic != rt_out_magic) {
		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		return;
	}

	nlen = fue->rt_out.l2_head_len + sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_header_len;

	if (fue->mode == FUE_MODE_UDP) {
		protocol = IPPROTO_UDP;
		nlen += 8;
	}

	skb = netdev_alloc_skb(fue->rt_out.outdev, nlen + NET_IP_ALIGN);
	if (skb == NULL) {
		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		return;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	skb_put(skb, nlen);
	skb_reset_mac_header(skb);
	skb_pull(skb, fue->rt_out.l2_head_len);
	skb_reset_network_header(skb);

	memcpy((void *)eth_hdr(skb), fue->rt_out.l2_head, fue->rt_out.l2_head_len);

	iph = ip_hdr(skb);
	memset(iph, 0, sizeof(struct iphdr));
	iph->saddr = user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	iph->daddr = user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->tos = 0;
	iph->tot_len = htons(skb->len);
	iph->ttl = 255;
	iph->protocol = protocol;
	iph->id = htons(jiffies);
	iph->frag_off = 0x0;

	tcph = (struct tcphdr *)((char *)ip_hdr(skb) + sizeof(struct iphdr));
	tcph->source = user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
	tcph->dest = user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
	if (protocol == IPPROTO_UDP) {
		UDPH(tcph)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
		set_byte4((void *)UDPH(tcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
		tcph = (struct tcphdr *)((char *)tcph + 8);
	}
	tcph->ack_seq = htonl(fue->remote_seq + 1);
	tcph->seq = htonl(fue->local_seq + 1);
	tcp_flag_word(tcph) = TCP_FLAG_ACK;
	tcph->res1 = 0;
	tcph->doff = (sizeof(struct tcphdr) + opt_header_len) / 4;
	tcph->window = __constant_htons(65535);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)tcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = TCPOPT_PEER_V2;
	tcpopt->header.opsize = opt_header_len;
	tcpopt->header.encryption = 0;
	tcpopt->header.subtype =  SUBTYPE_PEER_AUTH;

	set_byte4((void *)&tcpopt->peer.data.user.ip, client_ip);
	memcpy(tcpopt->peer.data.user.mac_addr, client_mac, ETH_ALEN);

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(skb);

	skb_push(skb, (char *)ip_hdr(skb) - (char *)eth_hdr(skb));
	dev_queue_xmit(skb);

	nf_ct_put(user);
	spin_unlock_bh(&ps->lock);
}

/*
 * return
 * <= 0 auth fail
 * >  0 auth success
 */
int natcap_auth_request(const unsigned char *client_mac, __be32 client_ip)
{
	int ret = 0;
	int check_auth = 0;
	struct user_expect *ue;
	struct nf_conn *user;
	struct nf_ct_ext *new;
	enum ip_conntrack_info ctinfo;
	unsigned int newoff;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;

	uskb = uskb_of_this_cpu();
	if (uskb == NULL) {
		return 0;
	}

	skb_reset_transport_header(uskb);
	skb_reset_network_header(uskb);
	skb_reset_mac_len(uskb);

	uskb->protocol = __constant_htons(ETH_P_IP);
	skb_set_tail_pointer(uskb, PEER_USKB_SIZE);
	uskb->len = PEER_USKB_SIZE;
	uskb->pkt_type = PACKET_HOST;
	uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

	iph = ip_hdr(uskb);
	iph->version = 4;
	iph->ihl = 5;
	iph->saddr = get_byte4(client_mac);
	iph->daddr = PEER_FAKEUSER_DADDR;
	iph->tos = 0;
	iph->tot_len = htons(PEER_USKB_SIZE);
	iph->ttl=255;
	iph->protocol = IPPROTO_UDP;
	iph->id = __constant_htons(0xdead);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = get_byte2(client_mac + 4);
	udph->dest = __constant_htons(65535);
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
	if (ret != NF_ACCEPT) {
		return 0;
	}
	user = nf_ct_get(uskb, &ctinfo);

	if (!user) {
		NATCAP_ERROR("auth user [%02x:%02x:%02x:%02x:%02x:%02x] not found\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
		return 0;
	}

	if (!user->ext) {
		NATCAP_ERROR("auth user [%02x:%02x:%02x:%02x:%02x:%02x] not found, user->ext is NULL\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
		skb_nfct_reset(uskb);
		return 0;
	}
	if (!nf_ct_is_confirmed(user) && !(IPS_NATCAP_PEER & user->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &user->status)) {
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
		new = __krealloc(user->ext, newoff + sizeof(struct user_expect), GFP_ATOMIC);
#else
		new = krealloc(user->ext, newoff + sizeof(struct user_expect), GFP_ATOMIC);
#endif
		if (!new) {
			NATCAP_ERROR("auth user [%02x:%02x:%02x:%02x:%02x:%02x] not found, realloc user->ext failed\n",
			             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
			skb_nfct_reset(uskb);
			return 0;
		}

		if (user->ext != new) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
			kfree_rcu(user->ext, rcu);
			user->ext = new;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
#else
			user->ext = new;
#endif
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, sizeof(struct user_expect));

		//Repeated initialization cannot happen, it is safe.
		ue = peer_user_expect(user);
		spin_lock_init(&ue->lock);

		spin_lock_bh(&ue->lock);
		ue->ip = 0;
		ue->local_ip = 0;
		ue->map_port = alloc_peer_port(user, client_mac);
		spin_unlock_bh(&ue->lock);

		user->mark = ntohl(client_ip);
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return 0;
	}
	user = nf_ct_get(uskb, &ctinfo);

	ue = peer_user_expect(user);

	if (user != peer_port_map[ntohs(ue->map_port)]) {
		//XXX this can only happen when alloc_peer_port get 0 or old user got timeout.
		//    so we re-alloc it
		spin_lock_bh(&ue->lock);
		//re-check-in-lock
		if (user != peer_port_map[ntohs(ue->map_port)]) {
			//re-alloc-map_port
			ue->map_port = alloc_peer_port(user, client_mac);
		}
		spin_unlock_bh(&ue->lock);

		if (user != peer_port_map[ntohs(ue->map_port)]) {
			NATCAP_WARN("auth user [%02x:%02x:%02x:%02x:%02x:%02x] alloc map_port fail\n",
			            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
			/* alloc_peer_port fail: portmap would not work, but sni should work */
		}
	}

	if (ntohl(client_ip) != user->mark) {
		__be32 old_ip = htonl(user->mark);
		NATCAP_WARN("auth user [%02x:%02x:%02x:%02x:%02x:%02x] change ip from %pI4 to %pI4 P=%u AS=%d\n",
		            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
		            &old_ip, &client_ip, ntohs(ue->map_port),
		            ue->last_active_auth != 0 ? (uintmindiff(ue->last_active_auth, jiffies) + HZ / 2) / HZ : (-1));
		user->mark = ntohl(client_ip);
	}

	if ((ue->status & PEER_SUBTYPE_AUTH)) {
		ret = 1;
		/*check upstream auth every 300s if AUTH */
		if (uintmindiff(jiffies, ue->last_active_auth) >= 300 * HZ) {
			ue->last_active_auth = jiffies;
			check_auth = 1;
		}
		natcap_user_timeout_touch(user, 3600 * 12); //12 hours
	} else {
		ret = -1;
		/*check upstream auth every 60s if not AUTH */
		if (uintmindiff(jiffies, ue->last_active_auth) >= 60 * HZ) {
			ue->last_active_auth = jiffies;
			check_auth = 1;
		}
		natcap_user_timeout_touch(user, peer_port_map_timeout);
	}

	skb_nfct_reset(uskb);

	if (check_auth) {
		//check upstream auth
		natcap_auth_request_upstream(client_mac, client_ip);
	}

	return ret;
}

static inline void natcap_auth_user_confirm(const unsigned char *client_mac, int auth)
{
	int ret;
	struct user_expect *ue;
	struct nf_conn *user;
	enum ip_conntrack_info ctinfo;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;

	uskb = uskb_of_this_cpu();
	if (uskb == NULL) {
		return;
	}

	skb_reset_transport_header(uskb);
	skb_reset_network_header(uskb);
	skb_reset_mac_len(uskb);

	uskb->protocol = __constant_htons(ETH_P_IP);
	skb_set_tail_pointer(uskb, PEER_USKB_SIZE);
	uskb->len = PEER_USKB_SIZE;
	uskb->pkt_type = PACKET_HOST;
	uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

	iph = ip_hdr(uskb);
	iph->version = 4;
	iph->ihl = 5;
	iph->saddr = get_byte4(client_mac);
	iph->daddr = PEER_FAKEUSER_DADDR;
	iph->tos = 0;
	iph->tot_len = htons(PEER_USKB_SIZE);
	iph->ttl=255;
	iph->protocol = IPPROTO_UDP;
	iph->id = __constant_htons(0xdead);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = get_byte2(client_mac + 4);
	udph->dest = __constant_htons(65535);
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
	if (ret != NF_ACCEPT) {
		return;
	}
	user = nf_ct_get(uskb, &ctinfo);

	if (!user) {
		NATCAP_ERROR("auth user [%02x:%02x:%02x:%02x:%02x:%02x] not found\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
		return;
	}

	if (!user->ext) {
		NATCAP_ERROR("auth user [%02x:%02x:%02x:%02x:%02x:%02x] not found, user->ext is NULL\n",
		             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
		skb_nfct_reset(uskb);
		return;
	}
	if (!nf_ct_is_confirmed(user) || !(IPS_NATCAP_PEER & user->status)) {
		return;
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return;
	}
	user = nf_ct_get(uskb, &ctinfo);

	ue = peer_user_expect(user);

	if (auth) {
		if (!(ue->status & PEER_SUBTYPE_AUTH))
			ue->status |= PEER_SUBTYPE_AUTH;
		natcap_user_timeout_touch(user, 3600 * 12); //12 hours
	} else {
		if ((ue->status & PEER_SUBTYPE_AUTH))
			ue->status &= ~PEER_SUBTYPE_AUTH;
		natcap_user_timeout_touch(user, peer_port_map_timeout);
	}

	skb_nfct_reset(uskb);
}

static inline void natcap_auth_reply(const struct net_device *dev, struct sk_buff *oskb, int pt_mode, unsigned char *client_mac, int auth)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, add_len;
	int header_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	u8 protocol = IPPROTO_TCP;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);
	tcpopt = (struct natcap_TCPOPT *)((void *)otcph + sizeof(struct tcphdr));
	if (tcpopt->header.opsize > header_len) {
		header_len = tcpopt->header.opsize;
	}
	if (pt_mode == PT_MODE_UDP) {
		protocol = IPPROTO_UDP;
		header_len += 8;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = oiph->ihl;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = protocol;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	//memset(ntcph, 0, sizeof(sizeof(struct tcphdr) + header_len + TCPOLEN_MSS));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	if (protocol == IPPROTO_UDP) {
		int offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4 - 8;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
		header_len -= 8;
	}

	ntcph->ack_seq = otcph->seq;
	ntcph->seq = otcph->ack_seq;
	tcp_flag_word(ntcph) = TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + header_len) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = TCPOPT_PEER_V2;
	tcpopt->header.opsize = header_len;
	tcpopt->header.encryption = 0;
	tcpopt->header.subtype = SUBTYPE_PEER_AUTHACK;
	set_byte2((void *)&tcpopt->peer.data.map_port, auth <= 0 ? 0 : 65535);

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);
	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;
	dev_queue_xmit(nskb);
}

static inline void natcap_peer_echo_request(const struct net_device *dev, struct sk_buff *oskb, unsigned char *client_mac)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	int offset, add_len;
	void *l4;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);

	offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 14 - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct udphdr) + 14;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = IPPROTO_UDP;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	l4 = (void *)niph + niph->ihl * 4;
	UDPH(l4)->source = htons(get_random_u32() % (65536 - 1024) + 1024);
	UDPH(l4)->dest = htons(get_random_u32() % (65536 - 1024) + 1024);
	UDPH(l4)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
	UDPH(l4)->check = CSUM_MANGLED_0;

	l4 += sizeof(struct udphdr);
	set_byte4(l4, __constant_htonl(NATCAP_A_MAGIC));
	set_byte4(l4 + 4, __constant_htonl(0x00000001)); //PEER_ECHO_REQUEST
	set_byte6(l4 + 8, client_mac);

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
}

static inline void natcap_peer_echo_reply(const struct net_device *dev, struct sk_buff *oskb)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct udphdr *oudph;
	int offset, add_len;
	void *l4;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	oudph = (struct udphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 14 - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct udphdr) + 14;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = IPPROTO_UDP;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	l4 = (void *)niph + niph->ihl * 4;
	UDPH(l4)->source = oudph->dest;
	UDPH(l4)->dest = oudph->source;
	UDPH(l4)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
	UDPH(l4)->check = CSUM_MANGLED_0;

	l4 += sizeof(struct udphdr);
	set_byte4(l4, __constant_htonl(NATCAP_A_MAGIC));
	set_byte4(l4 + 4, __constant_htonl(0x00000002)); //PEER_ECHO_REPLY
	if (oskb->len >= oiph->ihl * 4 + sizeof(struct udphdr) + 14) {
		set_byte6(l4 + 8, (void *)oudph + sizeof(struct udphdr) + 8);
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
}

static inline void natcap_peer_pong_send(const struct net_device *dev, struct sk_buff *oskb, __be16 map_port, struct peer_tuple *pt, int ssyn)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, add_len;
	int header_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	int ext_header_len = 0;
	u8 protocol = IPPROTO_TCP;
	u8 opcode = TCPOPT_PEER;

	if (pt == NULL)
		return;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);
	tcpopt = (struct natcap_TCPOPT *)((void *)otcph + sizeof(struct tcphdr));
	if (tcpopt->header.opsize > header_len) {
		header_len = tcpopt->header.opsize;
	}
	if (pt->connected && tcpopt->header.opcode == TCPOPT_PEER_V2) {
		opcode = TCPOPT_PEER_V2;
		ext_header_len = sizeof(peer_pub_ip);
	}
	if (pt->mode == PT_MODE_UDP) {
		protocol = IPPROTO_UDP;
		header_len += 8;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS + ext_header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS + ext_header_len;
	if (ext_header_len > 0) {
		ext_header_len = header_len + TCPOLEN_MSS;
		if (!skb_make_writable(nskb, nskb->len)) {
			consume_skb(nskb);
			return;
		}
	}

	if (pt->local_seq == 0) {
		pt->local_seq = ntohl(gen_seq_number());
	}

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = oiph->ihl;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = protocol;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	//memset(ntcph, 0, sizeof(sizeof(struct tcphdr) + header_len + TCPOLEN_MSS));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	if (protocol == IPPROTO_UDP) {
		int offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4 - 8;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
		header_len -= 8;
	}

	//ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + (1 * otcph->syn));
	ntcph->ack_seq = htonl(pt->remote_seq + 1);
	ntcph->seq = (pt->connected && ssyn) ? htonl(pt->local_seq + 1) : htonl(pt->local_seq);
	tcp_flag_word(ntcph) = (pt->connected && ssyn) ? (TCP_FLAG_ACK) : (TCP_FLAG_ACK | TCP_FLAG_SYN);
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + header_len + TCPOLEN_MSS) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = opcode;
	tcpopt->header.opsize = header_len;
	tcpopt->header.encryption = 0;
	tcpopt->header.subtype = pt->connected ? SUBTYPE_PEER_FSYNACK : SUBTYPE_PEER_SYNACK;
	set_byte2((void *)&tcpopt->peer.data.map_port, map_port);

	//just set a mss we do not care what it is
	set_byte1((void *)tcpopt + header_len + 0, TCPOPT_MSS);
	set_byte1((void *)tcpopt + header_len + 1, TCPOLEN_MSS);
	set_byte2((void *)tcpopt + header_len + 2, ntohs(TCP_MSS_DEFAULT)); //just set a fake mss

	if (ext_header_len > 0) {
		unsigned int i;
		unsigned int *dst = (void *)((char *)ip_hdr(nskb) + sizeof(struct iphdr) + sizeof(struct tcphdr) + ext_header_len);
		for (i = 0; i < PEER_PUB_NUM; i++) {
			if (uintmindiff(jiffies, peer_pub_active[i]) < 120 * HZ) {
				dst[i] = peer_pub_ip[i];
			} else {
				dst[i] = 0;
			}
		}
		if (!ssyn && protocol == IPPROTO_TCP) {
			//send syn,ack, then send ack with payload
			oskb = skb_copy(nskb, GFP_ATOMIC);
			if (oskb) {
				oskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + ext_header_len;
				oeth = eth_hdr(oskb);
				oiph = ip_hdr(oskb);
				oiph->id = htons(ntohs(oiph->id) - 1);
				oiph->tot_len = htons(oskb->len);
				otcph = (struct tcphdr *)((char *)ip_hdr(oskb) + sizeof(struct iphdr));
				tcpopt = (struct natcap_TCPOPT *)((void *)otcph + sizeof(struct tcphdr));
				tcpopt->header.opcode = TCPOPT_PEER;

				oskb->ip_summed = CHECKSUM_UNNECESSARY;
				skb_rcsum_tcpudp(oskb);
				skb_push(oskb, (char *)oiph - (char *)oeth);
				oskb->dev = (struct net_device *)dev;
				dev_queue_xmit(oskb);

				ntcph->seq = htonl(ntohl(ntcph->seq) + 1);
				ntcph->syn = 0;
			} else {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
			}
		}
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);
	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;
	dev_queue_xmit(nskb);
}

/*
 *XXX
 * send [syn SYN] if connected == 0
 * send [ack SYN] if connected != 0 and ops == NULL
 * send [ack ACK] if connected != 0 and ops != NULL
 * PS: oskb is icmp if ops == NULL, dev is outgoing dev of oskb
 * PS: oskb is tcp if ops != NULL, dev is incomming dev of oskb
 */
static inline struct sk_buff *natcap_peer_ping_send(struct sk_buff *oskb, const struct net_device *dev, struct peer_server_node *ops, int opmi, unsigned short omss)
{
	struct fakeuser_expect *fue;
	struct nf_conn *user;
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *ntcph, *otcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, add_len;
	int header_len;
	int pmi;
	int tcpolen_mss = TCPOLEN_MSS;
	struct peer_server_node *ps = NULL;
	u8 protocol = IPPROTO_TCP;

	oiph = ip_hdr(oskb);
	otcph = (void *)oiph + oiph->ihl * 4;

	if (ops != NULL && dev == NULL) {
		//invalid input
		return NULL;
	}

	ps = (ops != NULL) ? ops : peer_server_node_in(oiph->daddr, oskb->len - oiph->ihl * 4 - sizeof(struct icmphdr), 1);
	if (ps == NULL) {
		return NULL;
	}

	spin_lock_bh(&ps->lock);

	pmi = opmi;
	if (ops == NULL) {
		if (ps->last_inuse != 0 && before(jiffies, ps->last_inuse + peer_conn_timeout * HZ)) {
			pmi = ntohs(ICMPH(otcph)->un.echo.sequence) % MAX_PEER_CONN;
		} else {
			pmi = ntohs(ICMPH(otcph)->un.echo.sequence) % ps->conn;
			if (pmi != 0) {
				/* change connection in every 512s */
				if ((jiffies / HZ) % 512 == 0 && ps->port_map[0] != NULL) {
					nf_ct_put(ps->port_map[0]);
					ps->port_map[0] = NULL;
				}
				spin_unlock_bh(&ps->lock);
				return NULL;
			}
		}
	}
	user = ps->port_map[pmi];

	header_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	if (ops == NULL) {
		header_len += 16; //for timestamp
	}
	/* change connection if route/path changed */
	if (user != NULL && ops == NULL && (oskb->mark & 0x3f00) && (
	            user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip != oiph->saddr ||
	            user->mark != oskb->mark)) {
		nf_ct_put(ps->port_map[pmi]);
		user = ps->port_map[pmi] = NULL;
	}
	/* change connection in every 512s */
	if ((jiffies / HZ) % 512 == 0 && user != NULL) {
		nf_ct_put(ps->port_map[pmi]);
		user = ps->port_map[pmi] = NULL;
	}

	if (user != NULL) {
		nf_conntrack_get(&user->ct_general);
	} else {
		__be16 sport = htons(get_random_u32() % (65536 - 1024) + 1024);
		__be16 dport = htons(get_random_u32() % (65536 - 1024) + 1024);
		__be32 saddr = (ops != NULL) ? oiph->daddr : oiph->saddr;
		__be32 daddr = (ops != NULL) ? oiph->saddr : oiph->daddr;
		user = peer_fakeuser_expect_new(saddr, daddr, sport, dport, pmi);
		if (user == NULL) {
			spin_unlock_bh(&ps->lock);
			return NULL;
		}
		user->mark = oskb->mark;
	}
	if (ps->port_map[pmi] == NULL) {
		nf_conntrack_get(&user->ct_general);
		ps->port_map[pmi] = user;
	}
	fue = peer_fakeuser_expect(user);
	if (fue->pmi != pmi) {
		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		return NULL;
	}

	if (fue->state == FUE_STATE_CONNECTED) {
		tcpolen_mss = 0;
		if (fue->mode == FUE_MODE_UDP) {
			protocol = IPPROTO_UDP;
			header_len += 8;
		}
	} else {
		if (peer_mode == 1) {
			if (fue->mode != FUE_MODE_UDP) fue->mode = FUE_MODE_UDP;
			protocol = IPPROTO_UDP;
			header_len += 8;
		}
	}

	offset = oiph->ihl * 4 + sizeof(struct tcphdr) + header_len + tcpolen_mss - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		return NULL;
	}
	nskb->mark = user->mark;
	nskb->tail += offset;
	nskb->len = oiph->ihl * 4 + sizeof(struct tcphdr) + header_len + tcpolen_mss;

	skb_nfct_reset(nskb);

	oeth = eth_hdr(oskb);
	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if (ops != NULL) {
		if ((char *)niph - (char *)neth >= ETH_HLEN) {
			memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
			memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
			//neth->h_proto = htons(ETH_P_IP);
		}
		if (fue->mss == 0 && omss != 0) {
			fue->mss = omss;
		}
	} else {
		if (fue->mss == 0 || fue->state == FUE_STATE_INIT) {
			unsigned short mss;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
			mss = ip_skb_dst_mtu(oskb);
#else
			mss = ip_skb_dst_mtu(NULL, oskb);
#endif
			mss = mss - (sizeof(struct iphdr) + sizeof(struct tcphdr));
			if (mss < TCP_MSS_DEFAULT) {
				mss = TCP_MSS_DEFAULT;
			}
			fue->mss = mss;
		}
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	niph->daddr = user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = oiph->ihl;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = protocol;
	niph->id = (ops != NULL) ? htons(jiffies) : oiph->id;
	niph->frag_off = 0x0;

	ntcph = (void *)niph + niph->ihl * 4;
	//memset((void *)ntcph, 0, sizeof(sizeof(struct tcphdr) + header_len + tcpolen_mss));
	ntcph->source = user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
	ntcph->dest = user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
		header_len -= 8;
	}
	ntcph->seq = htonl(fue->local_seq);
	ntcph->ack_seq = 0;
	tcp_flag_word(ntcph) = TCP_FLAG_SYN;
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + header_len + tcpolen_mss) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = peer_multipath ? TCPOPT_PEER_V2 : TCPOPT_PEER;
	tcpopt->header.opsize = header_len;
	tcpopt->header.encryption = !!peer_sni_ban; //use encryption to carry peer_sni_ban
	tcpopt->header.subtype = SUBTYPE_PEER_SYN;
	if (ops != NULL) {
		set_byte2((void *)&tcpopt->peer.data.icmp_id, 0); //__constant_htons(0)
		set_byte2((void *)&tcpopt->peer.data.icmp_sequence, 0);
		set_byte2((void *)&tcpopt->peer.data.icmp_payload_len, 0);
	} else {
		u16 payload_len = oskb->len - oiph->ihl * 4 - sizeof(struct icmphdr);
		set_byte2((void *)&tcpopt->peer.data.icmp_id, __constant_htons(65535));
		set_byte2((void *)&tcpopt->peer.data.icmp_sequence, ICMPH(otcph)->un.echo.sequence);
		set_byte2((void *)&tcpopt->peer.data.icmp_payload_len, htons(payload_len));
		if (payload_len > 16)
			payload_len = 16;
		memcpy(fue->fake_icmp_time, (const void *)otcph + sizeof(struct icmphdr), payload_len);
		memset((void *)fue->fake_icmp_time + payload_len, 0, 16 - payload_len);
		set_byte2((void *)&fue->fake_icmp_time[16], ICMPH(otcph)->un.echo.id);
		memcpy((void *)tcpopt->peer.data.timeval, peer_local_ip6_addr.s6_addr, payload_len);
		memcpy((void *)tcpopt->peer.data.timeval + payload_len, peer_local_ip6_addr.s6_addr + payload_len, 16 - payload_len);
	}
	set_byte4((void *)&tcpopt->peer.data.user.ip, niph->saddr);
	memcpy(tcpopt->peer.data.user.mac_addr, default_mac_addr, ETH_ALEN);

	if (fue->state == FUE_STATE_CONNECTED) {
		ntcph->ack_seq = htonl(fue->remote_seq + 1);
		ntcph->seq = htonl(fue->local_seq + 1);
		ntcph->syn = 0;
		ntcph->ack = 1;

		if (ops != NULL) {
			tcpopt->header.subtype = SUBTYPE_PEER_ACK;
		} else if ((peer_subtype == 2) ||
		           (peer_subtype == 0 && !(ps->status & PEER_SUBTYPE_SYN) && after(jiffies, fue->last_active + 64 * HZ))) {
			//XXX auto switch to SSYN mode if fue no active for more than 64s
			tcpopt->header.subtype = SUBTYPE_PEER_SSYN;
		}
	}

	if (tcpolen_mss == TCPOLEN_MSS) {
		set_byte1((void *)tcpopt + header_len + 0, TCPOPT_MSS);
		set_byte1((void *)tcpopt + header_len + 1, TCPOLEN_MSS);
		set_byte2((void *)tcpopt + header_len + 2, ntohs(fue->mss));
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	if (ops != NULL) {
		skb_push(nskb, (char *)niph - (char *)neth);
		nskb->dev = (struct net_device *)dev;
		//back l2 header
		if (fue->rt_out_magic != rt_out_magic || fue->rt_out.outdev != nskb->dev) {
			fue->rt_out.l2_head_len = (char *)niph - (char *)neth; //assume l2_head_len <= NF_L2_MAX_LEN
			memcpy(fue->rt_out.l2_head, (char *)neth, (char *)niph - (char *)neth);
			fue->rt_out.outdev = nskb->dev;
			fue->rt_out_magic = rt_out_magic;
		}
		if ((nskb->mark & 0x3f00)) {
			struct natcap_fastpath_route *pfr;
			int line = (nskb->mark & 0x3f00) >> 8;
			if (line >= 1 && line <= MAX_PEER_NUM) {
				line--;
				pfr = &natcap_pfr[line];

				if (pfr->saddr != niph->saddr || pfr->rt_out_magic != rt_out_magic || pfr->rt_out.outdev != nskb->dev) {
					pfr->saddr = niph->saddr;
					pfr->rt_out.l2_head_len = (char *)niph - (char *)neth;
					memcpy(pfr->rt_out.l2_head, (char *)neth, (char *)niph - (char *)neth);
					pfr->rt_out.outdev = nskb->dev;
					pfr->rt_out_magic = rt_out_magic;
					pfr->is_dead = 1;
					pfr->weight = 100;
				}
			}
		}

		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		NATCAP_INFO(DEBUG_FMT_PREFIX DEBUG_FMT_TCP ": %s\n", DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(niph,ntcph),
		            ntcph->syn ? "sent ping(syn) SYN out" : "sent ping(ack) ACK out");
		dev_queue_xmit(nskb);
		return NULL;
	} else if (fue->rt_out.outdev && fue->rt_out_magic == rt_out_magic) {
		skb_push(nskb, fue->rt_out.l2_head_len);
		skb_reset_mac_header(nskb);
		memcpy(skb_mac_header(nskb), fue->rt_out.l2_head, fue->rt_out.l2_head_len);
		nskb->dev = fue->rt_out.outdev;
		nf_ct_put(user);
		spin_unlock_bh(&ps->lock);
		NATCAP_INFO(DEBUG_FMT_PREFIX DEBUG_FMT_TCP ": %s\n", DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(niph,ntcph),
		            ntcph->syn ? "sent ping(syn) SYN out" : "sent ping(ack) ACK out");
		dev_queue_xmit(nskb);
		return NULL;
	}

	nf_ct_put(user);
	spin_unlock_bh(&ps->lock);

	return nskb;
}

static inline struct sk_buff *peer_sni_to_syn(struct sk_buff *oskb, unsigned short mss)
{
	struct sk_buff *nskb;
	struct iphdr *oiph;
	struct tcphdr *otcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, add_len;
	//int header_len = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));
	int header_len = 0;

	nskb = skb_copy(oskb, GFP_ATOMIC);
	if (nskb == NULL) {
		return NULL;
	}
	if (mss < TCP_MSS_DEFAULT) {
		mss = TCP_MSS_DEFAULT;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);

	if (add_len > 0 && skb_tailroom(oskb) < add_len && pskb_expand_head(oskb, 0, add_len, GFP_ATOMIC)) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head() fail\n", DEBUG_ARG_PREFIX);
		return NULL;
	}
	oskb->tail += offset;
	oskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS;

	oiph = ip_hdr(oskb);
	oiph->tot_len = htons(oskb->len);

	otcph = (struct tcphdr *)((char *)ip_hdr(oskb) + sizeof(struct iphdr));
	otcph->seq = htonl(ntohl(otcph->seq) - 1);
	otcph->ack_seq = __constant_htonl(0);
	tcp_flag_word(otcph) = TCP_FLAG_SYN;
	otcph->res1 = 0;
	otcph->doff = (sizeof(struct tcphdr) + header_len + TCPOLEN_MSS) / 4;
	otcph->window = __constant_htons(65535);
	otcph->check = 0;
	otcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)otcph + sizeof(struct tcphdr));
	//tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	//tcpopt->header.opcode = TCPOPT_PEER;
	//tcpopt->header.opsize = add_len;
	//tcpopt->header.encryption = 0;
	//tcpopt->header.subtype = SUBTYPE_PEER_FSYN;

	set_byte1((void *)tcpopt + header_len + 0, TCPOPT_MSS);
	set_byte1((void *)tcpopt + header_len + 1, TCPOLEN_MSS);
	set_byte2((void *)tcpopt + header_len + 2, ntohs(mss)); //just use mss from client.

	oskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(oskb);

	return nskb;
}

static inline int peer_sni_send_synack(const struct net_device *dev, struct sk_buff *oskb)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, add_len;
	int header_len = 0;
	unsigned short mss;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	mss = natcap_tcpmss_get(otcph);
	if (mss < TCP_MSS_DEFAULT) {
		mss = TCP_MSS_DEFAULT;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return -1;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len + TCPOLEN_MSS;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = IPPROTO_TCP;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = gen_seq_number();
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);
	tcp_flag_word(ntcph) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + header_len + TCPOLEN_MSS) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
	set_byte1((void *)tcpopt + header_len + 0, TCPOPT_MSS);
	set_byte1((void *)tcpopt + header_len + 1, TCPOLEN_MSS);
	set_byte2((void *)tcpopt + header_len + 2, ntohs(mss)); //just use mss from client.

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
	return 0;
}

static inline int peer_sni_send_ack(const struct net_device *dev, struct sk_buff *oskb)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, add_len;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return -1;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = IPPROTO_TCP;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + (ntohs(oiph->tot_len) - (oiph->ihl * 4 + otcph->doff * 4)));
	tcp_flag_word(ntcph) = TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr)) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
	return 0;
}

static unsigned char *tls_sni_search(unsigned char *data, int *data_len, int *needmore)
{
	unsigned char *p = data;
	int p_len = *data_len;
	int i_data_len = p_len;
	unsigned int i = 0;
	unsigned short len;

	if (p[i + 0] != 0x16) {//Content Type NOT HandShake
		return NULL;
	}
	i += 1 + 2;
	if (i >= p_len) return NULL;
	len = ntohs(get_byte2(p + i + 0)); //content_len
	i += 2;
	if (i >= p_len) return NULL;
	if (i + len > p_len) {
		if (needmore && p[i] == 0x01) //HanShake Type is Client Hello
			*needmore = 1;
	}

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	if (p[i + 0] != 0x01) { //HanShake Type NOT Client Hello
		return NULL;
	}
	i += 1;
	if (i >= p_len || i >= i_data_len) return NULL;
	len = (p[i + 0] << 8) + ntohs(get_byte2(p + i + 0 + 1)); //hanshake_len
	i += 1 + 2;
	if (i >= p_len || i >= i_data_len) return NULL;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	i += 2 + 32;
	if (i >= p_len || i >= i_data_len) return NULL; //tls_v, random
	i += 1 + p[i + 0];
	if (i >= p_len || i >= i_data_len) return NULL; //session id
	i += 2 + ntohs(get_byte2(p + i + 0));
	if (i >= p_len || i >= i_data_len) return NULL; //Cipher Suites
	i += 1 + p[i + 0];
	if (i >= p_len || i >= i_data_len) return NULL; //Compression Methods

	len = ntohs(get_byte2(p + i + 0)); //ext_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (get_byte2(p + i + 0) != __constant_htons(0)) {
			i += 2 + 2 + ntohs(get_byte2(p + i + 0 + 2));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 2)); //sn_len
		i = i + 2 + 2;
		if (i + len > p_len || i + len > i_data_len) return NULL;

		p = p + i;
		p_len = len;
		i_data_len -= i;
		i = 0;
		break;
	}
	if (i >= p_len || i >= i_data_len) return NULL;

	len = ntohs(get_byte2(p + i + 0)); //snl_len
	i += 2;
	if (i + len > p_len || i + len > i_data_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (p[i + 0] != 0) {
			i += 1 + 2 + ntohs(get_byte2(p + i + 0 + 1));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 1 + 2;
		if (i + len > p_len || i + len > i_data_len) return NULL;

		*data_len = len;
		return (p + i);
	}

	return NULL;
}

static inline void sni_ack_pass_back(struct sk_buff *oskb, struct sk_buff *cache_skb,
                                     struct nf_conn *ct, struct natcap_session *ns, const struct net_device *dev)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, add_len;
	u8 protocol = IPPROTO_TCP;
	int header_len = 0;

	if ((NS_PEER_TCPUDPENC & ns->p.status)) {
		header_len += 8;
		protocol = IPPROTO_UDP;
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(cache_skb); //use cache_skb
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);
	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset - header_len;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = IPPROTO_TCP;
	niph->id = htons(jiffies);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->seq = otcph->seq;
	ntcph->ack_seq = otcph->ack_seq;
	tcp_flag_word(ntcph) = TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = sizeof(struct tcphdr) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);
	skb_nfct_reset(nskb);

	nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, nskb);
	nf_conntrack_confirm(nskb);

	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);

	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;

	if (protocol == IPPROTO_UDP) {
		int offlen;
		offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		niph->tot_len = htons(ntohs(niph->tot_len) + 8);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		nskb->len += 8;
		nskb->tail += 8;
		niph->protocol = IPPROTO_UDP;
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
	}

	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;
	skb_nfct_reset(nskb);
	dev_queue_xmit(nskb);
}


static inline void sni_cache_skb_pass_back(struct sk_buff *oskb, struct sk_buff *cache_skb,
        struct nf_conn *ct, struct natcap_session *ns, const struct net_device *dev, enum ip_conntrack_info ctinfo)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *ntcph, *otcph;
	int offset, add_len;
	u8 protocol = IPPROTO_TCP;
	int header_len = 0;

	if ((NS_PEER_TCPUDPENC & ns->p.status)) {
		header_len += 8;
		protocol = IPPROTO_UDP;
	}

	if (cache_skb == NULL)
		return;
	if (!skb_make_writable(cache_skb, ntohs(ip_hdr(cache_skb)->tot_len))) {
		return;
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	offset = ntohs(ip_hdr(cache_skb)->tot_len) + header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset - header_len;
	nskb->len = ntohs(ip_hdr(cache_skb)->tot_len);

	//use cache_skb
	oiph = ip_hdr(cache_skb);

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memcpy(niph, oiph, nskb->len);

	ntcph = (struct tcphdr *)((char *)niph + sizeof(struct iphdr));

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);
	skb_nfct_reset(nskb);

	nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, nskb);
	nf_conntrack_confirm(nskb);

	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);

	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;

	if (protocol == IPPROTO_UDP) {
		int offlen;
		offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		niph->tot_len = htons(ntohs(niph->tot_len) + 8);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		nskb->len += 8;
		nskb->tail += 8;
		niph->protocol = IPPROTO_UDP;
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
	}

	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;
	skb_nfct_reset(nskb);
	dev_queue_xmit(nskb);
}

static struct work_struct request_natcapd_restart_work;

static void request_natcapd_restart_work_func(struct work_struct *work)
{
	static char *argv[] = {
		"/usr/sbin/natcapd", "start", NULL
	};
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};

	int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	printk(KERN_INFO "natcapd start %d\n", ret);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_pre_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_pre_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct natcap_TCPOPT *tcpopt;
	unsigned int pt_mode = 0;

	if (peer_stop)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (hooknum == NF_INET_LOCAL_OUT) {
		if (iph->protocol == IPPROTO_ICMP && iph->ttl == 1) {
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
		}
		return NF_ACCEPT;
	}
	if (iph->protocol == IPPROTO_UDP) {
		if (skb->len < iph->ihl * 4 + sizeof(struct udphdr) + 8) {
			return NF_ACCEPT;
		}
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 8)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_A_MAGIC)) {
			if (!inet_is_local(in, iph->daddr)) {
				int ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				return NF_ACCEPT;
			}
			if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(0x00000001)) {
				//get PEER_ECHO_REQUEST
				if (skb->len >= iph->ihl * 4 + sizeof(struct udphdr) + 14) {
					unsigned char client_mac[ETH_ALEN];
					if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 14)) {
						return NF_ACCEPT;
					}
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;

					get_byte6(l4 + sizeof(struct udphdr) + 8, client_mac);
					if (memcmp(default_mac_addr, client_mac, ETH_ALEN) != 0) {
						//target not me
						return NF_ACCEPT;
					}
				}
				natcap_peer_echo_reply(in, skb);
				consume_skb(skb);
				return NF_STOLEN;
			} else if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(0x00000002)) {
				//get PEER_ECHO_REPLY
				unsigned int i;
				if (skb->len >= iph->ihl * 4 + sizeof(struct udphdr) + 14) {
					unsigned char client_mac[ETH_ALEN];
					struct nf_conntrack_tuple tuple;
					struct nf_conntrack_tuple_hash *h;

					if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 14)) {
						return NF_ACCEPT;
					}
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;

					get_byte6(l4 + sizeof(struct udphdr) + 8, client_mac);

					memset(&tuple, 0, sizeof(tuple));
					tuple.src.u3.ip = get_byte4(client_mac);
					tuple.src.u.udp.port = get_byte2(client_mac + 4);
					tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
					tuple.dst.u.udp.port = __constant_htons(65535);
					tuple.src.l3num = PF_INET;
					tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
					h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
					h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
					if (h) {
						struct user_expect *ue;
						struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
						if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
							nf_ct_put(user);
						} else {
							ue = peer_user_expect(user);
							short_set_bit(PEER_SUBTYPE_PUB_BIT, &ue->status);
							nf_ct_put(user);
						}
					}
				}
				for (i = 0; i < PEER_PUB_NUM; i++) {
					if (peer_pub_ip[i] == iph->saddr) {
						peer_pub_active[i] = jiffies;
						consume_skb(skb);
						return NF_STOLEN;
					}
				}
				i = peer_pub_idx;
				peer_pub_idx = (peer_pub_idx + 1) % PEER_PUB_NUM;
				peer_pub_ip[i] = iph->saddr;
				peer_pub_active[i] = jiffies;
				consume_skb(skb);
				return NF_STOLEN;
			}

			return NF_ACCEPT;
		}

		if (skb->len < iph->ihl * 4 + sizeof(struct tcphdr) + 8) {
			return NF_ACCEPT;
		}
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr) + 8)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_C_MAGIC)) {
			int offlen;
			if (!inet_is_local(in, iph->daddr)) {
				int ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				return NF_ACCEPT;
			} else {
				struct nf_conntrack_tuple tuple;
				struct nf_conntrack_tuple_hash *h;
				memset(&tuple, 0, sizeof(tuple));
				tuple.src.u3.ip = iph->saddr;
				tuple.src.u.udp.port = UDPH(l4)->source;
				tuple.dst.u3.ip = iph->daddr;
				tuple.dst.u.udp.port = UDPH(l4)->dest;
				tuple.src.l3num = PF_INET;
				tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
				h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
				h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
				if (h) {
					struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
					if (!(IPS_NATCAP_PEER & user->status)) {
						nf_ct_put(user);
						skb_nfct_reset(skb);
						return NF_ACCEPT;
					}
					nf_ct_put(user);
				}
			}
			if (skb->ip_summed == CHECKSUM_NONE) {
				if (skb_rcsum_verify(skb) != 0) {
					return NF_DROP;
				}
				skb->csum = 0;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}

			if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4 + 8)->doff * 4 + 8)) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4 - 8;
			BUG_ON(offlen < 0);
			memmove((void *)UDPH(l4) + 4, (void *)UDPH(l4) + 4 + 8, offlen);
			iph->tot_len = htons(ntohs(iph->tot_len) - 8);
			skb->len -= 8;
			skb->tail -= 8;
			iph->protocol = IPPROTO_TCP;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			pt_mode = PT_MODE_UDP;
			skb_nfct_reset(skb);
		} else {
			return NF_ACCEPT;
		}
	}
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	if (skb->len < iph->ihl * 4 + sizeof(struct tcphdr)) {
		return NF_ACCEPT;
	}
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (!pskb_may_pull(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (TCPH(l4)->dest == peer_sni_port && (peer_sni_ip == 0 || peer_sni_ip == iph->daddr)) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct;
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;
		struct sk_buff *prev_skb = NULL;
		unsigned char *data;
		int data_len;
		unsigned short add_data_len = 0;

		if (hooknum != NF_INET_PRE_ROUTING || !inet_is_local(in, iph->daddr)) {
			return NF_ACCEPT;
		}

		memset(&tuple, 0, sizeof(tuple));
		tuple.src.u3.ip = iph->saddr;
		tuple.src.u.tcp.port = TCPH(l4)->source;
		tuple.dst.u3.ip = iph->daddr;
		tuple.dst.u.tcp.port = TCPH(l4)->dest;
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = IPPROTO_TCP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
			nf_ct_put(user);
			skb_nfct_reset(skb);
			return NF_ACCEPT;
		}

		if (TCPH(l4)->syn && !TCPH(l4)->ack) {
			//got syn, send synack back.
			peer_sni_send_synack(in, skb);
			consume_skb(skb);
			return NF_STOLEN;
		}
		if (!skb_make_writable(skb, skb->len)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		prev_skb = peer_sni_cache_detach(iph->saddr, TCPH(l4)->source, &add_data_len);
		if (prev_skb) {
			struct iphdr *prev_iph = ip_hdr(prev_skb);
			void *prev_l4 = (void *)prev_iph + prev_iph->ihl * 4;
			int prev_data_len = ntohs(prev_iph->tot_len) - (prev_iph->ihl * 4 + TCPH(prev_l4)->doff * 4);

			data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
			data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);

			if (ntohl(TCPH(l4)->seq) == ntohl(TCPH(prev_l4)->seq) + prev_data_len + add_data_len) {
				int needmore = 0;
				if (skb->len < prev_skb->len + data_len + add_data_len &&
				        skb_tailroom(skb) < prev_skb->len + data_len + add_data_len - skb->len &&
				        pskb_expand_head(skb, 0, prev_skb->len + data_len + add_data_len - skb->len, GFP_ATOMIC)) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": pskb_expand_head failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(prev_skb);
					consume_skb(skb);
					return NF_STOLEN;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;
				data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;

				memmove(skb->data + prev_skb->len + add_data_len, data, data_len);
				memcpy(skb->data, prev_skb->data, prev_skb->len + add_data_len);
				skb->tail += prev_skb->len - skb->len;
				skb->len += prev_skb->len - skb->len;

				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;
				data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;

				consume_skb(prev_skb);

				add_data_len += data_len;
				data_len = prev_data_len + add_data_len;
				data = tls_sni_search(data, &data_len, &needmore);
				if (!data && needmore == 1) {
					if (add_data_len >= 32 * 1024 || peer_sni_cache_attach(iph->saddr, TCPH(l4)->source, skb, add_data_len) != 0) {
						NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": peer_sni_cache_attach failed with add_data_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_data_len);
						consume_skb(skb);
					}
					return NF_STOLEN;
				}
			} else {
				if (peer_sni_cache_attach(iph->saddr, TCPH(l4)->source, prev_skb, add_data_len) != 0) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": peer_sni_cache_attach failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(prev_skb);
				}
				consume_skb(skb);
				return NF_STOLEN;
			}
		} else {
			int needmore = 0;
			data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
			data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
			data = tls_sni_search(data, &data_len, &needmore);
			if (!data && needmore == 1) {
				peer_sni_send_ack(in, skb);
				if (peer_sni_cache_attach(iph->saddr, TCPH(l4)->source, skb, 0) != 0) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": peer_sni_cache_attach failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(skb);
				}
				return NF_STOLEN;
			}
		}

		if (data && data_len > 15 && data[14] == '.') { //m-0b1a29384756.xxx.com
			int n;
			int sni_type = 0;
			unsigned int a, b, c, d, e, f;
			unsigned char client_mac[ETH_ALEN];
			unsigned char x = data[data_len];
			data[data_len] = 0;
			NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got tls sni: %s\n", DEBUG_TCP_ARG(iph,l4), data);
			n = sscanf(data, "m-%02x%02x%02x%02x%02x%02x.", &a, &b, &c, &d, &e, &f);
			if (n != 6) {
				n = sscanf(data, "x-%02x%02x%02x%02x%02x%02x.", &a, &b, &c, &d, &e, &f);
				if (n != 6) {
					data[data_len] = x;
					consume_skb(skb);
					return NF_STOLEN;
				}
				sni_type = 1;
			}
			data[data_len] = x;

			client_mac[0] = a;
			client_mac[1] = b;
			client_mac[2] = c;
			client_mac[3] = d;
			client_mac[4] = e;
			client_mac[5] = f;

			if (peer_sni_auth) {
				int ret;
				struct sk_buff *uskb = uskb_of_this_cpu();
				memcpy(eth_hdr(uskb)->h_source, client_mac, ETH_ALEN);
				ret = IP_SET_test_src_mac(state, in, out, uskb, "snilist");
				if (ret <= 0) {
					return NF_DROP;
				}
			}

			memset(&tuple, 0, sizeof(tuple));
			tuple.src.u3.ip = get_byte4(client_mac);
			tuple.src.u.udp.port = get_byte2(client_mac + 4);
			tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
			tuple.dst.u.udp.port = __constant_htons(65535);
			tuple.src.l3num = PF_INET;
			tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
			h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
			h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
			if (h) {
				int ret;
				unsigned int i;
				struct tuple server;
				unsigned long mindiff = peer_port_map_timeout * HZ;
				struct sk_buff *cache_skb;
				struct peer_tuple *pt = NULL;
				struct natcap_session *ns;
				struct user_expect *ue;
				struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
				if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
					nf_ct_put(user);
					goto sni_out;
				}

				ue = peer_user_expect(user);
				for (i = 0; i < MAX_PEER_TUPLE; i++) {
					if (ue->tuple[i].connected && ue->tuple[i].sip != 0 && mindiff > uintmindiff(jiffies, ue->tuple[i].last_active)) {
						pt = &ue->tuple[i];
						mindiff = uintmindiff(jiffies, ue->tuple[i].last_active);
					}
				}
				if (pt == NULL) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					            DEBUG_TCP_ARG(iph,l4),
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
					           );
					nf_ct_put(user);
					goto sni_out;
				}
				if (pt->sni_ban && sni_type == 0) {
					nf_ct_put(user);
					goto sni_out;
				}

				spin_lock_bh(&ue->lock);
				//re-check-in-lock
				if (pt->sip == 0) {
					spin_unlock_bh(&ue->lock);
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					            DEBUG_TCP_ARG(iph,l4),
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
					            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
					           );
					nf_ct_put(user);
					goto sni_out;
				}
				if (pt->connected == 0 || pt->local_seq == 0 || pt->remote_seq == 0) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": port mapping(%s,local_seq=%u,remote_seq=%u) last_active(%u,%u) not ok\n",
					            DEBUG_TCP_ARG(iph,l4), pt->connected ? "connected" : "disconnected",
					            pt->local_seq, pt->remote_seq, pt->last_active, (unsigned int)jiffies);
					spin_unlock_bh(&ue->lock);
					nf_ct_put(user);
					goto sni_out;
				}

				cache_skb = peer_sni_to_syn(skb, pt->mode != PT_MODE_UDP ? (pt->mss < peer_max_pmtu - 40 ? pt->mss : peer_max_pmtu - 40) : peer_max_pmtu - 40);
				if (cache_skb == NULL) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": tls sni: peer_sni_to_syn failed\n", DEBUG_TCP_ARG(iph,l4));
					spin_unlock_bh(&ue->lock);
					nf_ct_put(user);
					consume_skb(cache_skb);
					goto sni_out;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, skb);
				if (ret != NF_ACCEPT) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": tls sni: nf_conntrack_in fail=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
					spin_unlock_bh(&ue->lock);
					nf_ct_put(user);
					consume_skb(cache_skb);
					goto sni_out;
				}
				ct = nf_ct_get(skb, &ctinfo);
				if (NULL == ct) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": tls sni: ct is NULL\n", DEBUG_TCP_ARG(iph,l4));
					spin_unlock_bh(&ue->lock);
					nf_ct_put(user);
					consume_skb(cache_skb);
					goto sni_out;
				}
				ns = natcap_session_in(ct);
				if (!ns) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": tls sni: natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
					spin_unlock_bh(&ue->lock);
					nf_ct_put(user);
					consume_skb(cache_skb);
					goto sni_out;
				}
				if (peer_cache_attach(ct, cache_skb) != 0) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": tls sni: peer_cache_attach failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(cache_skb);
				}

				server.ip = pt->sip;
				server.port = pt->sport;

				ns->p.peer_sip = pt->dip;
				ns->p.peer_sport = pt->dport;
				ns->p.tcp_seq_offset = pt->local_seq - (ntohl(TCPH(l4)->seq) - 1);
				ns->p.remote_seq = pt->remote_seq;
				ns->p.remote_mss = pt->mss;
				if (pt->mode == PT_MODE_UDP) {
					short_set_bit(NS_PEER_TCPUDPENC_BIT, &ns->p.status);
				}
				if (!nfct_seqadj(ct) && !nfct_seqadj_ext_add(ct)) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": seqadj_ext add failed\n", DEBUG_TCP_ARG(iph,l4));
				}

				//clear this pt
				pt->sip = 0;
				pt->dip = 0;
				pt->sport = 0;
				pt->dport = 0;
				pt->local_seq = 0;
				pt->remote_seq = 0;
				pt->connected = 0;
				pt->mode = 0;

				if ((ue->status & PEER_SUBTYPE_SSYN)) {
					short_set_bit(NS_PEER_SSYN_BIT, &ns->p.status);
				}
				spin_unlock_bh(&ue->lock);

				ret = natcap_dnat_setup(ct, server.ip, server.port);
				if (ret != NF_ACCEPT) {
					NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
				}
				xt_mark_natcap_set(XT_MARK_NATCAP_PEER2, &skb->mark);
#if defined(CONFIG_NF_CONNTRACK_MARK)
				xt_mark_natcap_set(XT_MARK_NATCAP_PEER2, &ct->mark);
#endif
				if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

				if (!(IPS_NATCAP_PEER & ct->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &ct->status)) {
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": found user expect, do DNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
				}

				nf_ct_put(user);

				return NF_ACCEPT;
			}
		}
		//got ack and payload is 0, drop ignore
		//got ack with payload > 0, parse sni host, redirect to target(send syn), cache this pkt(wait for synack)
sni_out:
		consume_skb(skb);
		return NF_STOLEN;
	}

	tcpopt = natcap_peer_decode_header(TCPH(l4));
	if (tcpopt == NULL) {
		return NF_ACCEPT;
	}

	skb_nfct_reset(skb);

	if (hooknum == NF_INET_PRE_ROUTING && !inet_is_local(in, iph->daddr)) {
		return NF_ACCEPT;
	}

	if ((TCPH(l4)->syn && TCPH(l4)->ack) ||
	        tcpopt->header.subtype == SUBTYPE_PEER_FSYN ||
	        tcpopt->header.subtype == SUBTYPE_PEER_XSYN ||
	        tcpopt->header.subtype == SUBTYPE_PEER_FSYNACK ||
	        tcpopt->header.subtype == SUBTYPE_PEER_FMSG ||
	        tcpopt->header.subtype == SUBTYPE_PEER_AUTHACK) {
		//got syn ack
		//first. lookup fakeuser_expect
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.u3.ip = iph->saddr;
		tuple.src.u.udp.port = TCPH(l4)->source;
		tuple.dst.u3.ip = iph->daddr;
		tuple.dst.u.udp.port = TCPH(l4)->dest;
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
			if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_REPLY) {
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got unexpected pong in, bypass\n", DEBUG_TCP_ARG(iph,l4));
				nf_ct_put(user);
				return NF_ACCEPT;
			}

			if (tcpopt->header.subtype == SUBTYPE_PEER_FSYN || tcpopt->header.subtype == SUBTYPE_PEER_XSYN) {
				NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got pong(ack->syn) FSYN in, pass up\n", DEBUG_TCP_ARG(iph,l4));
				TCPH(l4)->ack = 0;
				if (!TCPH(l4)->syn) {
					TCPH(l4)->syn = 1;
					TCPH(l4)->seq = htonl(ntohl(TCPH(l4)->seq) - 1);
				}
				TCPH(l4)->ack_seq = 0;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				skb_rcsum_tcpudp(skb);
				nf_ct_put(user);
				return NF_ACCEPT;
			}

			if (tcpopt->header.subtype == SUBTYPE_PEER_AUTHACK) {
				//TODO get AUTHACK
				unsigned char client_mac[ETH_ALEN];
				int auth = !!get_byte2((const void *)&tcpopt->peer.data.map_port);
				memcpy(client_mac, tcpopt->peer.data.user.mac_addr, ETH_ALEN);
				NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": get SUBTYPE_PEER_AUTHACK, mac=%02x:%02x:%02x:%02x:%02x:%02x auth=%d\n",
				            DEBUG_TCP_ARG(iph,l4), client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], auth);
				natcap_auth_user_confirm(client_mac, auth);
				nf_ct_put(user);
				consume_skb(skb);
				return NF_STOLEN;
			}

			if (tcpopt->header.subtype == SUBTYPE_PEER_FMSG) {
				//TODO get FMSG
				NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": get SUBTYPE_PEER_FMSG\n", DEBUG_TCP_ARG(iph,l4));
				nf_ct_put(user);
				consume_skb(skb);
				schedule_work(&request_natcapd_restart_work);
				return NF_STOLEN;
			}

			if (tcpopt->header.subtype == SUBTYPE_PEER_SYNACK || tcpopt->header.subtype == SUBTYPE_PEER_FSYNACK) {
				struct fakeuser_expect *fue;
				struct peer_server_node *ps;
				int pmi;
				__be16 map_port;

				ps = peer_server_node_in(iph->saddr, 0, 0);
				if (ps == NULL) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": peer_server_node not found\n", DEBUG_TCP_ARG(iph,l4));
					nf_ct_put(user);
					return NF_ACCEPT;
				}

				fue = peer_fakeuser_expect(user);
				pmi = fue->pmi;

				spin_lock_bh(&ps->lock);
				if (ps->port_map[pmi] != user || fue->local_seq + 1 != ntohl(TCPH(l4)->ack_seq)) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": peer_server_node pmi user=%px,%px mismatch\n",
					            DEBUG_TCP_ARG(iph,l4), ps->port_map[pmi], user);
					spin_unlock_bh(&ps->lock);
					nf_ct_put(user);
					return NF_ACCEPT;
				}

				map_port = get_byte2((const void *)&tcpopt->peer.data.map_port);
				if (map_port != ps->map_port) {
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": update map_port from %u to %u\n", DEBUG_TCP_ARG(iph,l4), ntohs(ps->map_port), ntohs(map_port));
					ps->map_port = map_port;
				}

				ps->last_active = fue->last_active = jiffies;
				natcap_user_timeout_touch(user, peer_conn_timeout);

				if (tcpopt->header.subtype == SUBTYPE_PEER_FSYNACK) {
					//if any synack+FSYNACK keepalive success, mark as SYN mode
					if (TCPH(l4)->syn && !(ps->status & PEER_SUBTYPE_SYN)) short_set_bit(PEER_SUBTYPE_SYN_BIT, &ps->status);
					spin_unlock_bh(&ps->lock);
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got pong(ack) SYNACK in. keepalive\n", DEBUG_TCP_ARG(iph,l4));
				} else {
					fue->state = FUE_STATE_CONNECTED;
					fue->remote_seq = ntohl(TCPH(l4)->seq);
					spin_unlock_bh(&ps->lock);
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got pong(synack) SYNACK, sending ping(ack) ACK out\n", DEBUG_TCP_ARG(iph,l4));
					natcap_peer_ping_send(skb, in, ps, pmi, fue->mss);
				}
				nf_ct_put(user);

				if (tcpopt->header.opcode == TCPOPT_PEER_V2) {
					if (skb->len >= iph->ihl * 4 + TCPH(l4)->doff * 4 + sizeof(peer_pub_ip)) {
						if (!pskb_may_pull(skb, skb->len)) {
							return NF_DROP;
						}
						iph = ip_hdr(skb);
						l4 = (void *)iph + iph->ihl * 4;
						tcpopt = natcap_peer_decode_header(TCPH(l4));

						memcpy(peer_pub_ip, l4 + TCPH(l4)->doff * 4, sizeof(peer_pub_ip));
					}
				}

				if ((user->mark & 0x3f00)) {
					struct natcap_fastpath_route *pfr;
					int line = (user->mark & 0x3f00) >> 8;
					if (line >= 1 && line <= MAX_PEER_NUM) {
						line--;
						pfr = &natcap_pfr[line];
						if (pfr->is_dead) {
							pfr->is_dead = 0;
						}
					}
				}

				skb_nfct_reset(skb);
				//pass up to icmp
				do {
					int offset, add_len;
					u8 timeval[16] = { };
					__be16 id = get_byte2((const void *)&fue->fake_icmp_time[16]);
					__be16 sequence = get_byte2((const void *)&tcpopt->peer.data.icmp_sequence);
					u16 payload_len = get_byte2((const void *)&tcpopt->peer.data.icmp_payload_len);

					payload_len = ntohs(payload_len);

					NATCAP_DEBUG("(PPI)" DEBUG_TCP_FMT ": got pong(%s) SYNACK in, id=%u seq=%u\n", DEBUG_TCP_ARG(iph,l4),
					             TCPH(l4)->syn ? "synack" : "ack", ntohs(id), ntohs(sequence));

					if (tcpopt->header.opsize >= \
					        16 + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int)) &&
					        skb->len >= iph->ihl * 4 + sizeof(struct tcphdr) + \
					        16 + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int))) {
						memcpy(timeval, fue->fake_icmp_time, 16);
					}
					if (payload_len > ICMP_PAYLOAD_LIMIT)
						payload_len = ICMP_PAYLOAD_LIMIT;

					offset = iph->ihl * 4 + sizeof(struct icmphdr) + payload_len - (skb_headlen(skb) + skb_tailroom(skb));
					add_len = offset < 0 ? 0 : offset;
					offset += skb_tailroom(skb);
					if (add_len > 0 && pskb_expand_head(skb, 0, add_len, GFP_ATOMIC)) {
						NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": pskb_expand_head failed add_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_len);
						return NF_DROP;
					}
					skb->tail += offset;
					skb->len = iph->ihl * 4 + sizeof(struct icmphdr) + payload_len;

					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;

					iph->protocol = IPPROTO_ICMP;
					iph->check = 0;
					iph->tot_len = htons(skb->len);

					ICMPH(l4)->type = ICMP_ECHOREPLY;
					ICMPH(l4)->code = 0;
					ICMPH(l4)->un.echo.id = id;
					ICMPH(l4)->un.echo.sequence = sequence;
					ICMPH(l4)->checksum = 0;
					if (payload_len >= 16) {
						memcpy(l4 + sizeof(struct icmphdr), timeval, 16);
						memset(l4 + sizeof(struct icmphdr) + 16, 0, payload_len - 16);
					} else if (payload_len > 0) {
						memcpy(l4 + sizeof(struct icmphdr), timeval, payload_len);
					}

					ip_fast_csum(iph, iph->ihl);
					ICMPH(l4)->checksum = csum_fold(skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0));
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					//set xmark to pass up
					xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
				} while (0);
			}
		} else { /* XXX no expect found, bypass */ }
		return NF_ACCEPT;

	} else if (TCPH(l4)->syn && !TCPH(l4)->ack) {
		//got syn
		struct peer_tuple *pt = NULL;
		struct nf_conn *user = NULL;
		__be32 client_ip;
		unsigned char client_mac[ETH_ALEN];

		if (tcpopt->header.subtype != SUBTYPE_PEER_SYN) {
			return NF_ACCEPT;
		}

		if (ntohl(TCPH(l4)->seq) == 0) {
			NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, but seq is 0, drop\n", DEBUG_TCP_ARG(iph,l4));
			goto syn_out;
		}

		do {
			__be16 id = get_byte2((const void *)&tcpopt->peer.data.icmp_id);
			__be16 sequence = get_byte2((const void *)&tcpopt->peer.data.icmp_sequence);
			NATCAP_DEBUG("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, id=%u seq=%u\n", DEBUG_TCP_ARG(iph,l4), ntohs(id), ntohs(sequence));
		} while (0);

		client_ip = get_byte4((const void *)&tcpopt->peer.data.user.ip);
		memcpy(client_mac, tcpopt->peer.data.user.mac_addr, ETH_ALEN);

		user = peer_user_expect_in(iph->ttl, iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, client_ip, client_mac, &pt);
		if (user != NULL && pt != NULL) {
			struct user_expect *ue = peer_user_expect(user);
			spin_lock_bh(&ue->lock);
			//re-check-in-lock
			if (pt->sip != iph->saddr || pt->dip != iph->daddr || pt->sport != TCPH(l4)->source || pt->dport != TCPH(l4)->dest) {
				//The caught duck flew
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, but pt[%pI4:%u->%pI4:%u] mismatch\n",
				            DEBUG_TCP_ARG(iph,l4), &pt->sip, ntohs(pt->sport), &pt->dip, ntohs(pt->dport));
				spin_unlock_bh(&ue->lock);
				goto syn_out;
			}

			if (ue->rt_out_magic != rt_out_magic || ue->rt_out.outdev != skb->dev) {
				ue->rt_out.l2_head_len = (char *)iph - (char *)eth_hdr(skb);
				if (ue->rt_out.l2_head_len <= NF_L2_MAX_LEN) {
					if (ue->rt_out.l2_head_len >= ETH_HLEN) {
						memcpy(((struct ethhdr *)ue->rt_out.l2_head)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
						memcpy(((struct ethhdr *)ue->rt_out.l2_head)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
						((struct ethhdr *)ue->rt_out.l2_head)->h_proto = eth_hdr(skb)->h_proto;
						memcpy(ue->rt_out.l2_head + ETH_HLEN, (char *)eth_hdr(skb) + ETH_HLEN, ue->rt_out.l2_head_len - ETH_HLEN);
					}
					ue->rt_out.outdev = skb->dev;
					ue->rt_out_magic = rt_out_magic;
				}
			}

			if (pt->sni_ban != tcpopt->header.encryption)
				pt->sni_ban = tcpopt->header.encryption;

			if (!pt->connected) {
				if (pt->remote_seq == 0) {
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, new, sending pong(synack) SYNACK back\n", DEBUG_TCP_ARG(iph,l4));
					pt->remote_seq = ntohl(TCPH(l4)->seq);
					pt->mss = natcap_tcpmss_get(TCPH(l4));
					pt->last_active = ue->last_active = jiffies;
					/* initial */
				} else if (pt->remote_seq == ntohl(TCPH(l4)->seq)) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, dup, re-sending pong(synack) SYNACK back\n", DEBUG_TCP_ARG(iph,l4));
				} else {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, pt[disconnected], seq(=%u,remote_seq=%u) mismatch, drop \n",
					            DEBUG_TCP_ARG(iph,l4), ntohl(TCPH(l4)->seq), pt->remote_seq);
					spin_unlock_bh(&ue->lock);
					goto syn_out;
				}
			} else { /* XXX Impossible */
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(syn) SYN in, pt[connected], seq(=%u,remote_seq=%u) mismatch, ignore and drop\n",
				            DEBUG_TCP_ARG(iph,l4), ntohl(TCPH(l4)->seq), pt->remote_seq);
				spin_unlock_bh(&ue->lock);
				goto syn_out;
			}
			if (pt_mode == PT_MODE_UDP) {
				pt->mode = PT_MODE_UDP;
			}
			natcap_peer_pong_send(in, skb, ue->map_port, pt, (ue->status & PEER_SUBTYPE_SSYN));
			if (tcpopt->header.opcode == TCPOPT_PEER_V2 && uintmindiff(jiffies, ue->last_active_peer) >= 60 * HZ) {
				ue->last_active_peer = jiffies;
				natcap_peer_echo_request(in, skb, client_mac);
			}

			do {
				unsigned short payload_len = get_byte2((const void *)&tcpopt->peer.data.icmp_payload_len);
				payload_len = ntohs(payload_len);
				if (payload_len >= 16 && get_byte2((const void *)&tcpopt->peer.data.icmp_id) == __constant_htons(65535)) {
					if ((tcpopt->peer.data.timeval[0] & 0xE0) == 0x20) {
						if (memcmp(&ue->in6, tcpopt->peer.data.timeval, 16) != 0) {
							memcpy(&ue->in6, tcpopt->peer.data.timeval, sizeof(ue->in6));
						}
						if (!(ue->status & PEER_SUBTYPE_PUB6)) {
							short_set_bit(PEER_SUBTYPE_PUB6_BIT, &ue->status);
						}
					} else if ((ue->status & PEER_SUBTYPE_PUB6)) {
						short_clear_bit(PEER_SUBTYPE_PUB6_BIT, &ue->status);
					}
				}
			} while (0);

			spin_unlock_bh(&ue->lock);
		}

syn_out:
		consume_skb(skb);
		if (user) put_peer_user(user);
		return NF_STOLEN;

	} else if (!TCPH(l4)->syn && TCPH(l4)->ack) {
		//got ack
		struct peer_tuple *pt = NULL;
		struct nf_conn *user = NULL;
		__be32 client_ip;
		unsigned char client_mac[ETH_ALEN];

		if (tcpopt->header.subtype == SUBTYPE_PEER_AUTH) {
			int ret = 1;

			client_ip = get_byte4((const void *)&tcpopt->peer.data.user.ip);
			memcpy(client_mac, tcpopt->peer.data.user.mac_addr, ETH_ALEN);

			if ((auth_enabled & NATCAP_AUTH_MATCH_MAC)) {
				struct sk_buff *uskb = uskb_of_this_cpu();
				memcpy(eth_hdr(uskb)->h_source, client_mac, ETH_ALEN);
				ret = IP_SET_test_src_mac(state, in, out, uskb, "vclist");
				if (ret > 0 && (auth_enabled & NATCAP_AUTH_MATCH_IP)) {
					__be32 old_ip = iph->saddr;
					iph->saddr = client_ip;
					ret = IP_SET_test_src_ip(state, in, out, skb, "vciplist");
					iph->saddr = old_ip;
				}
			}
			if (ret > 0) {
				struct nf_conntrack_tuple tuple;
				struct nf_conntrack_tuple_hash *h;
				memset(&tuple, 0, sizeof(tuple));
				tuple.src.u3.ip = get_byte4(client_mac);
				tuple.src.u.udp.port = get_byte2(client_mac + 4);
				tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
				tuple.dst.u.udp.port = __constant_htons(65535);
				tuple.src.l3num = PF_INET;
				tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
				h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
				h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
				if (h) {
					struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
					if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
						ret = 0;
						NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": SUBTYPE_PEER_AUTH, mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%pI4 auth fail0\n",
						            DEBUG_TCP_ARG(iph,l4), client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], &client_ip);
					}
					nf_ct_put(user);
				} else {
					ret = 0;
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": SUBTYPE_PEER_AUTH, mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%pI4 auth fail0\n",
					            DEBUG_TCP_ARG(iph,l4), client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], &client_ip);
				}
			}

			if (ret <= 0) {
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": SUBTYPE_PEER_AUTH, mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%pI4 auth fail\n",
				            DEBUG_TCP_ARG(iph,l4), client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], &client_ip);
			} else {
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": SUBTYPE_PEER_AUTH, mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%pI4 auth success\n",
				            DEBUG_TCP_ARG(iph,l4), client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], &client_ip);
			}

			natcap_auth_reply(in, skb, pt_mode, client_mac, ret);

			goto ack_out;
		}

		if (tcpopt->header.subtype == SUBTYPE_PEER_FACK) {
			struct nf_conntrack_tuple tuple;
			struct nf_conntrack_tuple_hash *h;
			memset(&tuple, 0, sizeof(tuple));
			tuple.src.u3.ip = iph->saddr;
			tuple.src.u.tcp.port = TCPH(l4)->source;
			tuple.dst.u3.ip = iph->daddr;
			tuple.dst.u.tcp.port = TCPH(l4)->dest;
			tuple.src.l3num = PF_INET;
			tuple.dst.protonum = IPPROTO_TCP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
			h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
			h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
			if (h) {
				struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
				struct natcap_session *ns = natcap_session_get(user);
				if ((IPS_NATCAP_PEER & user->status) && ns && NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
					TCPH(l4)->syn = 1;
					TCPH(l4)->seq = htonl(ntohl(TCPH(l4)->seq) - 1);
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);
					if (ns->p.remote_mss)
						natcap_tcpmss_set(skb, TCPH(l4), ns->p.remote_mss);
					if (ns->p.cache_index != 0) {
						int ret;
						enum ip_conntrack_info ctinfo;
						struct nf_conn *ct;
						struct sk_buff *cache_skb;

						NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": FACK https sni\n", DEBUG_TCP_ARG(iph,l4));
						ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, skb);
						if (ret != NF_ACCEPT) {
							NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": FACK https sni, nf_conntrack_in fail=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
							goto sni_skip;
						}
						ct = nf_ct_get(skb, &ctinfo);
						if (ct == NULL || ct != user) {
							NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": FACK https sni, ct=%px, user=%px mismatch\n", DEBUG_TCP_ARG(iph,l4), ct, user);
							goto sni_skip;
						}
						ret = nf_conntrack_confirm(skb);
						if (ret != NF_ACCEPT) {
							NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": FACK https sni, nf_conntrack_confirm fail=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
							goto sni_skip;
						}
						ct = nf_ct_get(skb, &ctinfo);

						cache_skb = peer_cache_detach(ct);
						if (cache_skb == NULL) {
							NATCAP_ERROR("(PPI)" DEBUG_TCP_FMT ": FACK https sni, peer_cache_detach got NULL\n", DEBUG_TCP_ARG(iph,l4));
							goto sni_skip;
						}
						nf_ct_seqadj_init(ct, ctinfo, ntohl(TCPH((char *)ip_hdr(cache_skb) + sizeof(struct iphdr))->ack_seq) - 1 - ntohl(TCPH(l4)->seq));
						sni_ack_pass_back(skb, cache_skb, ct, ns, in);
						sni_cache_skb_pass_back(skb, cache_skb, ct, ns, in, ctinfo);
						consume_skb(cache_skb);
sni_skip:
						consume_skb(skb);
						nf_ct_put(user);
						return NF_STOLEN;
					}
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(ack->synack) FACK in, pass up\n", DEBUG_TCP_ARG(iph,l4));
				} else {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack->synack) FACK in, but ct status or dir error\n", DEBUG_TCP_ARG(iph,l4));
				}
				nf_ct_put(user);
			} else {
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack->synack) FACK in, but ct not found\n", DEBUG_TCP_ARG(iph,l4));
			}
			return NF_ACCEPT;
		}

		if (tcpopt->header.subtype != SUBTYPE_PEER_SYN && tcpopt->header.subtype != SUBTYPE_PEER_SSYN && tcpopt->header.subtype != SUBTYPE_PEER_ACK) {
			NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got unexpected PEER packet in opcode=%u type=%u opsize=%u subtype=%u, ignore pass\n",
			            DEBUG_TCP_ARG(iph,l4), tcpopt->header.opcode, tcpopt->header.type, tcpopt->header.opsize, tcpopt->header.subtype);
			return NF_ACCEPT;
		}
		if (ntohl(TCPH(l4)->seq) - 1 == 0) {
			NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) %s in, but seq is 1, drop\n", DEBUG_TCP_ARG(iph,l4),
			            tcpopt->header.subtype != SUBTYPE_PEER_ACK ? "SYN" : "ACK");
			goto ack_out;
		}

		do {
			__be16 id = get_byte2((const void *)&tcpopt->peer.data.icmp_id);
			__be16 sequence = get_byte2((const void *)&tcpopt->peer.data.icmp_sequence);
			NATCAP_DEBUG("(PPI)" DEBUG_TCP_FMT ": got ping(ack) %s in, id=%u seq=%u\n", DEBUG_TCP_ARG(iph,l4),
			             tcpopt->header.subtype != SUBTYPE_PEER_ACK ? "SYN" : "ACK", ntohs(id), ntohs(sequence));
		} while (0);

		client_ip = get_byte4((const void *)&tcpopt->peer.data.user.ip);
		memcpy(client_mac, tcpopt->peer.data.user.mac_addr, ETH_ALEN);

		user = peer_user_expect_in(iph->ttl, iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, client_ip, client_mac, &pt);
		if (user != NULL && pt != NULL) {
			struct user_expect *ue = peer_user_expect(user);
			spin_lock_bh(&ue->lock);
			//re-check-in-lock
			if (pt->sip != iph->saddr || pt->dip != iph->daddr || pt->sport != TCPH(l4)->source || pt->dport != TCPH(l4)->dest) {
				//The caught duck flew
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) in, but pt[%pI4:%u->%pI4:%u] mismatch\n",
				            DEBUG_TCP_ARG(iph,l4), &pt->sip, ntohs(pt->sport), &pt->dip, ntohs(pt->dport));
				spin_unlock_bh(&ue->lock);
				goto ack_out;
			}

			if (ue->rt_out_magic != rt_out_magic || ue->rt_out.outdev != skb->dev) {
				ue->rt_out.l2_head_len = (char *)iph - (char *)eth_hdr(skb);
				if (ue->rt_out.l2_head_len <= NF_L2_MAX_LEN) {
					if (ue->rt_out.l2_head_len >= ETH_HLEN) {
						memcpy(((struct ethhdr *)ue->rt_out.l2_head)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
						memcpy(((struct ethhdr *)ue->rt_out.l2_head)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
						((struct ethhdr *)ue->rt_out.l2_head)->h_proto = eth_hdr(skb)->h_proto;
						memcpy(ue->rt_out.l2_head + ETH_HLEN, (char *)eth_hdr(skb) + ETH_HLEN, ue->rt_out.l2_head_len - ETH_HLEN);
					}
					ue->rt_out.outdev = skb->dev;
					ue->rt_out_magic = rt_out_magic;
				}
			}

			if (pt->sni_ban != tcpopt->header.encryption)
				pt->sni_ban = tcpopt->header.encryption;

			if (!pt->connected) {
				switch (tcpopt->header.subtype) {
				case SUBTYPE_PEER_ACK:
					if (pt->local_seq != 0 &&
					        pt->remote_seq != 0 &&
					        pt->remote_seq + 1 == ntohl(TCPH(l4)->seq) &&
					        pt->local_seq + 1 == ntohl(TCPH(l4)->ack_seq)) {
						NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(ack) ACK in, 3-way handshake complete\n", DEBUG_TCP_ARG(iph,l4));
						pt->connected = 1;
						pt->last_active = ue->last_active = jiffies;
						spin_unlock_bh(&ue->lock);
						goto ack_out;
					} else if (pt->local_seq == 0 && pt->remote_seq == 0 &&
					           ntohl(TCPH(l4)->seq) != 1 && ntohl(TCPH(l4)->ack_seq) != 1) {
						//This means server reload or packet droped on-the-way
						pt->remote_seq = ntohl(TCPH(l4)->seq) - 1;
						pt->local_seq = ntohl(TCPH(l4)->ack_seq) - 1;
						pt->connected = 1;
						pt->last_active = ue->last_active = jiffies;
						NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) ACK in, assume, sending pong(ack) ACK out\n", DEBUG_TCP_ARG(iph,l4));
					} else {
						NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) ACK in, seq(=%u,remote_seq=%u) ack_seq(=%u,local_seq=%u) mismatch\n",
						            DEBUG_TCP_ARG(iph,l4), ntohl(TCPH(l4)->seq), pt->remote_seq, ntohl(TCPH(l4)->ack_seq), pt->local_seq);
						spin_unlock_bh(&ue->lock);
						goto ack_out;
					}
					break;
				case SUBTYPE_PEER_SSYN:
				/* fall through */
				case SUBTYPE_PEER_SYN:
					if (tcpopt->header.subtype == SUBTYPE_PEER_SSYN) {
						if (!(ue->status & PEER_SUBTYPE_SSYN)) short_set_bit(PEER_SUBTYPE_SSYN_BIT, &ue->status);
					} else {
						if ((ue->status & PEER_SUBTYPE_SSYN)) short_clear_bit(PEER_SUBTYPE_SSYN_BIT, &ue->status);
					}
					if (pt->local_seq != 0 &&
					        pt->remote_seq != 0 &&
					        pt->remote_seq + 1 == ntohl(TCPH(l4)->seq) &&
					        pt->local_seq + 1 == ntohl(TCPH(l4)->ack_seq)) {
						NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(ack) SYN in, 3-way handshake complete\n", DEBUG_TCP_ARG(iph,l4));
						pt->connected = 1;
						pt->last_active = ue->last_active = jiffies;
						spin_unlock_bh(&ue->lock);
						goto ack_out;
					}
					if (pt->local_seq == 0 && pt->remote_seq == 0 &&
					        ntohl(TCPH(l4)->seq) != 1 && ntohl(TCPH(l4)->ack_seq) != 1) {
						//This means server reload or packet droped on-the-way
						pt->remote_seq = ntohl(TCPH(l4)->seq) - 1;
						pt->local_seq = ntohl(TCPH(l4)->ack_seq) - 1;
						pt->connected = 1;
						pt->last_active = ue->last_active = jiffies;
						NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(ack) SYN in, assume, sending pong(ack) ACK out\n", DEBUG_TCP_ARG(iph,l4));
					} else {
						NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) ACK in, seq(=%u,remote_seq=%u) ack_seq(=%u,local_seq=%u) mismatch\n",
						            DEBUG_TCP_ARG(iph,l4), ntohl(TCPH(l4)->seq), pt->remote_seq, ntohl(TCPH(l4)->ack_seq), pt->local_seq);
						spin_unlock_bh(&ue->lock);
						goto ack_out;
					}
					break;
				default: /* BUG: cannot happen, ignore */
					break;
				}
			} else if (pt->remote_seq + 1 == ntohl(TCPH(l4)->seq) && pt->local_seq + 1 == ntohl(TCPH(l4)->ack_seq)) {
				/* XXX: pt->local_seq != 0 && pt->remote_seq */
				NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": got ping(ack) %s in, keepalive, sending pong(ack) ACK out\n",
				            DEBUG_TCP_ARG(iph,l4), tcpopt->header.subtype != SUBTYPE_PEER_ACK ? "SYN" : "ACK");
				pt->last_active = ue->last_active = jiffies;
				if (tcpopt->header.subtype == SUBTYPE_PEER_SSYN) {
					if (!(ue->status & PEER_SUBTYPE_SSYN)) short_set_bit(PEER_SUBTYPE_SSYN_BIT, &ue->status);
				} else {
					if ((ue->status & PEER_SUBTYPE_SSYN)) short_clear_bit(PEER_SUBTYPE_SSYN_BIT, &ue->status);
				}
			} else {
				NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": got ping(ack) %s in, seq(=%u,remote_seq=%u) ack_seq(=%u,local_seq=%u) mismatch\n",
				            DEBUG_TCP_ARG(iph,l4),
				            tcpopt->header.subtype != SUBTYPE_PEER_ACK ? "SYN" : "ACK",
				            ntohl(TCPH(l4)->seq), pt->remote_seq, ntohl(TCPH(l4)->ack_seq), pt->local_seq);
				spin_unlock_bh(&ue->lock);
				goto ack_out;
			}
			natcap_peer_pong_send(in, skb, ue->map_port, pt, (ue->status & PEER_SUBTYPE_SSYN));
			if (tcpopt->header.opcode == TCPOPT_PEER_V2 && uintmindiff(jiffies, ue->last_active_peer) >= 120 * HZ) {
				ue->last_active_peer = jiffies;
				natcap_peer_echo_request(in, skb, client_mac);
			}

			do {
				unsigned short payload_len = get_byte2((const void *)&tcpopt->peer.data.icmp_payload_len);
				payload_len = ntohs(payload_len);
				if (payload_len >= 16 && get_byte2((const void *)&tcpopt->peer.data.icmp_id) == __constant_htons(65535)) {
					if ((tcpopt->peer.data.timeval[0] & 0xE0) == 0x20) {
						if (memcmp(&ue->in6, tcpopt->peer.data.timeval, 16) != 0) {
							memcpy(&ue->in6, tcpopt->peer.data.timeval, sizeof(ue->in6));
						}
						if (!(ue->status & PEER_SUBTYPE_PUB6)) {
							short_set_bit(PEER_SUBTYPE_PUB6_BIT, &ue->status);
						}
					} else if ((ue->status & PEER_SUBTYPE_PUB6)) {
						short_clear_bit(PEER_SUBTYPE_PUB6_BIT, &ue->status);
					}
				}
			} while (0);

			spin_unlock_bh(&ue->lock);
		}

ack_out:
		consume_skb(skb);
		if (user) put_peer_user(user);
		return NF_STOLEN;
	} else { /* XXX no expect found, bypass */ }

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_icmpv6_pre_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET6;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_icmpv6_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_icmpv6_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_icmpv6_pre_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	struct ipv6hdr *ipv6h;
	struct icmp6hdr *icmp6h;
	unsigned char client_mac[ETH_ALEN];
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct net *net = &init_net;

	if (peer_stop)
		return NF_ACCEPT;

	ipv6h = ipv6_hdr(skb);
	if (ipv6h->nexthdr != NEXTHDR_ICMP ||
	        (ipv6h->daddr.s6_addr[0] != 0x3f || ipv6h->daddr.s6_addr[1] != 0x99)) {
		return NF_ACCEPT;
	}

	if (memcmp(ipv6h->daddr.s6_addr, "\x3f\x99\xAA\xBB\xCC\xDD\xEE\xFF", 8) == 0) {
		NATCAP_INFO("(IPI): local ip6=%pI6\n", &ipv6h->saddr);
		memcpy(&peer_local_ip6_addr, &ipv6h->saddr, sizeof(peer_local_ip6_addr));
		consume_skb(skb);
		return NF_STOLEN;
	}

	//ping6 ff99:AABB:CCDD:EEFF:: -t1 -s1 -w1
	memcpy(client_mac, &ipv6h->daddr.s6_addr[2], ETH_ALEN);

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = get_byte4(client_mac);
	tuple.src.u.udp.port = get_byte2(client_mac + 4);
	tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
	tuple.dst.u.udp.port = __constant_htons(65535);
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif

	if (h) {
		struct peer_tuple pt_m;
		struct peer_tuple *pt = NULL;
		struct user_expect *ue;
		unsigned long mindiff = peer_port_map_timeout * HZ;
		int i;
		struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
		if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
			nf_ct_put(user);
			return NF_ACCEPT;
		}

		ue = peer_user_expect(user);
		if (ue->rt_out_magic != rt_out_magic) {
			nf_ct_put(user);
			return NF_ACCEPT;
		}

		for (i = 0; i < MAX_PEER_TUPLE; i++) {
			if (ue->tuple[i].connected && ue->tuple[i].sip != 0 && mindiff > uintmindiff(jiffies, ue->tuple[i].last_active)) {
				pt = &ue->tuple[i];
				mindiff = uintmindiff(jiffies, ue->tuple[i].last_active);
			}
		}

		if (pt == NULL) {
			NATCAP_WARN("(IPI): no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
			           );
			put_peer_user(user);
			return NF_ACCEPT;
		}

		spin_lock_bh(&ue->lock);
		//re-check-in-lock
		if (pt->sip == 0) {
			spin_unlock_bh(&ue->lock);
			NATCAP_WARN("(IPI): no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
			           );
			put_peer_user(user);
			return NF_ACCEPT;
		}
		if (pt->connected == 0 || pt->local_seq == 0 || pt->remote_seq == 0) {
			NATCAP_WARN("(IPI): port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x](%s,local_seq=%u,remote_seq=%u) last_active(%u,%u) not ok\n",
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
			            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1],
			            pt->connected ? "connected" : "disconnected",
			            pt->local_seq, pt->remote_seq, pt->last_active, (unsigned int)jiffies);
			spin_unlock_bh(&ue->lock);
			put_peer_user(user);
			return NF_ACCEPT;
		}
		memcpy(&pt_m, pt, sizeof(struct peer_tuple));
		spin_unlock_bh(&ue->lock);
		pt = &pt_m;

		do {
			struct sk_buff *nskb;
			struct iphdr *niph;
			struct tcphdr *ntcph;
			struct natcap_TCPOPT *tcpopt;

			u8 protocol = IPPROTO_TCP;
			int opt_header_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
			int nlen = ue->rt_out.l2_head_len + sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_header_len;

			if (pt->mode == PT_MODE_UDP) {
				protocol = IPPROTO_UDP;
				nlen += 8;
			}

			nskb = netdev_alloc_skb(ue->rt_out.outdev, nlen + NET_IP_ALIGN);
			if (nskb == NULL) {
				break;
			}
			skb_reserve(nskb, NET_IP_ALIGN);
			skb_put(nskb, nlen);
			skb_reset_mac_header(nskb);
			skb_pull(nskb, ue->rt_out.l2_head_len);
			skb_reset_network_header(nskb);

			memcpy((void *)eth_hdr(nskb), ue->rt_out.l2_head, ue->rt_out.l2_head_len);

			niph = ip_hdr(nskb);
			memset(niph, 0, sizeof(struct iphdr));
			niph->saddr = pt->dip;
			niph->daddr = pt->sip;
			niph->version = 4;
			niph->ihl = sizeof(struct iphdr) / 4;
			niph->tos = 0;
			niph->tot_len = htons(nskb->len);
			niph->ttl = 255;
			niph->protocol = protocol;
			niph->id = htons(jiffies);
			niph->frag_off = 0x0;

			ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
			ntcph->source = pt->dport;
			ntcph->dest = pt->sport;
			if (protocol == IPPROTO_UDP) {
				UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
				set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(NATCAP_C_MAGIC));
				ntcph = (struct tcphdr *)((char *)ntcph + 8);
			}
			ntcph->ack_seq = htonl(pt->remote_seq + 1);
			ntcph->seq = htonl(pt->local_seq + 1);
			tcp_flag_word(ntcph) = (TCP_FLAG_ACK);
			ntcph->res1 = 0;
			ntcph->doff = (sizeof(struct tcphdr) + opt_header_len) / 4;
			ntcph->window = __constant_htons(65535);
			ntcph->check = 0;
			ntcph->urg_ptr = 0;

			tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
			tcpopt->header.opcode = TCPOPT_PEER_V2;
			tcpopt->header.opsize = opt_header_len;
			tcpopt->header.encryption = 0;
			tcpopt->header.subtype =  SUBTYPE_PEER_FMSG;

			NATCAP_ERROR("(IPI)" DEBUG_TCP_FMT ": send FMSG nlen=%d,%d\n", DEBUG_TCP_ARG(niph,ntcph), nlen, nskb->len);

			nskb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(nskb);

			skb_push(nskb, (char *)ip_hdr(nskb) - (char *)eth_hdr(nskb));
			dev_queue_xmit(nskb);

			icmp6h = (struct icmp6hdr *)((char *)ipv6h + sizeof(struct ipv6hdr));
			//printk("%pI6->%pI6\n", &ipv6h->saddr, &ipv6h->daddr);
			//TODO ack icmp6 reply back

			consume_skb(skb);
			return NF_STOLEN;
		} while (0);
		//TODO
		nf_ct_put(user);
	} else {
		NATCAP_WARN("ICMP6: target %02x:%02x:%02x:%02x:%02x:%02x not found\n",
		            client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_post_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_post_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_post_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_post_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	int ret;
	struct sk_buff *nskb;
	struct iphdr *iph;
	void *l4;

	if (peer_stop)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	if (iph->protocol != IPPROTO_ICMP) {
		return NF_ACCEPT;
	}
	if (iph->ttl != 1 || xt_mark_natcap_get(&skb->mark) != XT_MARK_NATCAP) {
		return NF_ACCEPT;
	}
	if (skb->len > iph->ihl * 4 + sizeof(struct icmphdr) + ICMP_PAYLOAD_LIMIT) {
		return NF_ACCEPT;
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}
	skb_nfct_reset(skb);

	if ((skb->mark & 0x3f00)) {
		struct natcap_fastpath_route *pfr;
		int line = (skb->mark & 0x3f00) >> 8;
		if (line >= 1 && line <= MAX_PEER_NUM) {
			line--;
			pfr = &natcap_pfr[line];

			//printk("line %d outdev=%s saddr=%pI4\n", line, skb->dev->name, &iph->saddr);
			if (iph->daddr == PEER_DEAD_ADDR) { /* PEER_DEAD_ADDR = 13.14.10.13 dead */
				pfr->is_dead = 1;
				goto out;
			} else if (iph->daddr == PEER_SET_WEIGHT_ADDR) { /* PEER_SET_WEIGHT_ADDR = 13.14.10.14 set weight */
				pfr->weight = skb->len - iph->ihl * 4 - sizeof(struct icmphdr);
				goto out;
			}
		}
	}

	NATCAP_DEBUG("(PPO)" DEBUG_ICMP_FMT ": ping out\n", DEBUG_ICMP_ARG(iph,l4));
	nskb = natcap_peer_ping_send(skb, NULL, NULL, 0, 0);
	if (nskb != NULL) {
		iph = ip_hdr(nskb);
		l4 = (void *)iph + iph->ihl * 4;
		if (iph->protocol == IPPROTO_TCP) {
			NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": %s\n", DEBUG_TCP_ARG(iph,l4), TCPH(l4)->syn ? "send ping(syn) SYN out" : "send ping(ack) ACK out");
		} else {
			NATCAP_INFO("(PPI)" DEBUG_UDP_FMT ": %s\n", DEBUG_UDP_ARG(iph,l4), TCPH(l4 + 8)->syn ? "send ping(syn) SYN out" : "send ping(ack) ACK out");
		}
		NF_OKFN(nskb);
	}

out:
	consume_skb(skb);
	return NF_STOLEN;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_dnat_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_dnat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_dnat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_dnat_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret;
	enum ip_conntrack_info ctinfo;
	struct net *net = &init_net;
	struct nf_conn *ct;
	struct nf_conn *user;
	struct iphdr *iph;
	void *l4;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct tuple server;
	unsigned int port;
	int is_knock = 0;

	if (peer_stop)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_PEER & ct->status)) {
#if defined(CONFIG_NF_CONNTRACK_MARK)
		xt_mark_natcap_set(ct->mark, &skb->mark);
#else
		xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
#endif
		if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
		return NF_ACCEPT;
	}
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (!TCPH(l4)->syn || TCPH(l4)->ack) {
		//not syn
		return NF_ACCEPT;
	}

	if (hooknum == NF_INET_PRE_ROUTING && !inet_is_local(in, iph->daddr)) {
		return NF_ACCEPT;
	}
	if (ipv4_is_loopback(iph->daddr)) {
		return NF_ACCEPT;
	}

	if (TCPH(l4)->dest == peer_knock_local_port) {
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.u3.ip = get_byte4(peer_knock_mac);
		tuple.src.u.udp.port = get_byte2(peer_knock_mac + 4);
		tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
		tuple.dst.u.udp.port = htons(65535);
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = IPPROTO_UDP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct user_expect *ue;
			user = nf_ct_tuplehash_to_ctrack(h);
			ue = peer_user_expect(user);
			port = ntohs(ue->map_port);
			is_knock = 1;
			nf_ct_put(user);
			goto knock;
		}
		return NF_ACCEPT;
	}

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = iph->saddr;
	tuple.src.u.udp.port = TCPH(l4)->source;
	tuple.dst.u3.ip = iph->daddr;
	tuple.dst.u.udp.port = TCPH(l4)->dest;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = IPPROTO_UDP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
	if (h) {
		int pmi;
		unsigned short mss;
		struct peer_server_node *ps;
		struct fakeuser_expect *fue;
		struct natcap_session *ns;
		struct natcap_TCPOPT *tcpopt;

		user = nf_ct_tuplehash_to_ctrack(h);
		if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_REPLY) {
			NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": user found but status or dir mismatch\n", DEBUG_TCP_ARG(iph,l4));
			goto h_out;
		}
		//XXX fire expect. renew this user for fast timeout
		natcap_user_timeout_touch(user, NATCAP_PEER_EXPECT_TIMEOUT);

		fue = peer_fakeuser_expect(user);
		pmi = fue->pmi;

		ns = natcap_session_in(ct);
		if (!ns) {
			NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
			goto h_out;
		}
		ns->p.local_seq = fue->local_seq; //can't be 0
		if (fue->mode == FUE_MODE_UDP) {
			short_set_bit(NS_PEER_TCPUDPENC_BIT, &ns->p.status);
		}

		ps = peer_server_node_in(iph->saddr, 0, 0);
		if (ps == NULL) {
			NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": peer_server_node not found, just bypass\n", DEBUG_TCP_ARG(iph,l4));
			goto h_bypass;
		}

		spin_lock_bh(&ps->lock);
		if (ps->port_map[pmi] != user) {
			NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": mismatch pmi user=%p,%p, just bypass\n", DEBUG_TCP_ARG(iph,l4), ps->port_map[pmi], user);
			spin_unlock_bh(&ps->lock);
			goto h_bypass;
		}
		ps->last_inuse = jiffies;
		mss = fue->mss;
		nf_ct_put(ps->port_map[pmi]);
		ps->port_map[pmi] = NULL;
		spin_unlock_bh(&ps->lock);

		//create a new session
		//it must return NULL
		natcap_peer_ping_send(skb, in, ps, pmi, mss);

h_bypass:
		tcpopt = natcap_peer_decode_header(TCPH(l4));
		if (tcpopt != NULL && tcpopt->header.subtype == SUBTYPE_PEER_XSYN) {
			struct natcap_TCPOPT_dst *optdst = (struct natcap_TCPOPT_dst *)((void *)tcpopt + sizeof(struct natcap_TCPOPT_header));
			server.ip = get_byte4((void *)&optdst->ip);
			server.port = get_byte2((void *)&optdst->port);
			if (server.ip == 0) {
				server.ip = iph->daddr;
			} else if (server.ip == PEER_XSYN_MASK_ADDR) {
				server.ip = peer_xsyn_enumerate_addr();
			}
		} else {
			server.ip = peer_local_ip == 0 ? iph->daddr : peer_local_ip;
			server.port = peer_local_port;
		}

		ret = natcap_dnat_setup(ct, server.ip, server.port);
		if (ret != NF_ACCEPT) {
			NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		}
		xt_mark_natcap_set(XT_MARK_NATCAP_PEER1, &skb->mark);
#if defined(CONFIG_NF_CONNTRACK_MARK)
		xt_mark_natcap_set(XT_MARK_NATCAP_PEER1, &ct->mark);
#endif
		if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

		if (!(IPS_NATCAP_PEER & ct->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &ct->status)) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": found fakeuser expect, do DNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		}

h_out:
		nf_ct_put(user);
		return NF_ACCEPT;
	} else {
		if (peer_open_portmap == 0) {
			return NF_ACCEPT;
		}
		port = ntohs(TCPH(l4)->dest);
knock:
		user = get_peer_user(port);
		if (user) {
			unsigned int i;
			unsigned long mindiff = peer_port_map_timeout * HZ;
			struct peer_tuple *pt = NULL;
			struct natcap_session *ns;
			struct user_expect *ue = peer_user_expect(user);
			if (ntohs(ue->map_port) != port) {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": map_port=%u dest=%u mismatch\n", DEBUG_TCP_ARG(iph,l4), ntohs(ue->map_port), port);
				put_peer_user(user);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
				put_peer_user(user);
				return NF_ACCEPT;
			}

			for (i = 0; i < MAX_PEER_TUPLE; i++) {
				if (ue->tuple[i].connected && ue->tuple[i].sip != 0 && mindiff > uintmindiff(jiffies, ue->tuple[i].last_active)) {
					pt = &ue->tuple[i];
					mindiff = uintmindiff(jiffies, ue->tuple[i].last_active);
				}
			}

			if (pt == NULL) {
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
				            DEBUG_TCP_ARG(iph,l4),
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
				           );
				put_peer_user(user);
				return NF_ACCEPT;
			}

			spin_lock_bh(&ue->lock);
			//re-check-in-lock
			if (pt->sip == 0) {
				spin_unlock_bh(&ue->lock);
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": no available port mapping for user[%02x:%02x:%02x:%02x:%02x:%02x]\n",
				            DEBUG_TCP_ARG(iph,l4),
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[0],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[1],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[2],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)[3],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[0],
				            ((unsigned char *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all)[1]
				           );
				put_peer_user(user);
				return NF_ACCEPT;
			}
			if (pt->connected == 0 || pt->local_seq == 0 || pt->remote_seq == 0) {
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": port mapping(%s,local_seq=%u,remote_seq=%u) last_active(%u,%u) not ok\n",
				            DEBUG_TCP_ARG(iph,l4), pt->connected ? "connected" : "disconnected",
				            pt->local_seq, pt->remote_seq, pt->last_active, (unsigned int)jiffies);
				spin_unlock_bh(&ue->lock);
				put_peer_user(user);
				return NF_ACCEPT;
			}

			server.ip = pt->sip;
			server.port = pt->sport;

			ns->p.peer_sip = pt->dip;
			ns->p.peer_sport = pt->dport;
			ns->p.tcp_seq_offset = pt->local_seq - ntohl(TCPH(l4)->seq);
			ns->p.remote_seq = pt->remote_seq;
			ns->p.remote_mss = pt->mss;
			if (pt->mode == PT_MODE_UDP) {
				short_set_bit(NS_PEER_TCPUDPENC_BIT, &ns->p.status);
			}
			if (!nfct_seqadj(ct) && !nfct_seqadj_ext_add(ct)) {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": seqadj_ext add failed\n", DEBUG_TCP_ARG(iph,l4));
			}

			//clear this pt
			pt->sip = 0;
			pt->dip = 0;
			pt->sport = 0;
			pt->dport = 0;
			pt->local_seq = 0;
			pt->remote_seq = 0;
			pt->connected = 0;
			pt->mode = 0;

			if ((ue->status & PEER_SUBTYPE_SSYN)) {
				short_set_bit(NS_PEER_SSYN_BIT, &ns->p.status);
			}
			spin_unlock_bh(&ue->lock);

			if (is_knock) {
				short_set_bit(NS_PEER_KNOCK_BIT, &ns->p.status);
			}

			ret = natcap_dnat_setup(ct, server.ip, server.port);
			if (ret != NF_ACCEPT) {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			}
			xt_mark_natcap_set(XT_MARK_NATCAP_PEER3, &skb->mark);
#if defined(CONFIG_NF_CONNTRACK_MARK)
			xt_mark_natcap_set(XT_MARK_NATCAP_PEER3, &ct->mark);
#endif
			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

			if (!(IPS_NATCAP_PEER & ct->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &ct->status)) {
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": found user expect, do DNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			}
			put_peer_user(user);
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_snat_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_snat_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret;
	int dir;
	enum ip_conntrack_info ctinfo;
	struct net *net = &init_net;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_session *ns;
	struct tuple server;

	if (peer_stop)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP_PEER & ct->status)) {
		return NF_ACCEPT;
	}
	ns = natcap_session_get(ct);
	if (ns == NULL) {
		NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": ns not found\n", DEBUG_TCP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL) {
		if (ns->p.local_seq == 0) {
			//on server side
			return NF_ACCEPT;
		}

		if ((TCPH(l4)->syn && TCPH(l4)->ack)) {
			//encode synack
			struct natcap_TCPOPT *tcpopt;
			int offlen;
			int add_len = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

			if (add_len + TCPH(l4)->doff * 4 > 60) {
				NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": add_len=%u doff=%u over 60\n", DEBUG_TCP_ARG(iph,l4), add_len, TCPH(l4)->doff * 4);
				return NF_ACCEPT;
			}

			if (skb_tailroom(skb) < add_len && pskb_expand_head(skb, 0, add_len, GFP_ATOMIC)) {
				NATCAP_ERROR("(PS)" DEBUG_TCP_FMT ": pskb_expand_head failed add_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_len);
				return NF_ACCEPT;
			}
			iph = ip_hdr(skb);
			l4 = (struct tcphdr *)((void *)iph + iph->ihl * 4);

			offlen = skb_tail_pointer(skb) - (unsigned char *)l4 - sizeof(struct tcphdr);
			BUG_ON(offlen < 0);
			memmove((void *)l4 + sizeof(struct tcphdr) + add_len, (void *)l4 + sizeof(struct tcphdr), offlen);

			skb->len += add_len;
			skb->tail += add_len;

			tcpopt = (void *)l4 + sizeof(struct tcphdr);
			tcpopt = (struct natcap_TCPOPT *)((void *)l4 + sizeof(struct tcphdr));
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
			tcpopt->header.opcode = TCPOPT_PEER;
			tcpopt->header.opsize = add_len;
			tcpopt->header.encryption = 0;
			tcpopt->header.subtype = SUBTYPE_PEER_FACK;

			if (ns->p.tcp_seq_offset == 0) {
				ns->p.tcp_seq_offset = ns->p.local_seq - ntohl(TCPH(l4)->seq);
			}
			if (nf_ct_seq_offset(ct, dir, ntohl(TCPH(l4)->seq + 1)) != ns->p.tcp_seq_offset) {
				nf_ct_seqadj_init(ct, ctinfo, ns->p.tcp_seq_offset);
			}

			TCPH(l4)->seq = htonl(ntohl(TCPH(l4)->seq) + 1);
			TCPH(l4)->syn = 0;
			TCPH(l4)->doff = (TCPH(l4)->doff * 4 + add_len) / 4;
			iph->tot_len = htons(ntohs(iph->tot_len) + add_len);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if ((NS_PEER_TCPUDPENC & ns->p.status)) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8, peer_max_pmtu - 40);
			} else {
				natcap_tcpmss_adjust(skb, TCPH(l4), 0, peer_max_pmtu - 40);
			}
		}
		return NF_ACCEPT;

	} else {
		if (ns->p.local_seq != 0) {
			//on client
			return NF_ACCEPT;
		}

		if (TCPH(l4)->syn && !TCPH(l4)->ack) {
			//encode syn
			struct natcap_TCPOPT *tcpopt;
			struct natcap_TCPOPT_dst *optdst;
			int offlen;
			int add_len = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

			if ((NS_PEER_KNOCK & ns->p.status)) {
				add_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int));
			}

			if (add_len + TCPH(l4)->doff * 4 > 60) {
				NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": add_len=%u doff=%u over 60\n", DEBUG_TCP_ARG(iph,l4), add_len, TCPH(l4)->doff * 4);
				return NF_DROP;
			}

			if (skb_tailroom(skb) < add_len && pskb_expand_head(skb, 0, add_len, GFP_ATOMIC)) {
				NATCAP_ERROR("(PS)" DEBUG_TCP_FMT ": pskb_expand_head failed add_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_len);
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (struct tcphdr *)((void *)iph + iph->ihl * 4);

			offlen = skb_tail_pointer(skb) - (unsigned char *)l4 - sizeof(struct tcphdr);
			BUG_ON(offlen < 0);
			memmove((void *)l4 + sizeof(struct tcphdr) + add_len, (void *)l4 + sizeof(struct tcphdr), offlen);

			skb->len += add_len;
			skb->tail += add_len;

			tcpopt = (struct natcap_TCPOPT *)((void *)l4 + sizeof(struct tcphdr));
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
			tcpopt->header.opcode = TCPOPT_PEER;
			tcpopt->header.opsize = add_len;
			tcpopt->header.encryption = 0;
			tcpopt->header.subtype = SUBTYPE_PEER_FSYN;
			if ((NS_PEER_KNOCK & ns->p.status)) {
				tcpopt->header.subtype = SUBTYPE_PEER_XSYN;
				optdst = (struct natcap_TCPOPT_dst *)((void *)tcpopt + sizeof(struct natcap_TCPOPT_header));
				set_byte4((void *)&optdst->ip, peer_knock_ip);
				set_byte2((void *)&optdst->port, peer_knock_port);
			}

			if (nf_ct_seq_offset(ct, dir, ntohl(TCPH(l4)->seq) + 1) != ns->p.tcp_seq_offset) {
				nf_ct_seqadj_init(ct, ctinfo, ns->p.tcp_seq_offset);
			}

			if ((ns->p.status & NS_PEER_SSYN)) {
				TCPH(l4)->seq = htonl(ntohl(TCPH(l4)->seq) + 1);
				TCPH(l4)->syn = 0;
			}
			TCPH(l4)->ack_seq = htonl(ns->p.remote_seq + 1);
			TCPH(l4)->ack = 1;
			TCPH(l4)->doff = (TCPH(l4)->doff * 4 + add_len) / 4;
			iph->tot_len = htons(ntohs(iph->tot_len) + add_len);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if ((NS_PEER_TCPUDPENC & ns->p.status)) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8, peer_max_pmtu - 40);
			} else {
				natcap_tcpmss_adjust(skb, TCPH(l4), 0, peer_max_pmtu - 40);
			}
		}
	} // end dir IP_CT_DIR_ORIGINAL

	//for server side
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}

	server.ip = ns->p.peer_sip;
	server.port = ns->p.peer_sport;

	NATCAP_INFO("(PS)" DEBUG_TCP_FMT ": found user expect, doing SNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));

	ret = natcap_snat_setup(ct, server.ip, server.port);
	if (ret != NF_ACCEPT) {
		NATCAP_ERROR("(PS)" DEBUG_TCP_FMT ": natcap_snat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_push_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_push_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_push_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_push_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret;
	int dir;
	enum ip_conntrack_info ctinfo;
	struct net *net = &init_net;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_session *ns;

	if (peer_stop)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP_PEER & ct->status)) {
		return NF_ACCEPT;
	}
	ns = natcap_session_get(ct);
	if (ns == NULL) {
		NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": ns not found\n", DEBUG_TCP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL) {
		if (ns->p.local_seq == 0) {
			//on server side
			return NF_ACCEPT;
		}
	} else {
		if (ns->p.local_seq != 0) {
			//on client
			return NF_ACCEPT;
		}
	}

	if (!(NS_PEER_TCPUDPENC & ns->p.status)) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) && !nf_is_loopback_packet(skb)) {
		if (!nf_ct_seq_adjust(skb, ct, ctinfo, skb_network_offset(skb) + ip_hdrlen(skb))) {
			return NF_DROP;
		}
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	if (skb_is_gso(skb)) {
		struct sk_buff *segs;

		segs = skb_gso_segment(skb, 0);
		if (IS_ERR(segs)) {
			return NF_DROP;
		}
		consume_skb(skb);
		skb = segs;
	}

	do {
		int offlen;
		struct sk_buff *nskb = skb->next;

		if (skb_tailroom(skb) < 8 && pskb_expand_head(skb, 0, 8, GFP_ATOMIC)) {
			consume_skb(skb);
			skb = nskb;
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head failed\n", DEBUG_ARG_PREFIX);
			continue;
		}

		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(l4) + 4 + 8, (void *)UDPH(l4) + 4, offlen);
		iph->tot_len = htons(ntohs(iph->tot_len) + 8);
		UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
		UDPH(l4)->check = CSUM_MANGLED_0;
		skb->len += 8;
		skb->tail += 8;
		set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_C_MAGIC));
		iph->protocol = IPPROTO_UDP;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(skb);

		skb->next = NULL;
		NF_OKFN(skb);

		skb = nskb;
	} while (skb);

	return NF_STOLEN;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_dns_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_dns_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_dns_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_dns_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = NF_ACCEPT;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct net *net = &init_net;
	struct iphdr *iph;
	void *l4;

	if (peer_stop)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	if (UDPH(l4)->dest != __constant_htons(53)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (!skb_make_writable(skb, skb->len)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	do {
		struct in6_addr in6;
		__be32 ip = 0;
		unsigned short ip6 = 0;
		unsigned short id = 0;
		int i = 0, pos;
		unsigned int v;
		unsigned short flags;
		unsigned short qd_count;
		unsigned short an_count;
		unsigned short ns_count;
		unsigned short ar_count;
		struct sk_buff *nskb = NULL;

		unsigned char *p = (unsigned char *)UDPH(l4) + sizeof(struct udphdr);
		int len = skb->len - iph->ihl * 4 - sizeof(struct udphdr);

		id = ntohs(get_byte2(p + 0));
		flags = ntohs(get_byte2(p + 2));
		qd_count = ntohs(get_byte2(p + 4));
		an_count = ntohs(get_byte2(p + 6));
		ns_count = ntohs(get_byte2(p + 8));
		ar_count = ntohs(get_byte2(p + 10));

		pos = 12;
		for(i = 0; i < qd_count; i++) {
			unsigned char *an_p = NULL;
			unsigned short qtype, qclass;
			int ar_pad_len = 0;
			int qname_off = 0;
			int qname_len = 0;
			char qname[128];
			int n;
			unsigned int a, b, c, d, e, f;
			unsigned char client_mac[ETH_ALEN];
			struct nf_conntrack_tuple tuple;
			struct nf_conntrack_tuple_hash *h;

			if (pos >= len) {
				break;
			}

			if ((qname_len = get_rdata(p, len, pos, qname, 127)) >= 0) {
				qname[qname_len] = 0;
			}
			if (qname_len <= 0) {
				break;
			}
			qname_off = pos;

			while (pos < len && ((v = get_byte1(p + pos)) != 0)) {
				if (v > 0x3f) {
					pos++;
					break;
				} else {
					pos += v + 1;
				}
			}
			pos++;

			if (pos + 1 >= len) {
				break;
			}
			qtype = ntohs(get_byte2(p + pos));
			pos += 2;

			if (pos + 1 >= len) {
				break;
			}
			qclass = ntohs(get_byte2(p + pos));
			pos += 2;

			NATCAP_DEBUG("(PD)" DEBUG_UDP_FMT ": id=0x%04x, qtype=%d, qclass=%d, qname=%s\n", DEBUG_UDP_ARG(iph,l4), id, qtype, qclass, qname);

			if (qtype != 0x0001 && qtype != 0x001c) {
				break;
			}

			if (strncasecmp(qname, "x-wrt.lan", 9) == 0) {
				ip = iph->daddr;
				goto reply_dns;
			}

			if (peer_dns_server == 0) {
				break;
			}

			if (ret != NF_DROP) {
				int i;
				while (qname[i] != '.' && qname[i]) i++;
				if (strncasecmp(qname + i, ".dns.x-wrt.", 11) == 0 ||
				        strncasecmp(qname + i, ".ns.x-wrt.", 10) == 0 ||
				        strncasecmp(qname + i, ".xns.x-wrt.", 11) == 0 ||
				        strncasecmp(qname + i, ".dns.ptpt52.", 12) == 0) {
					ret = NF_DROP;
				} else {
					break;
				}
			}

			n = sscanf(qname, "%02x%02x%02x%02x%02x%02x.", &a, &b, &c, &d, &e, &f);
			if (n != 6) {
				if (ret == NF_DROP) {
					goto reply_dns;
				}
				break;
			}
			client_mac[0] = a;
			client_mac[1] = b;
			client_mac[2] = c;
			client_mac[3] = d;
			client_mac[4] = e;
			client_mac[5] = f;

			memset(&tuple, 0, sizeof(tuple));
			tuple.src.u3.ip = get_byte4(client_mac);
			tuple.src.u.udp.port = get_byte2(client_mac + 4);
			tuple.dst.u3.ip = PEER_FAKEUSER_DADDR;
			tuple.dst.u.udp.port = __constant_htons(65535);
			tuple.src.l3num = PF_INET;
			tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
			h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
			h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
			if (h) {
				struct user_expect *ue;
				struct nf_conn *user = nf_ct_tuplehash_to_ctrack(h);
				if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
					nf_ct_put(user);
					break;
				}

				ue = peer_user_expect(user);
				if ((ue->status & PEER_SUBTYPE_PUB6)) {
					ip6 = 1;
					memcpy(&in6, &ue->in6, sizeof(in6));
				}
				if (ue->ip == ue->local_ip || (ue->status & PEER_SUBTYPE_PUB) ||
				        (qname[12] == '.' && (qname[13] == 'n' || qname[13] == 'N') && (qname[14] == 's' || qname[14] == 'S') && qname[15] == '.')) {
					ip = ue->ip;
				}
				nf_ct_put(user);
			}
reply_dns:
			if (nskb == NULL) {
				struct ethhdr *neth;
				struct iphdr *niph;
				struct udphdr *nudph;
				int offset = skb_headlen(skb) + 128 - (skb_headlen(skb) + skb_tailroom(skb));
				int add_len = offset < 0 ? 0 : offset;
				nskb = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
				if (!nskb) {
					break;
				}

				neth = eth_hdr(nskb);
				niph = ip_hdr(nskb);
				if ((char *)niph - (char *)neth >= ETH_HLEN) {
					memcpy(neth->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
					memcpy(neth->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
					//neth->h_proto = htons(ETH_P_IP);
				}

				niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;

				nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);
				nudph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				nudph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				nudph->check = CSUM_MANGLED_0;

				if (skb->len > niph->ihl * 4 + sizeof(struct udphdr) + pos &&
				        an_count == 0 && ns_count == 0 && ar_count == 1) {
					ar_pad_len = skb->len - (niph->ihl * 4 + sizeof(struct udphdr) + pos);
				}

				skb_trim(nskb, niph->ihl * 4 + sizeof(struct udphdr) + pos);
				niph->tot_len = htons(nskb->len);
				nudph->len = ntohs(nskb->len - niph->ihl * 4);

				an_p = (unsigned char *)niph + nskb->len;
				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 2, __constant_htons(0x8180));
				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 6, __constant_htons(0));
				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 8, __constant_htons(0));
				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 10, __constant_htons(0));

			}
			if (nskb == NULL || an_p == NULL) {
				break;
			}

			if (qtype == 0x0001 && ip != 0) {
				struct iphdr *niph = ip_hdr(nskb);
				struct udphdr *nudph = nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);

				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 6, __constant_htons(1));

				skb_put(nskb, 16);
				if (ar_pad_len > 0) {
					skb_put(nskb, ar_pad_len);
					memmove(an_p + 16, an_p, ar_pad_len);
					set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 10, __constant_htons(1));
				}
				niph->tot_len = htons(nskb->len);
				nudph->len = ntohs(nskb->len - niph->ihl * 4);

				set_byte2(an_p, htons(0xc000 | qname_off));
				set_byte2(an_p + 2, __constant_htons(0x0001));
				set_byte2(an_p + 4, __constant_htons(0x0001));
				set_byte4(an_p + 6, __constant_htonl(128));
				set_byte2(an_p + 10, __constant_htons(4));
				set_byte4(an_p + 12, ip);
				break;
			} else if (qtype == 0x001c && ip6 != 0) {
				struct iphdr *niph = ip_hdr(nskb);
				struct udphdr *nudph = nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);

				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 6, __constant_htons(1));

				skb_put(nskb, 28);
				if (ar_pad_len > 0) {
					skb_put(nskb, ar_pad_len);
					memmove(an_p + 28, an_p, ar_pad_len);
					set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 10, __constant_htons(1));
				}
				niph->tot_len = htons(nskb->len);
				nudph->len = ntohs(nskb->len - niph->ihl * 4);

				set_byte2(an_p, htons(0xc000 | qname_off));
				set_byte2(an_p + 2, __constant_htons(0x001c));
				set_byte2(an_p + 4, __constant_htons(0x0001));
				set_byte4(an_p + 6, __constant_htonl(128));
				set_byte2(an_p + 10, __constant_htons(16));
				set_byte4(an_p + 12, in6.s6_addr32[0]);
				set_byte4(an_p + 12 + 4, in6.s6_addr32[1]);
				set_byte4(an_p + 12 + 8, in6.s6_addr32[2]);
				set_byte4(an_p + 12 + 12, in6.s6_addr32[3]);
				break;
			} else {
				struct iphdr *niph = ip_hdr(nskb);
				struct udphdr *nudph = nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);

				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 8, htons(1));
				set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 2, __constant_htons(0x8580));

				skb_put(nskb, 65);//
				if (ar_pad_len > 0) {
					skb_put(nskb, ar_pad_len);
					memmove(an_p + 65, an_p, ar_pad_len);
					set_byte2((unsigned char *)nudph + sizeof(struct udphdr) + 10, __constant_htons(1));
				}
				niph->tot_len = htons(nskb->len);
				nudph->len = ntohs(nskb->len - niph->ihl * 4);

				set_byte2(an_p, htons(0xc000 | (qname_off + 13)));
				set_byte2(an_p + 2, __constant_htons(0x0006));
				set_byte2(an_p + 4, __constant_htons(0x0001));
				set_byte4(an_p + 6, __constant_htonl(300));
				set_byte2(an_p + 10, __constant_htons(53));
				set_byte1(an_p + 12, 5);
				memcpy(an_p + 13, "ec2ns", 5);
				set_byte1(an_p + 18, 6);
				memcpy(an_p + 19, "ptpt52", 6);
				set_byte1(an_p + 25, 3);
				memcpy(an_p + 26, "com", 3);
				set_byte1(an_p + 29, 0);
				set_byte1(an_p + 30, 3);
				memcpy(an_p + 31, "dev", 3);
				set_byte1(an_p + 34, 5);
				memcpy(an_p + 35, "x-wrt", 5);
				set_byte1(an_p + 40, 3);
				memcpy(an_p + 41, "com", 3);
				set_byte1(an_p + 44, 0);
				set_byte4(an_p + 45, __constant_htonl(20250605));
				set_byte4(an_p + 49, __constant_htonl(300));
				set_byte4(an_p + 53, __constant_htonl(300));
				set_byte4(an_p + 57, __constant_htonl(1209600));
				set_byte4(an_p + 61, __constant_htonl(300));
				break;
			}
		}

		if (nskb == NULL) {
			break;
		}

		nskb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(nskb);
		nskb->dev = (struct net_device *)in;

		skb_push(nskb, (char *)ip_hdr(nskb) - (char *)eth_hdr(nskb));
		dev_queue_xmit(nskb);

		consume_skb(skb);
		//ct and post out
		return NF_STOLEN;
	} while (0);

	return ret;
}


static struct nf_hook_ops peer_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_push_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 4,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_NAT_DST - 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_snat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_snat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_NAT_SRC - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_dns_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_NAT_SRC - 10 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_icmpv6_pre_in_hook,
		.pf = PF_INET6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 25,
	},
};


static int natcap_peer_major = 0;
static int natcap_peer_minor = 0;
static int number_of_devices = 1;
static struct cdev natcap_peer_cdev;
const char *natcap_peer_dev_name = "natcap_peer_ctl";
static struct class *natcap_peer_class;
static struct device *natcap_peer_dev;

static inline struct peer_server_node *peer_server_node_get(unsigned int idx)
{
	if (idx < MAX_PEER_SERVER) {
		return &(peer_server[idx]);
	}
	return NULL;
}

static void *natcap_peer_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;
	char *natcap_peer_ctl_buffer = m->private;

	if ((*pos) == 0) {
		n = snprintf(natcap_peer_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Info:\n"
		             "#    local_target=%pI4:%u\n"
		             "#    peer_conn_timeout=%us\n"
		             "#    peer_port_map_timeout=%us\n"
		             "#    KN=%pI4:%u MAC=%02x:%02x:%02x:%02x:%02x:%02x LP=%u\n"
		             "#    peer_open_portmap=%u\n"
		             "#    peer_sni_listen=%pI4:%u\n"
		             "#    peer_sni_auth=%u\n"
		             "#    peer_mode=%u\n"
		             "#    peer_max_pmtu=%u\n"
		             "#    peer_sni_ban=%u\n"
		             "#    peer_subtype=%u (auto=0, 1=SYN, 2=SSYN)\n"
		             "#    peer_upstream_auth_ip=%pI4\n"
		             "#\n"
		             "\n",
		             &peer_local_ip, ntohs(peer_local_port),
		             peer_conn_timeout, peer_port_map_timeout,
		             &peer_knock_ip, ntohs(peer_knock_port),
		             peer_knock_mac[0], peer_knock_mac[1], peer_knock_mac[2], peer_knock_mac[3], peer_knock_mac[4], peer_knock_mac[5],
		             ntohs(peer_knock_local_port),
		             peer_open_portmap,
		             &peer_sni_ip, ntohs(peer_sni_port),
		             peer_sni_auth,
		             peer_mode,
		             peer_max_pmtu,
		             peer_sni_ban,
		             peer_subtype,
		             &peer_upstream_auth_ip
		            );
		natcap_peer_ctl_buffer[n] = 0;
		return natcap_peer_ctl_buffer;
	} else if ((*pos) > 0) {
		unsigned char client_mac[ETH_ALEN];
		struct nf_conn *user;
		struct user_expect *ue;
		struct peer_server_node *ps = peer_server_node_get((*pos) - 1);
		if (ps) {
			spin_lock_bh(&ps->lock);
			natcap_peer_ctl_buffer[0] = 0;
			n = snprintf(natcap_peer_ctl_buffer,
			             PAGE_SIZE - 1,
			             "N[%pI4:%u] [AS %ds]\n"
			             "    conn[%u:%u,%u:%u,%u:%u,%u:%u,%u:%u,%u:%u,%u:%u,%u:%u]\n",
			             &ps->ip, ntohs(ps->map_port), ps->last_active != 0 ? (uintmindiff(ps->last_active, jiffies) + HZ / 2) / HZ : (-1),
			             ntohs(peer_fakeuser_sport(ps->port_map[0])), ntohs(peer_fakeuser_dport(ps->port_map[0])),
			             ntohs(peer_fakeuser_sport(ps->port_map[1])), ntohs(peer_fakeuser_dport(ps->port_map[1])),
			             ntohs(peer_fakeuser_sport(ps->port_map[2])), ntohs(peer_fakeuser_dport(ps->port_map[2])),
			             ntohs(peer_fakeuser_sport(ps->port_map[3])), ntohs(peer_fakeuser_dport(ps->port_map[3])),
			             ntohs(peer_fakeuser_sport(ps->port_map[4])), ntohs(peer_fakeuser_dport(ps->port_map[4])),
			             ntohs(peer_fakeuser_sport(ps->port_map[5])), ntohs(peer_fakeuser_dport(ps->port_map[5])),
			             ntohs(peer_fakeuser_sport(ps->port_map[6])), ntohs(peer_fakeuser_dport(ps->port_map[6])),
			             ntohs(peer_fakeuser_sport(ps->port_map[7])), ntohs(peer_fakeuser_dport(ps->port_map[7]))
			            );
			spin_unlock_bh(&ps->lock);
			natcap_peer_ctl_buffer[n] = 0;
			return natcap_peer_ctl_buffer;
		}

		while ((*pos) - MAX_PEER_SERVER < MAX_PEER_PORT_MAP) {
			user = get_peer_user((*pos) - MAX_PEER_SERVER);
			if (user == NULL) {
				(*pos)++;
				continue;
			}
			natcap_peer_ctl_buffer[0] = 0;
			set_byte4(client_mac, get_byte4((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip));
			set_byte2(client_mac + 4, get_byte2((void *)&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all));
			ue = peer_user_expect(user);
			spin_lock_bh(&ue->lock);
			n = snprintf(natcap_peer_ctl_buffer,
			             PAGE_SIZE - 1,
			             "C[%02x:%02x:%02x:%02x:%02x:%02x,%pI4,%pI4] P=%u [AS %ds] pub=%d pub6=%d\n",
			             client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
			             &ue->local_ip, &ue->ip, ntohs(ue->map_port), ue->last_active != 0 ? (uintmindiff(ue->last_active, jiffies) + HZ / 2) / HZ : (-1),
			             !!(ue->status & PEER_SUBTYPE_PUB), !!(ue->status & PEER_SUBTYPE_PUB6)
			            );
			spin_unlock_bh(&ue->lock);
			put_peer_user(user);
			natcap_peer_ctl_buffer[n] = 0;
			return natcap_peer_ctl_buffer;
		}

		while ((*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP < PEER_PUB_NUM) {
			if (peer_pub_ip[(*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP] == 0) {
				(*pos)++;
				continue;
			}
			natcap_peer_ctl_buffer[0] = 0;
			n = snprintf(natcap_peer_ctl_buffer,
			             PAGE_SIZE - 1,
			             "peer=%pI4\n",
			             &peer_pub_ip[(*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP]
			            );
			natcap_peer_ctl_buffer[n] = 0;
			return natcap_peer_ctl_buffer;
		}

		while ((*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP - PEER_PUB_NUM < MAX_PEER_NUM) {
			unsigned int idx = (jiffies / HZ);
			struct natcap_fastpath_route *pfr = &natcap_pfr[(*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP - PEER_PUB_NUM];

			if (pfr->rt_out_magic != rt_out_magic || pfr->rt_out.outdev == NULL) {
				(*pos)++;
				continue;
			}
			natcap_peer_ctl_buffer[0] = 0;
			n = snprintf(natcap_peer_ctl_buffer,
			             PAGE_SIZE - 1,
			             "PFR=%u outdev=%s saddr=%pI4 ready=%d weight=%u last_rx=%u, tx=%u,%u,%u,%u,%u,%u,%u,%u, rx=%u,%u,%u,%u,%u,%u,%u,%u\n",
			             (unsigned int)((*pos) - MAX_PEER_SERVER - MAX_PEER_PORT_MAP - PEER_PUB_NUM + 1),
			             pfr->rt_out.outdev->name,
			             &pfr->saddr,
			             is_fastpath_route_ready(pfr),
			             pfr->weight,
			             uintmindiff(jiffies, pfr->last_rx_jiffies),
			             atomic_read(&pfr->tx_speed[(idx + 1) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 2) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 3) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 4) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 5) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 6) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 7) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->tx_speed[(idx + 8) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 1) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 2) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 3) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 4) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 5) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 6) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 7) % SPEED_SAMPLE_COUNT]),
			             atomic_read(&pfr->rx_speed[(idx + 8) % SPEED_SAMPLE_COUNT])
			            );
			natcap_peer_ctl_buffer[n] = 0;
			return natcap_peer_ctl_buffer;
		}
	}

	return NULL;
}

static void *natcap_peer_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return natcap_peer_start(m, pos);
	}
	return NULL;
}

static void natcap_peer_stop(struct seq_file *m, void *v)
{
}

static int natcap_peer_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations natcap_peer_seq_ops = {
	.start = natcap_peer_start,
	.next = natcap_peer_next,
	.stop = natcap_peer_stop,
	.show = natcap_peer_show,
};

static ssize_t natcap_peer_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t natcap_peer_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <= MAX_IOCTL_LEN
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATCAP_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "local_target=", 13) == 0) {
		unsigned int a, b, c, d, e;
		n = sscanf(data, "local_target=%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
		if ( (n == 5 && e <= 0xffff) &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			peer_local_ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			peer_local_port = htons(e);
			goto done;
		}
	} else if (strncmp(data, "peer_conn_timeout=", 18) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_conn_timeout=%u", &d);
		if (n == 1) {
			peer_conn_timeout = d;
			goto done;
		}
	} else if (strncmp(data, "peer_port_map_timeout=", 22) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_port_map_timeout=%u", &d);
		if (n == 1) {
			peer_port_map_timeout = d;
			goto done;
		}
	} else if (strncmp(data, "KN=", 3) == 0) {
		unsigned int a, b, c, d, e, f;
		unsigned int x0, x1, x2, x3, x4, x5;
		n = sscanf(data, "KN=%u.%u.%u.%u:%u MAC=%02x:%02x:%02x:%02x:%02x:%02x LP=%u\n",
		           &a, &b, &c, &d, &e,
		           &x0, &x1, &x2, &x3, &x4, &x5,
		           &f);
		if (n != 12) {
			n = sscanf(data, "KN=%u.%u.%u.%u:%u MAC=%02x-%02x-%02x-%02x-%02x-%02x LP=%u\n",
			           &a, &b, &c, &d, &e,
			           &x0, &x1, &x2, &x3, &x4, &x5,
			           &f);
		}
		if ( (n == 12 && e <= 0xffff) &&
		        ((a & 0xff) == a) &&
		        ((b & 0xff) == b) &&
		        ((c & 0xff) == c) &&
		        ((d & 0xff) == d) &&
		        ((x0 & 0xff) == x0) &&
		        ((x1 & 0xff) == x1) &&
		        ((x2 & 0xff) == x2) &&
		        ((x3 & 0xff) == x3) &&
		        ((x4 & 0xff) == x4) &&
		        ((x5 & 0xff) == x5) &&
		        (f <= 0xffff)) {
			if (f > 0 && f < 1024) {
				peer_knock_ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
				peer_knock_port = htons(e);
				peer_knock_mac[0] = x0;
				peer_knock_mac[1] = x1;
				peer_knock_mac[2] = x2;
				peer_knock_mac[3] = x3;
				peer_knock_mac[4] = x4;
				peer_knock_mac[5] = x5;
				peer_knock_local_port = htons(f);
				goto done;
			}
		}
	} else if (strncmp(data, "peer_open_portmap=", 18) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_open_portmap=%u", &d);
		if (n == 1) {
			peer_open_portmap = !!d;
			goto done;
		}
	} else if (strncmp(data, "peer_sni_listen=", 16) == 0) {
		unsigned int a, b, c, d, e;
		n = sscanf(data, "peer_sni_listen=%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
		if ( (n == 5 && e <= 0xffff) &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			peer_sni_ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			peer_sni_port = htons(e);
			goto done;
		}
	} else if (strncmp(data, "peer_sni_auth=", 14) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_sni_auth=%u", &d);
		if (n == 1) {
			peer_sni_auth = d;
			goto done;
		}
	} else if (strncmp(data, "peer_mode=", 10) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_mode=%u", &d);
		if (n == 1) {
			peer_mode = d;
			goto done;
		}
	} else if (strncmp(data, "peer_max_pmtu=", 14) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_max_pmtu=%u", &d);
		if (n == 1 && d >= NATCAP_MIN_PMTU && d <= NATCAP_MAX_PMTU) {
			peer_max_pmtu = d;
			goto done;
		}
	} else if (strncmp(data, "peer_sni_ban=", 13) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_sni_ban=%u", &d);
		if (n == 1) {
			peer_sni_ban = d;
			goto done;
		}
	} else if (strncmp(data, "peer_subtype=", 13) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_subtype=%u", &d);
		if (n == 1) {
			peer_subtype = d;
			goto done;
		}
	} else if (strncmp(data, "peer_upstream_auth_ip=", 22) == 0) {
		unsigned int a, b, c, d;
		n = sscanf(data, "peer_upstream_auth_ip=%u.%u.%u.%u", &a, &b, &c, &d);
		if ( (n == 4) &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			peer_upstream_auth_ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			goto done;
		}
	} else if (strncmp(data, "peer_dns_server=", 16) == 0) {
		unsigned int d;
		n = sscanf(data, "peer_dns_server=%u", &d);
		if (n == 1) {
			peer_dns_server = d;
			goto done;
		}
	}

	NATCAP_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int natcap_peer_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	ret = seq_open_private(file, &natcap_peer_seq_ops, PAGE_SIZE);
	if (ret)
		return ret;
	return 0;
}

static int natcap_peer_release(struct inode *inode, struct file *file)
{
	int ret = seq_release_private(inode, file);
	return ret;
}

static struct file_operations natcap_peer_fops = {
	.owner = THIS_MODULE,
	.open = natcap_peer_open,
	.release = natcap_peer_release,
	.read = natcap_peer_read,
	.write = natcap_peer_write,
	.llseek  = seq_lseek,
};

static int peer_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	unsigned int i, j;
	struct nf_conn *user;
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (peer_stop)
		return NOTIFY_DONE;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		struct peer_server_node *ps = &peer_server[i];
		spin_lock_bh(&ps->lock);
		for (j = 0; j < MAX_PEER_CONN; j++) {
			user = ps->port_map[j];
			if (user != NULL) {
				struct fakeuser_expect *fue = peer_fakeuser_expect(user);
				if (fue->rt_out.outdev == dev) {
					ps->port_map[j] = NULL;
					nf_ct_put(user);
				}
			}
		}
		spin_unlock_bh(&ps->lock);
	}

	rt_out_magic += 1;

	NATCAP_WARN("catch unregister event for dev=%s\n", dev ? dev->name : "(null)");

	return NOTIFY_DONE;
}

static struct notifier_block peer_netdev_notifier = {
	.notifier_call  = peer_netdev_event,
};

int natcap_peer_init(void)
{
	dev_t devno;
	unsigned int i;
	int ret = 0;

	need_conntrack();

	memset(natcap_pfr, 0, sizeof(natcap_pfr[0]) * MAX_PEER_NUM);

	if (mode != CLIENT_MODE) {
		default_mac_addr_init();
	}

	rt_out_magic = jiffies + get_random_u32();

	memset(peer_pub_ip, 0, sizeof(peer_pub_ip));
	memset(peer_pub_active, 0, sizeof(peer_pub_active));

	peer_sni_cache_init();
	peer_cache_init();
	memset(peer_server, 0, sizeof(peer_server));
	for (i = 0; i < MAX_PEER_SERVER; i++) {
		spin_lock_init(&peer_server[i].lock);
	}
	peer_port_map = vmalloc(sizeof(struct nf_conn *) * MAX_PEER_PORT_MAP);
	if (peer_port_map == NULL) {
		return -ENOMEM;
	}
	memset(peer_port_map, 0, sizeof(struct nf_conn *) * MAX_PEER_PORT_MAP);

	register_netdevice_notifier(&peer_netdev_notifier);

	ret = peer_timer_init();
	if (ret != 0)
		goto peer_timer_init_failed;

	ret = nf_register_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	if (natcap_peer_major > 0) {
		devno = MKDEV(natcap_peer_major, natcap_peer_minor);
		ret = register_chrdev_region(devno, number_of_devices, natcap_peer_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, natcap_peer_minor, number_of_devices, natcap_peer_dev_name);
	}
	if (ret < 0) {
		NATCAP_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	natcap_peer_major = MAJOR(devno);
	natcap_peer_minor = MINOR(devno);
	NATCAP_println("natcap_peer_major=%d, natcap_peer_minor=%d", natcap_peer_major, natcap_peer_minor);

	cdev_init(&natcap_peer_cdev, &natcap_peer_fops);
	natcap_peer_cdev.owner = THIS_MODULE;
	natcap_peer_cdev.ops = &natcap_peer_fops;

	ret = cdev_add(&natcap_peer_cdev, devno, 1);
	if (ret) {
		NATCAP_println("adding chardev, error=%d", ret);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	natcap_peer_class = class_create(THIS_MODULE, "natcap_peer_class");
#else
	natcap_peer_class = class_create("natcap_peer_class");
#endif
	if (IS_ERR(natcap_peer_class)) {
		NATCAP_println("failed in creating class");
		ret = -EINVAL;
		goto class_create_failed;
	}

	natcap_peer_dev = device_create(natcap_peer_class, NULL, devno, NULL, natcap_peer_dev_name);
	if (IS_ERR(natcap_peer_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	peer_stop = 0;
	peer_timer_start();

	INIT_WORK(&request_natcapd_restart_work, request_natcapd_restart_work_func);

	return 0;

	//device_destroy(natcap_peer_class, devno);
device_create_failed:
	class_destroy(natcap_peer_class);
class_create_failed:
	cdev_del(&natcap_peer_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);
chrdev_region_failed:
	nf_unregister_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));
nf_register_hooks_failed:
	peer_timer_exit();
peer_timer_init_failed:
	unregister_netdevice_notifier(&peer_netdev_notifier);
	return ret;
}

void natcap_peer_exit(void)
{
	unsigned int i;
	dev_t devno;

	peer_stop = 1;
	synchronize_rcu();

	devno = MKDEV(natcap_peer_major, natcap_peer_minor);
	device_destroy(natcap_peer_class, devno);
	class_destroy(natcap_peer_class);
	cdev_del(&natcap_peer_cdev);
	unregister_chrdev_region(devno, number_of_devices);

	nf_unregister_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));

	peer_timer_exit();

	unregister_netdevice_notifier(&peer_netdev_notifier);

	spin_lock_bh(&peer_port_map_lock);
	for (i = 0; i < MAX_PEER_PORT_MAP; i++) {
		if (peer_port_map[i] != NULL) {
			nf_ct_put(peer_port_map[i]);
			peer_port_map[i] = NULL;
		}
	}
	spin_unlock_bh(&peer_port_map_lock);
	vfree(peer_port_map);

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		unsigned int j;
		spin_lock_bh(&peer_server[i].lock);
		for (j = 0; j < MAX_PEER_CONN; j++) {
			if (peer_server[i].port_map[j]) {
				nf_ct_put(peer_server[i].port_map[j]);
				peer_server[i].port_map[j] = NULL;
			}
		}
		spin_unlock_bh(&peer_server[i].lock);
	}

	peer_cache_cleanup();
	peer_sni_cache_cleanup();

	flush_work(&request_natcapd_restart_work);
}
