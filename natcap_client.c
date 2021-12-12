/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:04 +0800
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
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "net/netfilter/nf_conntrack_seqadj.h"
#include "natcap_common.h"
#include "natcap_client.h"
#include "natcap_knock.h"
#include "natcap_peer.h"

#define CN_DOMAIN_SIZE 32
static char *cn_domain = NULL;
static int cn_domain_size = 0;
static int cn_domain_count = 0;

unsigned int server_index_natcap_mask = 0x00000000;
#define server_index_natcap_set(index, at) *(unsigned int *)(at) = ((*(unsigned int *)(at)) & (~server_index_natcap_mask)) | ((index) & server_index_natcap_mask)
/* return 0: no index set */
static inline int server_index_natcap_get(unsigned int *at)
{
	unsigned int idx;
	unsigned int val;
	unsigned int mask = server_index_natcap_mask;

	if (mask == 0)
		return 0;

	idx = ffs(mask) - 1;

	val = ((*(unsigned int *)(at)) & mask);
	return (val >> idx);
}

unsigned int peer_multipath = 4;
unsigned int dns_proxy_drop = 0;
unsigned int server_persist_lock = 0;
unsigned int server_persist_timeout = 0;
module_param(server_persist_timeout, int, 0);
MODULE_PARM_DESC(server_persist_timeout, "Use diffrent server after timeout");

/* threshold pkts to start speed limit */
int tx_pkts_threshold = 128;
int rx_pkts_threshold = 512;
static int natcap_tx_speed = 0;
static int natcap_rx_speed = 0;
static struct natcap_token_ctrl tx_ntc;
static struct natcap_token_ctrl rx_ntc;
static void natcap_ntc_init(struct natcap_token_ctrl *ntc)
{
	spin_lock_init(&ntc->lock);
	ntc->tokens = 0;
	ntc->tokens_per_jiffy = 0;
	ntc->jiffies = 0;
}

void natcap_tx_speed_set(int speed)
{
	natcap_tx_speed = speed;
	spin_lock_bh(&tx_ntc.lock);
	tx_ntc.tokens = 0;
	tx_ntc.tokens_per_jiffy = natcap_tx_speed / HZ;
	tx_ntc.jiffies = jiffies;
	spin_unlock_bh(&tx_ntc.lock);
}
void natcap_rx_speed_set(int speed)
{
	natcap_rx_speed = speed;
	spin_lock_bh(&rx_ntc.lock);
	rx_ntc.tokens = 0;
	rx_ntc.tokens_per_jiffy = natcap_rx_speed / HZ;
	rx_ntc.jiffies = jiffies;
	spin_unlock_bh(&rx_ntc.lock);
}

int natcap_tx_speed_get(void)
{
	return natcap_tx_speed;
}
int natcap_rx_speed_get(void)
{
	return natcap_rx_speed;
}

static int natcap_flow_ctrl(struct sk_buff *skb, struct nf_conn *ct, struct natcap_token_ctrl *ntc)
{
	unsigned long feed_jiffies = 0;
	unsigned long current_jiffies;
	int ret = 0;
	int len = skb->len;
	struct iphdr *iph = ip_hdr(skb);
	void *l4 = (void *)iph + iph->ihl * 4;

	//speed up for UDP/TCP 53
	if ( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53) ||
	        (ct->master && ct->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53)) ) {
		return 0;
	}

	switch (iph->protocol) {
	case IPPROTO_TCP:
		len -= iph->ihl * 4 + TCPH(l4)->doff * 4;
		break;
	case IPPROTO_UDP:
		len -= iph->ihl * 4 + sizeof(struct udphdr);
		break;
	}
	if (len <= 0) {
		return 0;
	}
	if (ntc->tokens_per_jiffy == 0) {
		return 0;
	}

	spin_lock_bh(&ntc->lock);
	if (ntc->tokens > 0) {
		ntc->tokens -= len;
		ret = 0;
		goto out;
	}

	current_jiffies = jiffies;
	if (current_jiffies > ntc->jiffies) {
		feed_jiffies = current_jiffies - ntc->jiffies;
	} else {
		feed_jiffies = ntc->jiffies - current_jiffies;
	}
	if (feed_jiffies > 64 * HZ) {
		feed_jiffies = 64 * HZ;
	}

	ret = ntc->tokens + (int)(ntc->tokens_per_jiffy * feed_jiffies);

	if (feed_jiffies <= HZ) {
		ntc->tokens = ret;
	} else {
		if (ret <= 0) {
			ntc->tokens = ret;
		} else {
			ntc->tokens = 0;
		}
	}

	if (ntc->tokens >= 0) {
		ntc->tokens -= len;
		ret = 0;
	}
	ntc->jiffies = current_jiffies;

out:
	spin_unlock_bh(&ntc->lock);
	return ret;
}

static inline int natcap_tx_flow_ctrl(struct sk_buff *skb, struct nf_conn *ct)
{
	struct nf_conn_acct *acct;

	if (tx_ntc.tokens_per_jiffy == 0) {
		return 0;
	}
	if (tx_pkts_threshold != 0) {
		/*XXX we skip N pkts for no speed limit */
		acct = nf_conn_acct_find(ct);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;
			if (atomic64_read(&counter[IP_CT_DIR_ORIGINAL].packets) < tx_pkts_threshold) {
				return 0;
			}
		}
	}
	return natcap_flow_ctrl(skb, ct, &tx_ntc);
}
static inline int natcap_rx_flow_ctrl(struct sk_buff *skb, struct nf_conn *ct)
{
	struct nf_conn_acct *acct;

	if (rx_ntc.tokens_per_jiffy == 0) {
		return 0;
	}
	if (rx_pkts_threshold != 0) {
		/*XXX we skip N pkts for no speed limit */
		acct = nf_conn_acct_find(ct);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;
			if (atomic64_read(&counter[IP_CT_DIR_REPLY].packets) < rx_pkts_threshold) {
				return 0;
			}
		}
	}
	return natcap_flow_ctrl(skb, ct, &rx_ntc);
}

unsigned int cnipwhitelist_mode = 0;

unsigned int macfilter = 0;
const char *macfilter_acl_str[NATCAP_ACL_MAX] = {
	[NATCAP_ACL_NONE] = "none",
	[NATCAP_ACL_ALLOW] = "allow",
	[NATCAP_ACL_DENY] = "deny"
};

unsigned int ipfilter = 0;
const char *ipfilter_acl_str[NATCAP_ACL_MAX] = {
	[NATCAP_ACL_NONE] = "none",
	[NATCAP_ACL_ALLOW] = "allow",
	[NATCAP_ACL_DENY] = "deny"
};

unsigned int encode_http_only = 0;
unsigned int http_confusion = 0;
unsigned int sproxy = 0;
unsigned int dns_server = __constant_htonl((8<<24)|(8<<16)|(8<<8)|(8<<0));
unsigned short dns_port = __constant_htons(53);

const __be32 gfw0_dns_magic_server = __constant_htonl((0<<24)|(0<<16)|(0<<8)|(10<<0));
const __be32 gfw1_dns_magic_server = __constant_htonl((0<<24)|(0<<16)|(0<<8)|(11<<0));

u32 default_protocol = 0;
u32 default_u_hash = 0;
unsigned char default_mac_addr[ETH_ALEN];
void default_mac_addr_init(void)
{
	struct net_device *dev;

	memset(default_mac_addr, 0, ETH_ALEN);
	dev = first_net_device(&init_net);
	while (dev) {
		if (dev->type == ARPHRD_ETHER) {
			memcpy(default_mac_addr, dev->dev_addr, ETH_ALEN);
			break;
		}
		dev = next_net_device(dev);
	}

	dev = first_net_device(&init_net);
	while (dev) {
		if (strcmp("eth0", dev->name) == 0) {
			memcpy(default_mac_addr, dev->dev_addr, ETH_ALEN);
			break;
		} else if (strcmp("eth1", dev->name) == 0) {
			memcpy(default_mac_addr, dev->dev_addr, ETH_ALEN);
			// sometimes we use eth1
		}

		dev = next_net_device(dev);
	}
}

static unsigned long jiffies_diff(unsigned long j1, unsigned long j2)
{
	return (j1 > j2) ? (j1 - j2) : (j2 - j1);
}

static struct tuple m_dns_proxy_server = {
	.encryption = 0,
	.tcp_encode = 0,
	.udp_encode = 0,
	.port = 0,
	.ip = 0,
};

struct tuple *dns_proxy_server = &m_dns_proxy_server;

static inline void get_dns_proxy_server(__be16 port, struct tuple *dst)
{
	tuple_copy(dst, dns_proxy_server);
	if (dst->port == __constant_htons(0)) {
		dst->port = port;
	} else if (dst->port == __constant_htons(65535)) {
		dst->port = htons(prandom_u32() % (65536 - 1024) + 1024);
	}
}

#define MAX_NATCAP_SERVER 128
struct natcap_server_info {
	unsigned long server_jiffies;
	unsigned int active_index;
	unsigned int server_index;
	unsigned int server_count[2];
	struct tuple server[2][MAX_NATCAP_SERVER];
	unsigned long last_active[MAX_NATCAP_SERVER];
#define NATCAP_SERVER_IN 0
#define NATCAP_SERVER_OUT 1
	unsigned char last_dir[MAX_NATCAP_SERVER];
};

static struct natcap_server_info server_group[SERVER_GROUP_MAX];

void natcap_server_info_change(enum server_group_t x, int change)
{
	struct natcap_server_info *nsi = &server_group[x];
	if (change || nsi->server_jiffies == 0 ||
	        (!server_persist_lock &&
	         time_after(jiffies, nsi->server_jiffies + (7 * server_persist_timeout / 8 + jiffies % (server_persist_timeout / 4 + 1)) * HZ))) {
		nsi->server_jiffies = jiffies;
		nsi->server_index += 1 + prandom_u32();
	}
}

void natcap_server_info_cleanup(enum server_group_t x)
{
	struct natcap_server_info *nsi = &server_group[x];
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;

	nsi->server_count[m] = 0;
	nsi->server_count[n] = 0;
	nsi->active_index = n;
}

int natcap_server_info_add(enum server_group_t x, const struct tuple *dst)
{
	struct natcap_server_info *nsi = &server_group[x];
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	if (nsi->server_count[m] == MAX_NATCAP_SERVER)
		return -ENOSPC;

	for (i = 0; i < nsi->server_count[m]; i++) {
		if (tuple_eq(&nsi->server[m][i], dst)) {
			return -EEXIST;
		}
	}

	/* all dst(s) are stored from MAX to MIN */
	j = 0;
	for (i = 0; i < nsi->server_count[m] && tuple_lt(dst, &nsi->server[m][i]); i++) {
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}
	tuple_copy(&nsi->server[n][j++], dst);
	for (; i < nsi->server_count[m]; i++) {
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}

	nsi->server_count[n] = j;
	nsi->active_index = n;

	return 0;
}

int natcap_server_info_delete(enum server_group_t x, const struct tuple *dst)
{
	struct natcap_server_info *nsi = &server_group[x];
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	j = 0;
	for (i = 0; i < nsi->server_count[m]; i++) {
		if (tuple_eq(&nsi->server[m][i], dst)) {
			continue;
		}
		tuple_copy(&nsi->server[n][j++], &nsi->server[m][i]);
	}
	if (j == i)
		return -ENOENT;

	nsi->server_count[n] = j;

	nsi->active_index = n;

	return 0;
}

const struct tuple *natcap_server_info_current(enum server_group_t x)
{
	struct natcap_server_info *nsi = &server_group[x];
	int count = nsi->server_count[nsi->active_index];
	static struct tuple _tuple = {0};
	if (count > 0)
		return &nsi->server[nsi->active_index][nsi->server_index % count];
	return &_tuple;
}

void *natcap_server_info_get(enum server_group_t x, loff_t idx)
{
	struct natcap_server_info *nsi = &server_group[x];
	if (x > SERVER_GROUP_0) {
		int y;
		for (y = SERVER_GROUP_0; y < x; y++) {
			idx = idx - server_group[y].server_count[server_group[y].active_index];
		}
	}
	if (idx >= 0 && idx < nsi->server_count[nsi->active_index])
		return &nsi->server[nsi->active_index][idx];

	return NULL;
}

void natcap_server_in_touch(enum server_group_t x, __be32 ip)
{
	struct natcap_server_info *nsi;
	unsigned int m;
	unsigned int count;
	unsigned int hash;
	unsigned int i;

	if (x >= SERVER_GROUP_MAX)
		return;

	nsi = &server_group[x];
	m = nsi->active_index;
	count = nsi->server_count[m];

	if (count == 0)
		return;

	hash = nsi->server_index % count;

	for (i = hash; i < count; i++) {
		if (nsi->server[m][i].ip == ip) {
			if (nsi->last_dir[i] != NATCAP_SERVER_IN)
				nsi->last_dir[i] = NATCAP_SERVER_IN;
			return;
		}
	}
	for (i = 0; i < hash; i++) {
		if (nsi->server[m][i].ip == ip) {
			if (nsi->last_dir[i] != NATCAP_SERVER_IN)
				nsi->last_dir[i] = NATCAP_SERVER_IN;
			return;
		}
	}
}

// [T/U][T/U][o/e][0/1]
unsigned int natcap_server_use_peer = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
void __natcap_server_info_select(enum server_group_t x, const struct nf_hook_state *state, struct sk_buff *skb, __be32 ip, __be16 port, struct tuple *dst)
#define natcap_server_info_select(x, state, in, out, skb, ip, port, dst) __natcap_server_info_select(x, state, skb, ip, port, dst)
#else
void __natcap_server_info_select(enum server_group_t x, const struct net_device *in, const struct net_device *out, struct sk_buff *skb, __be32 ip, __be16 port, struct tuple *dst)
#define natcap_server_info_select(x, state, in, out, skb, ip, port, dst) __natcap_server_info_select(x, in, out, skb, ip, port, dst)
#endif
{
	static atomic_t server_port = ATOMIC_INIT(0);
	struct natcap_server_info *nsi;
	unsigned int m;
	unsigned int count;
	unsigned int hash;
	unsigned int i, found = 0;

	if (x == SERVER_GROUP_1) {
		if ((natcap_server_use_peer & 0x1)) {
			__be32 dst_ip;
			__be16 dst_port;
			unsigned int i, idx;
			unsigned int off = prandom_u32();
			struct sk_buff *uskb = uskb_of_this_cpu(smp_processor_id());
			for (i = 0; i < PEER_PUB_NUM; i++) {
				idx = (i + off) % PEER_PUB_NUM;
				dst_ip = peer_pub_ip[idx];
				ip_hdr(uskb)->daddr = dst_ip;
				if (dst_ip != 0 && dst_ip != ip &&
				        IP_SET_test_dst_ip(state, in, out, uskb, "ignorelist") <= 0) {
					dst_port = htons(prandom_u32() % (65536 - 1024) + 1024);
					dst->ip = dst_ip;
					dst->port = dst_port;
					dst->encryption = !!(natcap_server_use_peer & 0x2);
					dst->tcp_encode = (natcap_server_use_peer & 0x4) ? UDP_ENCODE : TCP_ENCODE;
					dst->udp_encode = (natcap_server_use_peer & 0x8) ? UDP_ENCODE : TCP_ENCODE;
					return;
				}
			}
		}
	}

	nsi = &server_group[x];
	m = nsi->active_index;
	count = nsi->server_count[m];

	dst->ip = 0;
	dst->port = 0;
	dst->encryption = 0;

	if (count == 0)
		return;

	for (i = 0; i < count; i++) {
		if (nsi->server[m][i].ip == ip) {
			hash = i;
			found = 1;
			goto found;
		}
	}

	natcap_server_info_change(x, 0);

	hash = nsi->server_index % count;

	if ((i = server_index_natcap_get(&skb->mark)) != 0) {
		hash = (i - 1) % count;
		found = 1;
	} else if (server_persist_lock || nsi->last_dir[hash] == NATCAP_SERVER_IN || jiffies_diff(jiffies, nsi->last_active[hash]) <= natcap_touch_timeout * HZ) {
		found = 1;
	} else {
		unsigned int oldhash = hash;
		hash = (hash + jiffies) % count;
		for (i = hash; i < count; i++) {
			if (nsi->last_dir[i] == NATCAP_SERVER_IN || jiffies_diff(jiffies, nsi->last_active[i]) > 512 * HZ) {
				found = 1;
				hash = i;
				nsi->server_index = i;
				nsi->last_dir[i] = NATCAP_SERVER_IN;
				NATCAP_WARN("current server(" TUPLE_FMT ") is blocked, switch to next=" TUPLE_FMT "\n",
				            TUPLE_ARG(&nsi->server[m][oldhash]),
				            TUPLE_ARG(&nsi->server[m][hash]));
				break;
			}
		}
		for (i = 0; !found && i < hash; i++) {
			if (nsi->last_dir[i] == NATCAP_SERVER_IN || jiffies_diff(jiffies, nsi->last_active[i]) > 512 * HZ) {
				found = 1;
				hash = i;
				nsi->server_index = i;
				nsi->last_dir[i] = NATCAP_SERVER_IN;
				NATCAP_WARN("current server(" TUPLE_FMT ") is blocked, switch to next=" TUPLE_FMT "\n",
				            TUPLE_ARG(&nsi->server[m][oldhash]),
				            TUPLE_ARG(&nsi->server[m][hash]));
				break;
			}
		}
		if (!found) {
			natcap_server_info_change(x, 1);
			hash = nsi->server_index % count;
			NATCAP_WARN("all servers are blocked, force change. " TUPLE_FMT " -> " TUPLE_FMT "\n",
			            TUPLE_ARG(&nsi->server[m][oldhash]),
			            TUPLE_ARG(&nsi->server[m][hash]));
		}
	}

found:
	if (nsi->last_dir[hash] == NATCAP_SERVER_IN || !found) {
		nsi->last_dir[hash] = NATCAP_SERVER_OUT;
		nsi->last_active[hash] = jiffies; /* ticks start */
	}

	tuple_copy(dst, &nsi->server[m][hash]);
	if (dst->port == __constant_htons(0)) {
		dst->port = port;
	} else if (dst->port == __constant_htons(65535)) {
		dst->port = atomic_add_return(1, &server_port) ^ (ip & 0xffff) ^ ((ip >> 16) & 0xffff);
	}

	if (encode_http_only == 0)
		return;

	//XXX: encode for port 80 and 53 only
	if (port != __constant_htons(80) && port != __constant_htons(53)) {
		dst->encryption = 0;
	}
}

int is_natcap_server(__be32 ip)
{
	struct natcap_server_info *nsi;
	unsigned int m;
	unsigned int i;
	int x;

	if (mode != MIXING_MODE && mode != CLIENT_MODE)
		return 0;

	for (x = 0; x < SERVER_GROUP_MAX; x++) {
		nsi = &server_group[x];
		m = nsi->active_index;
		for (i = 0; i < nsi->server_count[m]; i++) {
			if (nsi->server[m][i].ip == ip)
				return 1;
		}
	}

	return 0;
}

static inline int natcap_reset_synack(struct sk_buff *oskb, const struct net_device *dev, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_session *ns;
	int offset, add_len;
	int header_len = 0;
	u8 protocol = IPPROTO_TCP;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	ns = natcap_session_get(ct);
	if ((IPS_NATCAP & ct->status) && (NS_NATCAP_TCPUDPENC & ns->n.status)) {
		header_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return -1;
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
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;


	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, ns->peer.ver == 1 ? __constant_htonl(NATCAP_7_MAGIC) : __constant_htonl(NATCAP_F_MAGIC));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
	}
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);
	tcp_flag_word(ntcph) = TCP_FLAG_RST | TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->window = 0;
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_dnat_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_dnat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_dnat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_dnat_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_session *ns;
	struct tuple server;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if (!nf_ct_is_confirmed(ct)) {
		if (skb->mark & natcap_ignore_mask) {
			set_bit(IPS_NATCAP_PRE_BIT, &ct->status);
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_SERVER_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		if (!(IPS_NATCAP_ACK & ct->status)) {
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
		}
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		goto natcaped_out;
	}

	if (ipv4_is_loopback(iph->daddr) || ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr) || ipv4_is_zeronet(iph->daddr)) {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}

	/* natcapd server local out bypass */
	if (iph->protocol == IPPROTO_TCP && hooknum == NF_INET_LOCAL_OUT && skb->sk && sock_flag(skb->sk, SOCK_NATCAP_MARK)) {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcapd server local out bypass\n", DEBUG_TCP_ARG(iph,l4));
		return NF_ACCEPT;
	}
	if (hooknum == NF_INET_LOCAL_OUT) {
		char tname[TASK_COMM_LEN];
		get_task_comm(tname, current);

		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": p[%s]\n", DEBUG_TCP_ARG(iph,l4), tname);
			break;
		case IPPROTO_UDP:
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": p[%s]\n", DEBUG_UDP_ARG(iph,l4), tname);
			break;
		}
		if (strncmp(tname, "tinyproxy", 9) == 0 || strncmp(tname, "sockd", 5) == 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	if (hooknum != NF_INET_LOCAL_OUT) {
		if (macfilter == NATCAP_ACL_ALLOW && IP_SET_test_src_mac(state, in, out, skb, "natcap_maclist") <= 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		} else if (macfilter == NATCAP_ACL_DENY && IP_SET_test_src_mac(state, in, out, skb, "natcap_maclist") > 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		}

		if (ipfilter == NATCAP_ACL_ALLOW && IP_SET_test_src_ip(state, in, out, skb, "natcap_iplist") <= 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		} else if (ipfilter == NATCAP_ACL_DENY && IP_SET_test_src_ip(state, in, out, skb, "natcap_iplist") > 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	if (IP_SET_test_dst_netport(state, in, out, skb, "app_bypass_list") > 0) {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) { /* for TCP */
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (!TCPH(l4)->syn || TCPH(l4)->ack) {
			NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": first packet in but not syn, bypass\n", DEBUG_TCP_ARG(iph,l4));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		}
		if (hooknum == NF_INET_PRE_ROUTING && !nf_ct_is_confirmed(ct)) {
			if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (natcap_tcp_decode_header(TCPH(l4)) != NULL || natcap_peer_decode_header(TCPH(l4)) != NULL) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": first packet is already encoded, bypass\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (inet_is_local(in, iph->daddr)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": target is local, no encoded header, not client in\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
		}

		if (IP_SET_test_dst_ip(state, in, out, skb, "knocklist") > 0) {
			if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == peer_knock_local_port ||
			        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == peer_sni_port) {
				goto bypass_tcp;
			}
			natcap_knock_info_select(iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = SERVER_GROUP_MAX; // no use
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, knock select target server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else if (IP_SET_test_dst_ip(state, in, out, skb, "bypasslist") > 0 ||
		           IP_SET_test_dst_ip(state, in, out, skb, "cniplist") > 0 ||
		           IP_SET_test_dst_ip(state, in, out, skb, "cone_wan_ip") > 0) {
bypass_tcp:
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		} else {
			int x = -1;

			if (IP_SET_test_dst_ip(state, in, out, skb, "gfwlist1") > 0) {
				x = SERVER_GROUP_1;
			} else if (IP_SET_test_dst_port(state, in, out, skb, "gfw_tcp_port_list1") > 0 ||
			           IP_SET_test_dst_netport(state, in, out, skb, "app_list1") > 0) {
				x = SERVER_GROUP_1;
			} else if (IP_SET_test_dst_ip(state, in, out, skb, "gfwlist0") > 0 ||
			           (cnipwhitelist_mode == 2 && IP_SET_test_dst_ip(state, in, out, skb, "wechat_iplist") > 0)) {
				x = SERVER_GROUP_0;
			} else if (IP_SET_test_dst_port(state, in, out, skb, "gfw_tcp_port_list0") > 0 ||
			           IP_SET_test_dst_netport(state, in, out, skb, "app_list0") > 0) {
				x = SERVER_GROUP_0;
			}

			if (x == -1) {
				if (cnipwhitelist_mode == 1) {
					x = SERVER_GROUP_0;
				} else if (cnipwhitelist_mode == 2) {
					goto bypass_tcp;
				} else {
					//dual out
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					if (!nf_ct_is_confirmed(ct)) {
						struct nf_conn_help *help;
						if (ct->master) {
							set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
							return NF_ACCEPT;
						}
						help = nfct_help(ct);
						if (help && help->helper) {
							set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
							return NF_ACCEPT;
						}

						natcap_server_info_select(SERVER_GROUP_0, state, in, out, skb, iph->daddr, TCPH(l4)->dest, &server);
						if (server.ip == 0) {
							NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,l4));
							set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
							return NF_ACCEPT;
						}

						ns = natcap_session_in(ct);
						if (!ns) {
							NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
							set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
							return NF_ACCEPT;
						}
						natcap_tuple_to_ns(ns, &server, iph->protocol);
						ns->n.group_x = SERVER_GROUP_0;

						set_bit(IPS_NATCAP_DUAL_BIT, &ct->status);

						if (in && strncmp(in->name, "natcap", 6) == 0) {
							if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
						}
						NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": TCP dual out to server=%pI4\n", DEBUG_TCP_ARG(iph,l4), &server.ip);
					}
					xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
					if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
					return NF_ACCEPT;
				}
			}

			if (natcap_client_redirect_port != 0 && hooknum == NF_INET_PRE_ROUTING) {
				__be32 newdst = 0;
				struct in_device *indev;
				struct in_ifaddr *ifa;

				rcu_read_lock();
				indev = __in_dev_get_rcu(in);
				if (indev && indev->ifa_list) {
					ifa = indev->ifa_list;
					newdst = ifa->ifa_local;
				}
				rcu_read_unlock();

				if (newdst) {
					natcap_dnat_setup(ct, newdst, natcap_client_redirect_port);
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);

					NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection match g%d, use natcapd proxy\n", DEBUG_TCP_ARG(iph,l4), x);
					return NF_ACCEPT;
				}
			}
			natcap_server_info_select(x, state, in, out, skb, iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = x;

			if (in && strncmp(in->name, "natcap", 6) == 0) {
				if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
			}
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, select server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		}
	} else { /* for UDP */
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (hooknum == NF_INET_PRE_ROUTING && !nf_ct_is_confirmed(ct)) {
			if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12)) {
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_E_MAGIC) ||
				        (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_D_MAGIC) &&
				         skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 24))) {
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;
					NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": first packet is already encoded, bypass\n", DEBUG_UDP_ARG(iph,l4));
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (inet_is_local(in, iph->daddr)) {
				NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": target is local, no encoded header, not client in\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
		}

		if (UDPH(l4)->dest == __constant_htons(53) && dns_proxy_server->ip != 0) {
			get_dns_proxy_server(UDPH(l4)->dest, &server);
			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = SERVER_GROUP_MAX; //no use

			if (in && strncmp(in->name, "natcap", 6) == 0) {
				if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
			}
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": dns proxy out, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			goto dnat_out;
		}

		if (UDPH(l4)->dest == __constant_htons(53) && iph->daddr == gfw0_dns_magic_server) {
			natcap_server_info_select(SERVER_GROUP_0, state, in, out, skb, iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": gfw0 dns no server found\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = SERVER_GROUP_0;

			if (in && strncmp(in->name, "natcap", 6) == 0) {
				if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
			}
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": gfw0 dns proxy out, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			goto dnat_out;
		}

		if (UDPH(l4)->dest == __constant_htons(53) && iph->daddr == gfw1_dns_magic_server) {
			natcap_server_info_select(SERVER_GROUP_1, state, in, out, skb, iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": gfw1 dns no server found\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = SERVER_GROUP_1;

			if (in && strncmp(in->name, "natcap", 6) == 0) {
				if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
			}
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": gfw1 dns proxy out, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			goto dnat_out;
		}

		if ((cnipwhitelist_mode == 0 || cnipwhitelist_mode == 1) && /* this work for China */
		        UDPH(l4)->dest == __constant_htons(53) && !is_natcap_server(iph->daddr)) {
natcap_dual_out_udp:
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			if (!nf_ct_is_confirmed(ct)) {
				struct nf_conn_help *help;
				if (ct->master) {
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}
				help = nfct_help(ct);
				if (help && help->helper) {
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}

				if (is_natcap_server(dns_server)) {
					natcap_server_info_select(SERVER_GROUP_0, state, in, out, skb, dns_server, UDPH(l4)->dest, &server);
				} else {
					natcap_server_info_select(SERVER_GROUP_0, state, in, out, skb, iph->daddr, UDPH(l4)->dest, &server);
				}
				if (server.ip == 0) {
					NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": no server found\n", DEBUG_UDP_ARG(iph,l4));
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}

				ns = natcap_session_in(ct);
				if (!ns) {
					NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}
				natcap_tuple_to_ns(ns, &server, iph->protocol);
				ns->n.group_x = SERVER_GROUP_0;

				set_bit(IPS_NATCAP_DUAL_BIT, &ct->status);

				if (in && strncmp(in->name, "natcap", 6) == 0) {
					if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
				}
				NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": UDP dual out to server=%pI4\n", DEBUG_UDP_ARG(iph,l4), &server.ip);
			}
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			return NF_ACCEPT;
		}

		if (IP_SET_test_dst_ip(state, in, out, skb, "bypasslist") > 0 ||
		        IP_SET_test_dst_ip(state, in, out, skb, "cniplist") > 0 ||
		        IP_SET_test_dst_ip(state, in, out, skb, "cone_wan_ip") > 0) {
bypass_udp:
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		} else {
			int x = -1;

			if (IP_SET_test_dst_ip(state, in, out, skb, "gfwlist1") > 0) {
				x = SERVER_GROUP_1;
			} else if (IP_SET_test_dst_port(state, in, out, skb, "gfw_udp_port_list1") > 0 ||
			           IP_SET_test_dst_netport(state, in, out, skb, "app_list1") > 0) {
				x = SERVER_GROUP_1;
			} else if (IP_SET_test_dst_ip(state, in, out, skb, "gfwlist0") > 0 ||
			           (cnipwhitelist_mode == 2 && IP_SET_test_dst_ip(state, in, out, skb, "wechat_iplist") > 0)) {
				x = SERVER_GROUP_0;
			} else if (IP_SET_test_dst_port(state, in, out, skb, "gfw_udp_port_list0") > 0 ||
			           IP_SET_test_dst_netport(state, in, out, skb, "app_list0") > 0) {
				x = SERVER_GROUP_0;
			}

			if (x == -1) {
				if (cnipwhitelist_mode == 1) {
					x = SERVER_GROUP_0;
				} else if (cnipwhitelist_mode == 2) {
					goto bypass_udp;
				} else {
					goto natcap_dual_out_udp;
				}
			}

			natcap_server_info_select(x, state, in, out, skb, iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": no server found\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				return NF_ACCEPT;
			}
			natcap_tuple_to_ns(ns, &server, iph->protocol);
			ns->n.group_x = x;

			if (in && strncmp(in->name, "natcap", 6) == 0) {
				if (!(NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &ns->n.status);
			}
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
		}
	}

dnat_out:
	if (!(IPS_NATCAP & ct->status) && !test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time out */
		/* init natcap_session if needed */
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			if (natcap_session_in(ct) == NULL) {
				NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_init failed\n", DEBUG_TCP_ARG(iph,l4));
			}
			break;
		case IPPROTO_UDP:
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			if (natcap_session_in(ct) == NULL) {
				NATCAP_WARN("(CD)" DEBUG_UDP_FMT ": natcap_session_init failed\n", DEBUG_UDP_ARG(iph,l4));
			}
			break;
		}
		if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			switch (iph->protocol) {
			case IPPROTO_TCP:
				NATCAP_ERROR("(CD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
				break;
			case IPPROTO_UDP:
				NATCAP_ERROR("(CD)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
				break;
			}
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_DROP;
		}
	}

	switch (iph->protocol) {
	case IPPROTO_TCP:
		NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));
		break;
	case IPPROTO_UDP:
		NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": after encode\n", DEBUG_UDP_ARG(iph,l4));
		break;
	}

natcaped_out:
	xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
	if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
	if (iph->protocol == IPPROTO_TCP && cnipwhitelist_mode == 0) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (TCPH(l4)->syn && !TCPH(l4)->ack && cnipwhitelist_mode == 0) {
			if (!(IPS_NATCAP_SYN1 & ct->status) && !test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn1\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if (!(IPS_NATCAP_SYN2 & ct->status) && !test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn2\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if ((IPS_NATCAP_SYN1 & ct->status) && (IPS_NATCAP_SYN2 & ct->status)) {
				if (!is_natcap_server(iph->daddr)) {
					NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn3 del target from gfwlist0\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_del_dst_ip(state, in, out, skb, "gfwlist0");
				}
			}
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_pre_ct_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_ct_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct natcap_session *ns;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt = { };

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		if (iph->protocol == IPPROTO_TCP) {
			if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (TCPH(l4)->syn && !TCPH(l4)->ack) {
				struct natcap_TCPOPT *opt;
				if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
					return NF_DROP;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				opt = natcap_tcp_decode_header(TCPH(l4));
				if (opt != NULL) {
					if (!inet_is_local(in, iph->daddr)) {
						set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
						return NF_ACCEPT;
					}
					if (opt->header.opcode == TCPOPT_NATCAP) {
						struct tuple server;
						if (NATCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_DST) {
							server.ip = opt->dst.data.ip;
							server.port = opt->dst.data.port;
							//server.encryption = opt->header.encryption;
							if (natcap_dnat_setup(ct, server.ip, server.port) == NF_ACCEPT) {
								NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup ok, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
							}
						} else if (NATCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_ALL) {
							server.ip = opt->all.data.ip;
							server.port = opt->all.data.port;
							//server.encryption = opt->header.encryption;
							if (natcap_dnat_setup(ct, server.ip, server.port) == NF_ACCEPT) {
								NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup ok, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
							}
						}
					}
					xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": set mark 0x%x\n", DEBUG_TCP_ARG(iph,l4), XT_MARK_NATCAP);
					return NF_ACCEPT;
				}
			}
		}
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
	ns = natcap_session_get(ct);
	if (NULL == ns) {
		return NF_ACCEPT;
	}

	if (!(NS_NATCAP_NOLIMIT & ns->n.status) && natcap_rx_flow_ctrl(skb, ct) < 0) {
		return NF_DROP;
	}

	flow_total_rx_bytes += skb->len;

	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (TCPH(l4)->syn || TCPH(l4)->rst) {
			NATCAP_INFO("(CPCI)" DEBUG_TCP_FMT ": touch for server%d ip=%pI4\n", DEBUG_TCP_ARG(iph,l4),
			            ns->n.group_x, &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
			natcap_server_in_touch(ns->n.group_x, ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,l4));

		tcpopt.header.encryption = !!(NS_NATCAP_ENC & ns->n.status);
		ret = natcap_tcp_decode(ct, skb, &tcpopt, IP_CT_DIR_REPLY);
		if (ret != 0) {
			NATCAP_ERROR("(CPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
			return NF_DROP;
		}
		if ((tcpopt.header.type & NATCAP_TCPOPT_CONFUSION)) {
			__be32 offset = get_byte4((const void *)&tcpopt + tcpopt.header.opsize - sizeof(unsigned int));
			ns->n.tcp_ack_offset = ntohl(offset);
			//short_set_bit(NS_NATCAP_CONFUSION_BIT, &ns->n.status);
		}
		if (NATCAP_TCPOPT_TYPE(tcpopt.header.type) == NATCAP_TCPOPT_TYPE_CONFUSION && (NS_NATCAP_CONFUSION & ns->n.status)) {
			if (nf_ct_seq_offset(ct, IP_CT_DIR_REPLY, ntohl(TCPH(l4)->seq + 1)) != 0 - ns->n.tcp_ack_offset) {
				nf_ct_seqadj_init(ct, ctinfo, 0 - ns->n.tcp_ack_offset);
			}
			consume_skb(skb);
			return NF_STOLEN;
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_E_MAGIC_A) &&
		        UDPH(l4)->len == __constant_htons(sizeof(struct udphdr) + 4)) {
			if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
				NATCAP_INFO("(CPCI)" DEBUG_UDP_FMT ": got CFM pkt\n", DEBUG_UDP_ARG(iph,l4));
			}
			natcap_server_in_touch(ns->n.group_x, ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
			consume_skb(skb);
			return NF_STOLEN;
		}

		if ((NS_NATCAP_ENC & ns->n.status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(CPCI)" DEBUG_UDP_FMT ": skb_make_writable() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_decode);
			skb_rcsum_tcpudp(skb);
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_UDP_FMT ": after decode\n", DEBUG_UDP_ARG(iph,l4));
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_pre_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_pre_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct, *master;
	struct natcap_session *ns;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;

	if (mode == MIXING_MODE)
		return NF_ACCEPT;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	master = nf_ct_get(skb, &ctinfo);
	if (NULL == master) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & master->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_PRE & master->status)) {
		return NF_ACCEPT;
	}
	if (!nf_ct_is_confirmed(master)) {
		if (skb->mark & natcap_ignore_mask) {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			set_bit(IPS_NATCAP_BYPASS_BIT, &master->status);
			set_bit(IPS_NATCAP_SERVER_BIT, &master->status);
			return NF_ACCEPT;
		}
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (skb->len < iph->ihl * 4 + sizeof(struct tcphdr)) {
			return NF_ACCEPT;
		}
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if ( ntohs(TCPH(l4)->window) == (ntohs(iph->id) ^ (ntohl(TCPH(l4)->seq) & 0xffff) ^ (ntohl(TCPH(l4)->ack_seq) & 0xffff)) ) {
			int dir = CTINFO2DIR(ctinfo);
			int lock_seq = (TCPH(l4)->syn && TCPH(l4)->urg_ptr == __constant_htons(1)) ? 1 : 0;
			unsigned int tcphdr_len = TCPH(l4)->doff * 4;
			unsigned int foreign_seq = ntohl(TCPH(l4)->seq) + ntohs(iph->tot_len) - iph->ihl * 4 - tcphdr_len + !!TCPH(l4)->syn;

			if (!inet_is_local(in, iph->daddr)) {
				set_bit(IPS_NATCAP_PRE_BIT, &master->status);
				return NF_ACCEPT;
			}

			NATCAP_DEBUG("(CPI)" DEBUG_TCP_FMT ": got UDP-to-TCP packet\n", DEBUG_TCP_ARG(iph,l4));

			if (skb->ip_summed == CHECKSUM_NONE) {
				if (skb_rcsum_verify(skb) != 0) {
					NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": skb_rcsum_verify fail\n", DEBUG_TCP_ARG(iph,l4));
					return NF_DROP;
				}
				skb->csum = 0;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}

			if (!skb_make_writable(skb, iph->ihl * 4 + tcphdr_len)) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			skb_nfct_reset(skb);

			memmove((void *)UDPH(l4) + sizeof(struct udphdr), (void *)UDPH(l4) + tcphdr_len, skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - tcphdr_len);
			iph->tot_len = htons(ntohs(iph->tot_len) - (tcphdr_len - sizeof(struct udphdr)));
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			UDPH(l4)->check = CSUM_MANGLED_0;
			skb->len -= tcphdr_len - sizeof(struct udphdr);
			skb->tail -= tcphdr_len - sizeof(struct udphdr);
			iph->protocol = IPPROTO_UDP;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			if (master->master) {
				iph->saddr = master->master->tuplehash[dir].tuple.src.u3.ip;
				iph->daddr = master->master->tuplehash[dir].tuple.dst.u3.ip;
				UDPH(l4)->source = master->master->tuplehash[dir].tuple.src.u.all;
				UDPH(l4)->dest = master->master->tuplehash[dir].tuple.dst.u.all;
			}
			skb_rcsum_tcpudp(skb);

			if (in)
				net = dev_net(in);
			else if (out)
				net = dev_net(out);
			ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			ct = nf_ct_get(skb, &ctinfo);
			if (!ct) {
				return NF_DROP;
			}
			natcap_clone_timeout(master, ct);

			ns = natcap_session_in(ct);
			if (ns == NULL) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
				short_set_bit(NS_NATCAP_TCPUDPENC_BIT, &ns->n.status);
			}

			ns->n.foreign_seq = foreign_seq;
			if (lock_seq)
				ns->ping.lock = 2;

			if (!master->master) {
				nf_conntrack_get(&ct->ct_general);
				master->master = ct;
			}
			if (dir == 1) {
				//on client side, try send ping
				if (((ns->n.foreign_seq / 1024) % 8 == 0) ||
				        (ns->ping.stage == 0 && uintmindiff(ns->ping.jiffies, jiffies) > 3 * HZ) ||
				        (ns->ping.stage == 1 && uintmindiff(ns->ping.jiffies, jiffies) > 1 * HZ)) {
					if (ns->ping.stage == 0)
						ns->ping.jiffies = jiffies;
					ns->ping.stage = 1;
					skb = skb_copy(skb, GFP_ATOMIC);
					if (skb == NULL) {
						NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
						return NF_ACCEPT;
					}
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;
					skb->len = sizeof(struct iphdr) + sizeof(struct tcphdr);

					iph->tot_len = htons(skb->len);
					iph->protocol = IPPROTO_TCP;
					iph->saddr = master->tuplehash[dir].tuple.dst.u3.ip;
					iph->daddr = master->tuplehash[dir].tuple.src.u3.ip;
					iph->ttl = 0x80;
					iph->id = htons(jiffies);
					iph->frag_off = 0x0;

					TCPH(l4)->source = master->tuplehash[dir].tuple.dst.u.all;
					TCPH(l4)->dest = master->tuplehash[dir].tuple.src.u.all;
					TCPH(l4)->seq = htonl(ns->n.current_seq);
					TCPH(l4)->ack_seq = htonl(ns->n.foreign_seq);
					tcp_flag_word(TCPH(l4)) = TCP_FLAG_ACK;
					TCPH(l4)->res1 = 0;
					TCPH(l4)->doff = (sizeof(struct tcphdr)) / 4;
					TCPH(l4)->window = htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff))));
					TCPH(l4)->check = 0;
					TCPH(l4)->urg_ptr = 0;

					iph->protocol = IPPROTO_TCP;
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);

					NATCAP_INFO("(CPI)" DEBUG_TCP_FMT ": ping: send\n", DEBUG_TCP_ARG(iph,l4));

					skb_nfct_reset(skb);
					nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, skb);
					master = nf_ct_get(skb, &ctinfo);
					if (!master) {
						consume_skb(skb);
						return NF_ACCEPT;
					}
					natcap_clone_timeout(master, ct);
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						if (ret != NF_STOLEN)
							consume_skb(skb);
						return NF_ACCEPT;
					}

					//response pong ack.
					skb_push(skb, (char *)iph - (char *)eth_hdr(skb));
					if ((char *)iph - (char *)eth_hdr(skb) >= ETH_HLEN) {
						unsigned char mac[ETH_ALEN];
						memcpy(mac, eth_hdr(skb)->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, mac, ETH_ALEN);
					}
					skb_nfct_reset(skb);
					dev_queue_xmit(skb);

					return NF_ACCEPT;
				}
				/*
				if (ns->ping.stage == 1 && uintmindiff(ns->ping.jiffies, jiffies) > 3 * HZ) {
					//timeout
				}
				*/
			}

			NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": after decode for UDP-to-TCP packet\n", DEBUG_UDP_ARG(iph,l4));
			return NF_ACCEPT;
		} else if ( TCPH(l4)->window == htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff)))) ) {
			int dir = CTINFO2DIR(ctinfo);
			unsigned int tcphdr_len = TCPH(l4)->doff * 4;
			unsigned int foreign_seq = ntohl(TCPH(l4)->seq) + ntohs(iph->tot_len) - iph->ihl * 4 - tcphdr_len + !!TCPH(l4)->syn;

			if (!inet_is_local(in, iph->daddr)) {
				set_bit(IPS_NATCAP_PRE_BIT, &master->status);
				return NF_ACCEPT;
			}

			if (master->master) {
				if (dir == 0) {
					/* on server side, got ping, response pong */
					/* XXX I just confirm it first  */
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						return ret;
					}

					ct = master->master;
					ns = natcap_session_in(ct);
					if (ns == NULL) {
						NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}

					if (skb_tailroom(skb) < 16 && pskb_expand_head(skb, 0, 16, GFP_ATOMIC)) {
						NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head failed\n", DEBUG_ARG_PREFIX);
						consume_skb(skb);
						return NF_STOLEN;
					}
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;

					skb->len = iph->ihl * 4 + sizeof(struct tcphdr) + 16;
					iph->tot_len = htons(skb->len);
					iph->protocol = IPPROTO_TCP;
					iph->saddr = master->tuplehash[dir].tuple.dst.u3.ip;
					iph->daddr = master->tuplehash[dir].tuple.src.u3.ip;
					iph->ttl = 0x80;
					iph->id = htons(jiffies);
					iph->frag_off = 0x0;

					TCPH(l4)->source = master->tuplehash[dir].tuple.dst.u.all;
					TCPH(l4)->dest = master->tuplehash[dir].tuple.src.u.all;

					TCPH(l4)->seq = htonl(ns->n.current_seq);
					TCPH(l4)->ack_seq = htonl(ns->n.foreign_seq);
					tcp_flag_word(TCPH(l4)) = TCP_FLAG_ACK;
					TCPH(l4)->res1 = 0;
					TCPH(l4)->doff = (sizeof(struct tcphdr) + 16) / 4;
					TCPH(l4)->window = htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff))));
					TCPH(l4)->check = 0;
					TCPH(l4)->urg_ptr = 0;

					set_byte1(l4 + sizeof(struct tcphdr), TCPOPT_NATCAP);
					set_byte1(l4 + sizeof(struct tcphdr) + 1, 16);
					set_byte2(l4 + sizeof(struct tcphdr) + 2, 0);
					set_byte4(l4 + sizeof(struct tcphdr) + 4, ct->tuplehash[dir].tuple.src.u3.ip);
					set_byte4(l4 + sizeof(struct tcphdr) + 4 + 4, ct->tuplehash[dir].tuple.dst.u3.ip);
					set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4, ct->tuplehash[dir].tuple.src.u.all);
					set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2, ct->tuplehash[dir].tuple.dst.u.all);

					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);

					NATCAP_INFO("(CPI)" DEBUG_TCP_FMT ": get ping: send pong\n", DEBUG_TCP_ARG(iph,l4));

					skb_nfct_reset(skb);
					nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, skb);
					master = nf_ct_get(skb, &ctinfo);
					if (!master) {
						consume_skb(skb);
						return NF_STOLEN;
					}
					natcap_clone_timeout(master, ct);
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						if (ret != NF_STOLEN)
							consume_skb(skb);
						return NF_STOLEN;
					}

					//response pong ack.
					skb_push(skb, (char *)iph - (char *)eth_hdr(skb));
					if ((char *)iph - (char *)eth_hdr(skb) >= ETH_HLEN) {
						unsigned char mac[ETH_ALEN];
						memcpy(mac, eth_hdr(skb)->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, mac, ETH_ALEN);
					}
					skb_nfct_reset(skb);
					dev_queue_xmit(skb);
					return NF_STOLEN;
				} else {
					/* on client side,, got pong */
					if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr) + 16)) {
						return NF_ACCEPT;
					}
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;

					/* XXX I just confirm it first  */
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						return ret;
					}

					ct = master->master;
					ns = natcap_session_in(ct);
					if (ns == NULL) {
						NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}

					if (!ns->ping.remote_saddr) {
						ns->ping.remote_saddr = get_byte4(l4 + sizeof(struct tcphdr) + 4);
						ns->ping.remote_daddr = get_byte4(l4 + sizeof(struct tcphdr) + 4 + 4);
						ns->ping.remote_source = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4);
						ns->ping.remote_dest = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2);
						NATCAP_INFO("(CPI)" DEBUG_TCP_FMT ": get pong for %pI4:%u->%pI4:%u\n", DEBUG_TCP_ARG(iph,l4),
						            &ns->ping.remote_saddr, ntohs(ns->ping.remote_source),
						            &ns->ping.remote_daddr, ntohs(ns->ping.remote_dest));
					}
					if (ns->ping.remote_saddr != get_byte4(l4 + sizeof(struct tcphdr) + 4) ||
					        ns->ping.remote_daddr != get_byte4(l4 + sizeof(struct tcphdr) + 4 + 4) ||
					        ns->ping.remote_source != get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4) ||
					        ns->ping.remote_dest != get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2)) {
						NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": invalid pong\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}

					NATCAP_INFO("(CPI)" DEBUG_TCP_FMT ": get pong\n", DEBUG_TCP_ARG(iph,l4));

					ns->n.foreign_seq = foreign_seq;
					ns->ping.jiffies = jiffies;
					ns->ping.stage = 0;
					if (ns->ping.lock == 1) ns->ping.lock = 0;

					consume_skb(skb);
					return NF_STOLEN;
				}
			} else {
				/* on server side, got ping syn */
				if (dir == 0 && TCPH(l4)->syn) {
					if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr) + 16 + TCPOLEN_MSS)) {
						return NF_ACCEPT;
					}

					NATCAP_INFO("(CPI)" DEBUG_TCP_FMT ": get ping syn\n", DEBUG_TCP_ARG(iph,l4));

					/* XXX I just confirm it first  */
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						return ret;
					}
					skb_nfct_reset(skb);

					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;
					iph->saddr = get_byte4(l4 + sizeof(struct tcphdr) + 4);
					iph->daddr = get_byte4(l4 + sizeof(struct tcphdr) + 4 + 4);
					TCPH(l4)->source = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4);
					TCPH(l4)->dest = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2);

					skb->len = iph->ihl * 4 + sizeof(struct udphdr);
					iph->tot_len = htons(skb->len);
					UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
					UDPH(l4)->check = CSUM_MANGLED_0;
					iph->protocol = IPPROTO_UDP;
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);

					NATCAP_INFO("(CPI)" DEBUG_UDP_FMT ": get ping syn [UDP]\n", DEBUG_UDP_ARG(iph,l4));

					if (in)
						net = dev_net(in);
					else if (out)
						net = dev_net(out);
					ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
					if (ret != NF_ACCEPT) {
						if (ret != NF_STOLEN)
							consume_skb(skb);
						return NF_STOLEN;
					}
					ct = nf_ct_get(skb, &ctinfo);
					if (!ct) {
						consume_skb(skb);
						return NF_STOLEN;
					}

					nf_conntrack_get(&ct->ct_general);
					master->master = ct;

					ns = natcap_session_in(ct);
					if (ns == NULL) {
						NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}
					if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
						consume_skb(skb);
						return NF_STOLEN;
					}

					ns->n.foreign_seq = foreign_seq;

					skb->len = iph->ihl * 4 + sizeof(struct tcphdr) + 16 + TCPOLEN_MSS;
					iph->tot_len = htons(skb->len);
					iph->protocol = IPPROTO_TCP;
					iph->saddr = master->tuplehash[dir].tuple.dst.u3.ip;
					iph->daddr = master->tuplehash[dir].tuple.src.u3.ip;
					iph->ttl = 0x80;
					iph->id = htons(jiffies);
					iph->frag_off = 0x0;

					TCPH(l4)->source = master->tuplehash[dir].tuple.dst.u.all;
					TCPH(l4)->dest = master->tuplehash[dir].tuple.src.u.all;

					TCPH(l4)->seq = htonl(ns->n.current_seq - 1);
					TCPH(l4)->ack_seq = htonl(ns->n.foreign_seq);
					tcp_flag_word(TCPH(l4)) = TCP_FLAG_SYN | TCP_FLAG_ACK;
					TCPH(l4)->res1 = 0;
					TCPH(l4)->doff = (sizeof(struct tcphdr) + 16 + TCPOLEN_MSS) / 4;
					TCPH(l4)->window = htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff))));
					TCPH(l4)->check = 0;
					TCPH(l4)->urg_ptr = 0;

					set_byte1(l4 + sizeof(struct tcphdr), TCPOPT_NATCAP);
					set_byte1(l4 + sizeof(struct tcphdr) + 1, 16);
					set_byte2(l4 + sizeof(struct tcphdr) + 2, 0);
					set_byte4(l4 + sizeof(struct tcphdr) + 4, ct->tuplehash[dir].tuple.src.u3.ip);
					set_byte4(l4 + sizeof(struct tcphdr) + 4 + 4, ct->tuplehash[dir].tuple.dst.u3.ip);
					set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4, ct->tuplehash[dir].tuple.src.u.all);
					set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2, ct->tuplehash[dir].tuple.dst.u.all);
					set_byte1(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2, TCPOPT_MSS);
					set_byte1(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2 + 1, TCPOLEN_MSS);
					set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2 + 1 + 1, ntohs(natcap_max_pmtu - 40));

					ns->ping.saddr = iph->saddr;
					ns->ping.daddr = iph->daddr;
					ns->ping.source = TCPH(l4)->source;
					ns->ping.dest = TCPH(l4)->dest;

					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);

					skb_nfct_reset(skb);
					nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, skb);
					master = nf_ct_get(skb, &ctinfo);
					if (!master) {
						consume_skb(skb);
						return NF_STOLEN;
					}
					natcap_clone_timeout(master, ct);
					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						if (ret != NF_STOLEN)
							consume_skb(skb);
						return NF_STOLEN;
					}

					//response syn ack.
					skb_push(skb, (char *)iph - (char *)eth_hdr(skb));
					if ((char *)iph - (char *)eth_hdr(skb) >= ETH_HLEN) {
						unsigned char mac[ETH_ALEN];
						memcpy(mac, eth_hdr(skb)->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, mac, ETH_ALEN);
					}
					skb_nfct_reset(skb);
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}
			}
			NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": got UDP-to-TCP packet syn\n", DEBUG_TCP_ARG(iph,l4));
			return NF_DROP;
		} else {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			return NF_ACCEPT;
		}
	}

	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	l4 = (void *)iph + iph->ihl * 4;
	if (skb_is_gso(skb)) {
		NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (skb->len < iph->ihl * 4 + sizeof(struct udphdr) + 8) {
		return NF_ACCEPT;
	}
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 8)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_F_MAGIC) || get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_7_MAGIC)) {
		int offlen;
		int ver = (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_7_MAGIC));

		if (skb->len < iph->ihl * 4 + sizeof(struct tcphdr) + 8) {
			return NF_ACCEPT;
		}
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr) + 8)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (!inet_is_local(in, iph->daddr)) {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			return NF_ACCEPT;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
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

		/* XXX I just confirm it first  */
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		skb_nfct_reset(skb);

		offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4 - 8;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(l4) + 4, (void *)UDPH(l4) + 4 + 8, offlen);
		iph->tot_len = htons(ntohs(iph->tot_len) - 8);
		skb->len -= 8;
		skb->tail -= 8;
		iph->protocol = IPPROTO_TCP;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(skb);

		if (in)
			net = dev_net(in);
		else if (out)
			net = dev_net(out);
		ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		ct = nf_ct_get(skb, &ctinfo);
		if (!ct) {
			return NF_DROP;
		}
		natcap_clone_timeout(master, ct);

		ns = natcap_session_in(ct);
		if (ns == NULL) {
			NATCAP_WARN("(CPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
		if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
			short_set_bit(NS_NATCAP_TCPUDPENC_BIT, &ns->n.status);
		}
		if (ns->peer.ver != ver) ns->peer.ver = ver;

		/* safe to set IPS_NATCAP_CFM here, this master only run in this hook */
		if (!(IPS_NATCAP_CFM & master->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &master->status)) {
			nf_conntrack_get(&ct->ct_general);
			master->master = ct;
			ns->peer.jiffies = jiffies; //set peer.jiffies once init
		}
		return NF_ACCEPT;

	} else if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_9_MAGIC)) {
		if (skb->len < iph->ihl * 4 + sizeof(struct udphdr) + 8 + 16 + 4) {
			return NF_ACCEPT;
		}
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 8 + 16 + 4)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (!inet_is_local(in, iph->daddr)) {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			return NF_ACCEPT;
		}

		if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(NATCAP_9_MAGIC_TYPE1)) {
			__be32 sip, dip;

			if (!master->master) {
				xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
				NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer pass forward: type1\n", DEBUG_UDP_ARG(iph,l4));
				return NF_ACCEPT;
			}

			ct = master->master;
			ns = natcap_session_get(ct);
			if (ns == NULL) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}

			sip = get_byte4((void *)UDPH(l4) + 8 + 4 + 4);
			dip = iph->saddr;

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			skb_nfct_reset(skb);

			UDPH(l4)->check = CSUM_MANGLED_0;

			if (ns->peer.cnt == 0 && peer_multipath && peer_multipath <= MAX_PEER_NUM) {
				set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE2));
				set_byte4((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2, iph->saddr);
				iph->saddr = iph->daddr;
				//lock once
				if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
					__be32 ip;
					unsigned int i, j, idx;
					unsigned int off = prandom_u32();
					for (i = 0; i < PEER_PUB_NUM; i++) {
						idx = (i + off) % PEER_PUB_NUM;
						ip = peer_pub_ip[idx];
						if (ip != 0 && ip != sip && ip != dip) {
							for (j = 0; j < MAX_PEER_NUM && j < peer_multipath; j++)
								if (ns->peer.tuple3[j].dip == ip)
									break;

							if (j == MAX_PEER_NUM || j == peer_multipath)
								for (j = 0; j < MAX_PEER_NUM && j < peer_multipath; j++)
									if (ns->peer.tuple3[j].dip == 0) {
										ns->peer.cnt++;
										ns->peer.tuple3[j].dip = ip;
										ns->peer.tuple3[j].dport = htons(prandom_u32() % (65536 - 1024) + 1024);
										ns->peer.tuple3[j].sport = htons(prandom_u32() % (65536 - 1024) + 1024);
										ns->peer.total_weight += 1;
										ns->peer.weight[j] = 1;
										NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer%px select %u-%pI4:%u j=%u\n", DEBUG_UDP_ARG(iph,l4), (void *)&ns,
										             ntohs(ns->peer.tuple3[j].sport), &ns->peer.tuple3[j].dip, ntohs(ns->peer.tuple3[j].dport), j);
										break;
									}
						}
						if (ns->peer.cnt == peer_multipath)
							break;
					}
				}
			} else if (ns->peer.cnt == 0 && peer_multipath > MAX_PEER_NUM) { /* peer_multipath = MAX_PEER_NUM + num_of_multipath */
				set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE3));
				set_byte4((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2, iph->saddr);
				//lock once
				if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
					unsigned int j;
					for (j = 0; j < MAX_PEER_NUM; j++)
						if (ns->peer.tuple3[j].dip == 0 && is_fastpath_route_ready(&natcap_pfr[j])) {
							ns->peer.cnt++;
							ns->peer.tuple3[j].dip = iph->saddr;
							ns->peer.tuple3[j].dport = htons(prandom_u32() % (65536 - 1024) + 1024);
							ns->peer.tuple3[j].sport = htons(prandom_u32() % (65536 - 1024) + 1024);
							ns->peer.total_weight += natcap_pfr[j].weight;
							ns->peer.weight[j] = natcap_pfr[j].weight;
							ns->peer.req_cnt = 3; /* init notify weight */
						}
				}
			}

			if (ns->peer.cnt > 0 && peer_multipath <= MAX_PEER_NUM) {
				int ret;
				unsigned int i;
				struct ethhdr *neth;
				struct sk_buff *nskb;
				for (i = 0; i < MAX_PEER_NUM; i++) {
					if (ns->peer.tuple3[i].dip == 0)
						break;
					if (short_test_bit(i, &ns->peer.mark))
						continue;

					nskb = skb_copy(skb, GFP_ATOMIC);
					if (nskb == NULL)
						break;

					neth = eth_hdr(nskb);
					iph = ip_hdr(nskb);
					if ((char *)iph - (char *)neth >= ETH_HLEN) {
						unsigned char mac[ETH_ALEN];
						memcpy(mac, neth->h_source, ETH_ALEN);
						memcpy(neth->h_source, neth->h_dest, ETH_ALEN);
						memcpy(neth->h_dest, mac, ETH_ALEN);
					}
					l4 = (void *)iph + iph->ihl * 4;

					iph->id = htons(jiffies);
					iph->daddr = ns->peer.tuple3[i].dip;
					UDPH(l4)->dest = ns->peer.tuple3[i].dport;
					UDPH(l4)->source = ns->peer.tuple3[i].sport;
					set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2, htons(i));

					nskb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(nskb);

					if (in)
						net = dev_net(in);
					else if (out)
						net = dev_net(out);
					ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, nskb);
					if (ret != NF_ACCEPT) {
						consume_skb(nskb);
						break;
					}
					ret = nf_conntrack_confirm(nskb);
					if (ret != NF_ACCEPT) {
						consume_skb(nskb);
						break;
					}
					ct = nf_ct_get(nskb, &ctinfo);
					if (!ct) {
						consume_skb(nskb);
						break;
					}
					if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
						ct->mark |= i;
						nf_conntrack_get(&master->master->ct_general);
						ct->master = master->master;
						ct = ct->master;
					}

					NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": BIND=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n", DEBUG_UDP_ARG(iph,l4), i,
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
					            );

					skb_push(nskb, (char *)iph - (char *)neth);
					dev_queue_xmit(nskb);
				}
			} else if (ns->peer.cnt > 0 && peer_multipath > MAX_PEER_NUM) {
				int ret;
				unsigned int i;
				struct sk_buff *nskb;
				for (i = 0; i < MAX_PEER_NUM; i++) {
					if (ns->peer.tuple3[i].dip == 0 || !is_fastpath_route_ready(&natcap_pfr[i]))
						continue;
					if (short_test_bit(i, &ns->peer.mark))
						continue;

					nskb = skb_copy(skb, GFP_ATOMIC);
					if (nskb == NULL)
						break;

					iph = ip_hdr(nskb);
					l4 = (void *)iph + iph->ihl * 4;

					iph->id = htons(jiffies);
					iph->daddr = ns->peer.tuple3[i].dip;
					iph->saddr = natcap_pfr[i].saddr;
					UDPH(l4)->dest = ns->peer.tuple3[i].dport;
					UDPH(l4)->source = ns->peer.tuple3[i].sport;
					set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2, htons(i));

					nskb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(nskb);
					nskb->dev = natcap_pfr[i].rt_out.outdev;

					net = dev_net(natcap_pfr[i].rt_out.outdev);
					ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, nskb);
					if (ret != NF_ACCEPT) {
						consume_skb(nskb);
						break;
					}
					ret = nf_conntrack_confirm(nskb);
					if (ret != NF_ACCEPT) {
						consume_skb(nskb);
						break;
					}
					ct = nf_ct_get(nskb, &ctinfo);
					if (!ct) {
						consume_skb(nskb);
						break;
					}
					if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
						ct->mark |= i;
						nf_conntrack_get(&master->master->ct_general);
						ct->master = master->master;
						ct = ct->master;
					}

					NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": BIND=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] outdev=%s\n", DEBUG_UDP_ARG(iph,l4), i,
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
					             natcap_pfr[i].rt_out.outdev->name
					            );

					skb_push(nskb, natcap_pfr[i].rt_out.l2_head_len);
					skb_reset_mac_header(nskb);
					memcpy(skb_mac_header(nskb), natcap_pfr[i].rt_out.l2_head, natcap_pfr[i].rt_out.l2_head_len);
					if (natcap_pfr[i].last_rxtx == 0) {
						natcap_pfr[i].last_tx_jiffies = jiffies;
						natcap_pfr[i].last_rxtx = 1;
					}
					dev_queue_xmit(nskb);
				}
			}

			consume_skb(skb);
			return NF_STOLEN;
		} else if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(NATCAP_9_MAGIC_TYPE2)) {
			set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE3));
			UDPH(l4)->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if (!nf_ct_is_confirmed(master)) {
				__be32 dip = get_byte4((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2);
				__be16 dport = htons(prandom_u32() % (65536 - 1024) + 1024);
				if (natcap_dnat_setup(master, dip, dport) != NF_ACCEPT) {
					return NF_DROP;
				}

				set_bit(IPS_NATCAP_BYPASS_BIT, &master->status);
				set_bit(IPS_NATCAP_ACK_BIT, &master->status);
				set_bit(IPS_NATFLOW_FF_STOP_BIT, &master->status);
				set_bit(IPS_NATCAP_CFM_BIT, &master->status);
				set_bit(IPS_NATCAP_CONE_BIT, &master->status);
			}

			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			return NF_ACCEPT;
		} else if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(NATCAP_9_MAGIC_TYPE3)) {
			int i, ret;
			unsigned int tmp;
			struct ethhdr *eth;
			if (!nf_ct_is_confirmed(master) && !master->master) {
				struct nf_conntrack_tuple tuple;
				struct nf_conntrack_tuple_hash *h;

				memset(&tuple, 0, sizeof(tuple));
				tuple.src.u3.ip = get_byte4((void *)UDPH(l4) + 8 + 4 + 4);
				tuple.src.u.udp.port = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4);
				tuple.dst.u3.ip = get_byte4((void *)UDPH(l4) + 8 + 4 + 4 + 4);
				tuple.dst.u.udp.port = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2);
				tuple.src.l3num = PF_INET;
				tuple.dst.protonum = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
				h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
				h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
				if (h) {
					struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
					if (!(IPS_NATCAP & ct->status)) {
						nf_ct_put(ct);
						return NF_DROP;
					}
					ns = natcap_session_get(ct);
					if (ns == NULL) {
						NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
						nf_ct_put(ct);
						return NF_DROP;
					}

					i = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2);
					i = ntohs(i) % MAX_PEER_NUM;

					if (!short_test_bit(i, &ns->peer.mark)) {
						short_set_bit(i, &ns->peer.mark);
						ns->peer.tuple3[i].dip = iph->saddr;
						ns->peer.tuple3[i].dport = UDPH(l4)->source;
						ns->peer.tuple3[i].sport = UDPH(l4)->dest;
						ns->peer.cnt++;
						ns->peer.total_weight += 1;
						ns->peer.weight[i] = 1;
						NATCAP_INFO("(CPI)" DEBUG_UDP_FMT ": CFM=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] peer.mark=0x%x\n", DEBUG_UDP_ARG(iph,l4), i,
						            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
						            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
						            &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
						            &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
						            ns->peer.mark);
					}

					if (!(IPS_NATCAP_CFM & master->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &master->status)) {
						nf_conntrack_get(&ct->ct_general);
						master->master = ct;
						master->mark |= i;
					}
					nf_ct_put(ct);
				}
			}

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			skb_nfct_reset(skb);

			eth = eth_hdr(skb);
			if ((char *)iph - (char *)eth >= ETH_HLEN) {
				unsigned char mac[ETH_ALEN];
				memcpy(mac, eth->h_source, ETH_ALEN);
				memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
				memcpy(eth->h_dest, mac, ETH_ALEN);
			}

			iph->id = htons(jiffies);

			tmp = iph->daddr;
			iph->daddr = iph->saddr;
			iph->saddr = tmp;

			set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE4));
			tmp = UDPH(l4)->dest;
			UDPH(l4)->dest = UDPH(l4)->source;
			UDPH(l4)->source = tmp;
			UDPH(l4)->check = CSUM_MANGLED_0;

			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if (in)
				net = dev_net(in);
			else if (out)
				net = dev_net(out);
			ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}

			skb_push(skb, (char *)iph - (char *)eth);
			dev_queue_xmit(skb);

			return NF_STOLEN;
		} else if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(NATCAP_9_MAGIC_TYPE4)) {
			int ret;
			unsigned int i;
			if (!master->master) {
				xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
				NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer pass forward: type4\n", DEBUG_UDP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			ct = master->master;
			ns = natcap_session_get(ct);
			if (ns == NULL) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}

			i = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2);
			i = ntohs(i) % MAX_PEER_NUM;
			if (!short_test_bit(i, &ns->peer.mark) &&
			        ns->peer.tuple3[i].dip == iph->saddr && ns->peer.tuple3[i].dport == UDPH(l4)->source && ns->peer.tuple3[i].sport == UDPH(l4)->dest) {
				master->mark |= i;
				short_set_bit(i, &ns->peer.mark);
				NATCAP_INFO("(CPI)" DEBUG_UDP_FMT ": CFM=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] peer.mark=0x%x\n", DEBUG_UDP_ARG(iph,l4), i,
				            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				            &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				            &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
				            ns->peer.mark);
			}

			if (i < MAX_PEER_NUM) {
				natcap_pfr[i].last_rx_jiffies = jiffies;
				if (natcap_pfr[i].last_rxtx == 1) {
					natcap_pfr[i].last_rxtx = 0;
				}
			}

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}

			consume_skb(skb);
			return NF_STOLEN;
		} else if (get_byte4((void *)UDPH(l4) + 8 + 4) == __constant_htonl(NATCAP_9_MAGIC_TYPE5)) {
			int i;

			if (!master->master) {
				xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
				NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer pass forward: type5\n", DEBUG_UDP_ARG(iph,l4));
				return NF_ACCEPT;
			}

			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + 8 + MAX_PEER_NUM * 2)) {
				return NF_ACCEPT;
			}

			ct = master->master;
			ns = natcap_session_get(ct);
			if (ns == NULL) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			for (i = 0; i < MAX_PEER_NUM; i++) {
				unsigned short val = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 2 * i);
				val = ntohs(val);
				if (ns->peer.weight[i] != val) {
					ns->peer.total_weight = ns->peer.total_weight - ns->peer.weight[i] + val;
					ns->peer.weight[i] = val;
				}
			}

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}

			consume_skb(skb);
			return NF_STOLEN;
		}
		return NF_ACCEPT;

	} else if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(NATCAP_8_MAGIC)) {
		int offlen;
		int dir = CTINFO2DIR(ctinfo);
		unsigned int idx = 0;

		if (!inet_is_local(in, iph->daddr)) {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			return NF_ACCEPT;
		}

		if (!master->master) {
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer pass forward: data\n", DEBUG_UDP_ARG(iph,l4));
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

		idx = (master->mark & 0xff);
		ct = master->master;
		ns = natcap_session_get(ct);
		if (ns == NULL) {
			NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
			return NF_DROP;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
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

		if (idx < MAX_PEER_NUM && !short_test_bit(idx, &ns->peer.mark)) {
			short_set_bit(idx, &ns->peer.mark);
		}

		NATCAP_DEBUG("(CPI)" DEBUG_UDP_FMT ": peer pass up: before\n", DEBUG_UDP_ARG(iph,l4));

		/* XXX I just confirm it first  */
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		skb_nfct_reset(skb);

		iph->saddr = ct->tuplehash[dir].tuple.src.u3.ip;
		iph->daddr = ct->tuplehash[dir].tuple.dst.u3.ip;
		UDPH(l4)->source = ct->tuplehash[dir].tuple.src.u.tcp.port;
		UDPH(l4)->dest = ct->tuplehash[dir].tuple.dst.u.tcp.port;
		//UDPH(l4)->check = CSUM_MANGLED_0;

		offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4 - 8;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(l4) + 4, (void *)UDPH(l4) + 4 + 8, offlen);
		iph->tot_len = htons(ntohs(iph->tot_len) - 8);
		skb->len -= 8;
		skb->tail -= 8;
		iph->protocol = IPPROTO_TCP;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(skb);

		if (in)
			net = dev_net(in);
		else if (out)
			net = dev_net(out);
		ret = nf_conntrack_in_compat(net, pf, hooknum, skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		ct = nf_ct_get(skb, &ctinfo);
		if (!ct) {
			return NF_DROP;
		}

		if (idx < MAX_PEER_NUM) {
			natcap_pfr[idx].last_rx_jiffies = jiffies;
			if (natcap_pfr[idx].last_rxtx == 1) {
				natcap_pfr[idx].last_rxtx = 0;
			}

			atomic_add(skb->len, &natcap_pfr[idx].rx_speed[(jiffies / HZ) % SPEED_SAMPLE_COUNT]);
			atomic_set(&natcap_pfr[idx].rx_speed[(jiffies / HZ + 1) % SPEED_SAMPLE_COUNT], 0);
		}

		NATCAP_DEBUG("(CPI)" DEBUG_TCP_FMT ": peer pass up: after ct=[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n", DEBUG_TCP_ARG(iph,l4),
		             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
		             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
		             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
		             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all));

		return NF_ACCEPT;
	} else if (master->master || (IPS_NATCAP_CFM & master->status)) {
		//ufo come in
		if (!inet_is_local(in, iph->daddr)) {
			set_bit(IPS_NATCAP_PRE_BIT, &master->status);
			return NF_ACCEPT;
		}
		return NF_ACCEPT;
	} else {
		set_bit(IPS_NATCAP_PRE_BIT, &master->status);
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_post_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_post_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	unsigned long status = NATCAP_CLIENT_MODE;
	struct nf_conn *ct;
	struct natcap_session *ns;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct natcap_TCPOPT tcpopt = { };

	if (disabled)
		return NF_ACCEPT;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		/* match for WECHAT */
		//	POST /mmtls/402f5d55 HTTP/1.1
		//	Accept: */*
		//	Cache-Control: no-cache
		//	Connection: close
		//	Content-Length: 491
		//	Content-Type: application/octet-stream
		//	Host: szextshort.weixin.qq.com
		//	Upgrade: mmtls
		//	User-Agent: MicroMessenger Client
#define WECHAT_C_POST "POST /mmtls"
#define WECHAT_C_UA "User-Agent: MicroMessenger Client"
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL &&
		        iph->protocol == IPPROTO_TCP &&
		        !(IPS_NATCAP & ct->status) &&
		        (TCPH(l4)->dest == __constant_htons(80) || TCPH(l4)->dest == __constant_htons(8080))) {
			int data_len;
			unsigned char *data;
			data = skb->data + (iph->ihl << 2) + (TCPH(l4)->doff << 2);
			data_len = ntohs(iph->tot_len) - ((iph->ihl << 2) + (TCPH(l4)->doff << 2));
			if (data_len > 0) {
				int i = 0;
				if (strncasecmp(data, WECHAT_C_POST, strlen(WECHAT_C_POST)) == 0) {
					i += 11;
					while (i < data_len) {
						while (i < data_len && data[i] != '\n') i++;
						i++;
						if (i + strlen(WECHAT_C_UA) < data_len && strncasecmp(data + i, WECHAT_C_UA, strlen(WECHAT_C_UA)) == 0) {
							IP_SET_add_dst_ip(state, in, out, skb, "wechat_iplist");
							NATCAP_INFO("(CPO)" DEBUG_TCP_FMT ": add to wechat_iplist\n", DEBUG_TCP_ARG(iph,l4));
						}
					}
				}
				set_bit(IPS_NATCAP_BIT, &ct->status);
				clear_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			} else if (TCPH(l4)->syn && !TCPH(l4)->ack &&
			           !(IPS_SEEN_REPLY & ct->status)) {
				if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			}
		}

		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL && iph->protocol == IPPROTO_TCP && cnipwhitelist_mode == 0) {
			if (TCPH(l4)->syn && !TCPH(l4)->ack) {
				if (!(IPS_NATCAP_SYN1 & ct->status) && !test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
					NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": bypass syn1\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if (!(IPS_NATCAP_SYN2 & ct->status) && !test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
					NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": bypass syn2\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if ((IPS_NATCAP_SYN1 & ct->status) && (IPS_NATCAP_SYN2 & ct->status)) {
					NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": bypass syn3 del target from bypasslist\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_del_dst_ip(state, in, out, skb, "bypasslist");
				}
			}
		}

		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	ns = natcap_session_get(ct);
	if (NULL == ns) {
		return NF_ACCEPT;
	}
	if (peer_multipath) {
		if (ns->peer.ver != 1) ns->peer.ver = 1;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		/* for REPLY post out */
		if (iph->protocol == IPPROTO_TCP) {
			if ((NS_NATCAP_TCPUDPENC & ns->n.status) && TCPH(l4)->syn) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8, natcap_max_pmtu - 40);
			}
		}
		return NF_ACCEPT;
	}

	if (!(NS_NATCAP_NOLIMIT & ns->n.status) && natcap_tx_flow_ctrl(skb, ct) < 0) {
		return NF_DROP;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct sk_buff *skb2 = NULL;
		struct sk_buff *skb_htp = NULL;

		if ((NS_NATCAP_ENC & ns->n.status)) {
			status |= NATCAP_NEED_ENC;
		}

		ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt,
		                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
		                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
		if (ret != 0) {
			u16 mss;
			/* skb cannot setup encode, means that tcp option space has no enough left
			 * so we dup a skb and mark it with NATCAP_TCPOPT_SYN as a pioneer to 'kick the door'
			 * just strim the tcp options
			 */
			if (skb_is_gso(skb) || (!TCPH(l4)->syn || TCPH(l4)->ack)) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				return NF_DROP;
			}

			skb2 = skb_copy(skb, GFP_ATOMIC);
			if (skb2 == NULL) {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
				return NF_DROP;
			}
			iph = ip_hdr(skb2);
			l4 = (void *)iph + iph->ihl * 4;
			mss = natcap_tcpmss_get(TCPH(l4));
			if (mss == 0) mss = TCP_MSS_DEFAULT;
			/* fake mss */
			set_byte1((void *)l4 + sizeof(struct tcphdr) + 0, TCPOPT_MSS);
			set_byte1((void *)l4 + sizeof(struct tcphdr) + 1, TCPOLEN_MSS);
			set_byte2((void *)l4 + sizeof(struct tcphdr) + 2, ntohs(mss));
			skb2->len = iph->ihl * 4 + sizeof(struct tcphdr) + TCPOLEN_MSS;
			iph->tot_len = htons(skb2->len);
			TCPH(l4)->doff = (sizeof(struct tcphdr) + TCPOLEN_MSS) / 4;
			skb_rcsum_tcpudp(skb2);

			ret = natcap_tcpopt_setup(status, skb2, ct, &tcpopt,
			                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
			                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
			if (ret != 0) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				consume_skb(skb2);
				return NF_DROP;
			}
			tcpopt.header.type |= NATCAP_TCPOPT_SYN;
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET;
			}
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY;
			}
			ret = natcap_tcp_encode(ct, skb2, &tcpopt, IP_CT_DIR_ORIGINAL);
			if (ret != 0) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				consume_skb(skb2);
				return NF_DROP;
			}
			tcpopt.header.type = NATCAP_TCPOPT_TYPE_NONE;
			tcpopt.header.opsize = 0;

			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}
		if (ret == 0) {
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET;
			}
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY;
			}
			ret = natcap_tcp_encode(ct, skb, &tcpopt, IP_CT_DIR_ORIGINAL);
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}
		if (ret != 0) {
			NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d, skb2=%p\n", DEBUG_TCP_ARG(iph,l4), ret, skb2);
			if (skb2) {
				consume_skb(skb2);
			}
			return NF_DROP;
		}

		if (ns->n.tcp_seq_offset && TCPH(l4)->ack && !(NS_NATCAP_TCPUDPENC & ns->n.status) &&
		        (NS_NATCAP_ENC & ns->n.status) && (IPS_SEEN_REPLY & ct->status) &&
		        !(NS_NATCAP_CONFUSION & ns->n.status) && !short_test_and_set_bit(NS_NATCAP_CONFUSION_BIT, &ns->n.status) &&
		        nf_ct_seq_offset(ct, IP_CT_DIR_ORIGINAL, ntohl(TCPH(l4)->seq + 1)) != ns->n.tcp_seq_offset) {
			struct natcap_TCPOPT *tcpopt;
			int offset, add_len;
			int size = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

			offset = iph->ihl * 4 + sizeof(struct tcphdr) + size + ns->n.tcp_seq_offset - (skb_headlen(skb) + skb_tailroom(skb));
			add_len = offset < 0 ? 0 : offset;
			offset += skb_tailroom(skb);
			skb_htp = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
			if (!skb_htp) {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
				if (skb2) {
					consume_skb(skb2);
				}
				return NF_DROP;
			}
			skb_htp->tail += offset;
			skb_htp->len = iph->ihl * 4 + sizeof(struct tcphdr) + size + ns->n.tcp_seq_offset;

			iph = ip_hdr(skb_htp);
			l4 = (void *)iph + iph->ihl * 4;
			tcpopt = (struct natcap_TCPOPT *)(l4 + sizeof(struct tcphdr));

			iph->tot_len = htons(skb_htp->len);
			TCPH(l4)->doff = (sizeof(struct tcphdr) + size) / 4;
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_CONFUSION;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->header.encryption = 0;
			memcpy((void *)tcpopt + size, htp_confusion_req, ns->n.tcp_seq_offset);
			skb_htp->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb_htp);

			nf_ct_seqadj_init(ct, ctinfo, ns->n.tcp_seq_offset);
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}

		NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));

		/* on client side original. skb_htp is gen by skb
		 * we post skb out first, then skb_htp.
		 */
		if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
			if (skb2) {
				flow_total_tx_bytes += skb2->len;
				NF_OKFN(skb2);
			}
			if (skb_htp) {
				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					consume_skb(skb_htp);
					return ret;
				}
				flow_total_tx_bytes += skb->len + skb_htp->len;
				NF_OKFN(skb);
				NF_OKFN(skb_htp);
				return NF_STOLEN;
			}
			flow_total_tx_bytes += skb->len;
			return NF_ACCEPT;
		}

		BUG_ON(skb_htp != NULL);

		/* XXX I just confirm it first  */
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			if (skb2) {
				consume_skb(skb2);
			}
			return ret;
		}

		if (skb_is_gso(skb)) {
			struct sk_buff *segs;

			segs = skb_gso_segment(skb, 0);
			if (IS_ERR(segs)) {
				if (skb2) {
					consume_skb(skb2);
				}
				return NF_DROP;
			}

			consume_skb(skb);
			skb = segs;
		}

		if (skb2) {
			skb2->next = skb;
			skb = skb2;
		}

		do {
			int offlen;
			struct sk_buff *pcskb = NULL;
			struct sk_buff *nskb = skb->next;
			struct sk_buff *dup_skb = NULL;
			unsigned int total_weight = ns->peer.total_weight;

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
			set_byte4((void *)UDPH(l4) + 8, ns->peer.ver == 1 ? __constant_htonl(NATCAP_7_MAGIC) : __constant_htonl(NATCAP_F_MAGIC));
			iph->protocol = IPPROTO_UDP;
			skb->next = NULL;

			if (ns->peer.ver == 1 && ns->peer.mark && total_weight > 0) {
				unsigned int ball = prandom_u32() % total_weight;
				unsigned int weight = 0;
				int i, idx = -1;
				for (i = 0; i < MAX_PEER_NUM; i++) {
					if (peer_multipath > MAX_PEER_NUM) {
						if (ns->peer.tuple3[i].dip == 0 || !short_test_bit(i, &ns->peer.mark) ||
						        !is_fastpath_route_ready(&natcap_pfr[i])) {
							ns->peer.total_weight = ns->peer.total_weight - ns->peer.weight[i] + 0;
							if (ns->peer.weight[i] != 0) {
								ns->peer.weight[i] = 0;
								ns->peer.req_cnt = 3;
							}
							continue;
						}
						if (natcap_pfr[i].weight != ns->peer.weight[i]) {
							ns->peer.total_weight = ns->peer.total_weight - ns->peer.weight[i] + natcap_pfr[i].weight;
							ns->peer.weight[i] = natcap_pfr[i].weight;
							ns->peer.req_cnt = 3;
						}
					} else if (ns->peer.tuple3[i].dip == 0 || !short_test_bit(i, &ns->peer.mark))
						continue;
					weight += ns->peer.weight[i];
					if (ball < weight) {
						idx = i;
						break;
					}
				}
				if (peer_multipath > MAX_PEER_NUM) {
					for (; i < MAX_PEER_NUM; i++) {
						if (ns->peer.tuple3[i].dip == 0 || !short_test_bit(i, &ns->peer.mark) ||
						        !is_fastpath_route_ready(&natcap_pfr[i])) {
							ns->peer.total_weight = ns->peer.total_weight - ns->peer.weight[i] + 0;
							if (ns->peer.weight[i] != 0) {
								ns->peer.weight[i] = 0;
								ns->peer.req_cnt = 3;
							}
							continue;
						}
						if (natcap_pfr[i].weight != ns->peer.weight[i]) {
							ns->peer.total_weight = ns->peer.total_weight - ns->peer.weight[i] + natcap_pfr[i].weight;
							ns->peer.weight[i] = natcap_pfr[i].weight;
							ns->peer.req_cnt = 3;
						}
					}
				}
				if (idx >= 0) {
					struct nf_conntrack_tuple tuple;
					struct nf_conntrack_tuple_hash *h;

					memset(&tuple, 0, sizeof(tuple));
					tuple.src.u3.ip = peer_multipath <= MAX_PEER_NUM ? iph->saddr : natcap_pfr[idx].saddr;
					tuple.src.u.udp.port = ns->peer.tuple3[idx].sport;
					tuple.dst.u3.ip = ns->peer.tuple3[idx].dip;
					tuple.dst.u.udp.port = ns->peer.tuple3[idx].dport;
					tuple.src.l3num = PF_INET;
					tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
					h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
					h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
					if (h) {
						ct = nf_ct_tuplehash_to_ctrack(h);
						nf_ct_put(ct);

						dup_skb = skb_copy(skb, GFP_ATOMIC);
						if (dup_skb) {
							iph = ip_hdr(dup_skb);
							l4 = (void *)iph + iph->ihl * 4;

							iph->saddr = peer_multipath <= MAX_PEER_NUM ? iph->saddr : natcap_pfr[idx].saddr;
							iph->daddr = ns->peer.tuple3[idx].dip;
							UDPH(l4)->dest = ns->peer.tuple3[idx].dport;
							UDPH(l4)->source = ns->peer.tuple3[idx].sport;
							set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_8_MAGIC));

							dup_skb->ip_summed = CHECKSUM_UNNECESSARY;
							skb_rcsum_tcpudp(dup_skb);

							if (peer_multipath > MAX_PEER_NUM) {
								atomic_add(dup_skb->len, &natcap_pfr[idx].tx_speed[(jiffies / HZ) % SPEED_SAMPLE_COUNT]);
								atomic_set(&natcap_pfr[idx].tx_speed[(jiffies / HZ + 1) % SPEED_SAMPLE_COUNT], 0);

								dup_skb->dev = natcap_pfr[idx].rt_out.outdev;
								skb_push(dup_skb, natcap_pfr[idx].rt_out.l2_head_len);
								skb_reset_mac_header(dup_skb);
								memcpy(skb_mac_header(dup_skb), natcap_pfr[idx].rt_out.l2_head, natcap_pfr[idx].rt_out.l2_head_len);
								if (natcap_pfr[idx].last_rxtx == 0) {
									natcap_pfr[idx].last_tx_jiffies = jiffies;
									natcap_pfr[idx].last_rxtx = 1;
								}
							} else {
								flow_total_tx_bytes += dup_skb->len;
							}
						}
						if (ns->peer.req_cnt > 0 || uintmindiff(ns->peer.jiffies, jiffies) > 5 * HZ) {
							ns->peer.jiffies = jiffies;
							if (ns->peer.req_cnt != 0) ns->peer.req_cnt--;

							pcskb = natcap_peer_ctrl_alloc(skb, 8 + MAX_PEER_NUM * 2);
							if (pcskb) {
								iph = ip_hdr(pcskb);
								l4 = (void *)iph + iph->ihl * 4;

								set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_9_MAGIC));
								set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE5));
								for (i = 0; i < MAX_PEER_NUM; i++) {
									__be16 weight = htons(ns->peer.weight[i]);
									if (ns->peer.tuple3[i].dip == 0 || !short_test_bit(i, &ns->peer.mark))
										weight = htons(0);
									else if (peer_multipath > MAX_PEER_NUM) {
										if (!is_fastpath_route_ready(&natcap_pfr[i])) {
											weight = htons(0);
										}
									}
									set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 2 * i, weight);
								}

								if (peer_multipath > MAX_PEER_NUM && ns->peer.idx != idx) { /* There is chance to select peer or master */
									iph->saddr = natcap_pfr[idx].saddr;
									iph->daddr = ns->peer.tuple3[idx].dip;
									UDPH(l4)->dest = ns->peer.tuple3[idx].dport;
									UDPH(l4)->source = ns->peer.tuple3[idx].sport;

									pcskb->ip_summed = CHECKSUM_UNNECESSARY;
									skb_rcsum_tcpudp(pcskb);

									pcskb->dev = natcap_pfr[idx].rt_out.outdev;
									skb_push(pcskb, natcap_pfr[idx].rt_out.l2_head_len);
									skb_reset_mac_header(pcskb);
									memcpy(skb_mac_header(pcskb), natcap_pfr[idx].rt_out.l2_head, natcap_pfr[idx].rt_out.l2_head_len);
									dev_queue_xmit(pcskb);
									pcskb = NULL;
								} else {
									pcskb->ip_summed = CHECKSUM_UNNECESSARY;
									skb_rcsum_tcpudp(pcskb);
								}

								ns->peer.idx = (ns->peer.idx + 1) % MAX_PEER_NUM;
							}
						}
					} else {
						ns->peer.total_weight -= ns->peer.weight[idx];
						ns->peer.weight[idx] = 0;
						ns->peer.tuple3[idx].dip = 0;
						ns->peer.tuple3[idx].dport = 0;
						ns->peer.tuple3[idx].sport = 0;
						short_clear_bit(idx, &ns->peer.mark);
					}
				}
			}

			NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));
			flow_total_tx_bytes += skb->len;

			if (pcskb) {
				NF_OKFN(pcskb);
			}

			if (peer_multipath <= MAX_PEER_NUM) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				skb_rcsum_tcpudp(skb);
				NF_OKFN(skb);
				if (dup_skb) {
					NF_OKFN(dup_skb);
				}
			} else {
				if (dup_skb) {
					consume_skb(skb);
					dev_queue_xmit(dup_skb);
				} else {
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(skb);
					NF_OKFN(skb);
				}
			}

			skb = nskb;
		} while (skb);

		return NF_STOLEN;
	} else if (iph->protocol == IPPROTO_UDP) {
		if ((NS_NATCAP_ENC & ns->n.status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(CPO)" DEBUG_UDP_FMT ": skb_make_writable() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_encode);
			skb_rcsum_tcpudp(skb);
		}

		if (!(IPS_NATCAP_CFM & ct->status)) {
			int off = default_protocol == 1 ? 24 : 12;
			if (skb->len > 1280) {
				struct sk_buff *nskb;
				int offset, add_len;
				unsigned short uflag = NATCAP_UDP_TYPE1;

				offset = iph->ihl * 4 + sizeof(struct udphdr) + off - (skb_headlen(skb) + skb_tailroom(skb));
				add_len = offset < 0 ? 0 : offset;
				offset += skb_tailroom(skb);
				nskb = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
				if (!nskb) {
					NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
					return NF_ACCEPT;
				}
				nskb->tail += offset;
				nskb->len = sizeof(struct iphdr) + sizeof(struct udphdr) + off;

				iph = ip_hdr(nskb);
				l4 = (void *)iph + iph->ihl * 4;
				iph->tot_len = htons(nskb->len);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				set_byte4(l4 + sizeof(struct udphdr), default_protocol == 1 ? __constant_htonl(NATCAP_D_MAGIC) : __constant_htonl(NATCAP_E_MAGIC));
				set_byte4(l4 + sizeof(struct udphdr) + 4, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip);
				set_byte2(l4 + sizeof(struct udphdr) + 8, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);

				//check and overwrite DNS
				if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53) && iph->daddr == dns_proxy_server->ip) {
					set_byte4(l4 + sizeof(struct udphdr) + 4, dns_proxy_server->ip);
					set_byte2(l4 + sizeof(struct udphdr) + 8, __constant_htons(53));
				} else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53) &&
				           (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip == gfw0_dns_magic_server ||
				            ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip == gfw1_dns_magic_server)) {
					uflag |= NATCAP_UDP_TARGET;
				}

				if (iph->daddr == get_byte4(l4 + sizeof(struct udphdr) + 4)) {
					uflag |= NATCAP_UDP_TARGET;
				}
				if ((NS_NATCAP_ENC & ns->n.status)) {
					uflag |= NATCAP_UDP_ENC;
				}
				set_byte2(l4 + sizeof(struct udphdr) + 10, uflag);

				if (default_protocol == 1) {
					set_byte4(l4 + sizeof(struct udphdr) + 12, default_u_hash);
					set_byte6(l4 + sizeof(struct udphdr) + 16, default_mac_addr);
				}

				skb_rcsum_tcpudp(nskb);

				NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

				/* XXX I just confirm it first  */
				/* confirm before post out */
				ret = nf_conntrack_confirm(nskb);
				if (ret != NF_ACCEPT) {
					return ret;
				}

				if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
					struct sk_buff *ping_skb = NULL;
					natcap_udp_to_tcp_pack(nskb, ns, 0, &ping_skb);
					if (ping_skb)
						NF_OKFN(ping_skb);
				}

				flow_total_tx_bytes += nskb->len;
				NF_OKFN(nskb);
			} else {
				int offlen;
				unsigned short uflag = NATCAP_UDP_TYPE2;

				if (skb_tailroom(skb) < off && pskb_expand_head(skb, 0, off, GFP_ATOMIC)) {
					NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head failed\n", DEBUG_ARG_PREFIX);
					return NF_ACCEPT;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr);
				BUG_ON(offlen < 0);
				memmove((void *)UDPH(l4) + sizeof(struct udphdr) + off, (void *)UDPH(l4) + sizeof(struct udphdr), offlen);
				iph->tot_len = htons(ntohs(iph->tot_len) + off);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				skb->len += off;
				skb->tail += off;
				set_byte4(l4 + sizeof(struct udphdr), default_protocol == 1 ? __constant_htonl(NATCAP_D_MAGIC) : __constant_htonl(NATCAP_E_MAGIC));
				set_byte4(l4 + sizeof(struct udphdr) + 4, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip);
				set_byte2(l4 + sizeof(struct udphdr) + 8, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);

				//check and overwrite DNS
				if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53) && iph->daddr == dns_proxy_server->ip) {
					set_byte4(l4 + sizeof(struct udphdr) + 4, dns_proxy_server->ip);
					set_byte2(l4 + sizeof(struct udphdr) + 8, __constant_htons(53));
				} else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(53) &&
				           (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip == gfw0_dns_magic_server ||
				            ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip == gfw1_dns_magic_server)) {
					uflag |= NATCAP_UDP_TARGET;
				}

				if (iph->daddr == get_byte4(l4 + sizeof(struct udphdr) + 4)) {
					uflag |= NATCAP_UDP_TARGET;
				}
				if ((NS_NATCAP_ENC & ns->n.status)) {
					uflag |= NATCAP_UDP_ENC;
				}
				set_byte2(l4 + sizeof(struct udphdr) + 10, uflag);

				if (default_protocol == 1) {
					set_byte4(l4 + sizeof(struct udphdr) + 12, default_u_hash);
					set_byte6(l4 + sizeof(struct udphdr) + 16, default_mac_addr);
				}

				skb_rcsum_tcpudp(skb);

				NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));
			}
		}

		if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
			struct sk_buff *ping_skb = NULL;
			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			natcap_udp_to_tcp_pack(skb, ns, 0, &ping_skb);
			if (ping_skb)
				NF_OKFN(ping_skb);
		}
	}

	flow_total_tx_bytes += skb->len;
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_post_master_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_post_master_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_post_master_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_post_master_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	unsigned long status = NATCAP_CLIENT_MODE;
	struct nf_conn *ct, *master = NULL;
	struct sk_buff *skb_orig = skb;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct natcap_session *ns = NULL;
	struct natcap_session *master_ns = NULL;
	struct natcap_TCPOPT tcpopt = { };

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP_DUAL & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_ACK & ct->status)) {
		return NF_ACCEPT;
	}

	ns = natcap_session_get(ct);
	if (!ns) {
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}

	if (nf_ct_is_confirmed(ct) && ns->n.new_source == 0) {
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}

	skb = skb_copy(skb_orig, GFP_ATOMIC);
	if (skb == NULL) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return NF_ACCEPT;
	}
	skb_nfct_reset(skb);
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (iph->protocol == IPPROTO_TCP) {
		if (ns->n.new_source == 0) {
			unsigned int range_size, min, i;
			__be16 *portptr;
			u_int16_t off;
			struct nf_conntrack_tuple tuple;

			memset(&tuple, 0, sizeof(tuple));
			tuple.src.u3.ip = iph->saddr;
			tuple.src.u.all = TCPH(l4)->source;
			tuple.src.l3num = AF_INET;
			tuple.dst.u3.ip = ns->n.target_ip;
			tuple.dst.u.all = ns->n.target_port;
			tuple.dst.protonum = IPPROTO_TCP;

			portptr = &tuple.src.u.all;

			min = 1024;
			range_size = 65535 - 1024 + 1;
			off = prandom_u32();

			if (nf_nat_used_tuple(&tuple, ct)) {
				for (i = 0; i != range_size; ++off, ++i) {
					*portptr = htons(min + off % range_size);
					if (nf_nat_used_tuple(&tuple, ct))
						continue;
				}
			}
			ns->n.new_source = *portptr;
		}

		NATCAP_DEBUG("(CPMO)" DEBUG_TCP_FMT ": before natcap post out\n", DEBUG_TCP_ARG(iph,l4));
		csum_replace4(&iph->check, iph->daddr, ns->n.target_ip);
		inet_proto_csum_replace4(&TCPH(l4)->check, skb, iph->daddr, ns->n.target_ip, true);
		inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->source, ns->n.new_source, false);
		inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->dest, ns->n.target_port, false);
		TCPH(l4)->source = ns->n.new_source;
		TCPH(l4)->dest = ns->n.target_port;
		iph->daddr = ns->n.target_ip;
	} else {
		if (ns->n.new_source == 0) {
			__be16 *portptr;
			u_int16_t off;
			unsigned int range_size, min, i;
			struct nf_conntrack_tuple tuple;

			if (cone_nat_array && cone_snat_array &&
			        (!(ns->n.status & NS_NATCAP_TCPUDPENC)) &&
			        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53) &&
			        ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53) &&
			        IP_SET_test_src_ip(state, in, out, skb, "cone_wan_ip") > 0) {
				unsigned int idx;
				struct cone_snat_session css;

				idx = cone_snat_hash(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port, iph->saddr) % 32768;
				memcpy(&css, &cone_snat_array[idx], sizeof(css));
				if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == css.lan_ip &&
				        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port == css.lan_port &&
				        iph->saddr == css.wan_ip) {
					ns->n.new_source = css.wan_port;
				}
			}

			if (ns->n.new_source == 0) {
				memset(&tuple, 0, sizeof(tuple));
				tuple.src.u3.ip = iph->saddr;
				tuple.src.u.all = UDPH(l4)->source;
				tuple.src.l3num = AF_INET;
				tuple.dst.u3.ip = ns->n.target_ip;
				tuple.dst.u.all = ns->n.target_port;
				tuple.dst.protonum = IPPROTO_UDP;

				portptr = &tuple.src.u.all;

				min = 1024;
				range_size = 65535 - 1024 + 1;
				off = prandom_u32();

				if (nf_nat_used_tuple(&tuple, ct)) {
					for (i = 0; i != range_size; ++off, ++i) {
						*portptr = htons(min + off % range_size);
						if (nf_nat_used_tuple(&tuple, ct))
							continue;
					}
				}
				ns->n.new_source = *portptr;
			}
		}

		NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": before natcap post out\n", DEBUG_UDP_ARG(iph,l4));
		csum_replace4(&iph->check, iph->daddr, ns->n.target_ip);
		if (UDPH(l4)->check) {
			inet_proto_csum_replace4(&UDPH(l4)->check, skb, iph->daddr, ns->n.target_ip, true);
			inet_proto_csum_replace2(&UDPH(l4)->check, skb, UDPH(l4)->source, ns->n.new_source, false);
			inet_proto_csum_replace2(&UDPH(l4)->check, skb, UDPH(l4)->dest, ns->n.target_port, false);
			if (UDPH(l4)->check == 0)
				UDPH(l4)->check = CSUM_MANGLED_0;
		}
		UDPH(l4)->source = ns->n.new_source;
		UDPH(l4)->dest = ns->n.target_port;
		iph->daddr = ns->n.target_ip;

		if (cone_nat_array && cone_snat_array && ntohs(UDPH(l4)->source) >= 1024 &&
		        (!(ns->n.status & NS_NATCAP_TCPUDPENC)) &&
		        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53) &&
		        ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53) &&
		        IP_SET_test_src_ip(state, in, out, skb, "cone_wan_ip") > 0) {
			unsigned int idx;
			struct cone_nat_session cns;
			struct cone_snat_session css;

			idx = ntohs(UDPH(l4)->source) % 65536;
			memcpy(&cns, &cone_nat_array[idx], sizeof(cns));
			if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != cns.ip ||
			        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port != cns.port) {

				NATCAP_INFO("(CPMO)" DEBUG_UDP_FMT ": update mapping from %pI4:%u to %pI4:%u @port=%u\n", DEBUG_UDP_ARG(iph,l4),
				            &cns.ip, ntohs(cns.port),
				            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				            ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
				            idx);

				cns.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				cns.port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
				memcpy(&cone_nat_array[idx], &cns, sizeof(cns));

				idx = cone_snat_hash(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port, iph->saddr) % 32768;
				memcpy(&css, &cone_snat_array[idx], sizeof(css));
				if ((css.wan_ip != iph->saddr || css.wan_port != UDPH(l4)->source) ||
				        css.lan_ip != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip ||
				        css.lan_port != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port) {

					NATCAP_INFO("(CPMO)" DEBUG_UDP_FMT ": update SNAT mapping from %pI4:%u=>%pI4:%u to %pI4:%u=>%pI4:%u\n", DEBUG_UDP_ARG(iph,l4),
					            &css.lan_ip, ntohs(css.lan_port),
					            &css.wan_ip, ntohs(css.wan_port),
					            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
					            &iph->saddr, ntohs(UDPH(l4)->source));

					css.wan_ip = iph->saddr;
					css.wan_port = UDPH(l4)->source;
					css.lan_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
					css.lan_port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
					memcpy(&cone_snat_array[idx], &css, sizeof(css));
				}
			}
		}
	}

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
	ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, skb);
	if (ret != NF_ACCEPT) {
		if (ret != NF_STOLEN) {
			consume_skb(skb);
		}
		return NF_ACCEPT;
	}

	master = nf_ct_get(skb, &ctinfo);
	if (!master || master == ct) {
		consume_skb(skb);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}
	master_ns = natcap_session_in(master);
	if (NULL == master_ns) {
		switch(iph->protocol) {
		case IPPROTO_TCP:
			NATCAP_WARN("(CPMO)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
			break;
		case IPPROTO_UDP:
			NATCAP_WARN("(CPMO)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
			break;
		}
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		consume_skb(skb);
		return NF_ACCEPT;
	}

	if (!(IPS_NATCAP_DUAL & master->status) && !test_and_set_bit(IPS_NATCAP_DUAL_BIT, &master->status)) {
		if (master->master) {
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			consume_skb(skb);
			return NF_ACCEPT;
		}
		if ((ns->n.status & NS_NATCAP_ENC)) {
			short_set_bit(NS_NATCAP_ENC_BIT, &master_ns->n.status);
		}
		if ((ns->n.status & NS_NATCAP_TCPUDPENC)) {
			short_set_bit(NS_NATCAP_TCPUDPENC_BIT, &master_ns->n.status);
		}
		if ((NS_NATCAP_NOLIMIT & ns->n.status)) short_set_bit(NS_NATCAP_NOLIMIT_BIT, &master_ns->n.status);

		nf_conntrack_get(&ct->ct_general);
		master->master = ct;
		if (!(IPS_NATCAP & master->status) && !test_and_set_bit(IPS_NATCAP_BIT, &master->status)) {
			if (natcap_session_init(master, GFP_ATOMIC) != 0) {
				switch(iph->protocol) {
				case IPPROTO_TCP:
					NATCAP_WARN("(CPMO)" DEBUG_TCP_FMT ": natcap_session_init failed\n", DEBUG_TCP_ARG(iph,l4));
					break;
				case IPPROTO_UDP:
					NATCAP_WARN("(CPMO)" DEBUG_UDP_FMT ": natcap_session_init failed\n", DEBUG_UDP_ARG(iph,l4));
					break;
				}
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				consume_skb(skb);
				return NF_ACCEPT;
			}
		}
	}

	if (master->master != ct) {
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATCAP_DEBUG("(CPMO)" DEBUG_TCP_FMT ": bad ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] and master[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n",
			             DEBUG_TCP_ARG(iph,l4),
			             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
			             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			             &master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			             &master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
			            );
			break;
		case IPPROTO_UDP:
			NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": bad ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] and master[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n",
			             DEBUG_UDP_ARG(iph,l4),
			             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
			             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			             &master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			             &master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
			            );
			break;
		}
		consume_skb(skb);
		return NF_ACCEPT;
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		if (ret != NF_STOLEN) {
			consume_skb(skb);
		}
		return NF_ACCEPT;
	}

	/* XXX I am going to eat it, make the caller happy  */
	ret = nf_conntrack_confirm(skb_orig);
	if (ret != NF_ACCEPT) {
		consume_skb(skb);
		return ret;
	}

	if (!(NS_NATCAP_NOLIMIT & master_ns->n.status) && natcap_tx_flow_ctrl(skb, master) < 0) {
		consume_skb(skb);
		goto out;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct sk_buff *skb_htp = NULL;
		struct sk_buff *skb2 = NULL;

		if ((NS_NATCAP_ENC & master_ns->n.status)) {
			status |= NATCAP_NEED_ENC;
		}
		ret = natcap_tcpopt_setup(status, skb, master, &tcpopt,
		                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
		                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
		if (ret != 0) {
			/* skb cannot setup encode, means that tcp option space has no enough left
			 * so we dup a skb and mark it with NATCAP_TCPOPT_SYN as a pioneer to 'kick the door'
			 */
			if (skb_is_gso(skb) || (!TCPH(l4)->syn || TCPH(l4)->ack)) {
				NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				consume_skb(skb);
				return NF_ACCEPT;
			}

			skb2 = skb_copy(skb, GFP_ATOMIC);
			if (skb2 == NULL) {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				consume_skb(skb);
				return NF_ACCEPT;
			}
			iph = ip_hdr(skb2);
			l4 = (void *)iph + iph->ihl * 4;
			skb2->len = iph->ihl * 4 + sizeof(struct tcphdr);
			iph->tot_len = htons(skb2->len);
			TCPH(l4)->doff = 5;
			skb_rcsum_tcpudp(skb2);

			ret = natcap_tcpopt_setup(status, skb2, master, &tcpopt,
			                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
			                          ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
			if (ret != 0) {
				NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				consume_skb(skb2);
				consume_skb(skb);
				return NF_ACCEPT;
			}
			tcpopt.header.type |= NATCAP_TCPOPT_SYN;
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET;
			}
			/* XXX we do not use sproxy for DUAL connection
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY;
			}
			*/
			ret = natcap_tcp_encode(master, skb2, &tcpopt, IP_CT_DIR_ORIGINAL);
			if (ret != 0) {
				NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				consume_skb(skb2);
				consume_skb(skb);
				return NF_ACCEPT;
			}
			tcpopt.header.type = NATCAP_TCPOPT_TYPE_NONE;
			tcpopt.header.opsize = 0;

			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}
		if (ret == 0) {
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET;
			}
			/* XXX we do not use sproxy for DUAL connection
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY;
			}
			*/
			ret = natcap_tcp_encode(master, skb, &tcpopt, IP_CT_DIR_ORIGINAL);
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}
		if (ret != 0) {
			NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d, skb2=%p\n", DEBUG_TCP_ARG(iph,l4), ret, skb2);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			if (skb2) {
				consume_skb(skb2);
			}
			consume_skb(skb);
			return NF_ACCEPT; /* NF_ACCEPT for skb_orig */
		}

		if (master_ns->n.tcp_seq_offset && TCPH(l4)->ack && !(NS_NATCAP_TCPUDPENC & master_ns->n.status) &&
		        (NS_NATCAP_ENC & master_ns->n.status) && (IPS_SEEN_REPLY & master->status) &&
		        !(NS_NATCAP_CONFUSION & master_ns->n.status) && !short_test_and_set_bit(NS_NATCAP_CONFUSION_BIT, &master_ns->n.status) &&
		        nf_ct_seq_offset(ct, IP_CT_DIR_ORIGINAL, ntohl(TCPH(l4)->seq + 1)) != master_ns->n.tcp_seq_offset) {
			struct natcap_TCPOPT *tcpopt;
			int offset, add_len;
			int size = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

			offset = iph->ihl * 4 + sizeof(struct tcphdr) + size + master_ns->n.tcp_seq_offset - (skb_headlen(skb) + skb_tailroom(skb));
			add_len = offset < 0 ? 0 : offset;
			offset += skb_tailroom(skb);
			skb_htp = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
			if (!skb_htp) {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
				if (skb2) {
					consume_skb(skb2);
				}
				consume_skb(skb);
				goto out;
			}
			skb_htp->tail += offset;
			skb_htp->len = iph->ihl * 4 + sizeof(struct tcphdr) + size + master_ns->n.tcp_seq_offset;;

			iph = ip_hdr(skb_htp);
			l4 = (void *)iph + iph->ihl * 4;
			tcpopt = (struct natcap_TCPOPT *)(l4 + sizeof(struct tcphdr));

			iph->tot_len = htons(skb_htp->len);
			TCPH(l4)->doff = (sizeof(struct tcphdr) + size) / 4;
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_CONFUSION;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->header.encryption = 0;
			memcpy((void *)tcpopt + size, htp_confusion_req, master_ns->n.tcp_seq_offset);
			skb_htp->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb_htp);

			nf_ct_seqadj_init(master, ctinfo, master_ns->n.tcp_seq_offset);
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
		}

		NATCAP_DEBUG("(CPMO)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));

		/* on client side original. skb_htp is gen by skb
		 * we post skb out first, then skb_htp.
		 */
		if (!(NS_NATCAP_TCPUDPENC & master_ns->n.status)) {
			if (skb2) {
				flow_total_tx_bytes += skb2->len;
				NF_OKFN(skb2);
			}
			if (skb_htp) {
				flow_total_tx_bytes += skb->len + skb_htp->len;
				NF_OKFN(skb);
				NF_OKFN(skb_htp);
			} else {
				if (nf_ct_seq_adjust(skb, master, ctinfo, ip_hdrlen(skb))) { /* we have to handle seqadj for DAUL skb */
					flow_total_tx_bytes += skb->len;
					NF_OKFN(skb);
				} else {
					consume_skb(skb);
				}
			}
			goto out;
		}

		BUG_ON(skb_htp != NULL);

		if (skb_is_gso(skb)) {
			struct sk_buff *segs;

			segs = skb_gso_segment(skb, 0);
			consume_skb(skb);
			if (IS_ERR(segs)) {
				if (skb2) {
					consume_skb(skb2);
				}
				goto out;
			}
			skb = segs;
		}

		if (skb2) {
			skb2->next = skb;
			skb = skb2;
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
			set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_F_MAGIC)); //no multipath for this case
			iph->protocol = IPPROTO_UDP;
			skb->next = NULL;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

			flow_total_tx_bytes += skb->len;
			NF_OKFN(skb);

			skb = nskb;
		} while (skb);

	} else {
		if ((NS_NATCAP_ENC & master_ns->n.status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(CPMO)" DEBUG_UDP_FMT ": skb_make_writable() failed\n", DEBUG_UDP_ARG(iph,l4));
				consume_skb(skb);
				return NF_ACCEPT;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_encode);
			skb_rcsum_tcpudp(skb);
		}

		if (!(IPS_NATCAP_CFM & master->status)) {
			int off = default_protocol == 1 ? 24 : 12;
			if (skb->len > 1280) {
				struct sk_buff *nskb;
				int offset, add_len;
				unsigned short uflag = NATCAP_UDP_TYPE1;

				offset = iph->ihl * 4 + sizeof(struct udphdr) + off - (skb_headlen(skb) + skb_tailroom(skb));
				add_len = offset < 0 ? 0 : offset;
				offset += skb_tailroom(skb);
				nskb = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
				if (!nskb) {
					NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
					consume_skb(skb);
					return NF_ACCEPT;
				}
				nskb->tail += offset;
				nskb->len = iph->ihl * 4 + sizeof(struct udphdr) + off;

				iph = ip_hdr(nskb);
				l4 = (void *)iph + iph->ihl * 4;
				iph->tot_len = htons(nskb->len);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				set_byte4(l4 + sizeof(struct udphdr), default_protocol == 1 ? __constant_htonl(NATCAP_D_MAGIC) : __constant_htonl(NATCAP_E_MAGIC));
				if (dns_server == 0 || ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53)) {
					set_byte4(l4 + sizeof(struct udphdr) + 4, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip);
					set_byte2(l4 + sizeof(struct udphdr) + 8, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
				} else {
					set_byte4(l4 + sizeof(struct udphdr) + 4, dns_server);
					set_byte2(l4 + sizeof(struct udphdr) + 8, dns_port);
					if (iph->daddr == dns_server) {
						if (!(IPS_NATCAP_ACK & master->status)) set_bit(IPS_NATCAP_ACK_BIT, &master->status);
					}
				}
				if (iph->daddr == get_byte4(l4 + sizeof(struct udphdr) + 4)) {
					uflag |= NATCAP_UDP_TARGET;
				}
				if ((NS_NATCAP_ENC & master_ns->n.status)) {
					uflag |= NATCAP_UDP_ENC;
				}
				set_byte2(l4 + sizeof(struct udphdr) + 10, uflag);

				if (default_protocol == 1) {
					set_byte4(l4 + sizeof(struct udphdr) + 12, default_u_hash);
					set_byte6(l4 + sizeof(struct udphdr) + 16, default_mac_addr);
				}

				skb_rcsum_tcpudp(nskb);

				NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

				if ((NS_NATCAP_TCPUDPENC & master_ns->n.status)) {
					struct sk_buff *ping_skb = NULL;
					/* XXX I just confirm it first  */
					/* master has been confirm */
					natcap_udp_to_tcp_pack(nskb, master_ns, 0, &ping_skb);
					if (ping_skb)
						NF_OKFN(ping_skb);
				}

				flow_total_tx_bytes += nskb->len;
				NF_OKFN(nskb);
			} else {
				int offlen;
				unsigned short uflag = NATCAP_UDP_TYPE2;

				if (skb_tailroom(skb) < off && pskb_expand_head(skb, 0, off, GFP_ATOMIC)) {
					NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head failed\n", DEBUG_ARG_PREFIX);
					consume_skb(skb);
					return NF_ACCEPT;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr);
				BUG_ON(offlen < 0);
				memmove((void *)UDPH(l4) + sizeof(struct udphdr) + off, (void *)UDPH(l4) + sizeof(struct udphdr), offlen);
				iph->tot_len = htons(ntohs(iph->tot_len) + off);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				skb->len += off;
				skb->tail += off;
				set_byte4(l4 + sizeof(struct udphdr), default_protocol == 1 ? __constant_htonl(NATCAP_D_MAGIC) : __constant_htonl(NATCAP_E_MAGIC));
				if (dns_server == 0 || ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53)) {
					set_byte4(l4 + sizeof(struct udphdr) + 4, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip);
					set_byte2(l4 + sizeof(struct udphdr) + 8, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
				} else {
					set_byte4(l4 + sizeof(struct udphdr) + 4, dns_server);
					set_byte2(l4 + sizeof(struct udphdr) + 8, dns_port);
					if (iph->daddr == dns_server) {
						if (!(IPS_NATCAP_ACK & master->status)) set_bit(IPS_NATCAP_ACK_BIT, &master->status);
					}
				}
				if (iph->daddr == get_byte4(l4 + sizeof(struct udphdr) + 4)) {
					uflag |= NATCAP_UDP_TARGET;
				}
				if ((NS_NATCAP_ENC & master_ns->n.status)) {
					uflag |= NATCAP_UDP_ENC;
				}
				set_byte2(l4 + sizeof(struct udphdr) + 10, uflag);

				if (default_protocol == 1) {
					set_byte4(l4 + sizeof(struct udphdr) + 12, default_u_hash);
					set_byte6(l4 + sizeof(struct udphdr) + 16, default_mac_addr);
				}

				skb_rcsum_tcpudp(skb);

				NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));
			}
		}

		if ((NS_NATCAP_TCPUDPENC & master_ns->n.status)) {
			struct sk_buff *ping_skb = NULL;
			/* XXX I just confirm it first  */
			/* master has been confirm */
			natcap_udp_to_tcp_pack(skb, master_ns, 0, &ping_skb);
			if (ping_skb)
				NF_OKFN(ping_skb);
		}

		flow_total_tx_bytes += skb->len;
		NF_OKFN(skb);
	}

out:
	iph = ip_hdr(skb_orig);
	if (iph->protocol == IPPROTO_TCP) {
		l4 = (void *)iph + iph->ihl * 4;
		if (!TCPH(l4)->syn) {
			goto eat;
		}
	}

	if ((IPS_NATCAP_ACK & master->status)) {
		goto eat;
	}

	return NF_ACCEPT;

eat:
	consume_skb(skb_orig);
	return NF_STOLEN;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_client_pre_master_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_pre_master_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_pre_master_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_master_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct, *master;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP_DUAL & ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) {
		/* for TCP */
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4)->doff * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": got reply\n", DEBUG_TCP_ARG(iph,l4));

		if ((IPS_NATCAP & ct->status)) {
			master = ct->master;
			if (!master || !(IPS_NATCAP_DUAL & master->status)) {
				return NF_DROP;
			}
			if (iph->daddr != master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip) {
				return NF_DROP;
			}

			if (!(IPS_NATCAP_CFM & master->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &master->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": got cfm\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);

				if (!TCPH(l4)->rst && cnipwhitelist_mode == 0) {
					__be32 saddr = iph->saddr;
					__be16 dest = TCPH(l4)->dest;
					__be16 source = TCPH(l4)->source;

					iph->saddr = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
					TCPH(l4)->dest = master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
					TCPH(l4)->source = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
					if (!is_natcap_server(iph->saddr) && IP_SET_test_src_ip(state, in, out, skb, "cniplist") <= 0) {
						NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": multi-conn natcap got response add target to gfwlist0\n", DEBUG_TCP_ARG(iph,l4));
						IP_SET_add_src_ip(state, in, out, skb, "gfwlist0");
					}
					iph->saddr = saddr;
					TCPH(l4)->dest = dest;
					TCPH(l4)->source = source;
				}
			}
			if (!(IPS_NATCAP_ACK & ct->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": drop without lock cfm\n", DEBUG_TCP_ARG(iph,l4));
				if (TCPH(l4)->syn && TCPH(l4)->ack) {
					natcap_reset_synack(skb, in, ct);
				}
				return NF_DROP;
			}

			if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)) {
				if (!nf_ct_seq_adjust(skb, ct, ctinfo, ip_hdrlen(skb))) {
					return NF_DROP;
				}
			}

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}

			skb_nfct_reset(skb);

			csum_replace4(&iph->check, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
			inet_proto_csum_replace4(&TCPH(l4)->check, skb, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, true);
			inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->dest, master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all, false);
			inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->source, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all, false);
			iph->saddr = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
			TCPH(l4)->dest = master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			TCPH(l4)->source = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;

			if (in)
				net = dev_net(in);
			else if (out)
				net = dev_net(out);
			ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			if ((struct nf_conn *)skb_nfct(skb) != master) {
				NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": skb->nfct != master, ct=%p, master=%p, skb_nfct(skb)=%p\n", DEBUG_TCP_ARG(iph,l4), ct, master, skb_nfct(skb));
				NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": bad ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] and master[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n",
				             DEBUG_TCP_ARG(iph,l4),
				             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
				             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				             &master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				             &master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
				            );
				return NF_DROP;
			}

			NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": after natcap reply\n", DEBUG_TCP_ARG(iph,l4));
		} else {
			if (TCPH(l4)->rst && cnipwhitelist_mode == 0) {
				if ((TCPH(l4)->source == __constant_htons(80) || TCPH(l4)->source == __constant_htons(443)) &&
				        IP_SET_test_src_ip(state, in, out, skb, "cniplist") <= 0) {
					NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": bypass get reset add target to gfwlist0\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_add_src_ip(state, in, out, skb, "gfwlist0");
				}
			}
			if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": got cfm\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				if (cnipwhitelist_mode == 0 && !TCPH(l4)->rst && IP_SET_test_src_ip(state, in, out, skb, "cniplist") > 0) {
					NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": multi-conn bypass got response add target to bypasslist\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_add_src_ip(state, in, out, skb, "bypasslist");
				}
			}
			if (!(IPS_NATCAP_ACK & ct->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": drop without lock cfm\n", DEBUG_TCP_ARG(iph,l4));
				if (TCPH(l4)->syn && TCPH(l4)->ack) {
					natcap_reset_synack(skb, in, ct);
				}
				return NF_DROP;
			}
		}
		return NF_ACCEPT;
	} else {
		/* for UDP */
		unsigned int ip = 0;
		unsigned short id = 0;
		struct natcap_session *ns = NULL;

		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": got reply\n", DEBUG_UDP_ARG(iph,l4));

		if ((IPS_NATCAP & ct->status)) {
			master = ct->master;
			if (!master || !(IPS_NATCAP_DUAL & master->status)) {
				return NF_DROP;
			}
			if (iph->daddr != master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip) {
				return NF_DROP;
			}

			if (!(IPS_NATCAP_CFM & master->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &master->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": got cfm\n", DEBUG_UDP_ARG(iph,l4));
				if (master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53)) {
					//not DNS
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				}
			}
			if (master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53)) {
				//not DNS
				if (!(IPS_NATCAP_ACK & ct->status)) {
					NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": drop without lock cfm\n", DEBUG_UDP_ARG(iph,l4));
					return NF_DROP;
				}
			}

			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}

			skb_nfct_reset(skb);

			csum_replace4(&iph->check, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
			if (UDPH(l4)->check) {
				inet_proto_csum_replace4(&UDPH(l4)->check, skb, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, true);
				inet_proto_csum_replace2(&UDPH(l4)->check, skb, UDPH(l4)->dest, master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all, false);
				inet_proto_csum_replace2(&UDPH(l4)->check, skb, UDPH(l4)->source, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all, false);
				if (UDPH(l4)->check == 0)
					UDPH(l4)->check = CSUM_MANGLED_0;
			}
			iph->saddr = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
			UDPH(l4)->dest = master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			UDPH(l4)->source = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;

			if (in)
				net = dev_net(in);
			else if (out)
				net = dev_net(out);
			ret = nf_conntrack_in_compat(net, pf, NF_INET_PRE_ROUTING, skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			if ((struct nf_conn *)skb_nfct(skb) != master) {
				NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": skb->nfct != master, ct=%p, master=%p, skb_nfct(skb)=%p\n", DEBUG_UDP_ARG(iph,l4), ct, master, skb_nfct(skb));
				NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": bad ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] and master[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n",
				             DEBUG_UDP_ARG(iph,l4),
				             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
				             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				             &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				             &master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				             &master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
				            );
				return NF_DROP;
			}

			NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": after natcap reply\n", DEBUG_UDP_ARG(iph,l4));

			if (master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53)) {
				//not DNS
				return NF_ACCEPT;
			}
			ns = natcap_session_get(master);
		} else {
			if (!(IPS_NATCAP_CFM & ct->status) && !test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
				NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": got cfm\n", DEBUG_UDP_ARG(iph,l4));
				if (ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53)) {
					//not DNS
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				}
			}
			if (ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53)) {
				//not DNS
				if (!(IPS_NATCAP_ACK & ct->status)) {
					NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": drop without lock cfm\n", DEBUG_UDP_ARG(iph,l4));
					return NF_DROP;
				}
				return NF_ACCEPT;
			}
			ns = natcap_session_get(ct);
		}
		if (NULL == ns) {
			return NF_ACCEPT;
		}

		if (!pskb_may_pull(skb, skb->len)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		do {
			int i, pos;
			unsigned int v;
			unsigned short flags;
			unsigned short qd_count;
			unsigned short an_count;
			unsigned short ns_count;
			unsigned short ar_count;
			int is_cn_domain;

			unsigned char *p = (unsigned char *)UDPH(l4) + sizeof(struct udphdr);
			int len = skb->len - iph->ihl * 4 - sizeof(struct udphdr);

			id = ntohs(get_byte2(p + 0));
			flags = ntohs(get_byte2(p + 2));
			qd_count = ntohs(get_byte2(p + 4));
			an_count = ntohs(get_byte2(p + 6));
			ns_count = ntohs(get_byte2(p + 8));
			ar_count = ntohs(get_byte2(p + 10));
			NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, flags=0x%04x, qd=%u, an=%u, ns=%u, ar=%u\n",
			             DEBUG_UDP_ARG(iph,l4),
			             id, flags, qd_count, an_count, ns_count, ar_count);

			if (!(IPS_NATCAP & ct->status) && (flags & 0xf) != 0) {
				NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x direct DNS ANS flags=%04x, drop\n", DEBUG_UDP_ARG(iph,l4), id, flags);
				return NF_DROP;
			}

			pos = 12;
			for(i = 0; i < qd_count; i++) {
				unsigned short qtype, qclass;

				if (pos >= len) {
					break;
				}

				if (IS_NATCAP_DEBUG()) {
					int qname_len;
					char *qname = kmalloc(2048, GFP_ATOMIC);

					if (qname != NULL) {
						if ((qname_len = get_rdata(p, len, pos, qname, 2047)) >= 0) {
							qname[qname_len] = 0;
							NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, qname=%s\n", DEBUG_UDP_ARG(iph,l4), id, qname);
						}
						kfree(qname);
					}
				}
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

				NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, qtype=%d, qclass=%d\n", DEBUG_UDP_ARG(iph,l4), id, qtype, qclass);
			}
			for(i = 0; i < an_count; i++) {
				unsigned int ttl;
				unsigned short type, class;
				unsigned short rdlength;

				if (pos >= len) {
					break;
				}

				if (IS_NATCAP_DEBUG()) {
					int name_len;
					char *name = kmalloc(2048, GFP_ATOMIC);

					if (name != NULL) {
						if ((name_len = get_rdata(p, len, pos, name, 2047)) >= 0) {
							name[name_len] = 0;
							NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, name=%s\n", DEBUG_UDP_ARG(iph,l4), id, name);
						}
						kfree(name);
					}
				}

				is_cn_domain = 0;
				if (cn_domain) {
					int name_len;
					char name[128];
					if ((name_len = get_rdata(p, len, pos, name, 127)) > 0) {
						name[name_len - 1] = 0;
						if (cn_domain_lookup(name)) {
							is_cn_domain = 1;
							NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, name=%s is_cn_domain\n", DEBUG_UDP_ARG(iph,l4), id, name);
						}
					}
				}

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
				type = ntohs(get_byte2(p + pos));
				pos += 2;

				if (pos + 1 >= len) {
					break;
				}
				class = ntohs(get_byte2(p + pos));
				pos += 2;

				if (pos + 3 >= len) {
					break;
				}
				ttl = ntohl(get_byte4(p + pos));
				pos += 4;

				if (pos + 1 >= len) {
					break;
				}
				rdlength = ntohs(get_byte2(p + pos));
				pos += 2;

				if (rdlength == 0 || pos + rdlength - 1 >= len) {
					break;
				}

				switch(type)
				{
				case 1: //A
					if (rdlength == 4) {
						ip = get_byte4(p + pos);
						NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x type=%d, class=%d, ttl=%d, rdlength=%d, ip=%pI4\n",
						             DEBUG_UDP_ARG(iph,l4), id, type, class, ttl, rdlength, &ip);
						do {
							unsigned int old_ip;

							if ((IPS_NATCAP & ct->status)) {
								old_ip = iph->daddr;
								iph->daddr = ip;
								if (IP_SET_test_dst_ip(state, in, out, skb, "cniplist") > 0) {
									iph->daddr = old_ip;
									if (dns_proxy_drop && !(NS_NATCAP_DNSDROP0 & ns->n.status)) {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x proxy DNS ANS is in cniplist ip = %pI4, drop\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
										short_set_bit(NS_NATCAP_DNSDROP1_BIT, &ns->n.status);
										return NF_DROP;
									} else {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x proxy DNS ANS is in cniplist ip = %pI4, ignore\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
									}
								}
								iph->daddr = old_ip;
								if (is_cn_domain && cn_domain) {
									if (!(NS_NATCAP_DNSDROP0 & ns->n.status)) {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x proxy DNS ANS is cn_domain ip = %pI4, drop\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
										short_set_bit(NS_NATCAP_DNSDROP1_BIT, &ns->n.status);
										return NF_DROP;
									} else {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x proxy DNS ANS is cn_domain ip = %pI4, ignore\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
									}
								}
							} else {
								old_ip = iph->daddr;
								iph->daddr = ip;
								if (IP_SET_test_dst_ip(state, in, out, skb, "dnsdroplist") > 0 || IP_SET_test_dst_ip(state, in, out, skb, "cniplist") <= 0) {
									iph->daddr = old_ip;
									if (!(NS_NATCAP_DNSDROP1 & ns->n.status)) {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x direct DNS ANS is not cniplist ip = %pI4, drop\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
										short_set_bit(NS_NATCAP_DNSDROP0_BIT, &ns->n.status);
										return NF_DROP;
									} else {
										NATCAP_INFO("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x direct DNS ANS is not cniplist ip = %pI4, ignore\n",
										            DEBUG_UDP_ARG(iph,l4), id, &ip);
									}
								}
								iph->daddr = old_ip;
							}
						} while (0);
					}
					break;

				case 28: //AAAA
					if (rdlength == 16) {
						unsigned char *ipv6 = p + pos;
						NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x type=%d, class=%d, ttl=%d, rdlength=%d, ipv6=%pI6\n", DEBUG_UDP_ARG(iph,l4), id, type, class, ttl, rdlength, ipv6);
					}
					break;

				case 2: //NS
				case 3: //MD
				case 4: //MF
				case 5: //CNAME
				case 15: //MX
				case 16: //TXT
					if (IS_NATCAP_DEBUG()) {
						int name_len;
						char *name = kmalloc(2048, GFP_ATOMIC);

						if (name != NULL) {
							if ((name_len = get_rdata(p, len, pos, name, 2047)) >= 0) {
								name[name_len] = 0;
								NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x, name=%s\n", DEBUG_UDP_ARG(iph,l4), id, name);
							}
							kfree(name);
						}
					}
					NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x type=%d, class=%d, ttl=%d, rdlength=%d\n", DEBUG_UDP_ARG(iph,l4), id, type, class, ttl, rdlength);
					break;

				default:
					NATCAP_DEBUG("(CPMI)" DEBUG_UDP_FMT ": id=0x%04x type=%d, class=%d, ttl=%d, rdlength=%d\n", DEBUG_UDP_ARG(iph,l4), id, type, class, ttl, rdlength);
					break;
				}

				pos += rdlength;
			}
		} while (0);
	}

	return NF_ACCEPT;
}

void cn_domain_clean(void)
{
	if (cn_domain) {
		vfree(cn_domain);
		cn_domain = NULL;
		cn_domain_size = 0;
		cn_domain_count = 0;
	}
}

void domain_copy(char *dst, char *from)
{
	int s = 0;
	int len = strlen(from);
	while (len > 0 && s < CN_DOMAIN_SIZE) {
		len--;
		dst[CN_DOMAIN_SIZE - 1 - s] = from[len];
		s++;
	}
	while (s < CN_DOMAIN_SIZE) {
		dst[CN_DOMAIN_SIZE - 1 - s] = 0;
		s++;
	}
}

int domain_cmp(char *dst, char *src)
{
	int i;
	int len = strlen(src);
	for (i = CN_DOMAIN_SIZE - 1; i >= 0 && len > 0;)
	{
		len--;
		if (dst[i] == 0) {
			return -1;
		}
		if (dst[i] == '.' && src[len] == '.') {
			i--;
			continue;
		}
		if (dst[i] == '.' && src[len] != '.') {
			return -1;
		}
		if (dst[i] != '.' && src[len] == '.') {
			return 1;
		}
		if (dst[i] < src[len]) {
			return -1;
		} else if (dst[i] > src[len]) {
			return 1;
		}
		i--;
	}

	if (len == 0 && (i == -1 || (i > 0 && dst[i] == 0))) {
		return 0;
	}
	if (i == -1 && len > 0) {
		return -1;
	}

	return 1;
}

int cn_domain_insert(char *d)
{
	int low;
	int high;
	int mid;
	int res = 0;

	if (cn_domain == NULL) {
		cn_domain_count = 0;
		cn_domain_size = 128 * 1024 / CN_DOMAIN_SIZE;
		cn_domain = vmalloc(CN_DOMAIN_SIZE * cn_domain_size);
		if (cn_domain == NULL) {
			return -ENOMEM;
		}
		memset(cn_domain, 0, CN_DOMAIN_SIZE * cn_domain_size);
	}
	if (cn_domain_count + 1 > cn_domain_size) {
		char *tmp;
		cn_domain_size = cn_domain_size + 128 * 1024 / CN_DOMAIN_SIZE;
		tmp = vmalloc(CN_DOMAIN_SIZE * cn_domain_size);
		if (tmp == NULL) {
			return -ENOMEM;
		}
		memset(tmp, 0, CN_DOMAIN_SIZE * cn_domain_size);
		memcpy(tmp, cn_domain, (cn_domain_size - 128 * 1024 / CN_DOMAIN_SIZE) * CN_DOMAIN_SIZE);
		vfree(cn_domain);
		cn_domain = tmp;
		printk("cn_domain_insert cn_domain_size=%d mem=%d\n", cn_domain_size, cn_domain_size * CN_DOMAIN_SIZE);
	}
	if (cn_domain_count == 0) {
		domain_copy(cn_domain + cn_domain_count * CN_DOMAIN_SIZE, d);
		cn_domain_count++;
		return 0;
	}

	low = 0;
	high = cn_domain_count - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		res = domain_cmp(cn_domain + mid * CN_DOMAIN_SIZE, d);
		if (res == 0) {
			return 0;
		}
		if (res < 0) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	if (res < 0) {
		memmove(cn_domain + mid * CN_DOMAIN_SIZE + CN_DOMAIN_SIZE + CN_DOMAIN_SIZE, cn_domain + mid * CN_DOMAIN_SIZE + CN_DOMAIN_SIZE, (cn_domain_count - mid - 1) * CN_DOMAIN_SIZE);
		domain_copy(cn_domain + (mid + 1) * CN_DOMAIN_SIZE, d);
		cn_domain_count++;
	} else {
		memmove(cn_domain + mid * CN_DOMAIN_SIZE + CN_DOMAIN_SIZE, cn_domain + mid * CN_DOMAIN_SIZE, (cn_domain_count - mid) * CN_DOMAIN_SIZE);
		domain_copy(cn_domain + mid * CN_DOMAIN_SIZE, d);
		cn_domain_count++;
	}

	return 0;
}

int domain_match(char *dst, char *src)
{
	int i;
	int len = strlen(src);
	for (i = CN_DOMAIN_SIZE - 1; i >= 0 && len > 0;)
	{
		len--;
		if (dst[i] == 0) {
			if (src[len] == '.')
				return 0;
			else
				return -1;
		}
		if (dst[i] == '.' && src[len] == '.') {
			i--;
			continue;
		}
		if (dst[i] == '.' && src[len] != '.') {
			return -1;
		}
		if (dst[i] != '.' && src[len] == '.') {
			return 1;
		}
		if (dst[i] < src[len]) {
			return -1;
		} else if (dst[i] > src[len]) {
			return 1;
		}
		i--;
	}

	if (len == 0 && (i == -1 || (i > 0 && dst[i] == 0))) {
		return 0;
	}
	if (i == -1 && len > 0) {
		if (src[len] == '.')
			return 0;
		else
			return -1;
	}

	return 1;
}

int cn_domain_lookup(char *d)
{
	int low;
	int high;
	int mid;
	int res;

	if (cn_domain == NULL || cn_domain_count == 0) {
		return 0;
	}

	low = 0;
	high = cn_domain_count - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		res = domain_match(cn_domain + mid * CN_DOMAIN_SIZE, d);
		if (res == 0) {
			/* found match */
			return 1;
		}
		if (res < 0) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return 0;
}

int cn_domain_load_from_path(char *path)
{
	loff_t pos = 0;
	ssize_t bytes = 0;
	struct file *filp;
	char *buf;
	int r_idx = 0;
	int r_cnt = 0;
	int i, s;
	int err;
	int count = 0;

	buf = kmalloc(4096, GFP_KERNEL);

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		printk("unable to open cn_domain file: %s\n", path);
		return -1;
	}

	while ((bytes = kernel_read(filp, buf + r_idx, 4096 - r_idx, &pos)) > 0) {
		r_cnt = r_idx + bytes;
		s = 0;
		for (i = 0; i < r_cnt;) {
			s = i;
			for (; i < r_cnt;) {
				if (buf[i] == '\n') {
					buf[i] = 0;
					err = cn_domain_insert(buf + s);
					if (err) {
						return err;
					}
					if (strlen(buf + s) > CN_DOMAIN_SIZE) printk("cn_domain_insert %d(%s)\n", count, buf + s);
					count++;
					s = i + 1;
					i++;
					break;
				}
				i++;
			}
		}
		memmove(buf, buf + s, i - s);
		r_idx = i - s;
	}
	kfree(buf);
	filp_close(filp, NULL);
	printk("cn_domain_load_from_path %d records loaded\n", count);
	return 0;
}

int cn_domain_load_from_raw(char *path)
{
	int ret = -1;
	loff_t pos = 0;
	ssize_t bytes = 0;
	struct file *filp;
	char *buf;
	char *cn_domain_tmp = NULL;
	int cn_domain_tmp_size = 0;
	int nbytes = 0;

	buf = kmalloc(4096, GFP_KERNEL);

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		printk("unable to open cn_domain raw: %s\n", path);
		return -1;
	}

	while ((bytes = kernel_read(filp, buf, 4096, &pos)) > 0) {
		if (cn_domain_tmp == NULL || nbytes + bytes > cn_domain_tmp_size * CN_DOMAIN_SIZE) {
			char *tmp;
			cn_domain_tmp_size += 128 * 1024 / CN_DOMAIN_SIZE;
			tmp = vmalloc(cn_domain_tmp_size * CN_DOMAIN_SIZE);
			if (tmp == NULL) {
				if (cn_domain_tmp)
					vfree(cn_domain_tmp);
				ret = -ENOMEM;
				goto out;
			}
			if (cn_domain_tmp) {
				memcpy(tmp, cn_domain_tmp, (cn_domain_tmp_size - 128 * 1024 / CN_DOMAIN_SIZE) * CN_DOMAIN_SIZE);
				vfree(cn_domain_tmp);
			}
			cn_domain_tmp = tmp;
		}
		memcpy(cn_domain_tmp + nbytes, buf, bytes);
		nbytes += bytes;
	}

	cn_domain_clean();

	cn_domain = cn_domain_tmp;
	cn_domain_size = cn_domain_tmp_size;
	cn_domain_count = nbytes / CN_DOMAIN_SIZE;

	printk("cn_domain_load_from_raw size:%d count:%d bytes:%d\n", cn_domain_size, cn_domain_count, nbytes);

out:
	kfree(buf);
	filp_close(filp, NULL);
	return 0;
}

int cn_domain_dump_path(char *path)
{
	loff_t pos = 0;
	ssize_t bytes = 0;
	struct file *filp;

	if (cn_domain == NULL) {
		return -1;
	}

	filp = filp_open(path, O_RDWR | O_CREAT | O_LARGEFILE | O_DSYNC, 0);
	if (IS_ERR(filp)) {
		printk("unable to open cn_domain dump: %s\n", path);
		return -1;
	}

	bytes = kernel_write(filp, cn_domain + pos, cn_domain_count * CN_DOMAIN_SIZE - pos, &pos);
	printk("cn_domain dump: write %d\n", (int)bytes);

	filp_close(filp, NULL);

	if (bytes != cn_domain_count * CN_DOMAIN_SIZE) {
		return -1;
	}
	return 0;
}

static struct nf_hook_ops client_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_master_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 10 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_NAT_DST - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_master_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 + 1,
	},
};

int natcap_client_init(void)
{
	int x;
	int ret = 0;

	need_conntrack();

	natcap_ntc_init(&tx_ntc);
	natcap_ntc_init(&rx_ntc);

	for (x = 0; x < SERVER_GROUP_MAX; x++) {
		natcap_server_info_cleanup(x);
	}

	default_mac_addr_init();
	ret = nf_register_hooks(client_hooks, ARRAY_SIZE(client_hooks));
	return ret;
}

void natcap_client_exit(void)
{
	nf_unregister_hooks(client_hooks, ARRAY_SIZE(client_hooks));

	if (cn_domain) {
		vfree(cn_domain);
		cn_domain = NULL;
	}
}
