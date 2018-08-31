/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:23:40 +0800
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
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/ip.h>
#include <net/tcp.h>
#include "natcap.h"
#include "natcap_common.h"
#include "natcap_server.h"

#define MAX_DNS_SERVER_NODE 32
static __be32 dns_server_node[MAX_DNS_SERVER_NODE];
static int dns_server_number = 0;
static void dns_server_node_random_select(__be32 *ip)
{
	unsigned int idx = dns_server_number;
	if (idx > 0) {
		idx = (jiffies % idx) % MAX_DNS_SERVER_NODE;
		idx = dns_server_node[idx];
		if (idx != 0) {
			*ip = idx;
		}
	}
}

/* called from user write */
int dns_server_node_add(__be32 ip)
{
	if (dns_server_number < MAX_DNS_SERVER_NODE) {
		dns_server_node[dns_server_number] = ip;
		dns_server_number++;
		return 0;
	}
	return -ENOMEM;
}
void dns_server_node_clean(void)
{
	dns_server_number = 0;
	memset(dns_server_node, 0, sizeof(__be32) * MAX_DNS_SERVER_NODE);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static inline int natcap_auth(const struct nf_hook_state *state,
		const struct net_device *in,
		const struct net_device *out,
		struct sk_buff *skb,
		struct nf_conn *ct,
		const struct natcap_TCPOPT *tcpopt,
		struct tuple *server)
#define NATCAP_AUTH(state, in, out, skb, ct, tcpopt, server) natcap_auth(state, in, out, skb, ct, tcpopt, server)
#else
static inline int natcap_auth(const struct net_device *in,
		const struct net_device *out,
		struct sk_buff *skb,
		struct nf_conn *ct,
		const struct natcap_TCPOPT *tcpopt,
		struct tuple *server)
#define NATCAP_AUTH(state, in, out, skb, ct, tcpopt, server) natcap_auth(in, out, skb, ct, tcpopt, server)
#endif
{
	int ret;
	unsigned char old_mac[ETH_ALEN];
	struct ethhdr *eth;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_ALL) {
		if (server) {
			server->ip = tcpopt->all.data.ip;
			server->port = tcpopt->all.data.port;
			server->encryption = tcpopt->header.encryption;
			if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET)) {
				server->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			}
		}
		if (auth_enabled) {
			eth = eth_hdr(skb);
			memcpy(old_mac, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, tcpopt->all.data.mac_addr, ETH_ALEN);
			ret = IP_SET_test_src_mac(state, in, out, skb, "vclist");
			memcpy(eth->h_source, old_mac, ETH_ALEN);
			if (ret <= 0) {
				NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth failed\n",
						__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
						tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
						tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
						ntohl(tcpopt->all.data.u_hash));
				return E_NATCAP_AUTH_FAIL;
			}
			NATCAP_DEBUG("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
					tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
					ntohl(tcpopt->all.data.u_hash));
		}
	} else if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_USER) {
		if (server) {
			return E_NATCAP_INVAL;
		}
		if (auth_enabled) {
			eth = eth_hdr(skb);
			memcpy(old_mac, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, tcpopt->user.data.mac_addr, ETH_ALEN);
			ret = IP_SET_test_src_mac(state, in, out, skb, "vclist");
			memcpy(eth->h_source, old_mac, ETH_ALEN);
			if (ret <= 0) {
				NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth failed\n",
						__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
						tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
						tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
						ntohl(tcpopt->user.data.u_hash));
				return E_NATCAP_AUTH_FAIL;
			}
			NATCAP_DEBUG("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
					tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
					ntohl(tcpopt->user.data.u_hash));
		}
	} else if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_DST) {
		if (server) {
			server->ip = tcpopt->dst.data.ip;
			server->port = tcpopt->dst.data.port;
			server->encryption = tcpopt->header.encryption;
			if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET)) {
				server->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			}
		} else if (!tcph->syn || tcph->ack) {
			return E_NATCAP_INVAL;
		}
	} else if (server) {
		return E_NATCAP_INVAL;
	}
	return E_NATCAP_OK;
}

static inline void natcap_udp_reply_cfm(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct) {
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct udphdr *oudph, *nudph;
	struct natcap_session *ns;
	int offset, header_len;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	oudph = (struct udphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 4 - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	//neth->h_proto = htons(ETH_P_IP);

	niph = ip_hdr(nskb);
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);
	set_byte4((void *)nudph + sizeof(struct udphdr), __constant_htonl(0xFFFE009A));
	nudph->source = oudph->dest;
	nudph->dest = oudph->source;
	nudph->len = ntohs(nskb->len - niph->ihl * 4);
	nudph->check = CSUM_MANGLED_0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	ns = natcap_session_get(ct);
	if (ns && (NS_NATCAP_TCPUDPENC & ns->status)) {
		natcap_udp_to_tcp_pack(nskb, ns, 1);
	}

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nf_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_tcp_reply_rst(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int dir)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_session *ns;
	int offset, header_len;
	int add_len = 0;
	u8 protocol = IPPROTO_TCP;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	ns = natcap_session_get(ct);
	if (ns && (NS_NATCAP_TCPUDPENC & ns->status)) {
		add_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + add_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	//neth->h_proto = htons(ETH_P_IP);

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[dir].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[dir].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[dir].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[dir].tuple.src.u.tcp.port;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(0xFFFF0099));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
	}
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + 1);
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->syn = 0;
	ntcph->rst = 1;
	ntcph->psh = 0;
	ntcph->ack = 0;
	ntcph->fin = 0;
	ntcph->urg = 0;
	ntcph->ece = 0;
	ntcph->cwr = 0;
	ntcph->window = __constant_htons(0);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	nf_reset(nskb);
	niph->saddr = ct->tuplehash[!dir].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[!dir].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[!dir].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[!dir].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[dir].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[dir].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[dir].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[dir].tuple.src.u.tcp.port;

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nf_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_tcp_reply_rstack(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_session *ns;
	int offset, header_len;
	int add_len = 0;
	u8 protocol = IPPROTO_TCP;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	ns = natcap_session_get(ct);
	if (ns && (NS_NATCAP_TCPUDPENC & ns->status)) {
		add_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + add_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	//neth->h_proto = htons(ETH_P_IP);

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(0xFFFF0099));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
	}
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + 1);
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->syn = 0;
	ntcph->rst = 1;
	ntcph->psh = 0;
	ntcph->ack = 1;
	ntcph->fin = 0;
	ntcph->urg = 0;
	ntcph->ece = 0;
	ntcph->cwr = 0;
	ntcph->window = __constant_htons(0);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	nf_reset(nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nf_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_reply_payload(const char *payload, int payload_len, struct sk_buff *oskb, const struct net_device *dev, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_session *ns;
	int offset, header_len;
	int add_len = 0;
	u8 protocol = IPPROTO_TCP;
	char *data;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	ns = natcap_session_get(ct);
	if (ns && (NS_NATCAP_TCPUDPENC & ns->status)) {
		add_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len + add_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	//neth->h_proto = htons(ETH_P_IP);

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		set_byte4((void *)UDPH(ntcph) + 8, __constant_htonl(0xFFFF0099));
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
	}
	data = (char *)ntcph + sizeof(struct tcphdr);
	memcpy(data, payload, payload_len);
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4);
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->syn = 0;
	ntcph->rst = 0;
	ntcph->psh = 1;
	ntcph->ack = 1;
	ntcph->fin = 1;
	ntcph->urg = 0;
	ntcph->ece = 0;
	ntcph->cwr = 0;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	if ((IPS_NATCAP_ENC & ct->status)) {
		natcap_data_encode(data, payload_len);
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	nf_reset(nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nf_reset(nskb);
	dev_queue_xmit(nskb);
}

char *auth_http_redirect_url = NULL;

static inline void natcap_auth_http_302(const struct net_device *dev, struct sk_buff *skb, struct nf_conn *ct)
{
	const char *http_header_fmt = ""
		"HTTP/1.1 302 Moved Temporarily\r\n"
		"Connection: close\r\n"
		"Cache-Control: no-cache\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Location: %s\r\n"
		"Content-Length: %u\r\n"
		"\r\n";
	const char *http_data_fmt = ""
		"<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\r\n"
		"<TITLE>302 Moved</TITLE></HEAD><BODY>\r\n"
		"<H1>302 Moved</H1>\r\n"
		"The document has moved\r\n"
		"<A HREF=\"%s\">here</A>.\r\n"
		"</BODY></HTML>\r\n";
	int n = 0;
	struct {
		char location[128];
		char data[384];
		char header[384];
		char payload[0];
	} *http = kmalloc(2048, GFP_ATOMIC);
	if (!http)
		return;

	if (auth_http_redirect_url) {
		snprintf(http->location, sizeof(http->location), "%s", auth_http_redirect_url);
	} else {
		snprintf(http->location, sizeof(http->location), "http://router-sh.ptpt52.com/index.html?_t=%lu", jiffies);
	}
	http->location[sizeof(http->location) - 1] = 0;
	snprintf(http->data, sizeof(http->data), http_data_fmt, http->location);
	http->data[sizeof(http->data) - 1] = 0;
	snprintf(http->header, sizeof(http->header), http_header_fmt, http->location, n);
	http->header[sizeof(http->header) - 1] = 0;
	n = sprintf(http->payload, "%s%s", http->header, http->data);

	natcap_auth_reply_payload(http->payload, n, skb, dev, ct);
	kfree(http);
}

static inline int natcap_auth_tcp_to_rst(struct sk_buff *skb)
{
	int offset = 0;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return -1;
	}
	if (skb->len < ntohs(iph->tot_len)) {
		return -1;
	}
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	offset = iph->ihl * 4 + sizeof(struct tcphdr) - skb->len;
	if (offset > 0) {
		return -1;
	}
	if (pskb_trim(skb, skb->len + offset)) {
		return -1;
	}

	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->fin = 0;
	tcph->urg = 0;
	tcph->ece = 0;
	tcph->cwr = 0;
	tcph->window = __constant_htons(0);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	iph->tot_len = htons(skb->len);
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;

	skb_rcsum_tcpudp(skb);
	return 0;
}

static inline unsigned int natcap_try_http_redirect(struct iphdr *iph, struct sk_buff *skb, struct nf_conn *ct, const struct net_device *in)
{
	void *l4;
	int data_len;
	unsigned char *data;

	if (!in) {
		return NF_ACCEPT;
	}

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

	data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
	data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
	if ((data_len > 4 && strncasecmp(data, "GET ", 4) == 0) ||
			(data_len > 5 && strncasecmp(data, "POST ", 5) == 0)) {
		set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
		natcap_auth_http_302(in, skb, ct);
		natcap_auth_tcp_to_rst(skb);
		return NF_ACCEPT;
	} else if (data_len > 0) {
		set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
		natcap_auth_tcp_reply_rst(in, skb, ct, IP_CT_DIR_ORIGINAL);
		natcap_auth_tcp_to_rst(skb);
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

static inline void natcap_confusion_tcp_reply_ack(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, struct natcap_session *ns)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, header_len;
	u8 protocol = IPPROTO_TCP;
	struct natcap_TCPOPT *tcpopt;
	int size = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + size + ns->tcp_ack_offset - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	//neth->h_proto = htons(ETH_P_IP);

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4);
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + size) / 4;
	ntcph->syn = 0;
	ntcph->rst = 0;
	ntcph->psh = 0;
	ntcph->ack = 1;
	ntcph->fin = 0;
	ntcph->urg = 0;
	ntcph->ece = 0;
	ntcph->cwr = 0;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((char *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_CONFUSION;
	tcpopt->header.opcode = TCPOPT_NATCAP;
	tcpopt->header.opsize = size;
	tcpopt->header.encryption = 0;

	memcpy((void *)tcpopt + size, htp_confusion_rsp, ns->tcp_ack_offset);

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nf_reset(nskb);
	dev_queue_xmit(nskb);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_forward_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_forward_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_forward_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	const struct net_device *in = state->in;
#else
static unsigned int natcap_server_forward_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	const struct net_device *in = state->in;
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct natcap_session *ns;
	struct iphdr *iph;

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
	if (!(IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_DROP & ct->status)) {
		if (iph->protocol == IPPROTO_TCP) {
			void *l4 = (void *)iph + iph->ihl * 4;
			if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
				if (TCPH(l4)->fin && TCPH(l4)->ack) {
					natcap_auth_tcp_reply_rstack(in, skb, ct);
				}
			} else {
				if (!(TCPH(l4)->syn && TCPH(l4)->ack)) {
					natcap_auth_tcp_reply_rst(in, skb, ct, IP_CT_DIR_REPLY);
					natcap_auth_tcp_to_rst(skb);
					return NF_ACCEPT;
				}
			}
		}
		return NF_DROP;
	}

	if (iph->protocol == IPPROTO_TCP) {
		ns = natcap_session_get(ct);
		if (ns && (NS_NATCAP_AUTH & ns->status)) {
			if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
				return natcap_try_http_redirect(iph, skb, ct, in);
			}
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_pre_ct_test_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_pre_ct_test_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_pre_ct_test_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_server_pre_ct_test_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;

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
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

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

		if (!TCPH(l4)->syn || TCPH(l4)->ack) {
			return NF_ACCEPT;
		}

		if (natcap_tcp_decode_header(TCPH(l4)) == NULL) {
			return NF_ACCEPT;
		}
		set_bit(IPS_NATCAP_SERVER_BIT, &ct->status);
		return NF_ACCEPT;
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12) &&
				get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(0xFFFE0099)) {
			set_bit(IPS_NATCAP_SERVER_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_pre_ct_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_server_pre_ct_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct natcap_session *ns;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt;
	struct tuple server;

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
	if (!(IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_DROP & ct->status)) {
		return NF_DROP;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		if ((IPS_NATCAP & ct->status)) {
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
		}
		return NF_ACCEPT;
	}

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

		if ((IPS_NATCAP & ct->status)) {
			NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,l4));

			ns = natcap_session_get(ct);
			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_session_get failed\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			tcpopt.header.encryption = !!(IPS_NATCAP_ENC & ct->status);
			ret = natcap_tcp_decode(ct, skb, &tcpopt, IP_CT_DIR_ORIGINAL);
			if (ret != 0) {
				NATCAP_ERROR("(SPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				return NF_DROP;
			}
			if (NTCAP_TCPOPT_TYPE(tcpopt.header.type) == NATCAP_TCPOPT_TYPE_CONFUSION) {
				natcap_confusion_tcp_reply_ack(in, skb, ct, ns);
				short_clear_bit(NS_NATCAP_CONFUSION_BIT, &ns->status);
				ns->tcp_seq_offset = 0;
				ns->tcp_ack_offset = 0;
				return NF_DROP;
			}
			ret = NATCAP_AUTH(state, in, out, skb, ct, &tcpopt, NULL);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					short_set_bit(NS_NATCAP_AUTH_BIT, &ns->status);
				} else {
					set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
					return NF_DROP;
				}
			}
		} else {
			if (!TCPH(l4)->syn || TCPH(l4)->ack) {
				NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": first packet in but not syn\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			
			tcpopt.header.encryption = 0;
			ret = natcap_tcp_decode(ct, skb, &tcpopt, IP_CT_DIR_ORIGINAL);
			if (ret != 0) {
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (tcpopt.header.opcode != TCPOPT_NATCAP) {
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			ns = natcap_session_in(ct);
			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			if (tcpopt.header.type & NATCAP_TCPOPT_CONFUSION) {
				short_set_bit(NS_NATCAP_CONFUSION_BIT, &ns->status);
			}

			ret = NATCAP_AUTH(state, in, out, skb, ct, &tcpopt, &server);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					short_set_bit(NS_NATCAP_AUTH_BIT, &ns->status);
				} else {
					set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
					return NF_DROP;
				}
			}
			if (server.ip == iph->saddr) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": connect target=%pI4 is saddr\n", DEBUG_TCP_ARG(iph,l4), &server.ip);
				set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				return NF_DROP;
			}

			if (!(IPS_NATCAP & ct->status) && !test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
				NATCAP_INFO("(SPCI)" DEBUG_TCP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));

				if (server.encryption) {
					set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
				}

				if (mode == SERVER_MODE && natcap_redirect_port != 0 && (tcpopt.header.type & NATCAP_TCPOPT_SPROXY)) {
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

					if (newdst && newdst != server.ip) {
						memcpy(&ns->tup, &server, sizeof(struct tuple));
						short_set_bit(NS_NATCAP_DST_BIT, &ns->status);

						server.ip = newdst;
						server.port = natcap_redirect_port;
					}
				}

				if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
					NATCAP_ERROR("(SPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					return NF_DROP;
				}
			}
		}

		flow_total_rx_bytes += skb->len;
		xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
		if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

		NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12) &&
				get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(0xFFFE0099)) {
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (skb->ip_summed == CHECKSUM_NONE) {
				if (skb_rcsum_verify(skb) != 0) {
					NATCAP_WARN("(SPCI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
					return NF_DROP;
				}
				skb->csum = 0;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}

			ns = natcap_session_in(ct);
			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			NATCAP_DEBUG("(SPCI)" DEBUG_UDP_FMT ": pass ctrl decode\n", DEBUG_UDP_ARG(iph,l4));
			if (NATCAP_UDP_GET_ENC(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == 0x01) {
				set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			}
			//reply ACK pkt
			natcap_udp_reply_cfm(in, skb, ct);

			server.ip = get_byte4((void *)UDPH(l4) + sizeof(struct udphdr) + 4);
			server.port = get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 8);

			if (!(IPS_NATCAP & ct->status) && !test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
				//XXX overwrite DNS server
				if (server.port == __constant_htons(53)) {
					dns_server_node_random_select(&server.ip);
				}
				NATCAP_INFO("(SPCI)" DEBUG_UDP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
				if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
					NATCAP_ERROR("(SPCI)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					return NF_DROP;
				}
			}

			if (NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == 0x01) {
				flow_total_rx_bytes += skb->len;
				xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
				if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
				return NF_ACCEPT;
			} else if (NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == 0x02) {
				int offlen;

				offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr) - 12;
				BUG_ON(offlen < 0);
				memmove((void *)UDPH(l4) + sizeof(struct udphdr), (void *)UDPH(l4) + sizeof(struct udphdr) + 12, offlen);
				iph->tot_len = htons(ntohs(iph->tot_len) - 12);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				skb->len -= 12;
				skb->tail -= 12;
				skb_rcsum_tcpudp(skb);
			}
		}

		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if ((IPS_NATCAP & ct->status)) {
			ns = natcap_session_get(ct);
			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			if ((IPS_NATCAP_ENC & ct->status)) {
				if (!skb_make_writable(skb, skb->len)) {
					NATCAP_ERROR("(SPCI)" DEBUG_UDP_FMT ": natcap_udp_decode() failed\n", DEBUG_UDP_ARG(iph,l4));
					return NF_DROP;
				}
				skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_decode);
				skb_rcsum_tcpudp(skb);
			}

			flow_total_rx_bytes += skb->len;
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			return NF_ACCEPT;
		} else {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			NATCAP_DEBUG("(SPCI)" DEBUG_UDP_FMT ": first packet in but not ctrl code\n", DEBUG_UDP_ARG(iph,l4));
		}
	}

	return NF_ACCEPT;
}

//PREROUTING->*POSTROUTING*
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_post_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_server_post_out_hook(void *priv,
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
	struct natcap_TCPOPT tcpopt;
	unsigned long status = 0;

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
	if (!(IPS_NATCAP_SERVER & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	ns = natcap_session_get(ct);
	if (NULL == ns) {
		NATCAP_ERROR("(SPO)" DEBUG_TCP_FMT ": natcap_session_get failed\n", DEBUG_TCP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		if (iph->protocol == IPPROTO_TCP) {
			if ((NS_NATCAP_AUTH & ns->status)) {
				if (TCPH(l4)->dest == natcap_redirect_port) {
					return natcap_try_http_redirect(iph, skb, ct, in);
				}
			}
			if ((NS_NATCAP_TCPUDPENC & ns->status) && TCPH(l4)->syn) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8);
				return NF_ACCEPT;
			}
			if ((TCPH(l4)->syn && !TCPH(l4)->ack) && TCPH(l4)->seq == TCPOPT_NATCAP && TCPH(l4)->ack_seq == TCPOPT_NATCAP) {
				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				return NF_DROP;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(0xFFFE0099) &&
					NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == 0x01) {
				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				return NF_DROP;
			}
		}
		return NF_ACCEPT;
	}

	flow_total_tx_bytes += skb->len;

	if (iph->protocol == IPPROTO_TCP) {
		if (TCPH(l4)->doff * 4 < sizeof(struct tcphdr)) {
			return NF_DROP;
		}

		NATCAP_DEBUG("(SPO)" DEBUG_TCP_FMT ": before encode\n", DEBUG_TCP_ARG(iph,l4));
		if ((IPS_NATCAP_ENC & ct->status)) {
			status |= NATCAP_NEED_ENC;
		}

		ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt, 0, 0);
		if (ret == 0) {
			ret = natcap_tcp_encode(ct, skb, &tcpopt, IP_CT_DIR_REPLY);
			iph = ip_hdr(skb);
			l4 = (struct tcphdr *)((void *)iph + iph->ihl * 4);
		}
		if (ret != 0) {
			NATCAP_ERROR("(SPO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}

		NATCAP_DEBUG("(SPO)" DEBUG_TCP_FMT ":after encode\n", DEBUG_TCP_ARG(iph,l4));

		if (!(NS_NATCAP_TCPUDPENC & ns->status)) {
			return NF_ACCEPT;
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
			set_byte4((void *)UDPH(l4) + 8, __constant_htonl(0xFFFF0099));
			iph->protocol = IPPROTO_UDP;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			skb->next = NULL;
			NF_OKFN(skb);

			skb = nskb;
		} while (skb);

		return NF_STOLEN;
	} else if (iph->protocol == IPPROTO_UDP) {
		NATCAP_DEBUG("(SPO)" DEBUG_UDP_FMT ": pass data reply\n", DEBUG_UDP_ARG(iph,l4));
		if ((IPS_NATCAP_ENC & ct->status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(SPO)" DEBUG_UDP_FMT ": natcap_udp_encode() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_encode);
			skb_rcsum_tcpudp(skb);
		}

		if ((NS_NATCAP_TCPUDPENC & ns->status)) {
			natcap_udp_to_tcp_pack(skb, ns, 1);
		}
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

/*XXX this function works exactly the same as natcap_client_pre_in_hook() */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_server_pre_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_server_pre_in_hook(void *priv,
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
	struct nf_conn *ct;
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

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP_PRE & ct->status)) {
		return NF_ACCEPT;
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

		if ( ntohs(TCPH(l4)->window) == (ntohs(iph->id) ^ (ntohl(TCPH(l4)->seq) & 0xFFFF) ^ (ntohl(TCPH(l4)->ack_seq) & 0xFFFF)) ) {
			unsigned int foreign_seq = ntohl(TCPH(l4)->seq) + (TCPH(l4)->syn ? 1 + ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct tcphdr) : ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct tcphdr));

			NATCAP_DEBUG("(SPI)" DEBUG_TCP_FMT ": got UDP-to-TCP packet\n", DEBUG_TCP_ARG(iph,l4));

			if (skb->ip_summed == CHECKSUM_NONE) {
				if (skb_rcsum_verify(skb) != 0) {
					NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": skb_rcsum_verify fail\n", DEBUG_TCP_ARG(iph,l4));
					return NF_DROP;
				}
				skb->csum = 0;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}

			if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
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

			memmove((void *)UDPH(l4) + sizeof(struct udphdr), (void *)UDPH(l4) + sizeof(struct tcphdr), skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct tcphdr));
			iph->tot_len = htons(ntohs(iph->tot_len) - (sizeof(struct tcphdr) - sizeof(struct udphdr)));
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			UDPH(l4)->check = CSUM_MANGLED_0;
			skb->len -= sizeof(struct tcphdr) - sizeof(struct udphdr);
			skb->tail -= sizeof(struct tcphdr) - sizeof(struct udphdr);
			iph->protocol = IPPROTO_UDP;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if (in)
				net = dev_net(in);
			else if (out)
				net = dev_net(out);
			ret = nf_conntrack_in(net, pf, hooknum, skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			ct = nf_ct_get(skb, &ctinfo);
			if (!ct) {
				return NF_DROP;
			}

			ns = natcap_session_in(ct);
			if (ns == NULL) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_DROP;
			}
			if (!(NS_NATCAP_TCPUDPENC & ns->status)) {
				short_set_bit(NS_NATCAP_TCPUDPENC_BIT, &ns->status);
			}

			ns->foreign_seq = foreign_seq;

			NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": after decode for UDP-to-TCP packet\n", DEBUG_UDP_ARG(iph,l4));
			return NF_ACCEPT;
		} else {
			set_bit(IPS_NATCAP_PRE_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	if (skb_is_gso(skb)) {
		NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
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

	if (get_byte4((void *)UDPH(l4) + 8) == __constant_htonl(0xFFFF0099)) {
		int offlen;

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb->csum = 0;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}

		if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4 + 8)->doff * 4)) {
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
		ret = nf_conntrack_in(net, pf, hooknum, skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		ct = nf_ct_get(skb, &ctinfo);
		if (!ct) {
			return NF_DROP;
		}

		ns = natcap_session_in(ct);
		if (ns == NULL) {
			NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
		if (!(NS_NATCAP_TCPUDPENC & ns->status)) {
			short_set_bit(NS_NATCAP_TCPUDPENC_BIT, &ns->status);
		}
	} else {
		set_bit(IPS_NATCAP_PRE_BIT, &ct->status);
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops server_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 5 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_ct_test_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 35 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST - 10 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 + 2,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_forward_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 10,
	},
};

static int get_natcap_dst(struct sock *sk, int optval, void __user *user, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = inet->inet_rcv_saddr;
	tuple.src.u.tcp.port = inet->inet_sport;
	tuple.dst.u3.ip = inet->inet_daddr;
	tuple.dst.u.tcp.port = inet->inet_dport;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = sk->sk_protocol;

	if (sk->sk_protocol != IPPROTO_TCP) {
		NATCAP_DEBUG("SO_NATCAP_DST: Not a TCP/SCTP socket\n");
		return -ENOPROTOOPT;
	}

	if ((unsigned int) *len < sizeof(struct sockaddr_in)) {
		NATCAP_DEBUG("SO_NATCAP_DST: len %d not %Zu\n",
				*len, sizeof(struct sockaddr_in));
		return -EINVAL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(sock_net(sk), NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
#endif
	if (h) {
		struct sockaddr_in sin;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		struct natcap_session *ns;

		ns = natcap_session_get(ct);
		if ((IPS_NATCAP & ct->status) && ns && (NS_NATCAP_DST & ns->status)) {
			sin.sin_family = AF_INET;
			sin.sin_port = ns->tup.port;
			sin.sin_addr.s_addr = ns->tup.ip;
			memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

			NATCAP_DEBUG("SO_NATCAP_DST: %pI4 %u\n", &sin.sin_addr.s_addr, ntohs(sin.sin_port));
			nf_ct_put(ct);
			if (copy_to_user(user, &sin, sizeof(sin)) != 0)
				return -EFAULT;
			else
				return 0;
		}
		nf_ct_put(ct);
	}
	NATCAP_DEBUG("SO_NATCAP_DST: Can't find %pI4/%u-%pI4/%u.\n",
			&tuple.src.u3.ip, ntohs(tuple.src.u.tcp.port),
			&tuple.dst.u3.ip, ntohs(tuple.dst.u.tcp.port));
	return -ENOENT;
}

static struct nf_sockopt_ops so_natcap_dst = {
	.pf = PF_INET,
	.get_optmin = SO_NATCAP_DST,
	.get_optmax = SO_NATCAP_DST + 1,
	.get = get_natcap_dst,
	.owner = THIS_MODULE,
};

int natcap_server_init(void)
{
	int ret = 0;

	need_conntrack();

	ret = nf_register_sockopt(&so_natcap_dst);
	if (ret < 0) {
		NATCAP_ERROR("Unable to register netfilter socket option\n");
		return ret;
	}

	ret = nf_register_hooks(server_hooks, ARRAY_SIZE(server_hooks));
	if (ret != 0) {
		NATCAP_ERROR("nf_register_hooks fail, ret=%d\n", ret);
		goto cleanup_sockopt;
	}
	return ret;

cleanup_sockopt:
	nf_unregister_sockopt(&so_natcap_dst);
	return ret;
}

void natcap_server_exit(void)
{
	nf_unregister_hooks(server_hooks, ARRAY_SIZE(server_hooks));

	if (auth_http_redirect_url) {
		kfree(auth_http_redirect_url);
		auth_http_redirect_url = NULL;
	}

	nf_unregister_sockopt(&so_natcap_dst);
}
