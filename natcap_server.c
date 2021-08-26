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
#include "net/netfilter/nf_conntrack_seqadj.h"
#include <net/netfilter/nf_nat.h>
#include <net/ip.h>
#include <net/tcp.h>
#include "natcap.h"
#include "natcap_common.h"
#include "natcap_server.h"
#include "natcap_peer.h"

unsigned int server_flow_stop = 0;
unsigned int user_mark_natcap_mask = 0x00000000;
#define user_mark_natcap_set(mark, at) *(unsigned int *)(at) = ((*(unsigned int *)(at)) & (~user_mark_natcap_mask)) | ((mark) & user_mark_natcap_mask)
static inline int user_mark_natcap_get(unsigned int *at)
{
	unsigned int idx;
	unsigned int val;
	unsigned int mask = user_mark_natcap_mask;

	if (mask == 0)
		return -1;

	idx = ffs(mask) - 1;

	val = ((*(unsigned int *)(at)) & mask);
	return (val >> idx);
}

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
                              struct natcap_session *ns,
                              struct natcap_TCPOPT *tcpopt,
                              struct tuple *server)
#define NATCAP_AUTH(state, in, out, skb, ct, ns, tcpopt, server) natcap_auth(state, in, out, skb, ct, ns, tcpopt, server)
#else
static inline int natcap_auth(const struct net_device *in,
                              const struct net_device *out,
                              struct sk_buff *skb,
                              struct nf_conn *ct,
                              struct natcap_session *ns,
                              struct natcap_TCPOPT *tcpopt,
                              struct tuple *server)
#define NATCAP_AUTH(state, in, out, skb, ct, ns, tcpopt, server) natcap_auth(in, out, skb, ct, ns, tcpopt, server)
#endif
{
	int ret;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_ALL) {
		if (server) {
			server->ip = tcpopt->all.data.ip;
			server->port = tcpopt->all.data.port;
			server->encryption = tcpopt->header.encryption;
			if (server->ip == PEER_XSYN_MASK_ADDR) {
				server->ip = peer_xsyn_enumerate_addr();
			} else if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET)) {
				server->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			}
		}
		if ((auth_enabled & NATCAP_AUTH_MATCH_MAC)) {
			struct sk_buff *uskb = uskb_of_this_cpu(smp_processor_id());
			memcpy(eth_hdr(uskb)->h_source, tcpopt->all.data.mac_addr, ETH_ALEN);
			ret = IP_SET_test_src_mac(state, in, out, uskb, "vclist");
			if (ret > 0 && (auth_enabled & NATCAP_AUTH_MATCH_IP))
				ret = IP_SET_test_src_ip(state, in, out, skb, "vciplist");
			if (ret <= 0) {
				ret = natcap_auth_request(tcpopt->all.data.mac_addr, iph->saddr);
			}
			if (ret <= 0) {
				NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth failed\n",
				            __FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
				            tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
				            tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
				            ntohl(tcpopt->all.data.u_hash));
				return E_NATCAP_AUTH_FAIL;
			}
			NATCAP_DEBUG("(%s)" DEBUG_FMT_TCP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth ok\n",
			             __FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
			             tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
			             tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
			             ntohl(tcpopt->all.data.u_hash));
		}
		ns->n.u_hash = ntohl(tcpopt->all.data.u_hash);
	} else if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_USER) {
		if (server) {
			return E_NATCAP_INVAL;
		}
		if ((auth_enabled & NATCAP_AUTH_MATCH_MAC)) {
			struct sk_buff *uskb = uskb_of_this_cpu(smp_processor_id());
			memcpy(eth_hdr(uskb)->h_source, tcpopt->user.data.mac_addr, ETH_ALEN);
			ret = IP_SET_test_src_mac(state, in, out, uskb, "vclist");
			if (ret > 0 && (auth_enabled & NATCAP_AUTH_MATCH_IP))
				ret = IP_SET_test_src_ip(state, in, out, skb, "vciplist");
			if (ret <= 0) {
				ret = natcap_auth_request(tcpopt->user.data.mac_addr, iph->saddr);
			}
			if (ret <= 0) {
				NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth failed\n",
				            __FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
				            tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
				            tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
				            ntohl(tcpopt->user.data.u_hash));
				return E_NATCAP_AUTH_FAIL;
			}
			NATCAP_DEBUG("(%s)" DEBUG_FMT_TCP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth ok\n",
			             __FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
			             tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
			             tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
			             ntohl(tcpopt->user.data.u_hash));
		}
		//clear NATCAP_TCPOPT_SPROXY if not ALL
		tcpopt->header.type &= ~NATCAP_TCPOPT_SPROXY;
	} else if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_DST) {
		if (server) {
			server->ip = tcpopt->dst.data.ip;
			server->port = tcpopt->dst.data.port;
			server->encryption = tcpopt->header.encryption;
			if (server->ip == PEER_XSYN_MASK_ADDR) {
				server->ip = peer_xsyn_enumerate_addr();
			} else if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET)) {
				server->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			}
			//clear NATCAP_TCPOPT_SPROXY if not ALL
			tcpopt->header.type &= ~NATCAP_TCPOPT_SPROXY;
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
	int offset, add_len;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	oudph = (struct udphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 4 - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct udphdr) + 4;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;

	nudph = (struct udphdr *)((void *)niph + niph->ihl * 4);
	set_byte4((void *)nudph + sizeof(struct udphdr), __constant_htonl(NATCAP_E_MAGIC_A));
	nudph->source = oudph->dest;
	nudph->dest = oudph->source;
	nudph->len = ntohs(nskb->len - niph->ihl * 4);
	nudph->check = CSUM_MANGLED_0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	ns = natcap_session_get(ct);
	if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
		natcap_udp_to_tcp_pack(nskb, ns, 1, NULL);
	}

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	skb_nfct_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_tcp_reply_rst(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int dir)
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
	if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
		header_len = 8;
		protocol = IPPROTO_UDP;
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
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[dir].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[dir].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[dir].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[dir].tuple.src.u.tcp.port;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + 1);
	tcp_flag_word(ntcph) = TCP_FLAG_RST;
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->window = __constant_htons(0);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	skb_nfct_reset(nskb);
	niph->saddr = ct->tuplehash[!dir].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[!dir].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[!dir].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[!dir].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in_compat(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[dir].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[dir].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[dir].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[dir].tuple.src.u.tcp.port;

	if (protocol == IPPROTO_UDP) {
		int offlen;
		offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		niph->tot_len = htons(ntohs(niph->tot_len) + 8);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		nskb->len += 8;
		set_byte4((void *)UDPH(ntcph) + 8, ns->peer.ver == 1 ? __constant_htonl(NATCAP_7_MAGIC) : __constant_htonl(NATCAP_F_MAGIC));
		niph->protocol = IPPROTO_UDP;
		skb_rcsum_tcpudp(nskb);
	}

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	skb_nfct_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_tcp_reply_rstack(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct)
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
	if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
		header_len = 8;
		protocol = IPPROTO_UDP;
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
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + 1);
	tcp_flag_word(ntcph) = TCP_FLAG_RST | TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->window = __constant_htons(0);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	skb_nfct_reset(nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in_compat(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;

	if (protocol == IPPROTO_UDP) {
		int offlen;
		offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		niph->tot_len = htons(ntohs(niph->tot_len) + 8);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		nskb->len += 8;
		set_byte4((void *)UDPH(ntcph) + 8, ns->peer.ver == 1 ? __constant_htonl(NATCAP_7_MAGIC) : __constant_htonl(NATCAP_F_MAGIC));
		niph->protocol = IPPROTO_UDP;
		skb_rcsum_tcpudp(nskb);
	}

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	skb_nfct_reset(nskb);
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_reply_payload(const char *payload, int payload_len, struct sk_buff *oskb, const struct net_device *dev, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_session *ns;
	int offset, add_len;
	int header_len = 0;
	u8 protocol = IPPROTO_TCP;
	char *data;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	ns = natcap_session_get(ct);
	if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
		header_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len + header_len - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	data = (char *)ntcph + sizeof(struct tcphdr);
	memcpy(data, payload, payload_len);
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4);
	tcp_flag_word(ntcph) = TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_FIN;
	ntcph->res1 = 0;
	ntcph->doff = 5;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	if ((NS_NATCAP_ENC & ns->n.status)) {
		natcap_data_encode(data, payload_len);
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	/*FIXME make TCP state happy */
	skb_nfct_reset(nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	/*XXX don't care what is returned */
	nf_conntrack_in_compat(dev_net(dev), PF_INET, NF_INET_PRE_ROUTING, nskb);
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;

	if (protocol == IPPROTO_UDP) {
		int offlen;
		offlen = skb_tail_pointer(nskb) - (unsigned char *)UDPH(ntcph) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(ntcph) + 4 + 8, (void *)UDPH(ntcph) + 4, offlen);
		niph->tot_len = htons(ntohs(niph->tot_len) + 8);
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		UDPH(ntcph)->check = CSUM_MANGLED_0;
		nskb->len += 8;
		set_byte4((void *)UDPH(ntcph) + 8, ns->peer.ver == 1 ? __constant_htonl(NATCAP_7_MAGIC) : __constant_htonl(NATCAP_F_MAGIC));
		niph->protocol = IPPROTO_UDP;
		skb_rcsum_tcpudp(nskb);
	}

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	skb_nfct_reset(nskb);
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

	tcp_flag_word(tcph) = TCP_FLAG_RST;
	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->window = __constant_htons(0);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	iph->tot_len = htons(skb->len);
	iph->id = __constant_htons(0xdead);
	iph->frag_off = 0;

	skb_rcsum_tcpudp(skb);
	return 0;
}

static inline unsigned int natcap_try_http_redirect(struct iphdr *iph, struct sk_buff *skb, struct nf_conn *ct, const struct net_device *in)
{
	void *l4;
	unsigned char *data;
	int data_len;
	struct natcap_session *ns = natcap_session_get(ct);

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
		short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
		natcap_auth_http_302(in, skb, ct);
		natcap_auth_tcp_to_rst(skb);
		return NF_ACCEPT;
	} else if (data_len > 0) {
		short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
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
	int offset, add_len;
	u8 protocol = IPPROTO_TCP;
	struct natcap_TCPOPT *tcpopt;
	int size = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + size + ns->n.tcp_ack_offset - (skb_headlen(oskb) + skb_tailroom(oskb));
	add_len = offset < 0 ? 0 : offset;
	offset += skb_tailroom(oskb);
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), skb_tailroom(oskb) + add_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return;
	}
	nskb->tail += offset;
	nskb->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + size + ns->n.tcp_ack_offset;

	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	niph->daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	niph->version = oiph->version;
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xdead);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	ntcph->dest = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4);
	tcp_flag_word(ntcph) = TCP_FLAG_ACK;
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + size) / 4;
	ntcph->window = __constant_htons(65535);
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)((char *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_CONFUSION;
	tcpopt->header.opcode = TCPOPT_NATCAP;
	tcpopt->header.opsize = size;
	tcpopt->header.encryption = 0;

	memcpy((void *)tcpopt + size, htp_confusion_rsp, ns->n.tcp_ack_offset);

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	skb_nfct_reset(nskb);
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

	ns = natcap_session_get(ct);

	if (ns && (NS_NATCAP_DROP & ns->n.status)) {
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
		//not drop here
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (ns && (NS_NATCAP_AUTH & ns->n.status)) {
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
	const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_server_pre_ct_test_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
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
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
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

		if (!inet_is_local(in, iph->daddr)) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		}
		return NF_ACCEPT;
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12)) {
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_E_MAGIC) ||
			        (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_D_MAGIC) &&
			         skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 24))) {
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				set_bit(IPS_NATCAP_SERVER_BIT, &ct->status);
				if (!inet_is_local(in, iph->daddr)) {
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				}
				return NF_ACCEPT;
			}
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

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
	struct natcap_TCPOPT tcpopt = { };
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

	ns = natcap_session_get(ct);

	if (ns && (NS_NATCAP_DROP & ns->n.status)) {
		return NF_DROP;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		if ((IPS_NATCAP & ct->status)) {
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			user_mark_natcap_set(ns->n.u_hash, &skb->mark);
			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
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

			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_session_get failed\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			tcpopt.header.encryption = !!(NS_NATCAP_ENC & ns->n.status);
			ret = natcap_tcp_decode(ct, skb, &tcpopt, IP_CT_DIR_ORIGINAL);
			if (ret != 0) {
				NATCAP_ERROR("(SPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				return NF_DROP;
			}
			if (!TCPH(l4)->syn && NATCAP_TCPOPT_TYPE(tcpopt.header.type) == NATCAP_TCPOPT_TYPE_CONFUSION && (NS_NATCAP_CONFUSION & ns->n.status)) {
				if (nf_ct_seq_offset(ct, IP_CT_DIR_ORIGINAL, ntohl(TCPH(l4)->seq + 1)) != 0 - ns->n.tcp_seq_offset) {
					nf_ct_seqadj_init(ct, ctinfo, 0 - ns->n.tcp_seq_offset);
				}
				if (nf_ct_seq_offset(ct, IP_CT_DIR_REPLY, ntohl(TCPH(l4)->ack + 1)) != ns->n.tcp_ack_offset) {
					nf_ct_seqadj_init(ct, IP_CT_ESTABLISHED_REPLY, ns->n.tcp_ack_offset);
				}
				natcap_confusion_tcp_reply_ack(in, skb, ct, ns);
				consume_skb(skb);
				return NF_STOLEN;
			}
			ret = NATCAP_AUTH(state, in, out, skb, ct, ns, &tcpopt, NULL);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					short_set_bit(NS_NATCAP_AUTH_BIT, &ns->n.status);
				} else {
					short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
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
			if ((tcpopt.header.type & NATCAP_TCPOPT_CONFUSION)) {
				__be32 offset = get_byte4((const void *)&tcpopt + tcpopt.header.opsize - sizeof(unsigned int));
				ns->n.tcp_seq_offset = ntohl(offset);
				short_set_bit(NS_NATCAP_CONFUSION_BIT, &ns->n.status);
			}

			ret = NATCAP_AUTH(state, in, out, skb, ct, ns, &tcpopt, &server);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					short_set_bit(NS_NATCAP_AUTH_BIT, &ns->n.status);
				} else {
					short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
					return NF_DROP;
				}
			}
			if (server.ip == iph->saddr) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": connect target=%pI4 is saddr\n", DEBUG_TCP_ARG(iph,l4), &server.ip);
				short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
				return NF_DROP;
			}

			if (!(IPS_NATCAP & ct->status) && !test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
				NATCAP_INFO("(SPCI)" DEBUG_TCP_FMT ": new connection, after decode target=" TUPLE_FMT " u_hash=0x%08x(%u)\n",
				            DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server), ns->n.u_hash, ns->n.u_hash);

				if (server.encryption) {
					short_set_bit(NS_NATCAP_ENC_BIT, &ns->n.status);
				}

				if (natcap_redirect_port != 0 && (tcpopt.header.type & NATCAP_TCPOPT_SPROXY) &&
				        (!(NS_NATCAP_AUTH & ns->n.status) && !(NS_NATCAP_DROP & ns->n.status))) {
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
						ns->n.target_ip = server.ip;
						ns->n.target_port = server.port;
						short_set_bit(NS_NATCAP_DST_BIT, &ns->n.status);

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
		user_mark_natcap_set(ns->n.u_hash, &skb->mark);
		if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

		NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12)) {
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_E_MAGIC) ||
			        (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_D_MAGIC) &&
			         skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 24))) {
				int off = 12;
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
				if (NATCAP_UDP_GET_ENC(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == NATCAP_UDP_ENC) {
					short_set_bit(NS_NATCAP_ENC_BIT, &ns->n.status);
				}
				//reply ACK pkt
				natcap_udp_reply_cfm(in, skb, ct);

				server.ip = get_byte4((void *)UDPH(l4) + sizeof(struct udphdr) + 4);
				server.port = get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 8);

				if (NATCAP_UDP_GET_TARGET(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == NATCAP_UDP_TARGET) {
					server.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				} else {
					//XXX overwrite DNS server
					if (server.port == __constant_htons(53)) {
						dns_server_node_random_select(&server.ip);
					}
				}

				if (get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_D_MAGIC)) {
					unsigned char client_mac[ETH_ALEN];
					unsigned int u_hash = get_byte4((void *)UDPH(l4) + sizeof(struct udphdr) + 12);
					ns->n.u_hash = ntohl(u_hash);
					off = 24;
					get_byte6((void *)UDPH(l4) + sizeof(struct udphdr) + 16, client_mac);

					if ((auth_enabled & NATCAP_AUTH_MATCH_MAC)) {
						struct sk_buff *uskb = uskb_of_this_cpu(smp_processor_id());
						memcpy(eth_hdr(uskb)->h_source, client_mac, ETH_ALEN);
						ret = IP_SET_test_src_mac(state, in, out, uskb, "vclist");
						if (ret > 0 && (auth_enabled & NATCAP_AUTH_MATCH_IP))
							ret = IP_SET_test_src_ip(state, in, out, skb, "vciplist");
						if (ret <= 0) {
							ret = natcap_auth_request(client_mac, iph->saddr);
						}
						if (ret <= 0) {
							//if not DNS port 53 then mark drop, we allow DNS forward
							if (server.port != __constant_htons(53)) {
								NATCAP_WARN("(SPCI)" DEBUG_FMT_UDP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth failed\n",
								            DEBUG_ARG_UDP(iph,l4),
								            client_mac[0], client_mac[1], client_mac[2],
								            client_mac[3], client_mac[4], client_mac[5],
								            ns->n.u_hash);
								short_set_bit(NS_NATCAP_DROP_BIT, &ns->n.status);
							} else {
								NATCAP_WARN("(SPCI)" DEBUG_FMT_UDP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth failed, but forward DNS port 53\n",
								            DEBUG_ARG_UDP(iph,l4),
								            client_mac[0], client_mac[1], client_mac[2],
								            client_mac[3], client_mac[4], client_mac[5],
								            ns->n.u_hash);
							}
						} else {
							NATCAP_DEBUG("(SPCI)" DEBUG_FMT_UDP ": client=%02x:%02x:%02x:%02x:%02x:%02x u_hash=%u auth ok\n",
							             DEBUG_ARG_UDP(iph,l4),
							             client_mac[0], client_mac[1], client_mac[2],
							             client_mac[3], client_mac[4], client_mac[5],
							             ns->n.u_hash);
						}
					}
				}

				if (!(IPS_NATCAP & ct->status) && !test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
					NATCAP_INFO("(SPCI)" DEBUG_UDP_FMT ": new connection, after decode target=" TUPLE_FMT " u_hash=0x%08x(%u)\n",
					            DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server), ns->n.u_hash, ns->n.u_hash);
					if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
						NATCAP_ERROR("(SPCI)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
						set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
						return NF_DROP;
					}
				}

				if (NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == NATCAP_UDP_TYPE1) {
					flow_total_rx_bytes += skb->len;
					xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
					user_mark_natcap_set(ns->n.u_hash, &skb->mark);
					if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
					return NF_ACCEPT;
				} else if (NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == NATCAP_UDP_TYPE2) {
					int offlen;

					offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr) - off;
					BUG_ON(offlen < 0);
					memmove((void *)UDPH(l4) + sizeof(struct udphdr), (void *)UDPH(l4) + sizeof(struct udphdr) + off, offlen);
					iph->tot_len = htons(ntohs(iph->tot_len) - off);
					UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
					skb->len -= off;
					skb->tail -= off;
					skb_rcsum_tcpudp(skb);
				}
			}
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if ((IPS_NATCAP & ct->status)) {
			if (NULL == ns) {
				NATCAP_WARN("(SPCI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}

			if ((NS_NATCAP_ENC & ns->n.status)) {
				if (!skb_make_writable(skb, skb->len)) {
					NATCAP_ERROR("(SPCI)" DEBUG_UDP_FMT ": skb_make_writable() failed\n", DEBUG_UDP_ARG(iph,l4));
					return NF_DROP;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_decode);
				skb_rcsum_tcpudp(skb);
			}

			flow_total_rx_bytes += skb->len;
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
			user_mark_natcap_set(ns->n.u_hash, &skb->mark);
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
	const struct net_device *out = state->out;
#else
static unsigned int natcap_server_post_out_hook(void *priv,
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
	struct net *net = &init_net;
	struct natcap_TCPOPT tcpopt = { };
	unsigned long status = 0;

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

	if ((NS_NATCAP_DROP & ns->n.status)) {
		if (iph->protocol == IPPROTO_TCP) {
			void *l4 = (void *)iph + iph->ihl * 4;
			if (TCPH(l4)->fin || TCPH(l4)->rst) {
				return NF_ACCEPT;
			}
		}
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		return NF_DROP;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		if (server_flow_stop && hooknum == NF_INET_POST_ROUTING) {
			/* no stop for UDP 53 */
			if (iph->protocol != IPPROTO_UDP || UDPH(l4)->dest != 53) {
				return NF_DROP;
			}
		}
		if (iph->protocol == IPPROTO_TCP) {
			if (server_flow_stop && TCPH(l4)->dest == natcap_redirect_port) {
				return NF_DROP;
			}
			if ((NS_NATCAP_AUTH & ns->n.status)) {
				if (TCPH(l4)->dest == natcap_redirect_port) {
					return natcap_try_http_redirect(iph, skb, ct, in);
				}
			}
			if ((NS_NATCAP_TCPUDPENC & ns->n.status) && TCPH(l4)->syn) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8, natcap_max_pmtu - 40);
				return NF_ACCEPT;
			}
			if ((TCPH(l4)->syn && !TCPH(l4)->ack) && TCPH(l4)->seq == TCPOPT_NATCAP && TCPH(l4)->ack_seq == TCPOPT_NATCAP) {
				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				consume_skb(skb);
				return NF_STOLEN;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			if ((get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_E_MAGIC) ||
			        get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htonl(NATCAP_D_MAGIC)) &&
			        NATCAP_UDP_GET_TYPE(get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == NATCAP_UDP_TYPE1) {
				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}
				consume_skb(skb);
				return NF_STOLEN;
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
		if ((NS_NATCAP_ENC & ns->n.status)) {
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

		if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
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

			if (nskb == NULL && ns->peer.ver == 1 && ns->peer.mark != 0xffff && ns->peer.req_cnt < 3 && uintmindiff(ns->peer.jiffies, jiffies) > 1*HZ ) {
				ns->peer.jiffies = jiffies;
				pcskb = natcap_peer_ctrl_alloc(skb);
				if (pcskb) {
					iph = ip_hdr(pcskb);
					l4 = (void *)iph + iph->ihl * 4;

					set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_9_MAGIC));
					set_byte4((void *)UDPH(l4) + 8 + 4, __constant_htonl(NATCAP_9_MAGIC_TYPE1));
					set_byte4((void *)UDPH(l4) + 8 + 4 + 4, iph->daddr); //sip
					set_byte4((void *)UDPH(l4) + 8 + 4 + 4 + 4, iph->saddr); //dip
					set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4, UDPH(l4)->dest); //sport
					set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2, UDPH(l4)->source); //dport
					set_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2, IPPROTO_TCP); //protocol

					pcskb->ip_summed = CHECKSUM_UNNECESSARY;
					skb_rcsum_tcpudp(pcskb);
					ns->peer.req_cnt++;

					/* restore iph/l4 */
					iph = ip_hdr(skb);
					l4 = (void *)iph + iph->ihl * 4;
				}
			}

			if (ns->peer.ver == 1 && ns->peer.mark && total_weight > 0) {
				unsigned int ball = prandom_u32() % total_weight;
				unsigned int weight = 0;
				int i, idx = -1;
				for (i = 0; i < MAX_PEER_NUM; i++) {
					weight += ns->peer.weight[i];
					if (ns->peer.tuple3[i].dip == 0 || !short_test_bit(i, &ns->peer.mark))
						continue;
					if (ball < weight) {
						idx = i;
						break;
					}
				}
				if (idx >= 0) {
					struct nf_conntrack_tuple tuple;
					struct nf_conntrack_tuple_hash *h;

					memset(&tuple, 0, sizeof(tuple));
					tuple.src.u3.ip = iph->saddr;
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

							iph->daddr = ns->peer.tuple3[idx].dip;
							UDPH(l4)->dest = ns->peer.tuple3[idx].dport;
							UDPH(l4)->source = ns->peer.tuple3[idx].sport;
							set_byte4((void *)UDPH(l4) + 8, __constant_htonl(NATCAP_8_MAGIC));

							dup_skb->ip_summed = CHECKSUM_UNNECESSARY;
							skb_rcsum_tcpudp(dup_skb);
							if (peer_multipath <= MAX_PEER_NUM)
								flow_total_tx_bytes += dup_skb->len;
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

			NATCAP_DEBUG("(SPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

			if (peer_multipath <= MAX_PEER_NUM || pcskb) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				skb_rcsum_tcpudp(skb);
				NF_OKFN(skb);
				if (pcskb) {
					NF_OKFN(pcskb);
				}
				if (dup_skb) {
					NF_OKFN(dup_skb);
				}
			} else {
				if (dup_skb) {
					consume_skb(skb);
					NF_OKFN(dup_skb);
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
		NATCAP_DEBUG("(SPO)" DEBUG_UDP_FMT ": pass data reply\n", DEBUG_UDP_ARG(iph,l4));
		if ((NS_NATCAP_ENC & ns->n.status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(SPO)" DEBUG_UDP_FMT ": skb_make_writable() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_encode);
			skb_rcsum_tcpudp(skb);
		}

		if ((NS_NATCAP_TCPUDPENC & ns->n.status)) {
			/* XXX I just confirm it first  */
			ret = nf_conntrack_confirm(skb);
			if (ret != NF_ACCEPT) {
				return ret;
			}
			natcap_udp_to_tcp_pack(skb, ns, 1, NULL);
		}
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}

/*XXX this function works exactly the same as natcap_client_pre_in_hook() */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_pre_in_hook(unsigned int hooknum,
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
	struct nf_conn *ct, *master;
	struct natcap_session *ns;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;

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
			if (natcap_ignore_forward) {
				__be32 ip;
				__be16 port;
				unsigned int i, idx;
				unsigned int off = prandom_u32();
				struct sk_buff *uskb = uskb_of_this_cpu(smp_processor_id());
				for (i = 0; i < PEER_PUB_NUM; i++) {
					idx = (i + off) % PEER_PUB_NUM;
					ip = peer_pub_ip[idx];
					ip_hdr(uskb)->daddr = ip;
					if (ip != 0 && ip != iph->saddr && ip != iph->daddr &&
					        IP_SET_test_dst_ip(state, in, out, uskb, "ignorelist") <= 0) {
						port = htons(prandom_u32() % (65536 - 1024) + 1024);
						natcap_dnat_setup(master, ip, port);
						break;
					}
				}
			}
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

			NATCAP_DEBUG("(SPI)" DEBUG_TCP_FMT ": got UDP-to-TCP packet\n", DEBUG_TCP_ARG(iph,l4));

			if (skb->ip_summed == CHECKSUM_NONE) {
				if (skb_rcsum_verify(skb) != 0) {
					NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": skb_rcsum_verify fail\n", DEBUG_TCP_ARG(iph,l4));
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
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
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

					NATCAP_INFO("(SPI)" DEBUG_TCP_FMT ": ping: send\n", DEBUG_TCP_ARG(iph,l4));

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

			NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": after decode for UDP-to-TCP packet\n", DEBUG_UDP_ARG(iph,l4));
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
						NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
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

					NATCAP_INFO("(SPI)" DEBUG_TCP_FMT ": get ping: send pong\n", DEBUG_TCP_ARG(iph,l4));

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
						NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}

					if (!ns->ping.remote_saddr) {
						ns->ping.remote_saddr = get_byte4(l4 + sizeof(struct tcphdr) + 4);
						ns->ping.remote_daddr = get_byte4(l4 + sizeof(struct tcphdr) + 4 + 4);
						ns->ping.remote_source = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4);
						ns->ping.remote_dest = get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2);
						NATCAP_INFO("(SPI)" DEBUG_TCP_FMT ": get pong for %pI4:%u->%pI4:%u\n", DEBUG_TCP_ARG(iph,l4),
						            &ns->ping.remote_saddr, ntohs(ns->ping.remote_source),
						            &ns->ping.remote_daddr, ntohs(ns->ping.remote_dest));
					}
					if (ns->ping.remote_saddr != get_byte4(l4 + sizeof(struct tcphdr) + 4) ||
					        ns->ping.remote_daddr != get_byte4(l4 + sizeof(struct tcphdr) + 4 + 4) ||
					        ns->ping.remote_source != get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4) ||
					        ns->ping.remote_dest != get_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2)) {
						NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": invalid pong\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}

					NATCAP_INFO("(SPI)" DEBUG_TCP_FMT ": get pong\n", DEBUG_TCP_ARG(iph,l4));

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

					NATCAP_INFO("(SPI)" DEBUG_TCP_FMT ": get ping syn\n", DEBUG_TCP_ARG(iph,l4));

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
						NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
						consume_skb(skb);
						return NF_STOLEN;
					}
					if (!(NS_NATCAP_TCPUDPENC & ns->n.status)) {
						consume_skb(skb);
						return NF_STOLEN;
					}

					NATCAP_INFO("(SPI)" DEBUG_UDP_FMT ": get ping syn [UDP]\n", DEBUG_UDP_ARG(iph,l4));

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
			NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": got UDP-to-TCP packet syn\n", DEBUG_TCP_ARG(iph,l4));
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
		NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
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
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
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
			NATCAP_WARN("(SPI)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
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

			ct = master->master;
			if (!ct) {
				NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": master->master == NULL\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			ns = natcap_session_get(ct);
			if (ns == NULL) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
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
										NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": peer%px select %u-%pI4:%u j=%u\n", DEBUG_UDP_ARG(iph,l4), (void *)&ns,
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
						}
				}
			}

			if (ns->peer.cnt > 0 && peer_multipath <= MAX_PEER_NUM) {
				int ret;
				unsigned int i;
				__be32 saddr;
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

					NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": BIND=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n", DEBUG_UDP_ARG(iph,l4), i,
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					             &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					             &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
					            );

					skb_nfct_reset(nskb);

					if (nf_unicast_output_route(net, NULL, nskb, &saddr) == 0) {
						if (saddr != iph->saddr) {
							iph->saddr = saddr;
							skb_rcsum_tcpudp(nskb);
						}
						if (skb_dst(nskb) && dst_output(net, NULL, nskb) == 0) {
							continue;
						}
					}

					/* may fail output */
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

					NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": BIND=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] outdev=%s\n", DEBUG_UDP_ARG(iph,l4), i,
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
			int ret;
			unsigned int i, tmp;
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
						NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
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
						NATCAP_INFO("(SPI)" DEBUG_UDP_FMT ": CFM=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] peer.mark=0x%x\n", DEBUG_UDP_ARG(iph,l4), i,
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
				NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": peer pass forward: type4\n", DEBUG_UDP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			ct = master->master;
			ns = natcap_session_get(ct);
			if (ns == NULL) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}

			i = get_byte2((void *)UDPH(l4) + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 2);
			i = ntohs(i) % MAX_PEER_NUM;
			if (!short_test_bit(i, &ns->peer.mark) &&
			        ns->peer.tuple3[i].dip == iph->saddr && ns->peer.tuple3[i].dport == UDPH(l4)->source && ns->peer.tuple3[i].sport == UDPH(l4)->dest) {
				master->mark |= i;
				short_set_bit(i, &ns->peer.mark);
				NATCAP_INFO("(SPI)" DEBUG_UDP_FMT ": CFM=%u: ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] peer.mark=0x%x\n", DEBUG_UDP_ARG(iph,l4), i,
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
			NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": peer pass forward: data\n", DEBUG_UDP_ARG(iph,l4));
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
			NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": natcap_session_get failed\n", DEBUG_UDP_ARG(iph,l4));
			return NF_DROP;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
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

		NATCAP_DEBUG("(SPI)" DEBUG_UDP_FMT ": peer pass up: before\n", DEBUG_UDP_ARG(iph,l4));

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
		}

		NATCAP_DEBUG("(SPI)" DEBUG_TCP_FMT ": peer pass up: after ct=[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n", DEBUG_TCP_ARG(iph,l4),
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

static struct nf_hook_ops server_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 5 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_ct_test_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 10 - 3,
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
		if ((IPS_NATCAP & ct->status) && ns && (NS_NATCAP_DST & ns->n.status)) {
			sin.sin_family = AF_INET;
			sin.sin_port = ns->n.target_port;
			sin.sin_addr.s_addr = ns->n.target_ip;
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

static int set_natcap_mark(struct sock *sk, int optval,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
                           sockptr_t sockptr,
#else
                           void __user *user,
#endif
                           unsigned int len)
{
	sock_set_flag(sk, SOCK_NATCAP_MARK);
	return 0;
}

static struct nf_sockopt_ops so_natcap_mark = {
	.pf = PF_INET,
	.set_optmin = SO_NATCAP_MARK,
	.set_optmax = SO_NATCAP_MARK + 1,
	.set = set_natcap_mark,
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

	ret = nf_register_sockopt(&so_natcap_mark);
	if (ret < 0) {
		NATCAP_ERROR("Unable to register netfilter socket option\n");
		goto cleanup_sockopt;
	}

	ret = nf_register_hooks(server_hooks, ARRAY_SIZE(server_hooks));
	if (ret != 0) {
		NATCAP_ERROR("nf_register_hooks fail, ret=%d\n", ret);
		goto cleanup_sockopt1;
	}
	return ret;

cleanup_sockopt1:
	nf_unregister_sockopt(&so_natcap_mark);
cleanup_sockopt:
	nf_unregister_sockopt(&so_natcap_dst);
	return ret;
}

void natcap_server_exit(void)
{
	void *tmp;

	nf_unregister_hooks(server_hooks, ARRAY_SIZE(server_hooks));

	tmp = auth_http_redirect_url;
	auth_http_redirect_url = NULL;
	if (tmp) {
		synchronize_rcu();
		kfree(tmp);
	}

	nf_unregister_sockopt(&so_natcap_mark);
	nf_unregister_sockopt(&so_natcap_dst);
}
