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
#include <linux/vmalloc.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "natcap_common.h"
#include "natcap_peer.h"
#include "natcap_client.h"

static inline __be32 gen_seq_number(void)
{
	__be32 s;
	do {
		s = prandom_u32();
	} while (s == 0);
	return s;
}

#define MAX_PEER_PORT_MAP 65536
static struct nf_conn **peer_port_map;

static int peer_port_map_init(void)
{
	peer_port_map = vmalloc(sizeof(struct nf_conn *) * MAX_PEER_PORT_MAP);
	if (peer_port_map == NULL) {
		return -ENOMEM;
	}
	memset(peer_port_map, 0, sizeof(struct nf_conn *) * MAX_PEER_PORT_MAP);

	return 0;
}

static void peer_port_map_exit(void)
{
	int i;

	for (i = 0; i < MAX_PEER_PORT_MAP; i++) {
		if (peer_port_map[i] != NULL) {
			nf_ct_put(peer_port_map[i]);
			peer_port_map[i] = NULL;
		}
	}
}

static __be16 alloc_peer_port(struct nf_conn *ct, const unsigned char *mac)
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
			peer_port_map[port] = ct;
			nf_conntrack_get(&ct->ct_general);
			return htons(port);
		}
	}

	for (port = 1024; port < 1024 + hash % (MAX_PEER_PORT_MAP - 1024); port++) {
		if (peer_port_map[port] == NULL) {
			peer_port_map[port] = ct;
			nf_conntrack_get(&ct->ct_general);
			return htons(port);
		}
	}

	return 0;
}

__be32 peer_local_ip = __constant_htonl(0);
__be16 peer_local_port = __constant_htons(443);

#define MAX_PEER_SERVER 8
struct peer_server_node peer_server[MAX_PEER_SERVER];
struct peer_server_node *peer_server_node_in(__be32 ip, int new)
{
	int i;
	for (i = 0; i < MAX_PEER_SERVER; i++) {
		if (peer_server[i].ip == ip) {
			return &peer_server[i];
		}
	}
	if (new == 0)
		return NULL;

	for (i = 0; i < MAX_PEER_SERVER; i++) {
		if (peer_server[i].ip == 0) {
			peer_server[i].ip = ip;
			peer_server[i].mss = 0;
			peer_server[i].map_port = 0;
			return  &peer_server[i];
		}
	}

	return NULL;
}

static struct sk_buff *peer_user_uskbs[NR_CPUS];
#define PEER_USKB_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define PEER_FAKEUSER_DADDR __constant_htonl(0x7ffffffe)

static inline struct sk_buff *uskb_of_this_cpu(int id)
{
	BUG_ON(id >= NR_CPUS);
	if (!peer_user_uskbs[id]) {
		peer_user_uskbs[id] = __alloc_skb(PEER_USKB_SIZE, GFP_ATOMIC, 0, numa_node_id());
	}
	return peer_user_uskbs[id];
}

#define NATCAP_PEER_USER_TIMEOUT_RELEASE 2
#define NATCAP_PEER_USER_TIMEOUT 180

void natcap_user_timeout_touch(struct nf_conn *ct, unsigned long timeout)
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

struct nf_conn *peer_client_expect_in(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, int pmi, __be32 *seq)
{
	struct nf_conn *user;
	struct nf_ct_ext *new = NULL;
	enum ip_conntrack_info ctinfo;
	unsigned int newoff = 0;
	int ret;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;

	uskb = uskb_of_this_cpu(smp_processor_id());
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
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = sport;
	udph->dest = dport;
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
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
	if (!nf_ct_is_confirmed(user) && !(IPS_NATCAP_PEER & user->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &user->status)) {
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
		new = __krealloc(user->ext, newoff + sizeof(struct fakeuser_expect), GFP_ATOMIC);
		if (!new) {
			NATCAP_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u] failed, realloc user->ext failed\n", &saddr, ntohs(sport), &daddr, ntohs(dport));
			skb_nfct_reset(uskb);
			return NULL;
		}

		if (user->ext != new) {
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, sizeof(struct fakeuser_expect));

		peer_fakeuser_expect(user)->pmi = pmi;
		if (seq) {
			//XXX BUG_ON(seq == NULL); just make happy
			peer_fakeuser_expect(user)->local_seq = ntohl(*seq);
		}
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return NULL;
	}

	skb_nfct_reset(uskb);
	natcap_user_timeout_touch(user, NATCAP_PEER_USER_TIMEOUT);

	if (seq) {
		*seq = htonl(peer_fakeuser_expect(user)->local_seq);
	}
	NATCAP_INFO("fakeuser create user[%pI4:%u->%pI4:%u] pmi=%d upmi=%d\n", &saddr, ntohs(sport), &daddr, ntohs(dport), pmi, peer_fakeuser_expect(user)->pmi);

	return user;
}

struct nf_conn *peer_user_expect_in(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const unsigned char *client_mac)
{
	int i;
	int ret;
	struct peer_tuple *pt = NULL;
	struct user_expect *ue;
	struct nf_conn *user;
	struct nf_ct_ext *new = NULL;
	enum ip_conntrack_info ctinfo;
	unsigned int newoff = 0;
	struct sk_buff *uskb;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned long last_jiffies = jiffies;

	uskb = uskb_of_this_cpu(smp_processor_id());
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
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udph->source = get_byte2(client_mac + 4);
	udph->dest = __constant_htons(65535);
	udph->len = __constant_htons(sizeof(struct udphdr));
	udph->check = 0;

	ret = nf_conntrack_in(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
	if (ret != NF_ACCEPT) {
		return NULL;
	}
	user = nf_ct_get(uskb, &ctinfo);

	if (!user) {
		NATCAP_ERROR("user [%02X:%02X:%02X:%02X:%02X:%02X] ct[%pI4:%u->%pI4:%u] failed\n",
				client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
				&saddr, ntohs(sport), &daddr, ntohs(dport));
		return NULL;
	}

	if (!user->ext) {
		NATCAP_ERROR("user [%02X:%02X:%02X:%02X:%02X:%02X] ct[%pI4:%u->%pI4:%u] failed, user->ext is NULL\n",
				client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
				&saddr, ntohs(sport), &daddr, ntohs(dport));
		skb_nfct_reset(uskb);
		return NULL;
	}
	if (!nf_ct_is_confirmed(user) && !(IPS_NATCAP_PEER & user->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &user->status)) {
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
		new = __krealloc(user->ext, newoff + sizeof(struct user_expect), GFP_ATOMIC);
		if (!new) {
			NATCAP_ERROR("user [%02X:%02X:%02X:%02X:%02X:%02X] ct[%pI4:%u->%pI4:%u] failed, realloc user->ext failed\n",
					client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
					&saddr, ntohs(sport), &daddr, ntohs(dport));
			skb_nfct_reset(uskb);
			return NULL;
		}

		if (user->ext != new) {
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, sizeof(struct user_expect));

		peer_user_expect(user)->ip = saddr;
		peer_user_expect(user)->map_port = alloc_peer_port(user, client_mac);
	}

	ret = nf_conntrack_confirm(uskb);
	if (ret != NF_ACCEPT) {
		skb_nfct_reset(uskb);
		return NULL;
	}

	skb_nfct_reset(uskb);
	natcap_user_timeout_touch(user, NATCAP_PEER_USER_TIMEOUT);

	ue = peer_user_expect(user);
	ue->last_active = last_jiffies;

	if (user != peer_port_map[ntohs(ue->map_port)]) {
		ue->map_port = alloc_peer_port(user, client_mac);
		NATCAP_INFO("user [%02X:%02X:%02X:%02X:%02X:%02X] ct[%pI4:%u->%pI4:%u] @map_port=%u reuse update mapping\n",
				client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
				&saddr, ntohs(sport), &daddr, ntohs(dport), ntohs(ue->map_port));
	}

	for (i = 0; i < MAX_PEER_TUPLE; i++) {
		if (ue->tuple[i].sip == saddr && ue->tuple[i].dip == daddr && ue->tuple[i].sport == sport && ue->tuple[i].dport) {
			pt = &ue->tuple[i];
			pt->last_active = last_jiffies;
			break;
		}
	}
	if (pt == NULL) {
		unsigned long maxdiff = 0;
		for (i = 0; i < MAX_PEER_TUPLE; i++) {
			if (maxdiff < ulongdiff(last_jiffies, ue->tuple[i].last_active)) {
				maxdiff = ulongdiff(last_jiffies, ue->tuple[i].last_active);
				pt = &ue->tuple[i];
			}
			if (ue->tuple[i].sip == 0) {
				pt = &ue->tuple[i];
				break;
			}
		}
		if (pt) {
			NATCAP_INFO("user [%02X:%02X:%02X:%02X:%02X:%02X] ct[%pI4:%u->%pI4:%u] @map_port=%u new session in\n",
					client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
					&saddr, ntohs(sport), &daddr, ntohs(dport), ntohs(ue->map_port));
			pt->sip = saddr;
			pt->dip = daddr;
			pt->sport = sport;
			pt->dport = dport;
			pt->last_active = last_jiffies;
		}
	}

	return user;
}

static inline void natcap_peer_reply_pong(const struct net_device *dev, struct sk_buff *oskb, __be16 map_port)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	struct natcap_TCPOPT *tcpopt;
	int offset, header_len;
	int add_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer_synack), sizeof(unsigned int));

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + add_len + TCPOLEN_MSS - oskb->len;
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
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = IPPROTO_TCP;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(sizeof(struct tcphdr) + add_len + TCPOLEN_MSS));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = gen_seq_number();
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - oiph->ihl * 4 - otcph->doff * 4 + 1);
	ntcph->res1 = 0;
	ntcph->doff = (sizeof(struct tcphdr) + add_len + TCPOLEN_MSS) / 4;
	ntcph->syn = 1;
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

	tcpopt = (struct natcap_TCPOPT *)((void *)ntcph + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER_SYNACK;
	tcpopt->header.opcode = TCPOPT_PEER;
	tcpopt->header.opsize = add_len;
	tcpopt->header.encryption = 0;
	set_byte2((void *)&tcpopt->peer_synack.data.port, map_port);

	//just set a mss we do not care what it is
	set_byte1((void *)tcpopt + add_len + 0, TCPOPT_MSS);
	set_byte1((void *)tcpopt + add_len + 1, TCPOLEN_MSS);
	set_byte2((void *)tcpopt + add_len + 2, ntohs(IPV4_MIN_MTU - (sizeof(struct iphdr) + sizeof(struct tcphdr))));

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	dev_queue_xmit(nskb);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_peer_pre_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_peer_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_peer_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_peer_pre_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct natcap_TCPOPT *tcpopt;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	iph = ip_hdr(skb);
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

	tcpopt = natcap_peer_decode_header(TCPH(l4));
	if (tcpopt == NULL) {
		return NF_ACCEPT;
	}

	if (!inet_is_local(in, iph->daddr)) {
		return NF_ACCEPT;
	}

	if (TCPH(l4)->syn && TCPH(l4)->ack) {
		//got syn ack
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
				goto h_out;
			}

			if (tcpopt->header.type == NATCAP_TCPOPT_TYPE_PEER_SYNACK) {
				struct peer_server_node *ps;
				int pmi;
				__be16 map_port;

				NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": get pong in\n", DEBUG_TCP_ARG(iph,l4));
				//TODO send ack back?
				peer_fakeuser_expect(user)->remote_seq = ntohl(TCPH(l4)->seq);

				ps = peer_server_node_in(iph->saddr, 0);
				if (ps == NULL) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": peer_server_node not found\n", DEBUG_TCP_ARG(iph,l4));
					goto h_out;
				}
				pmi = peer_fakeuser_expect(user)->pmi;
				if (ps->port_map[pmi].sport != TCPH(l4)->dest || ps->port_map[pmi].dport != TCPH(l4)->source) {
					NATCAP_WARN("(PPI)" DEBUG_TCP_FMT ": peer_server_node port(%u:%u) mismatch\n",
							DEBUG_TCP_ARG(iph,l4), ntohs(ps->port_map[pmi].sport), ntohs(ps->port_map[pmi].dport));
					goto h_out;
				}

				map_port = get_byte2((const void *)&tcpopt->peer_synack.data.port);
				if (map_port != ps->map_port) {
					NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": update map_port from %u to %u\n",
							DEBUG_TCP_ARG(iph,l4), ntohs(ps->map_port), ntohs(map_port));
					ps->map_port = map_port;
				}

				nf_ct_put(user);
				consume_skb(skb);
				return NF_STOLEN;
			} else if (tcpopt->header.type == NATCAP_TCPOPT_TYPE_PEER_SYN) {
				NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": get fake syn in\n", DEBUG_TCP_ARG(iph,l4));
				TCPH(l4)->ack = 0;
				skb_rcsum_tcpudp(skb);
			}
h_out:
			nf_ct_put(user);
			return NF_ACCEPT;
		} else {
			//XXX not expect found bypass
		}

	} else if (TCPH(l4)->syn && !TCPH(l4)->ack) {
		//got syn
		struct nf_conn *user;
		__be32 client_ip;
		unsigned char client_mac[ETH_ALEN];

		//TODO
		client_ip = get_byte4((const void *)&tcpopt->peer.data.ip);
		memcpy(client_mac, tcpopt->peer.data.mac_addr, ETH_ALEN);

		user = peer_user_expect_in(iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, client_mac);
		if (user != NULL) {
			//XXX send syn ack back
			NATCAP_INFO("(PPI)" DEBUG_TCP_FMT ": send pong out\n", DEBUG_TCP_ARG(iph,l4));
			natcap_peer_reply_pong(in, skb, peer_user_expect(user)->map_port);
		}
		consume_skb(skb);
		return NF_STOLEN;

	}

	return NF_ACCEPT;
}

static inline struct sk_buff *natcap_peer_ping_init(struct sk_buff *oskb, const struct net_device *dev, struct peer_server_node *ops, int opmi)
{
	struct nf_conn *user;
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	void *l4;
	struct natcap_TCPOPT *tcpopt;
	int offset, header_len;
	int add_len;
	int pmi;
	struct peer_server_node *ps = NULL;

	oiph = ip_hdr(oskb);
	l4 = (void *)oiph + oiph->ihl * 4;

	if (ops != NULL && dev == NULL) {
		//invalid input
		return NULL;
	}

	ps = (ops != NULL) ? ops : peer_server_node_in(oiph->daddr, 1);
	if (ps == NULL) {
		return NULL;
	}
	if (ops == NULL && ps->mss == 0) {
		unsigned int mss;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		mss = ip_skb_dst_mtu(oskb);
#else
		mss = ip_skb_dst_mtu(NULL, oskb);
#endif
		if (mss < IPV4_MIN_MTU) {
			mss = IPV4_MIN_MTU;
		}
		mss = mss - (sizeof(struct iphdr) + sizeof(struct tcphdr));
		ps->mss = mss;
	}
	pmi = (ops != NULL) ? opmi : ntohs(ICMPH(l4)->un.echo.sequence) % MAX_PEER_SERVER_PORT;
	if (ps->port_map[pmi].sport == 0) {
		ps->port_map[pmi].sport = htons(1024 + prandom_u32() % (65535 - 1024 + 1));
		ps->port_map[pmi].dport = htons(1024 + prandom_u32() % (65535 - 1024 + 1));
	}

	add_len = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_peer), sizeof(unsigned int));
	offset = oiph->ihl * 4 + sizeof(struct tcphdr) + add_len + TCPOLEN_MSS - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
		return NULL;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_trim fail: len=%d, offset=%d\n", DEBUG_ARG_PREFIX, nskb->len, offset);
			consume_skb(nskb);
			return NULL;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	skb_nfct_reset(nskb);

	if (ops != NULL) {
		oeth = eth_hdr(nskb);
		neth = eth_hdr(nskb);
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = (ops != NULL) ? oiph->daddr : oiph->saddr;
	niph->daddr = (ops != NULL) ? oiph->saddr : oiph->daddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len);
	niph->ttl = 255;
	niph->protocol = IPPROTO_TCP;
	niph->id = (ops != NULL) ? __constant_htons(0xDEAD) : oiph->id;
	niph->frag_off = 0x0;

	l4 = (void *)niph + niph->ihl * 4;
	memset(l4, 0, sizeof(sizeof(struct tcphdr) + add_len + TCPOLEN_MSS));
	TCPH(l4)->source = ps->port_map[pmi].sport;
	TCPH(l4)->dest = ps->port_map[pmi].dport;
	TCPH(l4)->seq = gen_seq_number();
	TCPH(l4)->ack_seq = 0;
	TCPH(l4)->res1 = 0;
	TCPH(l4)->doff = (sizeof(struct tcphdr) + add_len + TCPOLEN_MSS) / 4;
	TCPH(l4)->syn = 1;
	TCPH(l4)->rst = 0;
	TCPH(l4)->psh = 0;
	TCPH(l4)->ack = 0;
	TCPH(l4)->fin = 0;
	TCPH(l4)->urg = 0;
	TCPH(l4)->ece = 0;
	TCPH(l4)->cwr = 0;
	TCPH(l4)->window = __constant_htons(65535);
	TCPH(l4)->check = 0;
	TCPH(l4)->urg_ptr = 0;

	tcpopt = (struct natcap_TCPOPT *)(l4 + sizeof(struct tcphdr));
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER;
	tcpopt->header.opcode = TCPOPT_PEER;
	tcpopt->header.opsize = add_len;
	tcpopt->header.encryption = 0;
	set_byte4((void *)&tcpopt->peer.data.ip, niph->saddr);
	memcpy(tcpopt->peer.data.mac_addr, default_mac_addr, ETH_ALEN);

	//MUST set mss
	set_byte1((void *)tcpopt + add_len + 0, TCPOPT_MSS);
	set_byte1((void *)tcpopt + add_len + 1, TCPOLEN_MSS);
	set_byte2((void *)tcpopt + add_len + 2, ntohs(ps->mss));

	user = peer_client_expect_in(niph->saddr, niph->daddr, TCPH(l4)->source, TCPH(l4)->dest, pmi, &TCPH(l4)->seq);
	if (user == NULL) {
		consume_skb(nskb);
		return NULL;
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	if (ops != NULL) {
		skb_push(nskb, (char *)niph - (char *)neth);
		nskb->dev = (struct net_device *)dev;
	}

	return nskb;
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
	struct sk_buff *nskb;
	struct iphdr *iph;
	void *l4;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_ICMP) {
		return NF_ACCEPT;
	}
	if (iph->ttl != 1) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	NATCAP_INFO("(PPO)" DEBUG_ICMP_FMT ": ping out\n", DEBUG_ICMP_ARG(iph,l4));
	nskb = natcap_peer_ping_init(skb, NULL, NULL, 0);
	if (nskb != NULL) {
		NF_OKFN(nskb);
	}

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
	struct iphdr *iph;
	void *l4;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct tuple server;

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
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}

	if (!TCPH(l4)->syn || TCPH(l4)->ack) {
		//not syn
		return NF_ACCEPT;
	}

	if (!inet_is_local(in, iph->daddr)) {
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
		struct peer_server_node *ps;
		struct nf_conn *user;

		user = nf_ct_tuplehash_to_ctrack(h);
		if (!(IPS_NATCAP_PEER & user->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_REPLY) {
			NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": user found but status or dir mismatch\n", DEBUG_TCP_ARG(iph,l4));
			goto h_out;
		}

		ps = peer_server_node_in(iph->saddr, 0);
		if (ps == NULL) {
			NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": peer_server_node not found\n", DEBUG_TCP_ARG(iph,l4));
			goto h_out;
		}
		pmi = peer_fakeuser_expect(user)->pmi;
		if (ps->port_map[pmi].sport != TCPH(l4)->dest || ps->port_map[pmi].dport != TCPH(l4)->source) {
			NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": peer_server_node port(%u:%u) mismatch\n",
					DEBUG_TCP_ARG(iph,l4), ntohs(ps->port_map[pmi].sport), ntohs(ps->port_map[pmi].dport));
			goto h_out;
		}

		natcap_user_timeout_touch(user, NATCAP_PEER_USER_TIMEOUT_RELEASE);
		//renew port
		ps->port_map[pmi].sport = 0;

		server.ip = peer_local_ip == 0 ? iph->daddr : peer_local_ip;
		server.port = peer_local_port;
		NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": found fakeuser expect, mapping to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));

		ret = natcap_dnat_setup(ct, server.ip, server.port);
		if (ret != NF_ACCEPT) {
			NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		}
		xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);

		do {
			struct sk_buff *nskb;

			nskb = natcap_peer_ping_init(skb, in, ps, pmi);
			if (nskb) {
				iph = ip_hdr(nskb);
				l4 = (void *)iph + iph->ihl * 4;
				NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": sending new syn out\n", DEBUG_TCP_ARG(iph,l4));

				dev_queue_xmit(nskb);
			} else {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": sending new syn failed\n", DEBUG_TCP_ARG(iph,l4));
			}
		} while (0);
h_out:
		nf_ct_put(user);
		return NF_ACCEPT;

	} else {
		struct nf_conn *user;
		unsigned int port = ntohs(TCPH(l4)->dest);
		user = peer_port_map[port];

		if (user) {
			int i;
			int hash;
			struct peer_tuple *pt = NULL;
			struct natcap_session *ns;
			struct user_expect *ue = peer_user_expect(user);
			if (ntohs(ue->map_port) != port) {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": map_port=%u dest=%u mismatch\n", DEBUG_TCP_ARG(iph,l4), ntohs(ue->map_port), port);
				return NF_ACCEPT;
			}

			ns = natcap_session_in(ct);
			if (!ns) {
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": natcap_session_in failed\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}

			hash = jiffies % MAX_PEER_TUPLE;
			for (i = hash; i < MAX_PEER_TUPLE; i++) {
				if (ue->tuple[i].sip != 0) {
					pt = &ue->tuple[i];
					break;
				}
			}
			for (i = 0; i < hash && pt == NULL; i++) {
				if (ue->tuple[i].sip != 0) {
					pt = &ue->tuple[i];
					break;
				}
			}
			if (pt == NULL) {
				NATCAP_WARN("(PD)" DEBUG_TCP_FMT ": no available port mapping\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}

			server.ip = pt->sip;
			server.port = pt->sport;
			ns->peer_sip = pt->dip;
			ns->peer_sport = pt->dport;

			//clear pt
			pt->sip = 0;

			NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": found user expect, mapping to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));

			ret = natcap_dnat_setup(ct, server.ip, server.port);
			if (ret != NF_ACCEPT) {
				NATCAP_ERROR("(PD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			}
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);

			if (!(IPS_NATCAP_PEER & ct->status) && !test_and_set_bit(IPS_NATCAP_PEER_BIT, &ct->status)) {
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				NATCAP_INFO("(PD)" DEBUG_TCP_FMT ": found user expect, do DNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			}
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
	enum ip_conntrack_info ctinfo;
	struct net *net = &init_net;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_session *ns;
	struct tuple server;

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
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}
	if (!(IPS_NATCAP_PEER & ct->status)) {
		return NF_ACCEPT;
	}

	if (!TCPH(l4)->syn || TCPH(l4)->ack) {
		//not syn
		return NF_ACCEPT;
	}

	ns = natcap_session_get(ct);
	if (ns == NULL) {
		NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": ns not found\n", DEBUG_TCP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	server.ip = ns->peer_sip;
	server.port = ns->peer_sport;

	NATCAP_INFO("(PS)" DEBUG_TCP_FMT ": found user expect, doing SNAT to " TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));

	ret = natcap_snat_setup(ct, ns->peer_sip, ns->peer_sport);
	if (ret != NF_ACCEPT) {
		NATCAP_ERROR("(PS)" DEBUG_TCP_FMT ": natcap_snat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
	}

	//encode
	do {
		struct natcap_TCPOPT *tcpopt;
		int offlen;
		int add_len = ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int));

		if (add_len + TCPH(l4)->doff * 4 > 60) {
			NATCAP_WARN("(PS)" DEBUG_TCP_FMT ": add_len=%u doff=%u over 60\n", DEBUG_TCP_ARG(iph,l4), add_len, TCPH(l4)->doff * 4);
			break;
		}

		if (skb_tailroom(skb) < add_len && pskb_expand_head(skb, 0, add_len, GFP_ATOMIC)) {
			NATCAP_ERROR("(PS)" DEBUG_TCP_FMT ": pskb_expand_head failed add_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_len);
			break;
		}
		iph = ip_hdr(skb);
		l4 = (struct tcphdr *)((void *)iph + iph->ihl * 4);

		offlen = skb_tail_pointer(skb) - (unsigned char *)l4 - sizeof(struct tcphdr);
		BUG_ON(offlen < 0);
		memmove((void *)l4 + sizeof(struct tcphdr) + add_len, (void *)l4 + sizeof(struct tcphdr), offlen);

		tcpopt = (void *)l4 + sizeof(struct tcphdr);

		tcpopt = (struct natcap_TCPOPT *)((void *)l4 + sizeof(struct tcphdr));
		tcpopt->header.type = NATCAP_TCPOPT_TYPE_PEER_SYN;
		tcpopt->header.opcode = TCPOPT_PEER;
		tcpopt->header.opsize = add_len;
		tcpopt->header.encryption = 0;

		TCPH(l4)->ack = 1;
		TCPH(l4)->doff = (TCPH(l4)->doff * 4 + add_len) / 4;
		iph->tot_len = htons(ntohs(iph->tot_len) + add_len);
		skb->len += add_len;
		skb->tail += add_len;

		skb_rcsum_tcpudp(skb);
	} while (0);

	return NF_ACCEPT;
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
		.hook = natcap_peer_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_peer_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 40,
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
};

int natcap_peer_init(void)
{
	int i;
	int ret = 0;

	need_conntrack();
	memset(peer_server, 0, sizeof(peer_server));

	for (i = 0; i < NR_CPUS; i++) {
		peer_user_uskbs[i] = NULL;
	}

	if (mode == PEER_MODE) {
		default_mac_addr_init();
	}

	ret = peer_port_map_init();
	if (ret != 0)
		goto peer_port_map_init_failed;

	ret = nf_register_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	return 0;

nf_register_hooks_failed:
	peer_port_map_exit();
peer_port_map_init_failed:
	return ret;
}

void natcap_peer_exit(void)
{
	int i;

	nf_unregister_hooks(peer_hooks, ARRAY_SIZE(peer_hooks));

	for (i = 0; i < NR_CPUS; i++) {
		if (peer_user_uskbs[i]) {
			kfree(peer_user_uskbs[i]);
			peer_user_uskbs[i] = NULL;
		}
	}

	peer_port_map_exit();
}
