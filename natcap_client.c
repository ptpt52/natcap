/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:04 +0800
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
#include "natcap_common.h"
#include "natcap_client.h"
#include "natcap_knock.h"

unsigned int server_persist_timeout = 0;
module_param(server_persist_timeout, int, 0);
MODULE_PARM_DESC(server_persist_timeout, "Use diffrent server after timeout");

unsigned int shadowsocks = 0;
unsigned int sproxy = 0;
unsigned int enable_hosts = 0;

u32 default_u_hash = 0;
unsigned char default_mac_addr[ETH_ALEN];
static void default_mac_addr_init(void)
{
	struct net_device *dev;
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

#define MAX_NATCAP_SERVER 256
struct natcap_server_info {
	unsigned int active_index;
	unsigned int server_count[2];
	struct tuple server[2][MAX_NATCAP_SERVER];
};

static struct natcap_server_info natcap_server_info;

void natcap_server_info_cleanup(void)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;

	nsi->server_count[m] = 0;
	nsi->server_count[n] = 0;
	nsi->active_index = n;
}

int natcap_server_info_add(const struct tuple *dst)
{
	struct natcap_server_info *nsi = &natcap_server_info;
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

int natcap_server_info_delete(const struct tuple *dst)
{
	struct natcap_server_info *nsi = &natcap_server_info;
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

void *natcap_server_info_get(loff_t idx)
{
	if (idx < natcap_server_info.server_count[natcap_server_info.active_index])
		return &natcap_server_info.server[natcap_server_info.active_index][idx];
	return NULL;
}

void natcap_server_info_select(__be32 ip, __be16 port, struct tuple *dst)
{
	static unsigned int server_index = 0;
	static unsigned long server_jiffies = 0;
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int count = nsi->server_count[m];
	unsigned int hash;

	dst->ip = 0;
	dst->port = 0;
	dst->encryption = 0;

	if (count == 0)
		return;

	if (time_after(jiffies, server_jiffies + server_persist_timeout * HZ)) {
		server_jiffies = jiffies;
		server_index++;
	}

	//hash = server_index ^ ntohl(ip);
	hash = server_index;
	hash = hash % count;

	tuple_copy(dst, &nsi->server[m][hash]);
	if (dst->port == __constant_htons(0)) {
		dst->port = port;
	} else if (dst->port == __constant_htons(65535)) {
		dst->port = ((jiffies^ip) & 0xFFFF);
	}

	//XXX: encode for port 80 and 53 only
	if (port != __constant_htons(80) && port != __constant_htons(53)) {
		dst->encryption = 0;
	}
}

static inline int is_natcap_server(__be32 ip)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int i;

	for (i = 0; i < nsi->server_count[m]; i++) {
		if (nsi->server[m][i].ip == ip)
			return 1;
	}

	return 0;
}

static inline int natcap_reset_synack(struct sk_buff *oskb, const struct net_device *dev, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, header_len;
	int add_len = 0;
	u8 protocol = IPPROTO_TCP;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	if (test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
		add_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + add_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR("alloc_skb fail\n");
		return -1;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			return -1;
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
	niph->ttl = 0x80;
	niph->protocol = protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;


	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	if (protocol == IPPROTO_UDP) {
		UDPH(ntcph)->len = htons(ntohs(niph->tot_len) - niph->ihl * 4);
		*((unsigned int *)((void *)UDPH(ntcph) + 8)) = __constant_htonl(0xFFFF0099);
		ntcph = (struct tcphdr *)((char *)ntcph + 8);
	}
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + 1);
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
static unsigned natcap_client_dnat_hook(unsigned int hooknum,
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
	struct tuple *tup;
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
	if (test_bit(IPS_NATCAP_SERVER_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		goto natcaped_out;
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (IP_SET_test_dst_ip(state, in, out, skb, "knocklist") > 0) {
			natcap_knock_info_select(iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else if (IP_SET_test_dst_ip(state, in, out, skb, "bypasslist") > 0 || IP_SET_test_dst_ip(state, in, out, skb, "cniplist") > 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		} else if (IP_SET_test_dst_ip(state, in, out, skb, "gfwlist") > 0) {
			if (shadowsocks && hooknum == NF_INET_PRE_ROUTING &&
					(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(80) ||
					 ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(443))) {
				NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection match gfwlist, use shadowsocks\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (enable_hosts &&
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == __constant_htons(443) &&
					IP_SET_test_dst_ip(state, in, out, skb, "gfwhosts") > 0) {
				NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection match gfwlist, use natcapd hosts\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (natcap_redirect_port != 0 && hooknum == NF_INET_PRE_ROUTING) {
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
					natcap_dnat_setup(ct, newdst, natcap_redirect_port);
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);

					NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection match gfwlist, use natcapd proxy\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
			}
			natcap_server_info_select(iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (server.encryption) {
				set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			}
			if (encode_mode == UDP_ENCODE) {
				set_bit(IPS_NATCAP_UDPENC_BIT, &ct->status);
			}
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			if (!nf_ct_is_confirmed(ct)) {
				if (ipv4_is_lbcast(iph->saddr) || ipv4_is_lbcast(iph->daddr) ||
						ipv4_is_loopback(iph->saddr) || ipv4_is_loopback(iph->daddr) ||
						ipv4_is_multicast(iph->saddr) || ipv4_is_multicast(iph->daddr) ||
						ipv4_is_zeronet(iph->saddr) || ipv4_is_zeronet(iph->daddr)) {
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}
				if (ct->master) {
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}

				natcap_server_info_select(iph->daddr, TCPH(l4)->dest, &server);
				if (server.ip == 0) {
					NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,l4));
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}

				if (natcap_session_init(ct, GFP_ATOMIC) != 0) {
					NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_init failed\n", DEBUG_TCP_ARG(iph,l4));
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
				}
				tup = natcap_session_get(ct);
				if (!tup) {
					set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
					return NF_ACCEPT;
				}
				memcpy(tup, &server, sizeof(struct tuple));

				set_bit(IPS_NATCAP_SYN_BIT, &ct->status);
			}
			return NF_ACCEPT;
		}
	} else {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (IP_SET_test_dst_ip(state, in, out, skb, "udproxylist") > 0) {
			natcap_server_info_select(iph->daddr, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all, &server);
			if (server.ip == 0) {
				NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": no server found\n", DEBUG_UDP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			if (server.encryption) {
				set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			}
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, before encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
		} else {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time out */
		if (ipv4_is_lbcast(iph->saddr) || ipv4_is_lbcast(iph->daddr) ||
				ipv4_is_loopback(iph->saddr) || ipv4_is_loopback(iph->daddr) ||
				ipv4_is_multicast(iph->saddr) || ipv4_is_multicast(iph->daddr) ||
				ipv4_is_zeronet(iph->saddr) || ipv4_is_zeronet(iph->daddr)) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		if (iph->protocol == IPPROTO_TCP) {
			//not syn
			if (!TCPH(l4)->syn || TCPH(l4)->ack) {
				NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": first packet in but not syn, bypass\n", DEBUG_TCP_ARG(iph,l4));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_ACCEPT;
			}
			NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
		} else {
			NATCAP_INFO("(CD)" DEBUG_UDP_FMT ": new connection, after encode, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
		}
		if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			if (iph->protocol == IPPROTO_TCP) {
				NATCAP_ERROR("(CD)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
			} else {
				NATCAP_ERROR("(CD)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, server=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
			}
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
	}

	if (iph->protocol == IPPROTO_TCP) {
		NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));
	} else {
		NATCAP_DEBUG("(CD)" DEBUG_UDP_FMT ": after encode\n", DEBUG_UDP_ARG(iph,l4));
	}

natcaped_out:
	if (iph->protocol == IPPROTO_TCP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (TCPH(l4)->syn && !TCPH(l4)->ack) {
			if (!test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn1\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
				NATCAP_DEBUG("(CD)" DEBUG_TCP_FMT ": natcaped syn2\n", DEBUG_TCP_ARG(iph,l4));
				return NF_ACCEPT;
			}
			if (test_bit(IPS_NATCAP_SYN1_BIT, &ct->status) && test_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
				if (!is_natcap_server(iph->daddr)) {
					NATCAP_INFO("(CD)" DEBUG_TCP_FMT ": natcaped syn3 del target from gfwlist\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_del_dst_ip(state, in, out, skb, "gfwlist");
				}
			}
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_pre_ct_in_hook(unsigned int hooknum,
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
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_client_pre_ct_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_SERVER_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
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
					if (opt->header.opcode == TCPOPT_NATCAP) {
						struct tuple server;
						if (NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_DST) {
							server.ip = opt->dst.data.ip;
							server.port = opt->dst.data.port;
							server.encryption = opt->header.encryption;
							if (natcap_dnat_setup(ct, server.ip, server.port) == NF_ACCEPT) {
								NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup ok, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
							}
						} else if (NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_ALL) {
							server.ip = opt->all.data.ip;
							server.port = opt->all.data.port;
							server.encryption = opt->header.encryption;
							if (natcap_dnat_setup(ct, server.ip, server.port) == NF_ACCEPT) {
								NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup ok, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
							}
						}
					}
					skb->mark = XT_MARK_NATCAP;
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": set mark 0x%x\n", DEBUG_TCP_ARG(iph,l4), XT_MARK_NATCAP);
					return NF_ACCEPT;
				}
			}
		}
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
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

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,l4));

		tcpopt.header.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		ret = natcap_tcp_decode(skb, &tcpopt);
		if (ret != 0) {
			NATCAP_ERROR("(CPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
			return NF_DROP;
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (*((unsigned int *)((void *)UDPH(l4) + sizeof(struct udphdr))) == __constant_htonl(0xFFFE009A) &&
				UDPH(l4)->len == __constant_htons(sizeof(struct udphdr) + 4)) {
			if (!test_and_set_bit(IPS_NATCAP_ACK_BIT, &ct->status)) {
				NATCAP_INFO("(CPCI)" DEBUG_UDP_FMT ": got ACK pkt\n", DEBUG_UDP_ARG(iph,l4));
			}
			return NF_DROP;
		}

		if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(CPCI)" DEBUG_UDP_FMT ": natcap_udp_decode() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_decode);
			skb_rcsum_tcpudp(skb);
		}

		NATCAP_DEBUG("(CPCI)" DEBUG_UDP_FMT ": after decode\n", DEBUG_UDP_ARG(iph,l4));
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_pre_in_hook(unsigned int hooknum,
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
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (skb_is_gso(skb)) {
		NATCAP_ERROR("(CPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (*((unsigned int *)((void *)UDPH(l4) + 8)) == __constant_htonl(0xFFFF0099)) {
		int offlen;

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(CPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb->csum = 0;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}

		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr) + 8)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (!skb_make_writable(skb, iph->ihl * 4 + TCPH(l4 + 8)->doff * 4)) {
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

		if (!test_and_set_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) { /* first time in */
			return NF_ACCEPT;
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_post_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_post_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	unsigned long status = NATCAP_CLIENT_MODE;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct natcap_TCPOPT tcpopt;

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
	if (test_bit(IPS_NATCAP_SERVER_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL && iph->protocol == IPPROTO_TCP) {
			if (TCPH(l4)->syn && !TCPH(l4)->ack) {
				if (!test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
					NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": bypass syn1\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
					NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": bypass syn2\n", DEBUG_TCP_ARG(iph,l4));
					return NF_ACCEPT;
				}
				if (test_bit(IPS_NATCAP_SYN1_BIT, &ct->status) && test_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
					NATCAP_INFO("(CPO)" DEBUG_TCP_FMT ": bypass syn3 del target from bypasslist\n", DEBUG_TCP_ARG(iph,l4));
					IP_SET_del_dst_ip(state, in, out, skb, "bypasslist");
				}
			}
		}
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		/* for REPLY post out */
		if (iph->protocol == IPPROTO_TCP) {
			if (test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status) && TCPH(l4)->syn) {
				natcap_tcpmss_adjust(skb, TCPH(l4), -8);
			}
		}
		return NF_ACCEPT;
	}

	flow_total_tx_bytes += skb->len;

	if (iph->protocol == IPPROTO_TCP) {
		struct sk_buff *skb2 = NULL;

		if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
			status |= NATCAP_NEED_ENC;
		}

		ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt);
		if (ret != 0) {
			if (skb_is_gso(skb) || (!TCPH(l4)->syn || TCPH(l4)->ack)) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				return NF_DROP;
			}

			skb2 = skb_copy(skb, GFP_ATOMIC);
			if (skb2 == NULL) {
				NATCAP_ERROR("alloc_skb fail\n");
				return NF_DROP;
			}
			iph = ip_hdr(skb2);
			l4 = (void *)iph + iph->ihl * 4;
			skb2->len = sizeof(struct iphdr) + sizeof(struct tcphdr);
			iph->tot_len = htons(skb2->len);
			iph->ihl = 5;
			TCPH(l4)->doff = 5;
			skb_rcsum_tcpudp(skb2);

			ret = natcap_tcpopt_setup(status, skb2, ct, &tcpopt);
			if (ret != 0) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				consume_skb(skb2);
				return NF_DROP;
			}
			tcpopt.header.type |= NATCAP_TCPOPT_SYN_BIT;
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET_BIT;
			}
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY_BIT;
			}
			ret = natcap_tcp_encode(skb2, &tcpopt);
			if (ret != 0) {
				NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
				consume_skb(skb2);
				return NF_DROP;
			}
			tcpopt.header.type = NATCAP_TCPOPT_NONE;
			tcpopt.header.opsize = 0;
		}
		if (ret == 0) {
			if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
				tcpopt.header.type |= NATCAP_TCPOPT_TARGET_BIT;
			}
			if (sproxy) {
				tcpopt.header.type |= NATCAP_TCPOPT_SPROXY_BIT;
			}
			ret = natcap_tcp_encode(skb, &tcpopt);
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

		NATCAP_DEBUG("(CPO)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));

		if (!test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
			if (skb2) {
				NF_OKFN(skb2);
			}
			return NF_ACCEPT;
		}

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
			struct sk_buff *nskb = skb->next;

			if (skb_tailroom(skb) < 8 && pskb_expand_head(skb, 0, 8, GFP_ATOMIC)) {
				consume_skb(skb);
				skb = nskb;
				NATCAP_ERROR("pskb_expand_head failed\n");
				continue;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4;
			BUG_ON(offlen < 0);
			memmove((void *)UDPH(l4) + 4 + 8, (void *)UDPH(l4) + 4, offlen);
			iph->tot_len = htons(ntohs(iph->tot_len) + 8);
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			skb->len += 8;
			skb->tail += 8;
			*((unsigned int *)((void *)UDPH(l4) + 8)) = __constant_htonl(0xFFFF0099);
			iph->protocol = IPPROTO_UDP;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);
			skb->next = NULL;

			NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

			NF_OKFN(skb);

			skb = nskb;
		} while (skb);

		return NF_STOLEN;
	} else if (iph->protocol == IPPROTO_UDP) {
		if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
			if (!skb_make_writable(skb, skb->len)) {
				NATCAP_ERROR("(CPO)" DEBUG_UDP_FMT ": natcap_udp_encode() failed\n", DEBUG_UDP_ARG(iph,l4));
				return NF_DROP;
			}
			skb_data_hook(skb, iph->ihl * 4 + sizeof(struct udphdr), skb->len - (iph->ihl * 4 + sizeof(struct udphdr)), natcap_data_encode);
			skb_rcsum_tcpudp(skb);
		}

		if (!test_bit(IPS_NATCAP_ACK_BIT, &ct->status)) {
			if (skb->len > 1280) {
				struct sk_buff *nskb;
				int offset, header_len;

				offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 12 - skb->len;
				header_len = offset < 0 ? 0 : offset;
				nskb = skb_copy_expand(skb, skb_headroom(skb), header_len, GFP_ATOMIC);
				if (!nskb) {
					NATCAP_ERROR("alloc_skb fail\n");
					return NF_ACCEPT;
				}
				if (offset <= 0) {
					if (pskb_trim(nskb, nskb->len + offset)) {
						NATCAP_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
						consume_skb(nskb);
						return NF_DROP;
					}
				} else {
					nskb->len += offset;
					nskb->tail += offset;
				}

				iph = ip_hdr(nskb);
				l4 = (void *)iph + iph->ihl * 4;
				iph->tot_len = htons(nskb->len);
				UDPH(l4)->len = ntohs(ntohs(iph->tot_len) - iph->ihl * 4);
				*((unsigned int *)(l4 + sizeof(struct udphdr))) = __constant_htonl(0xFFFE0099);
				*((unsigned int *)(l4 + sizeof(struct udphdr) + 4)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 8)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x01);

				if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
					*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x0100 | 0x01);
				}

				skb_rcsum_tcpudp(nskb);

				NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

				NF_OKFN(nskb);
			} else {
				int offlen;

				if (skb_tailroom(skb) < 12 && pskb_expand_head(skb, 0, 12, GFP_ATOMIC)) {
					NATCAP_ERROR("pskb_expand_head failed\n");
					return NF_ACCEPT;
				}
				iph = ip_hdr(skb);
				l4 = (void *)iph + iph->ihl * 4;

				offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr);
				BUG_ON(offlen < 0);
				memmove((void *)UDPH(l4) + sizeof(struct udphdr) + 12, (void *)UDPH(l4) + sizeof(struct udphdr), offlen);
				iph->tot_len = htons(ntohs(iph->tot_len) + 12);
				UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
				skb->len += 12;
				skb->tail += 12;
				*((unsigned int *)(l4 + sizeof(struct udphdr))) = __constant_htonl(0xFFFE0099);
				*((unsigned int *)(l4 + sizeof(struct udphdr) + 4)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 8)) = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x02);

				if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
					*((unsigned short *)(l4 + sizeof(struct udphdr) + 10)) = __constant_htons(0x0100 | 0x02);
				}

				skb_rcsum_tcpudp(skb);

				NATCAP_DEBUG("(CPO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));
			}
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_post_master_out_hook(unsigned int hooknum,
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
	struct sk_buff *skb2 = NULL, *skb_orig = skb;
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;
	struct tuple *tup = NULL;
	struct natcap_TCPOPT tcpopt;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_SERVER_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_SYN_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_ACK_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	tup = natcap_session_get(ct);
	if (!tup) {
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}

	skb = skb_copy(skb, GFP_ATOMIC);
	if (skb == NULL) {
		NATCAP_ERROR("alloc_skb fail\n");
		return NF_ACCEPT;
	}
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	NATCAP_DEBUG("(CPMO)" DEBUG_TCP_FMT ": before natcap post out\n", DEBUG_TCP_ARG(iph,l4));

	csum_replace4(&iph->check, iph->daddr, tup->ip);
	inet_proto_csum_replace4(&TCPH(l4)->check, skb, iph->daddr, tup->ip, true);
	inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->dest, tup->port, false);
	iph->daddr = tup->ip;
	TCPH(l4)->dest = tup->port;

	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
	ret = nf_conntrack_in(net, pf, NF_INET_PRE_ROUTING, skb);
	if (ret != NF_ACCEPT) {
		if (ret != NF_STOLEN) {
			consume_skb(skb);
		}
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

	master = nf_ct_get(skb, &ctinfo);
	if (!master || master == ct) {
		consume_skb(skb);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		return NF_ACCEPT;
	}
	if (!test_and_set_bit(IPS_NATCAP_SYN_BIT, &master->status)) {
		if (master->master) {
			consume_skb(skb);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			return NF_ACCEPT;
		}
		if (tup->encryption) {
			set_bit(IPS_NATCAP_ENC_BIT, &master->status);
		}
		if (encode_mode == UDP_ENCODE) {
			set_bit(IPS_NATCAP_UDPENC_BIT, &master->status);
		}
		nf_conntrack_get(&ct->ct_general);
		master->master = ct;
		set_bit(IPS_NATCAP_BIT, &master->status);
	}

	if (master->master != ct) {
		consume_skb(skb);
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": bad ct=%p and master=%p\n", DEBUG_TCP_ARG(iph,l4), ct, master);
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_ENC_BIT, &master->status)) {
		status |= NATCAP_NEED_ENC;
	}
	ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt);
	if (ret != 0) {
		if (skb_is_gso(skb) || (!TCPH(l4)->syn || TCPH(l4)->ack)) {
			NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			consume_skb(skb);
			return NF_ACCEPT;
		}

		skb2 = skb_copy(skb, GFP_ATOMIC);
		if (skb2 == NULL) {
			NATCAP_ERROR("alloc_skb fail\n");
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			consume_skb(skb);
			return NF_ACCEPT;
		}
		iph = ip_hdr(skb2);
		l4 = (void *)iph + iph->ihl * 4;
		skb2->len = sizeof(struct iphdr) + sizeof(struct tcphdr);
		iph->tot_len = htons(skb2->len);
		iph->ihl = 5;
		TCPH(l4)->doff = 5;
		skb_rcsum_tcpudp(skb2);

		ret = natcap_tcpopt_setup(status, skb2, ct, &tcpopt);
		if (ret != 0) {
			NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			consume_skb(skb2);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			consume_skb(skb);
			return NF_ACCEPT;
		}
		tcpopt.header.type |= NATCAP_TCPOPT_SYN_BIT;
		if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
			tcpopt.header.type |= NATCAP_TCPOPT_TARGET_BIT;
		}
		if (sproxy) {
			tcpopt.header.type |= NATCAP_TCPOPT_SPROXY_BIT;
		}
		ret = natcap_tcp_encode(skb2, &tcpopt);
		if (ret != 0) {
			NATCAP_ERROR("(CPO)" DEBUG_TCP_FMT ": natcap_tcpopt_setup() failed ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			consume_skb(skb2);
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
			consume_skb(skb);
			return NF_ACCEPT;
		}
		tcpopt.header.type = NATCAP_TCPOPT_NONE;
		tcpopt.header.opsize = 0;
	}
	if (ret == 0) {
		if (iph->daddr == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) {
			tcpopt.header.type |= NATCAP_TCPOPT_TARGET_BIT;
		}
		if (sproxy) {
			tcpopt.header.type |= NATCAP_TCPOPT_SPROXY_BIT;
		}
		ret = natcap_tcp_encode(skb, &tcpopt);
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
	}
	if (ret != 0) {
		NATCAP_ERROR("(CPMO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d, skb2=%p\n", DEBUG_TCP_ARG(iph,l4), ret, skb2);
		if (skb2) {
			consume_skb(skb2);
		}
		set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		consume_skb(skb);
		return NF_ACCEPT;
	}

	NATCAP_DEBUG("(CPMO)" DEBUG_TCP_FMT ": after encode\n", DEBUG_TCP_ARG(iph,l4));

	if (!test_bit(IPS_NATCAP_UDPENC_BIT, &master->status)) {
		flow_total_tx_bytes += skb->len;
		if (skb2) {
			NF_OKFN(skb2);
		}
		NF_OKFN(skb);
		goto out;
	}

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
			NATCAP_ERROR("pskb_expand_head failed\n");
			continue;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		offlen = skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - 4;
		BUG_ON(offlen < 0);
		memmove((void *)UDPH(l4) + 4 + 8, (void *)UDPH(l4) + 4, offlen);
		iph->tot_len = htons(ntohs(iph->tot_len) + 8);
		UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
		skb->len += 8;
		skb->tail += 8;
		*((unsigned int *)((void *)UDPH(l4) + 8)) = __constant_htonl(0xFFFF0099);
		iph->protocol = IPPROTO_UDP;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(skb);
		skb->next = NULL;
		flow_total_tx_bytes += skb->len;

		NATCAP_DEBUG("(CPMO)" DEBUG_UDP_FMT ": after natcap post out\n", DEBUG_UDP_ARG(iph,l4));

		NF_OKFN(skb);

		skb = nskb;
	} while (skb);

out:
	if (test_bit(IPS_NATCAP_ACK_BIT, &master->status)) {
		/* XXX I eat it, make the caller happy  */
		ret = nf_conntrack_confirm(skb_orig);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		consume_skb(skb_orig);
		return NF_STOLEN;
	}

	return NF_ACCEPT;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_pre_master_in_hook(unsigned int hooknum,
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
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_SERVER_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_SYN_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
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

	NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": got reply\n", DEBUG_TCP_ARG(iph,l4));

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		master = ct->master;
		if (!master || !test_bit(IPS_NATCAP_SYN_BIT, &master->status)) {
			return NF_DROP;
		}
		if (iph->daddr != master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip ||
				TCPH(l4)->dest != master->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all) {
			return NF_DROP;
		}

		if (!test_and_set_bit(IPS_NATCAP_CFM_BIT, &master->status)) {
			NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": got cfm\n", DEBUG_TCP_ARG(iph,l4));
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		}
		if (!test_bit(IPS_NATCAP_ACK_BIT, &ct->status)) {
			NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": drop without lock cfm\n", DEBUG_TCP_ARG(iph,l4));
			if (TCPH(l4)->syn && TCPH(l4)->ack) {
				natcap_reset_synack(skb, in, ct);
			}
			return NF_DROP;
		}

		/* XXX I just confirm it first  */
		ret = nf_conntrack_confirm(skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}

		nf_conntrack_put(skb->nfct);
		skb->nfct = NULL;

		csum_replace4(&iph->check, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
		inet_proto_csum_replace4(&TCPH(l4)->check, skb, iph->saddr, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, true);
		inet_proto_csum_replace2(&TCPH(l4)->check, skb, TCPH(l4)->source, master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all, false);
		iph->saddr = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
		TCPH(l4)->source = master->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;

		if (in)
			net = dev_net(in);
		else if (out)
			net = dev_net(out);
		ret = nf_conntrack_in(net, pf, NF_INET_PRE_ROUTING, skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
		if ((struct nf_conn *)skb->nfct != master) {
			NATCAP_ERROR("(CPMI)" DEBUG_TCP_FMT ": skb->nfct != master, ignore and drop\n", DEBUG_TCP_ARG(iph,l4));
			return NF_DROP;
		}

		NATCAP_DEBUG("(CPMI)" DEBUG_TCP_FMT ": after natcap reply\n", DEBUG_TCP_ARG(iph,l4));

		if (!test_and_set_bit(IPS_NATCAP_MASTER_BIT, &ct->status) && !TCPH(l4)->rst) {
			if (!is_natcap_server(iph->saddr) && IP_SET_test_src_ip(state, in, out, skb, "cniplist") <= 0) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": multi-conn natcap got response add target to gfwlist\n", DEBUG_TCP_ARG(iph,l4));
				IP_SET_add_src_ip(state, in, out, skb, "gfwlist");
			}
		}
		return NF_ACCEPT;
	} else {
		if (TCPH(l4)->rst) {
			if (TCPH(l4)->source == __constant_htons(80) && IP_SET_test_src_ip(state, in, out, skb, "cniplist") <= 0) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": bypass get reset add target to gfwlist\n", DEBUG_TCP_ARG(iph,l4));
				IP_SET_add_src_ip(state, in, out, skb, "gfwlist");
			}
		}
		if (!test_and_set_bit(IPS_NATCAP_CFM_BIT, &ct->status)) {
			NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": got cfm\n", DEBUG_TCP_ARG(iph,l4));
			set_bit(IPS_NATCAP_ACK_BIT, &ct->status);
		}
		if (!test_bit(IPS_NATCAP_ACK_BIT, &ct->status)) {
			NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": drop without lock cfm\n", DEBUG_TCP_ARG(iph,l4));
			if (TCPH(l4)->syn && TCPH(l4)->ack) {
				natcap_reset_synack(skb, in, ct);
			}
			return NF_DROP;
		}
		if (!test_and_set_bit(IPS_NATCAP_MASTER_BIT, &ct->status) && !TCPH(l4)->rst) {
			if (IP_SET_test_src_ip(state, in, out, skb, "cniplist") > 0) {
				NATCAP_INFO("(CPMI)" DEBUG_TCP_FMT ": multi-conn bypass got response add target to bypasslist\n", DEBUG_TCP_ARG(iph,l4));
				IP_SET_add_src_ip(state, in, out, skb, "bypasslist");
			}
		}
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops client_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_pre_master_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 6,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 35,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_dnat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_NAT_DST - 35,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_post_master_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

int natcap_client_init(void)
{
	int ret = 0;

	need_conntrack();

	natcap_server_info_cleanup();
	default_mac_addr_init();
	ret = nf_register_hooks(client_hooks, ARRAY_SIZE(client_hooks));
	return ret;
}

void natcap_client_exit(void)
{
	nf_unregister_hooks(client_hooks, ARRAY_SIZE(client_hooks));
}
