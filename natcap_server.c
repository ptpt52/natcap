/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:23:40 +0800
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include "natcap.h"
#include "natcap_common.h"
#include "natcap_server.h"

static inline int natcap_auth(const struct net_device *in,
		const struct net_device *out,
		struct sk_buff *skb,
		struct nf_conn *ct,
		const struct natcap_TCPOPT *tcpopt,
		struct tuple *server)
{
	int ret;
	unsigned char old_mac[ETH_ALEN];
	struct ethhdr *eth;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (tcpopt->header.type == NATCAP_TCPOPT_ALL) {
		eth = eth_hdr(skb);
		memcpy(old_mac, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tcpopt->all.data.mac_addr, ETH_ALEN);
		ret = ip_set_test_src_mac(in, out, skb, "vclist");
		memcpy(eth->h_source, old_mac, ETH_ALEN);
		if (ret <= 0) {
			goto auth_fail;
		}
		if (!server) {
			return -EINVAL;
		}
		server->ip = tcpopt->all.data.ip;
		server->port = tcpopt->all.data.port;
		server->encryption = tcpopt->header.encryption;
	} else if (tcpopt->header.type == NATCAP_TCPOPT_USER) {
		eth = eth_hdr(skb);
		memcpy(old_mac, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tcpopt->user.data.mac_addr, ETH_ALEN);
		ret = ip_set_test_src_mac(in, out, skb, "vclist");
		memcpy(eth->h_source, old_mac, ETH_ALEN);
		if (ret <= 0) {
			goto auth_fail;
		}
		if (server) {
			return -EINVAL;
		}
	} else if (tcpopt->header.type == NATCAP_TCPOPT_DST) {
		if (!server) {
			return -EINVAL;
		}
		server->ip = tcpopt->dst.data.ip;
		server->port = tcpopt->dst.data.port;
		server->encryption = tcpopt->header.encryption;
	} else if (server) {
		return -EINVAL;
	}
	return 0;

auth_fail:
	set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
	NATCAP_WARN("(%s)" DEBUG_FMT ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth failed\n",
			__FUNCTION__, DEBUG_ARG(iph,tcph),
			tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
			tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
			ntohl(tcpopt->all.data.u_hash));
	return -1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_server_in_hook(void *priv,
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
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_TCPOPT tcpopt;
	struct tuple server;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_UDP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		if (test_bit(IPS_NATCAP_DROP_BIT, &ct->status)) {
			return NF_DROP;
		}
		if (skb_csum_test(skb) != 0) {
			NATCAP_ERROR("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": checksum failed\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));
			return NF_DROP;
		}
		NATCAP_DEBUG("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": before decode\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));
		tcpopt.header.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		ret = natcap_tcp_decode(skb, &tcpopt);
		if (natcap_auth(in, out, skb, ct, &tcpopt, NULL) != 0) {
			return NF_DROP;
		}
		//reload
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);
	} else {
		if (!tcph->syn || tcph->ack) {
			NATCAP_WARN("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": first packet in but not syn\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}

		tcpopt.header.encryption = 0;
		ret = natcap_tcp_decode(skb, &tcpopt);
		if (ret != 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		if (tcpopt.header.opcode != TCPOPT_NATCAP) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		//reload
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		if (natcap_auth(in, out, skb, ct, &tcpopt, &server) != 0) {
			return NF_DROP;
		}

		if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
			NATCAP_INFO("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": new natcaped connection in, after decode target=" TUPLE_FMT "\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));

			if (natcap_tcp_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
				NATCAP_ERROR("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": natcap_tcp_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_DROP;
			}
			if (server.encryption) {
				set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			}
		}
	}

	if (ret != 0) {
		NATCAP_ERROR("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": natcap_tcp_decode ret = %d\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph), ret);
		return NF_DROP;
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT ": after decode\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

//PREROUTING->*POSTROUTING*
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_server_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#else
static unsigned int natcap_server_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_TCPOPT tcpopt;
	unsigned long status = 0;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_UDP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_DROP_BIT, &ct->status)) {
		return NF_DROP;
	}

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_DEBUG("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT ": before encode\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));
	if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
		status |= NATCAP_NEED_ENC;
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}
	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt);
	if (ret >= 0) {
		ret = natcap_tcp_encode(skb, &tcpopt);
	}
	if (ret != 0) {
		NATCAP_ERROR("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT ": natcap_tcp_encode@server ret=%d\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph), ret);
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_DROP;
	}

	NATCAP_DEBUG("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT ":after encode\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_server_udp_proxy_in(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_udp_proxy_in(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_udp_proxy_in(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
	const struct net_device *in = state->in;
#else
static unsigned int natcap_server_udp_proxy_in(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#endif
	int ret;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct udphdr *udph;
	struct natcap_udp_tcpopt nuo;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	ret = natcap_udp_decode(skb, &nuo);
	if (ret != 0) {
		return NF_ACCEPT;
	}
	//reload
	iph = ip_hdr(skb);
	udph = (struct udphdr *)((void *)iph + iph->ihl*4);

	ret = nf_conntrack_in(dev_net(in), pf, hooknum, skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		return NF_DROP;
	}

	if (!test_and_set_bit(IPS_NATCAP_UDP_BIT, &ct->status)) { /* first time in */
		NATCAP_INFO("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT_UDP ": new natcaped connection in, after decode, target=%pI4:%u\n", DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(iph,udph), &nuo.ip, ntohs(nuo.port));
		if (natcap_tcp_dnat_setup(ct, nuo.ip, nuo.port) != NF_ACCEPT) {
			NATCAP_ERROR("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT_UDP ": natcap_tcp_dnat_setup failed, target=%pI4:%u\n", DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(iph,udph), &nuo.ip, ntohs(nuo.port));
			return NF_DROP;
		}
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(SI)" DEBUG_FMT_PREFIX DEBUG_FMT_UDP ": after decode\n", DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(iph,udph));

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_server_udp_proxy_out(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_server_udp_proxy_out(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_server_udp_proxy_out(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#else
static unsigned int natcap_server_udp_proxy_out(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#endif
	int ret;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned long status = 0;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (!test_bit(IPS_NATCAP_UDP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	udph = (struct udphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_DEBUG("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT_UDP ": before encode\n", DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(iph,udph));

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	ret = natcap_udp_encode(skb, status);
	if (ret != 0) {
		NATCAP_ERROR("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT_UDP ": natcap_udp_encode@server ret=%d\n", DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(iph,udph), ret);
		return NF_DROP;
	}

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_DEBUG("(SO)" DEBUG_FMT_PREFIX DEBUG_FMT ":after encode\n", DEBUG_ARG_PREFIX, DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

static struct nf_hook_ops server_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_udp_proxy_in,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_udp_proxy_out,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

int natcap_server_init(void)
{
	int ret = 0;

	need_conntrack();

	ret = nf_register_hooks(server_hooks, ARRAY_SIZE(server_hooks));
	return ret;
}

void natcap_server_exit(void)
{
	nf_unregister_hooks(server_hooks, ARRAY_SIZE(server_hooks));
}
