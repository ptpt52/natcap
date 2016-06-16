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
#include "natcap_forward.h"
#include "natcap_client.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_forward_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_forward_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_forward_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
#else
static unsigned int natcap_forward_in_hook(void *priv,
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
	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	} 
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return NF_DROP;
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	if (tcph->doff * 4 < sizeof(struct tcphdr))
		return NF_DROP;
	if (!skb_make_writable(skb, iph->ihl * 4 + tcph->doff * 4))
		return NF_DROP;
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (!tcph->syn || tcph->ack) {
		NATCAP_WARN("(FI)" DEBUG_TCP_FMT ": first packet in but not syn\n", DEBUG_TCP_ARG(iph,tcph));
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	tcpopt.header.encryption = 0;
	ret = natcap_tcp_decode(skb, &tcpopt);
	if (ret != 0 || tcpopt.header.opcode != TCPOPT_NATCAP) {
		struct natcap_udp_tcpopt nuo;
		ret = natcap_udp_decode(skb, &nuo);
		if (ret != 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
	}

	if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
		struct tuple server;
		NATCAP_INFO("(FI)" DEBUG_TCP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,tcph), TUPLE_ARG(&server));
		natcap_server_info_select(iph->daddr, tcph->dest, &server);
		if (server.ip == 0) {
			NATCAP_DEBUG("(FI)" DEBUG_TCP_FMT ": no server found\n", DEBUG_TCP_ARG(iph,tcph));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		if (natcap_tcp_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			NATCAP_ERROR("(FI)" DEBUG_TCP_FMT ": natcap_tcp_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,tcph), TUPLE_ARG(&server));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(FI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,tcph));

	return NF_ACCEPT;
}

static struct nf_hook_ops forward_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_forward_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
};

int natcap_forward_init(void)
{
	int ret = 0;

	need_conntrack();

	natcap_server_info_cleanup();
	ret = nf_register_hooks(forward_hooks, ARRAY_SIZE(forward_hooks));
	return ret;
}

void natcap_forward_exit(void)
{
	nf_unregister_hooks(forward_hooks, ARRAY_SIZE(forward_hooks));
}
