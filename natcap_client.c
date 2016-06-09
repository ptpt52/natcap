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
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include "natcap_common.h"
#include "natcap_client.h"

unsigned int client_forward_mode = 0;
module_param(client_forward_mode, int, 0);
MODULE_PARM_DESC(client_forward_mode, "Client forward mode (1=enable, 0=disable) default=0");

unsigned int server_persist_timeout = 0;
module_param(server_persist_timeout, int, 0);
MODULE_PARM_DESC(server_persist_timeout, "Use diffrent server after timeout");

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
}

#define MAX_NATCAP_SERVER 256
struct natcap_server_info {
	unsigned int active_index;
	unsigned int server_count[2];
	struct tuple server[2][MAX_NATCAP_SERVER];
};

static struct natcap_server_info natcap_server_info;

static inline void natcap_server_init(void)
{
	memset(&natcap_server_info, 0, sizeof(natcap_server_info));
}

void natcap_server_cleanup(void)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;

	nsi->server_count[m] = 0;
	nsi->server_count[n] = 0;
	nsi->active_index = n;
}

int natcap_server_add(const struct tuple *dst)
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

int natcap_server_delete(const struct tuple *dst)
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

void *natcap_server_get(loff_t idx)
{
	if (idx < natcap_server_info.server_count[natcap_server_info.active_index])
		return &natcap_server_info.server[natcap_server_info.active_index][idx];
	return NULL;
}

static inline void natcap_server_select(__be32 ip, __be16 port, struct tuple *dst)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_tcp_tcpopt nto;
	struct tuple server;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_UDP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
			if (tcph->rst) {
				NATCAP_INFO(DEBUG_FMT ": tcp rst by server\n", DEBUG_ARG(iph,tcph));
			}
			return NF_ACCEPT;
		}
		if (tcph->syn && !tcph->ack && test_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
			if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
				NATCAP_DEBUG(DEBUG_FMT ": bypass syn2\n", DEBUG_ARG(iph,tcph));
				return NF_ACCEPT;
			}
			if (!test_and_set_bit(IPS_NATCAP_SYN3_BIT, &ct->status)) {
				if (!is_natcap_server(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip) &&
						ip_set_test_dst_ip(in, out, skb, "cniplist") <= 0) {
					NATCAP_INFO(DEBUG_FMT ": bypass syn3 add target to gfwlist\n", DEBUG_ARG(iph,tcph));
					ip_set_add_dst_ip(in, out, skb, "gfwlist");
				}
				return NF_ACCEPT;
			}
		}
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		//matched
		NATCAP_DEBUG("(CLIENT_OUT)" DEBUG_FMT ": before encode\n", DEBUG_ARG(iph,tcph));

		nto.port = tcph->dest;
		nto.ip = iph->daddr;
		nto.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
	} else if (ip_set_test_dst_ip(in, out, skb, "gfwlist") > 0) {
		natcap_server_select(iph->daddr, tcph->dest, &server);
		if (server.ip == 0) {
			NATCAP_DEBUG("(CLIENT_OUT)" DEBUG_FMT ": no server found\n", DEBUG_ARG(iph,tcph));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}

		nto.port = tcph->dest;
		nto.ip = iph->daddr;
		nto.encryption = server.encryption;
		if (tcph->dest == __constant_htons(443) ||
				tcph->dest == __constant_htons(22)) {
			nto.encryption = 0;
		}

		NATCAP_INFO("(CLIENT_OUT)" DEBUG_FMT ": new natcaped connection out, before encode, server=" TUPLE_FMT "\n",
				DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));
	} else {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		if (tcph->syn && !tcph->ack) {
			set_bit(IPS_NATCAP_SYN1_BIT, &ct->status);
			NATCAP_DEBUG(DEBUG_FMT ": bypass syn1\n", DEBUG_ARG(iph,tcph));
		}
		return NF_ACCEPT;
	}

	if (tcph->syn && !tcph->ack) {
		if (!test_and_set_bit(IPS_NATCAP_SYN1_BIT, &ct->status)) {
			NATCAP_DEBUG(DEBUG_FMT ": natcaped syn1\n", DEBUG_ARG(iph,tcph));
			goto start_natcap;
		}
		if (!test_and_set_bit(IPS_NATCAP_SYN2_BIT, &ct->status)) {
			NATCAP_DEBUG(DEBUG_FMT ": natcaped syn2\n", DEBUG_ARG(iph,tcph));
			goto start_natcap;
		}
		if (!test_and_set_bit(IPS_NATCAP_SYN3_BIT, &ct->status)) {
			NATCAP_INFO(DEBUG_FMT ": natcaped syn3 del target from gfwlist\n", DEBUG_ARG(iph,tcph));
			ip_set_del_dst_ip(in, out, skb, "gfwlist");
			goto start_natcap;
		}
	}

start_natcap:
	ret = natcap_tcp_encode(skb, &nto);

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (ret != 0) {
		NATCAP_ERROR("(CLIENT_OUT)" DEBUG_FMT ": natcap_tcp_encode@client ret=%d\n",
			DEBUG_ARG(iph,tcph), ret);
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_DROP;
	}

	if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time out */
		NATCAP_INFO("(CLIENT_OUT)" DEBUG_FMT ": new natcaped connection out, after encode\n",
				DEBUG_ARG(iph,tcph));
		//setup DNAT
		if (natcap_tcp_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			NATCAP_ERROR("(CLIENT_OUT)" DEBUG_FMT ": natcap_tcp_dnat_setup failed, server=" TUPLE_FMT "\n",
					DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
		if (nto.encryption) {
			set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		}
	}

	NATCAP_DEBUG("(CLIENT_OUT)" DEBUG_FMT ": after encode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#else
static unsigned int natcap_client_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_tcp_tcpopt nto;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

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

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		//matched
		NATCAP_DEBUG("(CLIENT_IN)" DEBUG_FMT ": before decode\n", DEBUG_ARG(iph,tcph));
		nto.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
	} else {
		return NF_ACCEPT;
	}

	ret = natcap_tcp_decode(skb, &nto);

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (ret != 0) {
		NATCAP_ERROR("(CLIENT_IN)" DEBUG_FMT ": natcap_tcp_decode ret = %d\n",
			DEBUG_ARG(iph,tcph), ret);
		return NF_DROP;
	}

	NATCAP_DEBUG("(CLIENT_IN)" DEBUG_FMT ": after decode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_udp_proxy_out(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_udp_proxy_out(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_udp_proxy_out(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_client_udp_proxy_out(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
	int ret;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct tuple server;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	udph = (struct udphdr *)((void *)iph + iph->ihl * 4);

	if (ip_set_test_dst_ip(in, out, skb, "udproxylist") <= 0) {
		return NF_ACCEPT;
	}

	natcap_server_select(iph->daddr, udph->dest, &server);
	if (server.ip == 0) {
		return NF_ACCEPT;
	}
	server.port = __constant_htons(12315);

	ret = natcap_udp_encode(skb, 0);
	if (ret != 0) {
		NATCAP_ERROR("(CLIENT_OUT)" DEBUG_FMT_UDP ": natcap_udp_encode@client ret=%d\n", DEBUG_ARG_UDP(iph,udph), ret);
		return NF_ACCEPT;
	}

	ret = nf_conntrack_in(dev_net(in), pf, hooknum, skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		return NF_DROP;
	}

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

	if (!test_and_set_bit(IPS_NATCAP_UDP_BIT, &ct->status)) { /* first time out */
		NATCAP_INFO("(CLIENT_OUT)" DEBUG_FMT ": new natcaped connection out, server=" TUPLE_FMT "\n",
				DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));
		if (natcap_tcp_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
			NATCAP_ERROR("(CLIENT_OUT)" DEBUG_FMT ": natcap_tcp_dnat_setup failed, server=" TUPLE_FMT "\n",
					DEBUG_ARG(iph,tcph), TUPLE_ARG(&server));
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_client_udp_proxy_in(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_client_udp_proxy_in(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_client_udp_proxy_in(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#else
static unsigned int natcap_client_udp_proxy_in(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	int ret;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct natcap_udp_tcpopt nuo;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

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

	NATCAP_INFO("(CLIENT_IN)" DEBUG_FMT ": before decode\n", DEBUG_ARG(iph,tcph));

	ret = natcap_udp_decode(skb, &nuo);
	if (ret != 0) {
		NATCAP_ERROR("(CLIENT_IN)" DEBUG_FMT ": natcap_udp_decode ret = %d\n", DEBUG_ARG(iph,tcph), ret);
		return NF_DROP;
	}

	iph = ip_hdr(skb);
	udph = (struct udphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_INFO("(CLIENT_IN)" DEBUG_FMT_UDP ": after decode\n", DEBUG_ARG_UDP(iph,udph));

	return NF_ACCEPT;
}

static struct nf_hook_ops client_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_udp_proxy_out,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_udp_proxy_out,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_udp_proxy_in,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_client_udp_proxy_in,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST,
	},
};

int natcap_client_init(void)
{
	int ret = 0;

	need_conntrack();

	natcap_server_init();
	default_mac_addr_init();
	ret = nf_register_hooks(client_hooks, ARRAY_SIZE(client_hooks));
	return ret;
}

void natcap_client_exit(void)
{
	nf_unregister_hooks(client_hooks, ARRAY_SIZE(client_hooks));
	natcap_server_cleanup();
}
