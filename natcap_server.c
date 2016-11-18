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
#include <net/ip.h>
#include <net/tcp.h>
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
		if (server) {
			server->ip = tcpopt->all.data.ip;
			server->port = tcpopt->all.data.port;
			server->encryption = tcpopt->header.encryption;
		}
		eth = eth_hdr(skb);
		memcpy(old_mac, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tcpopt->all.data.mac_addr, ETH_ALEN);
		ret = ip_set_test_src_mac(in, out, skb, "vclist");
		memcpy(eth->h_source, old_mac, ETH_ALEN);
		if (ret <= 0) {
			NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth failed\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
					tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
					ntohl(tcpopt->all.data.u_hash));
			return E_NATCAP_FAIL;
		}
		NATCAP_INFO("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
				__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
				tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
				tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
				ntohl(tcpopt->all.data.u_hash));
	} else if (tcpopt->header.type == NATCAP_TCPOPT_USER) {
		if (server) {
			return E_NATCAP_INVAL;
		}
		eth = eth_hdr(skb);
		memcpy(old_mac, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tcpopt->user.data.mac_addr, ETH_ALEN);
		ret = ip_set_test_src_mac(in, out, skb, "vclist");
		memcpy(eth->h_source, old_mac, ETH_ALEN);
		if (ret <= 0) {
			NATCAP_WARN("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth failed\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
					tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
					ntohl(tcpopt->user.data.u_hash));
			return E_NATCAP_FAIL;
		}
		NATCAP_INFO("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
				__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
				tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
				tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
				ntohl(tcpopt->user.data.u_hash));
	} else if (tcpopt->header.type == NATCAP_TCPOPT_DST) {
		if (!server) {
			return E_NATCAP_INVAL;
		}
		server->ip = tcpopt->dst.data.ip;
		server->port = tcpopt->dst.data.port;
		server->encryption = tcpopt->header.encryption;
	} else if (server) {
		return E_NATCAP_INVAL;
	}
	return E_NATCAP_OK;
}

static inline void natcap_auth_reply_payload(const char *payload, int payload_len, struct sk_buff *oskb, const struct net_device *dev)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum;
	int offset, header_len;
	char *data;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl*4);

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		printk("alloc_skb fail\n");
		return;
	}

	data = (char *)ip_hdr(nskb) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(data, payload, payload_len);

	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->psh = 1;
	ntcph->fin = 1;
	ntcph->window = 65535;

	niph = ip_hdr(nskb);
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;
	ip_send_check(niph);

	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);

	neth = eth_hdr(nskb);
	memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
	memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	neth->h_proto = htons(ETH_P_IP);
	nskb->len += offset;
	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_segs = 0;
	skb_shinfo(nskb)->gso_type = 0;

	dev_queue_xmit(nskb);
}

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

	snprintf(http->location, sizeof(http->location), "http://router-sh.ptpt52.com/index.html?_t=%lu", jiffies);
	http->location[sizeof(http->location) - 1] = 0;
	snprintf(http->data, sizeof(http->data), http_data_fmt, http->location);
	http->data[sizeof(http->data) - 1] = 0;
	snprintf(http->header, sizeof(http->header), http_header_fmt, http->location, n);
	http->header[sizeof(http->header) - 1] = 0;
	n = sprintf(http->payload, "%s%s", http->header, http->data);

	if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
		natcap_data_encode(http->payload, n);
	}

	natcap_auth_reply_payload(http->payload, n, skb, dev);
	kfree(http);
}

static inline void natcap_auth_convert_tcprst(struct sk_buff *skb)
{
	int offset = 0;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return;
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	offset = ntohs(iph->tot_len) - ((iph->ihl << 2) + sizeof(struct tcphdr));
	tcph->ack = 0;
	tcph->psh = 0;
	tcph->rst = 1;
	tcph->fin = 0;
	tcph->window = htons(0);
	tcph->doff = sizeof(struct tcphdr) / 4;

	iph->tot_len = htons(ntohs(iph->tot_len) - offset);
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;

	skb->tail -= offset;
	skb->len -= offset;

	skb_rcsum_tcpudp(skb);
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

	if (disabled)
		return NF_ACCEPT;

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

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		if (test_bit(IPS_NATCAP_DROP_BIT, &ct->status)) {
			return NF_DROP;
		}

		NATCAP_DEBUG("(SI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,tcph));

		tcpopt.header.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		ret = natcap_tcp_decode(skb, &tcpopt);
		if (ret != 0) {
			NATCAP_ERROR("(SI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,tcph), ret);
			return NF_DROP;
		}
		ret = natcap_auth(in, out, skb, ct, &tcpopt, NULL);
		if (ret != E_NATCAP_OK) {
			NATCAP_WARN("(SI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,tcph), ret);
			if (ret == E_NATCAP_FAIL) {
				set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
			} else {
				set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				return NF_DROP;
			}
		}
	} else {
		if (!tcph->syn || tcph->ack) {
			NATCAP_WARN("(SI)" DEBUG_TCP_FMT ": first packet in but not syn\n", DEBUG_TCP_ARG(iph,tcph));
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

		ret = natcap_auth(in, out, skb, ct, &tcpopt, &server);
		if (ret != E_NATCAP_OK) {
			NATCAP_WARN("(SI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,tcph), ret);
			if (ret == E_NATCAP_FAIL) {
				set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
			} else {
				set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				return NF_DROP;
			}
		}

		if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
			NATCAP_INFO("(SI)" DEBUG_TCP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,tcph), TUPLE_ARG(&server));

			if (natcap_tcp_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
				NATCAP_ERROR("(SI)" DEBUG_TCP_FMT ": natcap_tcp_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,tcph), TUPLE_ARG(&server));
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_DROP;
			}
			if (server.encryption) {
				set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			}
		}
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(SI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,tcph));

	if (test_bit(IPS_NATCAP_AUTH_BIT, &ct->status)) {
		int data_len;
		unsigned char *data;
		data = skb->data + (iph->ihl << 2) + (tcph->doff << 2);
		data_len = ntohs(iph->tot_len) - ((iph->ihl << 2) + (tcph->doff << 2));
		if ((data_len > 4 && strncasecmp(data, "GET ", 4) == 0) ||
				(data_len > 5 && strncasecmp(data, "POST ", 5) == 0)) {
			natcap_auth_http_302(in, skb, ct);
			set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
			return NF_DROP;
		} else if (data_len > 0) {
			set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
			return NF_DROP;
		} else if (tcph->ack && !tcph->syn) {
			natcap_auth_convert_tcprst(skb);
			return NF_ACCEPT;
		}
	}

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

	if (disabled)
		return NF_ACCEPT;

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

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return NF_DROP;
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	if (tcph->doff * 4 < sizeof(struct tcphdr))
		return NF_DROP;

	NATCAP_DEBUG("(SO)" DEBUG_TCP_FMT ": before encode\n", DEBUG_TCP_ARG(iph,tcph));
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
	if (ret == 0) {
		ret = natcap_tcp_encode(skb, &tcpopt);
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	}
	if (ret != 0) {
		NATCAP_ERROR("(SO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d\n", DEBUG_TCP_ARG(iph,tcph), ret);
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_DROP;
	}

	NATCAP_DEBUG("(SO)" DEBUG_TCP_FMT ":after encode\n", DEBUG_TCP_ARG(iph,tcph));

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
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct natcap_udp_tcpopt nuo;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

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

	ret = natcap_udp_decode(skb, &nuo);
	if (ret != 0) {
		return NF_ACCEPT;
	}
	udph = (struct udphdr *)tcph;

	ret = nf_conntrack_in(dev_net(in), pf, hooknum, skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		return NF_DROP;
	}

	if (!test_and_set_bit(IPS_NATCAP_UDP_BIT, &ct->status)) { /* first time in */
		NATCAP_INFO("(SI)" DEBUG_UDP_FMT ": new connection, after decode, target=%pI4:%u\n", DEBUG_UDP_ARG(iph,udph), &nuo.ip, ntohs(nuo.port));
		if (nuo.opcode == TCPOPT_NATCAP_UDP_ENC) {
			set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
		}
		if (natcap_tcp_dnat_setup(ct, nuo.ip, nuo.port) != NF_ACCEPT) {
			NATCAP_ERROR("(SI)" DEBUG_UDP_FMT ": natcap_tcp_dnat_setup failed, target=%pI4:%u\n", DEBUG_UDP_ARG(iph,udph), &nuo.ip, ntohs(nuo.port));
			return NF_DROP;
		}
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(SI)" DEBUG_UDP_FMT ": after decode\n", DEBUG_UDP_ARG(iph,udph));

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
	unsigned int opcode = TCPOPT_NATCAP_UDP;

	if (disabled)
		return NF_ACCEPT;

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

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr)))
		return NF_DROP;
	iph = ip_hdr(skb);
	udph = (struct udphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_DEBUG("(SO)" DEBUG_UDP_FMT ": before encode\n", DEBUG_UDP_ARG(iph,udph));

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
		opcode = TCPOPT_NATCAP_UDP_ENC;
	}
	ret = natcap_udp_encode(skb, status, opcode);
	if (ret != 0) {
		NATCAP_ERROR("(SO)" DEBUG_UDP_FMT ": natcap_udp_encode() ret=%d\n", DEBUG_UDP_ARG(iph,udph), ret);
		return NF_DROP;
	}
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	NATCAP_DEBUG("(SO)" DEBUG_TCP_FMT ":after encode\n", DEBUG_TCP_ARG(iph,tcph));

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
		.priority = NF_IP_PRI_NAT_DST - 35,
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
