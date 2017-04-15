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

	if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_ALL) {
		if (server) {
			server->ip = tcpopt->all.data.ip;
			server->port = tcpopt->all.data.port;
			server->encryption = tcpopt->header.encryption;
			if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET_BIT)) {
				server->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			}
		}
		if (!auth_disabled) {
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
			NATCAP_INFO("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->all.data.mac_addr[0], tcpopt->all.data.mac_addr[1], tcpopt->all.data.mac_addr[2],
					tcpopt->all.data.mac_addr[3], tcpopt->all.data.mac_addr[4], tcpopt->all.data.mac_addr[5],
					ntohl(tcpopt->all.data.u_hash));
		}
	} else if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_USER) {
		if (server) {
			return E_NATCAP_INVAL;
		}
		if (!auth_disabled) {
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
			NATCAP_INFO("(%s)" DEBUG_FMT_TCP ": client=%02X:%02X:%02X:%02X:%02X:%02X u_hash=%u auth ok\n",
					__FUNCTION__, DEBUG_ARG_TCP(iph,tcph),
					tcpopt->user.data.mac_addr[0], tcpopt->user.data.mac_addr[1], tcpopt->user.data.mac_addr[2],
					tcpopt->user.data.mac_addr[3], tcpopt->user.data.mac_addr[4], tcpopt->user.data.mac_addr[5],
					ntohl(tcpopt->user.data.u_hash));
		}
	} else if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_DST) {
		if (server) {
			server->ip = tcpopt->dst.data.ip;
			server->port = tcpopt->dst.data.port;
			server->encryption = tcpopt->header.encryption;
			if ((tcpopt->header.type & NATCAP_TCPOPT_TARGET_BIT)) {
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

static inline void natcap_udp_reply_cfm(const struct net_device *dev, struct sk_buff *oskb) {
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct udphdr *oudph, *nudph;
	int offset, header_len;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	oudph = (struct udphdr *)((void *)oiph + oiph->ihl * 4);

	offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 4 - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR("alloc_skb fail\n");
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
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
	*((unsigned int *)((void *)nudph + sizeof(struct udphdr))) = __constant_htonl(0xFFFE009A);
	nudph->source = oudph->dest;
	nudph->dest = oudph->source;
	nudph->len = ntohs(nskb->len - niph->ihl * 4);

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;
	dev_queue_xmit(nskb);
}

static inline void natcap_auth_reply_payload(const char *payload, int payload_len, struct sk_buff *oskb, const struct net_device *dev, struct nf_conn *ct)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int offset, header_len;
	int add_len = 0;
	u8 protocol = IPPROTO_TCP;
	char *data;

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl * 4);

	if (test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
		add_len = 8;
		protocol = IPPROTO_UDP;
	}

	offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len + add_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATCAP_ERROR("alloc_skb fail\n");
		return;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATCAP_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
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
		*((unsigned int *)((void *)UDPH(ntcph) + 8)) = __constant_htonl(0xFFFF0099);
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
	ntcph->window = 65535;
	ntcph->check = 0;
	ntcph->urg_ptr = 0;

	if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
		natcap_data_encode(data, payload_len);
	}

	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_rcsum_tcpudp(nskb);

	skb_push(nskb, (char *)niph - (char *)neth);
	nskb->dev = (struct net_device *)dev;

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

static inline int natcap_auth_convert_tcprst(struct sk_buff *skb)
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
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_DROP_BIT, &ct->status)) {
		return NF_DROP;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP) {
		if (test_bit(IPS_NATCAP_AUTH_BIT, &ct->status)) {
			int data_len;
			unsigned char *data;

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
				natcap_auth_http_302(in, skb, ct);
				set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				return NF_DROP;
			} else if (data_len > 0) {
				set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				return NF_DROP;
			} else if (TCPH(l4)->ack && !TCPH(l4)->syn) {
				natcap_auth_convert_tcprst(skb);
				return NF_ACCEPT;
			}
		}
	}

	return NF_ACCEPT;
}

unsigned short natcap_redirect_port = 0;

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
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (test_bit(IPS_NATCAP_DROP_BIT, &ct->status)) {
		return NF_DROP;
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

		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": before decode\n", DEBUG_TCP_ARG(iph,l4));

			tcpopt.header.encryption = !!test_bit(IPS_NATCAP_ENC_BIT, &ct->status);
			ret = natcap_tcp_decode(skb, &tcpopt);
			if (ret != 0) {
				NATCAP_ERROR("(SPCI)" DEBUG_TCP_FMT ": natcap_tcp_decode() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				return NF_DROP;
			}
			ret = NATCAP_AUTH(state, in, out, skb, ct, &tcpopt, NULL);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
				} else {
					set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				}
			}
		} else {
			if (!TCPH(l4)->syn || TCPH(l4)->ack) {
				NATCAP_INFO("(SPCI)" DEBUG_TCP_FMT ": first packet in but not syn\n", DEBUG_TCP_ARG(iph,l4));
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

			ret = NATCAP_AUTH(state, in, out, skb, ct, &tcpopt, &server);
			if (ret != E_NATCAP_OK) {
				NATCAP_WARN("(SPCI)" DEBUG_TCP_FMT ": natcap_auth() ret = %d\n", DEBUG_TCP_ARG(iph,l4), ret);
				if (ret == E_NATCAP_AUTH_FAIL) {
					set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
				} else {
					set_bit(IPS_NATCAP_DROP_BIT, &ct->status);
				}
			}

			if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
				NATCAP_INFO("(SPCI)" DEBUG_TCP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
				if (natcap_redirect_port != 0 && (tcpopt.header.type & NATCAP_TCPOPT_SPROXY_BIT)) {
					__be32 newdst = 0;
					struct in_device *indev;
					struct in_ifaddr *ifa;
					struct tuple *tup;

					rcu_read_lock();
					indev = __in_dev_get_rcu(in);
					if (indev && indev->ifa_list) {
						ifa = indev->ifa_list;
						newdst = ifa->ifa_local;
					}
					rcu_read_unlock();

					if (!newdst || newdst == server.ip) {
						goto do_dnat_setup;
					}
					if (natcap_session_init(ct, GFP_ATOMIC) != 0) {
						NATCAP_WARN("(CD)" DEBUG_TCP_FMT ": natcap_session_init failed\n", DEBUG_TCP_ARG(iph,l4));
						goto do_dnat_setup;
					}
					tup = natcap_session_get(ct);
					if (!tup) {
						goto do_dnat_setup;
					}
					memcpy(tup, &server, sizeof(struct tuple));
					set_bit(IPS_NATCAP_DST_BIT, &ct->status);

					server.ip = newdst;
					server.port = natcap_redirect_port;
				}
do_dnat_setup:
				if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
					NATCAP_ERROR("(SPCI)" DEBUG_TCP_FMT ": natcap_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_TCP_ARG(iph,l4), TUPLE_ARG(&server));
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					return NF_DROP;
				}
				if (server.encryption) {
					set_bit(IPS_NATCAP_ENC_BIT, &ct->status);
				}
			}
		}

		flow_total_rx_bytes += skb->len;
		skb->mark = XT_MARK_NATCAP;

		NATCAP_DEBUG("(SPCI)" DEBUG_TCP_FMT ": after decode\n", DEBUG_TCP_ARG(iph,l4));
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 12) &&
				*((unsigned int *)((void *)UDPH(l4) + sizeof(struct udphdr))) == __constant_htonl(0xFFFE0099)) {
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

			server.ip = *((unsigned int *)((void *)UDPH(l4) + sizeof(struct udphdr) + 4));
			server.port = *((unsigned short *)((void *)UDPH(l4) + sizeof(struct udphdr) + 8));

			if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time in*/
				NATCAP_INFO("(SPCI)" DEBUG_UDP_FMT ": new connection, after decode target=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
				if (natcap_dnat_setup(ct, server.ip, server.port) != NF_ACCEPT) {
					NATCAP_ERROR("(SPCI)" DEBUG_UDP_FMT ": natcap_dnat_setup failed, target=" TUPLE_FMT "\n", DEBUG_UDP_ARG(iph,l4), TUPLE_ARG(&server));
					set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
					return NF_DROP;
				}
			}

			if (*((unsigned short *)((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == __constant_htons(0x2)) {
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

			NATCAP_INFO("(SPCI)" DEBUG_UDP_FMT ": pass ctrl decode\n", DEBUG_UDP_ARG(iph,l4));
			//reply ACK pkt
			natcap_udp_reply_cfm(in, skb);
		}

		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			flow_total_rx_bytes += skb->len;
			skb->mark = XT_MARK_NATCAP;
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
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natcap_server_post_out_hook(void *priv,
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
	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (!test_bit(IPS_NATCAP_BIT, &ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		if (iph->protocol == IPPROTO_TCP) {
			if (test_bit(IPS_NATCAP_AUTH_BIT, &ct->status) &&
					(TCPH(l4)->dest == __constant_htons(8388) || TCPH(l4)->dest == natcap_redirect_port)) {
				return NF_DROP;
			}
			if (test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status) && TCPH(l4)->syn) {
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
			if (*((unsigned int *)((void *)UDPH(l4) + sizeof(struct udphdr))) == __constant_htonl(0xFFFE0099) &&
					*((unsigned short *)((void *)UDPH(l4) + sizeof(struct udphdr) + 10)) == __constant_htons(0x1)) {
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
		if (test_bit(IPS_NATCAP_ENC_BIT, &ct->status)) {
			status |= NATCAP_NEED_ENC;
		}

		ret = natcap_tcpopt_setup(status, skb, ct, &tcpopt);
		if (ret == 0) {
			ret = natcap_tcp_encode(skb, &tcpopt);
			iph = ip_hdr(skb);
			l4 = (struct tcphdr *)((void *)iph + iph->ihl * 4);
		}
		if (ret != 0) {
			NATCAP_ERROR("(SPO)" DEBUG_TCP_FMT ": natcap_tcp_encode() ret=%d\n", DEBUG_TCP_ARG(iph,l4), ret);
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}

		NATCAP_DEBUG("(SPO)" DEBUG_TCP_FMT ":after encode\n", DEBUG_TCP_ARG(iph,l4));

		if (!test_bit(IPS_NATCAP_UDPENC_BIT, &ct->status)) {
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
			NF_OKFN(skb);

			skb = nskb;
		} while (skb);

		return NF_STOLEN;
	} else if (iph->protocol == IPPROTO_UDP) {
		NATCAP_DEBUG("(SPO)" DEBUG_UDP_FMT ": pass data reply\n", DEBUG_UDP_ARG(iph,l4));
	}

	return NF_ACCEPT;
}

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
	struct iphdr *iph;
	void *l4;
	struct net *net = &init_net;

	if (disabled)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (skb_is_gso(skb)) {
		NATCAP_ERROR("(SPI)" DEBUG_UDP_FMT ": skb_is_gso\n", DEBUG_UDP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (*((unsigned int *)((void *)UDPH(l4) + 8)) == __constant_htonl(0xFFFF0099)) {
		int offlen;

		if (skb->ip_summed == CHECKSUM_NONE) {
			if (skb_rcsum_verify(skb) != 0) {
				NATCAP_WARN("(SPI)" DEBUG_UDP_FMT ": skb_rcsum_verify fail\n", DEBUG_UDP_ARG(iph,l4));
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

static struct nf_hook_ops server_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 5,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 35,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_post_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_server_forward_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST,
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
		struct tuple *tup;

		if (test_bit(IPS_NATCAP_BIT, &ct->status) && test_bit(IPS_NATCAP_DST_BIT, &ct->status)) {
			tup = natcap_session_get(ct);
			if (tup) {
				sin.sin_family = AF_INET;
				sin.sin_port = tup->port;
				sin.sin_addr.s_addr = tup->ip;
				memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

				NATCAP_DEBUG("SO_NATCAP_DST: %pI4 %u\n", &sin.sin_addr.s_addr, ntohs(sin.sin_port));
				nf_ct_put(ct);
				if (copy_to_user(user, &sin, sizeof(sin)) != 0)
					return -EFAULT;
				else
					return 0;
			}
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
