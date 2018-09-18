/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:27:20 +0800
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
#ifndef _NATCAP_COMMON_H_
#define _NATCAP_COMMON_H_
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include "natcap.h"

enum {
	CLIENT_MODE = 0,
	SERVER_MODE = 1,
	FORWARD_MODE = 2,
	MIXING_MODE = 3,
	KNOCK_MODE = 4,
	PEER_MODE = 5,
};

enum {
	TCP_ENCODE = 0,
	UDP_ENCODE = 1,
};

extern struct cone_nat_session *cone_nat_array;

extern unsigned int natcap_touch_timeout;

extern unsigned short natcap_redirect_port;

extern unsigned long long flow_total_tx_bytes;
extern unsigned long long flow_total_rx_bytes;

extern unsigned int auth_enabled;
extern unsigned int mode;
extern const char *const mode_str[];

extern unsigned int disabled;
extern unsigned int debug;
extern unsigned int server_seed;

extern const char *const hooknames[];

extern char htp_confusion_req[1024];
extern char htp_confusion_rsp[1024];

extern char htp_confusion_host[64];

#define htp_confusion_req_format "" \
		"GET /%08X HTTP/1.1\r\n" \
		"Host: %s\r\n" \
		"Connection: keep-alive\r\n" \
		"Pragma: no-cache\r\n" \
		"Cache-Control: no-cache\r\n" \
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n" \
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n" \
		"Accept-Encoding: gzip, deflate, sdch\r\n" \
		"Accept-Language: zh-CN,en-US;q=0.8,en;q=0.6,zh;q=0.4\r\n" \
		"\r\n"

#define IS_NATCAP_FIXME() (debug & 0x10)
#define IS_NATCAP_DEBUG() (debug & 0x8)
#define IS_NATCAP_INFO() (debug & 0x4)
#define IS_NATCAP_WARN() (debug & 0x2)
#define IS_NATCAP_ERROR() (debug & 0x1)

#define NATCAP_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

#define NATCAP_FIXME(fmt, ...) \
	do { \
		if (IS_NATCAP_FIXME()) { \
			printk(KERN_ALERT "fixme: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_DEBUG(fmt, ...) \
	do { \
		if (IS_NATCAP_DEBUG()) { \
			printk(KERN_DEBUG "debug: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_INFO(fmt, ...) \
	do { \
		if (IS_NATCAP_INFO()) { \
			printk(KERN_DEFAULT "info: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_WARN(fmt, ...) \
	do { \
		if (IS_NATCAP_WARN()) { \
			printk(KERN_WARNING "warning: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_ERROR(fmt, ...) \
	do { \
		if (IS_NATCAP_ERROR()) { \
			printk(KERN_ERR "error: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#ifdef NO_DEBUG
#undef NATCAP_FIXME
#undef NATCAP_DEBUG
#undef NATCAP_INFO
#undef NATCAP_WARN
#undef NATCAP_ERROR
#define NATCAP_FIXME(fmt, ...)
#define NATCAP_DEBUG(fmt, ...)
#define NATCAP_INFO(fmt, ...)
#define NATCAP_WARN(fmt, ...)
#define NATCAP_ERROR(fmt, ...)
#endif

#define IP_TCPUDP_FMT	"%pI4:%u->%pI4:%u"
#define IP_TCPUDP_ARG(i,t)	&(i)->saddr, ntohs(((struct tcphdr *)(t))->source), &(i)->daddr, ntohs(((struct tcphdr *)(t))->dest)
#define TCP_ST_FMT	"%c%c%c%c%c%c%c%c"
#define TCP_ST_ARG(t) \
	((struct tcphdr *)(t))->cwr ? 'C' : '.', \
	((struct tcphdr *)(t))->ece ? 'E' : '.', \
	((struct tcphdr *)(t))->urg ? 'U' : '.', \
	((struct tcphdr *)(t))->ack ? 'A' : '.', \
	((struct tcphdr *)(t))->psh ? 'P' : '.', \
	((struct tcphdr *)(t))->rst ? 'R' : '.', \
	((struct tcphdr *)(t))->syn ? 'S' : '.', \
	((struct tcphdr *)(t))->fin ? 'F' : '.'
#define UDP_ST_FMT "UL:%u,UC:%04X"
#define UDP_ST_ARG(u) ntohs(((struct udphdr *)(u))->len), ntohs(((struct udphdr *)(u))->check)
#define ICMP_ST_FMT "T:%u,C:%u,ID:%u:SEQ:%u"
#define ICMP_ST_ARG(m) ((struct icmphdr *)(m))->type, ((struct icmphdr *)(m))->code, ntohs(((struct icmphdr *)(m))->un.echo.id), ntohs(((struct icmphdr *)(m))->un.echo.sequence)

#define DEBUG_FMT_PREFIX "(%s:%u)"
#define DEBUG_ARG_PREFIX __FUNCTION__, __LINE__

#define DEBUG_FMT_TCP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG_TCP(i, t) IP_TCPUDP_ARG(i,t), ntohs(((struct iphdr *)(i))->id), ntohs(((struct iphdr *)(i))->tot_len), TCP_ST_ARG(t)

#define DEBUG_FMT_UDP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG_UDP(i, u) IP_TCPUDP_ARG(i,u), ntohs((i)->id), ntohs((i)->tot_len), UDP_ST_ARG(u)

#define DEBUG_FMT_ICMP "[%pI4->%pI4|ID:%04X,IL:%u|" ICMP_ST_FMT "]"
#define DEBUG_ARG_ICMP(i, m) &(i)->saddr, &(i)->daddr, ntohs((i)->id), ntohs((i)->tot_len), ICMP_ST_ARG(m)

#define DEBUG_TCP_FMT "[%s]" DEBUG_FMT_PREFIX DEBUG_FMT_TCP
#define DEBUG_TCP_ARG(i, t) hooknames[hooknum], DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(i, t)

#define DEBUG_UDP_FMT "[%s]" DEBUG_FMT_PREFIX DEBUG_FMT_UDP
#define DEBUG_UDP_ARG(i, u) hooknames[hooknum], DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(i, u)

#define DEBUG_ICMP_FMT "[%s]" DEBUG_FMT_PREFIX DEBUG_FMT_ICMP
#define DEBUG_ICMP_ARG(i, m) hooknames[hooknum], DEBUG_ARG_PREFIX, DEBUG_ARG_ICMP(i, m)

#define TUPLE_FMT "%pI4:%u-%c-%c-%c"
#define TUPLE_ARG(t) &((struct tuple *)(t))->ip, ntohs(((struct tuple *)(t))->port), ((struct tuple *)(t))->encryption ? 'e' : 'o', ((struct tuple *)(t))->tcp_encode == TCP_ENCODE ? 'T' : 'U', ((struct tuple *)(t))->udp_encode == UDP_ENCODE ? 'U' : 'T'

#define TCPH(t) ((struct tcphdr *)(t))
#define UDPH(u) ((struct udphdr *)(u))
#define ICMPH(i) ((struct icmphdr *)(i))

extern void natcap_data_encode(unsigned char *buf, int len);
extern void natcap_data_decode(unsigned char *buf, int len);
extern void skb_data_hook(struct sk_buff *skb, int offset, int len, void (*update)(unsigned char *, int));

extern int skb_rcsum_verify(struct sk_buff *skb);
extern int skb_rcsum_tcpudp(struct sk_buff *skb);

extern int natcap_tcpopt_setup(unsigned long status, struct sk_buff *skb, struct nf_conn *ct, struct natcap_TCPOPT *tcpopt, __be32 ip, __be16 port);
extern int natcap_tcp_encode(struct nf_conn *ct, struct sk_buff *skb, const struct natcap_TCPOPT *tcpopt, int dir);
extern int natcap_tcp_decode(struct nf_conn *ct, struct sk_buff *skb, struct natcap_TCPOPT *tcpopt, int dir);
extern int natcap_tcp_encode_fwdupdate(struct sk_buff *skb, struct tcphdr *tcph, const struct tuple *server);
static inline struct natcap_TCPOPT *natcap_tcp_decode_header(struct tcphdr *tcph)
{
	struct natcap_TCPOPT *opt;

	opt = (struct natcap_TCPOPT *)((void *)tcph + sizeof(struct tcphdr));
	if (
			!(
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_ALL &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_DST &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_USER &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_CONFUSION &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_ADD &&
				 opt->header.opsize >= ALIGN(sizeof(struct natcap_TCPOPT_header), sizeof(unsigned int)))

			 )
	   )
	{
		return NULL;
	}

	return opt;
}

static inline unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
		return 1;
	else
		return opt[offset+1];
}

static inline u_int32_t tcpmss_reverse_mtu(struct net *net, const struct sk_buff *skb)
{
	struct flowi fl;
#if ! defined(NF_MOVED_ROUTE_INDIRECTION) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	const struct nf_afinfo *ai;
#endif
	struct rtable *rt = NULL;
	u_int32_t mtu     = ~0U;

	struct flowi4 *fl4 = &fl.u.ip4;
	memset(fl4, 0, sizeof(*fl4));
	fl4->daddr = ip_hdr(skb)->saddr;

	rcu_read_lock();
#if ! defined(NF_MOVED_ROUTE_INDIRECTION) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	ai = nf_get_afinfo(PF_INET);
	if (ai != NULL)
		ai->route(net, (struct dst_entry **)&rt, &fl, false);
#else
	nf_route(net, (struct dst_entry **)&rt, &fl, false, PF_INET);
#endif
	rcu_read_unlock();

	if (rt != NULL) {
		mtu = dst_mtu(&rt->dst);
		dst_release(&rt->dst);
	}
	return mtu;
}

static inline int natcap_tcpmss_adjust(struct sk_buff *skb, struct tcphdr *tcph, int delta) {
	u16 oldmss, newmss;
	unsigned int i;
	int tcp_hdrlen;
	u8 *opt;

	tcp_hdrlen = tcph->doff * 4;
	opt = (u_int8_t *)tcph;
	for (i = sizeof(struct tcphdr); i <= tcp_hdrlen - TCPOLEN_MSS; i += optlen(opt, i)) {
		if (opt[i] == TCPOPT_MSS && opt[i+1] == TCPOLEN_MSS) {

			oldmss = (opt[i+2] << 8) | opt[i+3];
			if ((int)oldmss + delta <= 0) {
				return -1;
			}
			newmss = oldmss + delta;
			if (oldmss <= newmss) {
				return -1;
			}

			opt[i+2] = (newmss & 0xff00) >> 8;
			opt[i+3] = newmss & 0x00ff;

			inet_proto_csum_replace2(&tcph->check, skb, htons(oldmss), htons(newmss), false);

			NATCAP_INFO("Change TCP MSS %d to %d\n", oldmss, newmss);
			return 0;
		}
	}
	return -1;
}

static inline int natcap_tcpmss_clamp_pmtu_adjust(struct sk_buff *skb, struct net *net, struct tcphdr *tcph, int delta) {
	u16 oldmss, newmss;
	unsigned int i;
	unsigned int minlen, in_mtu, min_mtu;
	int tcp_hdrlen;
	u8 *opt;

	minlen = sizeof(struct iphdr) + sizeof(struct tcphdr);
	in_mtu = tcpmss_reverse_mtu(net, skb);
	min_mtu = min(dst_mtu(skb_dst(skb)), in_mtu);

	if (min_mtu <= minlen) {
		return -1;
	}
	newmss = min_mtu - minlen;
	newmss = newmss + delta;

	tcp_hdrlen = tcph->doff * 4;
	opt = (u_int8_t *)tcph;
	for (i = sizeof(struct tcphdr); i <= tcp_hdrlen - TCPOLEN_MSS; i += optlen(opt, i)) {
		if (opt[i] == TCPOPT_MSS && opt[i+1] == TCPOLEN_MSS) {

			oldmss = (opt[i+2] << 8) | opt[i+3];
			if (oldmss <= newmss) {
				if ((int)oldmss + delta <= 0) {
					return -1;
				}
				newmss = oldmss + delta;
			}
			if (oldmss <= newmss) {
				return -1;
			}

			opt[i+2] = (newmss & 0xff00) >> 8;
			opt[i+3] = newmss & 0x00ff;

			inet_proto_csum_replace2(&tcph->check, skb, htons(oldmss), htons(newmss), false);

			NATCAP_INFO("Change TCP MSS %d to %d\n", oldmss, newmss);
			return 0;
		}
	}
	return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
extern int ip_set_test_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_ip(state, in, out, skb, name) ip_set_test_src_ip(state, skb, name)
extern int ip_set_test_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_ip(state, in, out, skb, name) ip_set_test_dst_ip(state, skb, name)
extern int ip_set_add_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_src_ip(state, in, out, skb, name) ip_set_add_src_ip(state, skb, name)
extern int ip_set_add_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_dst_ip(state, in, out, skb, name) ip_set_add_dst_ip(state, skb, name)
extern int ip_set_del_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_src_ip(state, in, out, skb, name) ip_set_del_src_ip(state, skb, name)
extern int ip_set_del_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_dst_ip(state, in, out, skb, name) ip_set_del_dst_ip(state, skb, name)
extern int ip_set_test_src_mac(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_mac(state, in, out, skb, name) ip_set_test_src_mac(state, skb, name)
#else
extern int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_ip(state, in, out, skb, name) ip_set_test_src_ip(in, out, skb, name)
extern int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_ip(state, in, out, skb, name) ip_set_test_dst_ip(in, out, skb, name)
extern int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_src_ip(state, in, out, skb, name) ip_set_add_src_ip(in, out, skb, name)
extern int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_dst_ip(state, in, out, skb, name) ip_set_add_dst_ip(in, out, skb, name)
extern int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_src_ip(state, in, out, skb, name) ip_set_del_src_ip(in, out, skb, name)
extern int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_dst_ip(state, in, out, skb, name) ip_set_del_dst_ip(in, out, skb, name)
extern int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_mac(state, in, out, skb, name) ip_set_test_src_mac(in, out, skb, name)
#endif

extern unsigned int natcap_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto);

extern int natcap_session_init(struct nf_conn *ct, gfp_t gfp);
extern struct natcap_session *natcap_session_get(struct nf_conn *ct);
static inline struct natcap_session *natcap_session_in(struct nf_conn *ct)
{
	if (natcap_session_init(ct, GFP_ATOMIC) != 0) {
		return NULL;
	}
	return natcap_session_get(ct);
}

extern void natcap_clone_timeout(struct nf_conn *dst, struct nf_conn *src);
extern int natcap_udp_to_tcp_pack(struct sk_buff *skb, struct natcap_session *ns, int m);

extern int natcap_common_init(void);

extern void natcap_common_exit(void);

#define NF_GW_REROUTE(skb) do { \
	struct dst_entry *dst = skb_dst(skb); \
	struct rtable *rt = (struct rtable *)dst; \
	if (!rt->rt_gateway) { \
		rt = ip_route_output(dev_net(dst->dev), iph->daddr, 0, RT_TOS(iph->tos), 0); \
		if (!IS_ERR(rt)) { \
			skb_dst_drop(skb); \
			skb_dst_set(skb, &rt->dst); \
			skb->dev = rt->dst.dev; \
		} \
	} \
} while (0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define NF_OKFN(skb) do { \
	if (okfn) { \
		NF_GW_REROUTE(skb); \
		okfn(skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#define NF_OKFN(skb) do { \
	if (okfn) { \
		NF_GW_REROUTE(skb); \
		okfn(skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#define NF_OKFN(skb) do { \
	if (state->okfn) { \
		NF_GW_REROUTE(skb); \
		state->okfn(state->sk, skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#else
#define NF_OKFN(skb) do { \
	if (state->net && state->okfn) { \
		NF_GW_REROUTE(skb); \
		state->okfn(state->net, state->sk, skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#endif

static inline unsigned char get_byte1(const unsigned char *p)
{
	return p[0];
}

static inline unsigned short get_byte2(const unsigned char *p)
{
	unsigned short v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline unsigned int get_byte4(const unsigned char *p)
{
	unsigned int v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline void set_byte1(unsigned char *p, unsigned char v)
{
	p[0] = v;
}

static inline void set_byte2(unsigned char *p, unsigned short v)
{
	memcpy(p, &v, sizeof(v));
}

static inline void set_byte4(unsigned char *p, unsigned int v)
{
	memcpy(p, &v, sizeof(v));
}

#ifndef SKB_NFCT_PTRMASK
static inline struct nf_conntrack *skb_nfct(const struct sk_buff *skb)
{
	return (void *)skb->nfct;
}
#endif

static inline void skb_nfct_reset(struct sk_buff *skb)
{
	nf_conntrack_put(skb_nfct(skb));
#ifndef SKB_NFCT_PTRMASK
	skb->nfct = NULL;
#else
	skb->_nfct = 0;
#endif
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static inline int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	return nf_register_net_hooks(&init_net, reg, n);
}

static inline void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	nf_unregister_net_hooks(&init_net, reg, n);
}
#endif

#endif /* _NATCAP_COMMON_H_ */
