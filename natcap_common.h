/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:27:20 +0800
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
};

enum {
	TCP_ENCODE = 0,
	UDP_ENCODE = 1,
};

extern unsigned short natcap_redirect_port;

extern unsigned long long flow_total_tx_bytes;
extern unsigned long long flow_total_rx_bytes;

extern unsigned int auth_enabled;
extern unsigned int mode;
extern const char *const mode_str[];

extern unsigned int encode_mode;
extern const char *const encode_mode_str[];

extern unsigned int disabled;
extern unsigned int debug;
extern unsigned int server_seed;

extern const char *const hooknames[];

#define NATCAP_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

#define NATCAP_FIXME(fmt, ...) \
	do { \
		if (debug & 0x10) { \
			printk(KERN_ALERT "fixme: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_DEBUG(fmt, ...) \
	do { \
		if (debug & 0x8) { \
			printk(KERN_DEBUG "debug: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_INFO(fmt, ...) \
	do { \
		if (debug & 0x4) { \
			printk(KERN_DEFAULT "info: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_WARN(fmt, ...) \
	do { \
		if (debug & 0x2) { \
			printk(KERN_WARNING "warning: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_ERROR(fmt, ...) \
	do { \
		if (debug & 0x1) { \
			printk(KERN_ERR "error: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

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

#define DEBUG_FMT_PREFIX "[%s](%s:%u)"
#define DEBUG_ARG_PREFIX hooknames[hooknum], __FUNCTION__, __LINE__

#define DEBUG_FMT_TCP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG_TCP(i, t) IP_TCPUDP_ARG(i,t), ntohs(((struct iphdr *)(i))->id), ntohs(((struct iphdr *)(i))->tot_len), TCP_ST_ARG(t)

#define DEBUG_FMT_UDP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG_UDP(i, u) IP_TCPUDP_ARG(i,u), ntohs((i)->id), ntohs((i)->tot_len), UDP_ST_ARG(u)

#define DEBUG_TCP_FMT DEBUG_FMT_PREFIX DEBUG_FMT_TCP
#define DEBUG_TCP_ARG(i, t) DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(i, t)

#define DEBUG_UDP_FMT DEBUG_FMT_PREFIX DEBUG_FMT_UDP
#define DEBUG_UDP_ARG(i, u) DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(i, u)

#define TUPLE_FMT "%pI4:%u-%c"
#define TUPLE_ARG(t) &((struct tuple *)(t))->ip, ntohs(((struct tuple *)(t))->port), ((struct tuple *)(t))->encryption ? 'e' : 'o'

#define TCPH(t) ((struct tcphdr *)(t))
#define UDPH(u) ((struct udphdr *)(u))
#define ICMPH(i) ((struct icmphdr *)(i))

extern void natcap_data_encode(unsigned char *buf, int len);
extern void natcap_data_decode(unsigned char *buf, int len);
extern void skb_data_hook(struct sk_buff *skb, int offset, int len, void (*update)(unsigned char *, int));

extern int skb_rcsum_verify(struct sk_buff *skb);
extern int skb_rcsum_tcpudp(struct sk_buff *skb);

extern int natcap_tcpopt_setup(unsigned long status, struct sk_buff *skb, struct nf_conn *ct, struct natcap_TCPOPT *tcpopt);
extern int natcap_tcp_encode(struct sk_buff *skb, const struct natcap_TCPOPT *tcpopt);
extern int natcap_tcp_decode(struct sk_buff *skb, struct natcap_TCPOPT *tcpopt);
extern int natcap_tcp_encode_fwdupdate(struct sk_buff *skb, struct tcphdr *tcph, const struct tuple *server);
static inline struct natcap_TCPOPT *natcap_tcp_decode_header(struct tcphdr *tcph)
{
	struct natcap_TCPOPT *opt;

	opt = (struct natcap_TCPOPT *)((void *)tcph + sizeof(struct tcphdr));
	if (
			!(
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_ALL &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_DST &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_USER &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int)))
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
	const struct nf_afinfo *ai;
	struct rtable *rt = NULL;
	u_int32_t mtu     = ~0U;

	struct flowi4 *fl4 = &fl.u.ip4;
	memset(fl4, 0, sizeof(*fl4));
	fl4->daddr = ip_hdr(skb)->saddr;

	rcu_read_lock();
	ai = nf_get_afinfo(PF_INET);
	if (ai != NULL)
		ai->route(net, (struct dst_entry **)&rt, &fl, false);
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
extern struct tuple *natcap_session_get(struct nf_conn *ct);

extern int natcap_common_init(void);

extern void natcap_common_exit(void);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define NF_OKFN(skb) do { \
	if (okfn) { \
		okfn(skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#define NF_OKFN(skb) do { \
	if (okfn) { \
		okfn(skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#define NF_OKFN(skb) do { \
	if (state->okfn) { \
		state->okfn(state->sk, skb); \
	} else { \
		kfree_skb(skb); \
		NATCAP_println("NF_OKFN is null, drop pkt=%p", skb); \
	} \
} while (0)

#else
#define NF_OKFN(skb) do { \
	if (state->net && state->okfn) { \
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

#endif /* _NATCAP_COMMON_H_ */
