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
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
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
};

enum {
	TCP_ENCODE = 0,
	UDP_ENCODE = 1,
};

extern unsigned int encode_mode;
extern const char *const encode_mode_str[];

extern unsigned int disabled;
extern unsigned int debug;
extern unsigned int mode;
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
#define IP_TCPUDP_ARG(i,t)	&(i)->saddr, ntohs((t)->source), &(i)->daddr, ntohs((t)->dest)
#define TCP_ST_FMT	"%c%c%c%c%c%c%c%c"
#define TCP_ST_ARG(t) \
	(t)->cwr ? 'C' : '.', \
	(t)->ece ? 'E' : '.', \
	(t)->urg ? 'U' : '.', \
	(t)->ack ? 'A' : '.', \
	(t)->psh ? 'P' : '.', \
	(t)->rst ? 'R' : '.', \
	(t)->syn ? 'S' : '.', \
	(t)->fin ? 'F' : '.'
#define UDP_ST_FMT "UL:%u,UC:%04X"
#define UDP_ST_ARG(u) ntohs((u)->len), ntohs((u)->check)

#define DEBUG_FMT_PREFIX "[%s](%s:%u)"
#define DEBUG_ARG_PREFIX hooknames[hooknum], __FUNCTION__, __LINE__

#define DEBUG_FMT_TCP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG_TCP(i, t) IP_TCPUDP_ARG(i,t), ntohs((i)->id), ntohs((i)->tot_len), TCP_ST_ARG(t)

#define DEBUG_FMT_UDP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG_UDP(i, u) IP_TCPUDP_ARG(i,u), ntohs((i)->id), ntohs((i)->tot_len), UDP_ST_ARG(u)

#define DEBUG_TCP_FMT DEBUG_FMT_PREFIX DEBUG_FMT_TCP
#define DEBUG_TCP_ARG(i, t) DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(i, t)

#define DEBUG_UDP_FMT DEBUG_FMT_PREFIX DEBUG_FMT_UDP
#define DEBUG_UDP_ARG(i, u) DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(i, u)

#define TUPLE_FMT "%pI4:%u-%c"
#define TUPLE_ARG(t) &(t)->ip, ntohs((t)->port), (t)->encryption ? 'e' : 'o'

void natcap_data_encode(unsigned char *buf, int len);
void natcap_data_decode(unsigned char *buf, int len);

int skb_rcsum_tcpudp(struct sk_buff *skb);

int natcap_tcpopt_setup(unsigned long status, struct sk_buff *skb, struct nf_conn *ct, struct natcap_TCPOPT *tcpopt);
int natcap_tcp_encode(struct sk_buff *skb, const struct natcap_TCPOPT *tcpopt);
int natcap_tcp_decode(struct sk_buff *skb, struct natcap_TCPOPT *tcpopt);
static inline struct natcap_TCPOPT *natcap_tcp_decode_header(struct tcphdr *tcph)
{
	struct natcap_TCPOPT *opt;

	opt = (struct natcap_TCPOPT *)((void *)tcph + sizeof(struct tcphdr));
	if (
			!(
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 opt->header.type == NATCAP_TCPOPT_ALL &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 opt->header.type == NATCAP_TCPOPT_DST &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int))) ||
				(tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int)) &&
				 opt->header.opcode == TCPOPT_NATCAP &&
				 opt->header.type == NATCAP_TCPOPT_USER &&
				 opt->header.opsize == ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int)))
			 )
	   )
	{
		return NULL;
	}

	return opt;
}

int natcap_udp_encode(struct sk_buff *skb, unsigned long status, unsigned int opcode);
int natcap_udp_decode(struct sk_buff *skb, struct natcap_udp_tcpopt *nuo);
static inline struct natcap_udp_tcpopt *natcap_udp_decode_header(struct tcphdr *tcph)
{
	struct natcap_udp_tcpopt *pnuo = NULL;

	if (!((tcph->syn && !tcph->ack) || (tcph->rst && tcph->ack))) {
		return NULL;
	}

	pnuo = (struct natcap_udp_tcpopt *)((void *)tcph + sizeof(struct tcphdr));
	if (
			!(
				tcph->doff * 4 >= sizeof(struct tcphdr) + ALIGN(sizeof(struct natcap_udp_tcpopt), sizeof(unsigned int)) &&
				(pnuo->opcode == TCPOPT_NATCAP_UDP || pnuo->opcode == TCPOPT_NATCAP_UDP_ENC) &&
				pnuo->opsize == ALIGN(sizeof(struct natcap_udp_tcpopt), sizeof(unsigned int))
			 )
	   )
	{
		return NULL;
	}

	return pnuo;
}

static inline void natcap_adjust_tcp_mss(struct tcphdr *tcph, int delta)
{
	unsigned int optlen, i;
	__be16 oldmss, newmss;
	unsigned char *op;

	if (tcph->doff * 4 < sizeof(struct tcphdr))
		return;

	optlen = tcph->doff * 4 - sizeof(struct tcphdr);
	if (!optlen)
		return;

	op = (unsigned char *)tcph + sizeof(struct tcphdr);

	for (i = 0; i < optlen; ) {
		if (op[i] == TCPOPT_MSS && (optlen - i) >= TCPOLEN_MSS &&
		        op[i+1] == TCPOLEN_MSS) {
			__be32 diff[2];

			oldmss = *((unsigned short *)(op + i + 2));
			newmss = htons(ntohs(oldmss) + delta);

			*((unsigned short *)(op + i + 2)) = newmss;

			diff[0] =~((__force __be32)oldmss);
			diff[1] = (__force __be32)newmss;
			tcph->check = csum_fold(csum_partial(diff, sizeof(diff),
			                                     ~csum_unfold(tcph->check)));

			NATCAP_INFO("Change TCP MSS %d to %d\n", ntohs(oldmss), ntohs(newmss));
		}

		if (op[i] < 2) {
			i++;
		} else {
			i += op[i+1] ? : 1;
		}
	}
}

int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);

unsigned int natcap_tcp_dnat_setup(struct nf_conn *ct, __be32 ip, __be16 port);

int natcap_common_init(void);

void natcap_common_exit(void);

#endif /* _NATCAP_COMMON_H_ */
