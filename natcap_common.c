/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:27:20 +0800
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include "natcap_common.h"
#include "natcap_client.h"

unsigned int disabled = 1;

unsigned int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,1=error,2=warn,4=info,8=debug,16=fixme,...,31=all) default=0");

unsigned int mode = CLIENT_MODE;
module_param(mode, int, 0);
MODULE_PARM_DESC(mode, "Working mode (0=client,1=server,2=forward) default=0");

unsigned int server_seed = 0;
module_param(server_seed, int, 0);
MODULE_PARM_DESC(server_seed, "Server side seed number for encode");

unsigned int encode_mode = TCP_ENCODE;
const char *const encode_mode_str[] = {
	[TCP_ENCODE] = "TCP",
	[UDP_ENCODE] = "UDP",
};

const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING] = "PRE",
	[NF_INET_LOCAL_IN] = "IN",
	[NF_INET_FORWARD] = "FD",
	[NF_INET_LOCAL_OUT] = "OUT",
	[NF_INET_POST_ROUTING] = "POST",
};

static unsigned char natcap_map[256] = {
	152, 151, 106, 224,  13,  90, 137, 200, 178, 138, 212, 156, 238,  54,  44, 237,
	101,  42,  97,  91, 163, 191, 119, 157, 123, 102, 124, 125, 197,  35,  15,  26,
	 40, 179, 129, 229,  38, 221,  71, 175,  95,  77, 245, 153,  31,  56, 253, 107,
	109, 243,  67, 225, 167, 133,  19,  32, 150, 180, 160, 203, 110, 131, 169,  16,
	130, 210, 183,  24,  12,  79, 114, 118, 215, 250,  10, 165, 164,  27, 112, 233,
	213,  49, 204, 139,  65,  98,  34, 115, 173, 228, 207,  47,  59, 143, 135, 219,
	199,  66,  76, 113,  33, 186, 187, 134, 105, 155, 190, 249, 181,  21, 201,  88,
	  9,  70,  89,  62, 241, 220, 236, 148, 227, 116, 214,  41, 185, 244, 211, 184,
	166,  18, 140,  63,   3, 222, 136, 248,  84,  93, 121, 120, 132, 171, 108,  73,
	 55,  30,  83,   1,  68, 117, 128,  87, 209, 231, 239,   5, 223, 172,  17, 246,
	 39, 254, 170,  94,  48, 182, 196,  58, 149,  86, 216,  22, 202,  20, 159,  53,
	 78, 174, 141, 189, 252,   4,  25,  69,   8,  64, 147,  37,  60, 111,  74,  11,
	192, 146, 198, 255, 240,  61,  36,  51, 247, 226,  57, 154, 194,   6,  80,  50,
	208,  72, 144, 234, 158, 217,  23,  82, 242, 122, 195, 177, 193, 205,   7, 232,
	 96, 206, 145, 103,  43,  45, 162, 176, 104, 126, 100, 188,  81, 218, 161,  92,
	 46, 251,  52,  75,   0, 142,  28,  14,   2, 168, 235, 127, 230,  85,  99,  29,
};
static unsigned char dnatcap_map[256];

static void dnatcap_map_init(void)
{
	int i;

	for (i = 0; i < 256; i++) {
		natcap_map[i] = (natcap_map[i] + server_seed) & 0xff;
	}

	for (i = 0; i < 256; i++) {
		dnatcap_map[natcap_map[i]] = i;
	}
}

void natcap_data_encode(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = natcap_map[buf[i]];
	}
}

void natcap_data_decode(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = dnatcap_map[buf[i]];
	}
}

static void skb_data_hook(struct sk_buff *skb, int offset, int len, void (*update)(unsigned char *, int))
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int pos = 0;

	if (copy > 0) {
		if (copy > len)
			copy = len;
		update(skb->data + offset, copy);
		if ((len -= copy) == 0)
			return;
		offset += copy;
		pos	= copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		WARN_ON(start > offset + len);

		end = start + skb_frag_size(frag);
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;
			vaddr = kmap_atomic(skb_frag_page(frag));
			update(vaddr + frag->page_offset + offset - start, copy);
			kunmap_atomic(vaddr);
			if (!(len -= copy))
				return;
			offset += copy;
			pos    += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			skb_data_hook(frag_iter, offset - start, copy, update);
			if ((len -= copy) == 0)
				return;
			offset += copy;
			pos    += copy;
		}
		start = end;
	}
	BUG_ON(len);

	return;
}

int skb_rcsum_verify(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);
	int ret = 0;
	__sum16 l3_sum, l4_sum;
	__sum16 skbcsum;

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		skbcsum = skb->csum;
		l3_sum = iph->check;
		l4_sum = tcph->check;

		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		skb->csum = 0;
		tcph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);

		if (l3_sum != iph->check || l4_sum != tcph->check) {
			ret = -1;
			iph->check = l3_sum;
			tcph->check = l4_sum;
		}
		skb->csum = skbcsum;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		skbcsum = skb->csum;
		l3_sum = iph->check;
		l4_sum = udph->check;

		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		skb->csum = 0;
		udph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
		udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);

		if (l3_sum != iph->check || l4_sum != udph->check) {
			ret = -1;
			iph->check = l3_sum;
			udph->check = l4_sum;
		}
		skb->csum = skbcsum;
	} else {
		return -1;
	}

	return ret;
}

int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			tcph->check = 0;
			tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
			skb->csum_start = (unsigned char *)tcph - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			skb->csum = 0;
			tcph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			udph->check = 0;
			udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, 0);
			skb->csum_start = (unsigned char *)udph - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			skb->csum = 0;
			udph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
		}
	} else {
		return -1;
	}

	return 0;
}

int natcap_tcpopt_setup(unsigned long status, struct sk_buff *skb, struct nf_conn *ct, struct natcap_TCPOPT *tcpopt)
{
	int size;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if ((status & NATCAP_NEED_ENC))
		tcpopt->header.encryption = 1;
	else
		tcpopt->header.encryption = 0;

	if ((status & NATCAP_CLIENT_MODE)) {
		//not syn
		if (!(tcph->syn && !tcph->ack)) {
			if (test_bit(IPS_NATCAP_AUTH_BIT, &ct->status)) {
				tcpopt->header.type = NATCAP_TCPOPT_NONE;
				tcpopt->header.opsize = 0;
				return 0;
			}
			size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int));
			if (tcph->doff * 4 + size <= 60) {
				tcpopt->header.type = NATCAP_TCPOPT_USER;
				tcpopt->header.opcode = TCPOPT_NATCAP;
				tcpopt->header.opsize = size;
				memcpy(tcpopt->user.data.mac_addr, default_mac_addr, ETH_ALEN);
				tcpopt->user.data.u_hash = default_u_hash;
				set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
				return 0;
			}
			tcpopt->header.type = NATCAP_TCPOPT_NONE;
			tcpopt->header.opsize = 0;
			return 0;
		}
		//syn
		size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data), sizeof(unsigned int));
		if (tcph->doff * 4 + size <= 60)
		{
			tcpopt->header.type = NATCAP_TCPOPT_ALL;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->all.data.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			tcpopt->all.data.port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
			memcpy(tcpopt->all.data.mac_addr, default_mac_addr, ETH_ALEN);
			tcpopt->all.data.u_hash = default_u_hash;
			set_bit(IPS_NATCAP_AUTH_BIT, &ct->status);
			return 0;
		}
		size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst), sizeof(unsigned int));
		if (tcph->doff * 4 + size <= 60) {
			tcpopt->header.type = NATCAP_TCPOPT_DST;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->dst.data.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			tcpopt->dst.data.port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
			return 0;
		}
		return -1;
	} else {
		tcpopt->header.type = NATCAP_TCPOPT_NONE;
		tcpopt->header.opsize = 0;
		return 0;
	}
}

int natcap_tcp_encode(struct sk_buff *skb, const struct natcap_TCPOPT *tcpopt)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (tcpopt->header.type == NATCAP_TCPOPT_NONE) {
		goto do_encode;
	}

	if (tcph->doff * 4 + tcpopt->header.opsize > 60)
		return -1;
	if (skb->end - skb->tail < tcpopt->header.opsize && pskb_expand_head(skb, 0, tcpopt->header.opsize, GFP_ATOMIC)) {
		return -2;
	}
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	offlen = skb_tail_pointer(skb) - (unsigned char *)tcph - sizeof(struct tcphdr);
	BUG_ON(offlen < 0);
	memmove((void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize, (void *)tcph + sizeof(struct tcphdr), offlen);
	memcpy((void *)tcph + sizeof(struct tcphdr), (void *)tcpopt, tcpopt->header.opsize);

	tcph->doff = (tcph->doff * 4 + tcpopt->header.opsize) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) + tcpopt->header.opsize);
	skb->len += tcpopt->header.opsize;
	skb->tail += tcpopt->header.opsize;

do_encode:
	if (tcpopt->header.encryption) {
		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_encode);
	}
	if (tcpopt->header.encryption || tcpopt->header.type != NATCAP_TCPOPT_NONE) {
		skb_rcsum_tcpudp(skb);
	}

	return 0;
}

int natcap_tcp_decode(struct sk_buff *skb, struct natcap_TCPOPT *tcpopt)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_TCPOPT *opt;
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	tcpopt->header.opcode = 0;
	tcpopt->header.opsize = 0;
	tcpopt->header.type = NATCAP_TCPOPT_NONE;
	opt = natcap_tcp_decode_header(tcph);
	if (opt == NULL) {
		goto do_decode;
	}

	memcpy((void *)tcpopt, (void *)opt, opt->header.opsize);
	if (mode == FORWARD_MODE)
		goto done;
	offlen = skb_tail_pointer(skb) - (unsigned char *)((void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize);
	BUG_ON(offlen < 0);
	memmove((void *)tcph + sizeof(struct tcphdr), (void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize, offlen);

	tcph->doff = (tcph->doff * 4 - tcpopt->header.opsize) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) - tcpopt->header.opsize);
	skb->len -= tcpopt->header.opsize;
	skb->tail -= tcpopt->header.opsize;

do_decode:
	if (tcpopt->header.encryption) {
		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_decode);
	}
	if (tcpopt->header.encryption || tcpopt->header.type != NATCAP_TCPOPT_NONE) {
		skb_rcsum_tcpudp(skb);
	}
done:
	return 0;
}

int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_UNSPEC;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif

	id = ip_set_get_byname(net, ip_set_name, &set);
	if (id == IPSET_INVALID_ID) {
		NATCAP_WARN("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

	ip_set_put_byindex(net, id);

	return ret;
}

unsigned int natcap_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, IP_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct nf_nat_ipv4_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#else
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.ip = addr;
	range.max_addr.ip = addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#endif
}

int natcap_common_init(void)
{
	dnatcap_map_init();
	return 0;
}

void natcap_common_exit(void)
{

}
