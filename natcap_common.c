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
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include "natcap_common.h"
#include "natcap_client.h"

unsigned int natcap_touch_timeout = 32;

unsigned short natcap_redirect_port = 0;

unsigned int disabled = 1;
unsigned long long flow_total_tx_bytes = 0;
unsigned long long flow_total_rx_bytes = 0;

unsigned int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,1=error,2=warn,4=info,8=debug,16=fixme,...,31=all) default=0");

unsigned int mode = MIXING_MODE;
module_param(mode, int, 0);
MODULE_PARM_DESC(mode, "Working mode (0=client,1=server,2=forward,3=client+server) default=0");

unsigned int auth_enabled = 0;
module_param(auth_enabled, int, 0);
MODULE_PARM_DESC(auth_enabled, "Disable auth default=0");

unsigned int server_seed = 0;
module_param(server_seed, int, 0);
MODULE_PARM_DESC(server_seed, "Server side seed number for encode");

char htp_confusion_host[64] = "bing.com";

char htp_confusion_req[1024] = ""
		"GET /00000000 HTTP/1.1\r\n"
		"Host: bing.com\r\n"
		"Connection: keep-alive\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
		"Accept-Encoding: gzip, deflate, sdch\r\n"
		"Accept-Language: zh-CN,en-US;q=0.8,en;q=0.6,zh;q=0.4\r\n"
		"\r\n";

char htp_confusion_rsp[1024] = ""
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html;charset=ISO-8859-1\r\n"
		"Content-Length: 4294967295\r\n"
		"Connection: keep-alive\r\n"
		"\r\n";

const char *const mode_str[] = {
	[CLIENT_MODE] = "CLIENT",
	[SERVER_MODE] = "SERVER",
	[FORWARD_MODE] = "FORWARD",
	[MIXING_MODE] = "CLIENT+SERVER",
	[KNOCK_MODE] = "KNOCK",
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

void skb_data_hook(struct sk_buff *skb, int offset, int len, void (*update)(unsigned char *, int))
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
	__wsum skbcsum;

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		l3_sum = iph->check;
		l4_sum = tcph->check;

		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		if (l3_sum != iph->check) {
			iph->check = l3_sum;
			return -1;
		}
		tcph->check = 0;
		skbcsum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skbcsum);
		if (l4_sum != tcph->check) {
			tcph->check = l4_sum;
			return -1;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		l3_sum = iph->check;
		l4_sum = udph->check;

		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		if (l3_sum != iph->check) {
			iph->check = l3_sum;
			return -1;
		}
		if (udph->check != 0) {
			udph->check = 0;
			skbcsum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skbcsum);
			if (udph->check == 0)
				udph->check = CSUM_MANGLED_0;
			if (l4_sum != udph->check) {
				udph->check = l4_sum;
				return -1;
			}
		}
	} else {
		return -1;
	}

	return ret;
}

int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);
	__wsum skbcsum;

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
			tcph->check = 0;
			skbcsum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skbcsum);
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
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
			if (udph->check) {
				udph->check = 0;
				skbcsum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
				udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skbcsum);
				if (udph->check == 0)
					udph->check = CSUM_MANGLED_0;
			}
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else {
		return -1;
	}

	return 0;
}

int natcap_tcpopt_setup(unsigned long status, struct sk_buff *skb, struct nf_conn *ct, struct natcap_TCPOPT *tcpopt, __be32 ip, __be16 port)
{
	int size;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	struct natcap_session *ns = natcap_session_get(ct);

	if (NULL == ns) {
		return -1;
	}

	if ((status & NATCAP_NEED_ENC))
		tcpopt->header.encryption = 1;
	else
		tcpopt->header.encryption = 0;

	if ((status & NATCAP_CLIENT_MODE)) {
		int add_len = 0;
		//not syn
		if (!(tcph->syn && !tcph->ack)) {
			if ((NS_NATCAP_AUTH & ns->status)) {
				tcpopt->header.type = NATCAP_TCPOPT_TYPE_NONE;
				tcpopt->header.opsize = 0;
				return 0;
			}
			size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_user), sizeof(unsigned int));
			if (tcph->doff * 4 + size <= 60) {
				tcpopt->header.type = NATCAP_TCPOPT_TYPE_USER;
				tcpopt->header.opcode = TCPOPT_NATCAP;
				tcpopt->header.opsize = size;
				memcpy(tcpopt->user.data.mac_addr, default_mac_addr, ETH_ALEN);
				tcpopt->user.data.u_hash = default_u_hash;
				short_set_bit(NS_NATCAP_AUTH_BIT, &ns->status);
				return 0;
			}
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_NONE;
			tcpopt->header.opsize = 0;
			return 0;
		}
		//syn
		if (http_confusion && ns && !(NS_NATCAP_TCPUDPENC & ns->status) && (IPS_NATCAP_ENC & ct->status)) {
			add_len += sizeof(unsigned int);
			if (ns->tcp_seq_offset == 0) {
				ns->tcp_seq_offset = sizeof(htp_confusion_req) / 2 + jiffies % (sizeof(htp_confusion_req) / 4);
			}
		}
		size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_data) + add_len, sizeof(unsigned int));
		if (tcph->doff * 4 + size <= 60)
		{
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_ALL;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->all.data.ip = ip;
			tcpopt->all.data.port = port;
			memcpy(tcpopt->all.data.mac_addr, default_mac_addr, ETH_ALEN);
			tcpopt->all.data.u_hash = default_u_hash;
			if (add_len == sizeof(unsigned int)) {
				set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->tcp_seq_offset));
				tcpopt->header.type |= NATCAP_TCPOPT_CONFUSION;
			}
			short_set_bit(NS_NATCAP_AUTH_BIT, &ns->status);
			return 0;
		}
		size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst) + add_len, sizeof(unsigned int));
		if (tcph->doff * 4 + size <= 60) {
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_DST;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->dst.data.ip = ip;
			tcpopt->dst.data.port = port;
			if (add_len == sizeof(unsigned int)) {
				set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->tcp_seq_offset));
				tcpopt->header.type |= NATCAP_TCPOPT_CONFUSION;
			}
			return 0;
		}
		return -1;
	} else {
		if (ns && (NS_NATCAP_CONFUSION & ns->status)) {
			int add_len = 0;
			if (tcph->syn && tcph->ack) {
				add_len += sizeof(unsigned int);
				if (ns->tcp_ack_offset == 0) {
					ns->tcp_ack_offset = sizeof(htp_confusion_rsp) / 4 + jiffies % (sizeof(htp_confusion_rsp) / 8);
				}
				size = ALIGN(sizeof(struct natcap_TCPOPT_header) + add_len, sizeof(unsigned int));
				tcpopt->header.type = NATCAP_TCPOPT_TYPE_ADD;
				tcpopt->header.opcode = TCPOPT_NATCAP;
				tcpopt->header.opsize = size;
				if (add_len == sizeof(unsigned int)) {
					set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->tcp_ack_offset));
					tcpopt->header.type |= NATCAP_TCPOPT_CONFUSION;
				}
				return 0;
			}
		}
		tcpopt->header.type = NATCAP_TCPOPT_TYPE_NONE;
		tcpopt->header.opsize = 0;
		return 0;
	}
}

int natcap_tcp_encode(struct nf_conn *ct, struct sk_buff *skb, const struct natcap_TCPOPT *tcpopt, int dir)
{
	struct natcap_session *ns = natcap_session_get(ct);
	struct iphdr *iph;
	struct tcphdr *tcph;
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_NONE) {
		goto do_encode;
	}

	if (tcph->doff * 4 + tcpopt->header.opsize > 60)
		return -1;
	if (skb_tailroom(skb) < tcpopt->header.opsize && pskb_expand_head(skb, 0, tcpopt->header.opsize, GFP_ATOMIC)) {
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
	if (ns) {
		if (dir == IP_CT_DIR_ORIGINAL) {
			if (ns->tcp_seq_offset) {
				spin_lock_bh(&ct->lock);
				if (ct->proto.tcp.last_seq == 0 || ct->proto.tcp.last_seq == ntohl(tcph->seq)) {
					ct->proto.tcp.seen[0].td_end -= ns->tcp_seq_offset;
					ct->proto.tcp.seen[0].td_maxend -= ns->tcp_seq_offset;
				}
				spin_unlock_bh(&ct->lock);
				tcph->seq = htonl(ntohl(tcph->seq) - ns->tcp_seq_offset);
			}
			if (ns->tcp_ack_offset) {
				tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - ns->tcp_ack_offset);
			}
		} else {
			if (ns->tcp_ack_offset) {
				spin_lock_bh(&ct->lock);
				if (ct->proto.tcp.last_seq == 0 || ct->proto.tcp.last_seq == ntohl(tcph->seq)) {
					ct->proto.tcp.seen[1].td_end -= ns->tcp_ack_offset;
					ct->proto.tcp.seen[1].td_maxend -= ns->tcp_ack_offset;
				}
				spin_unlock_bh(&ct->lock);
				tcph->seq = htonl(ntohl(tcph->seq) - ns->tcp_ack_offset);
			}
			if (ns->tcp_seq_offset) {
				tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - ns->tcp_seq_offset);
			}
		}
	}

	if (tcpopt->header.encryption) {
		if (!skb_make_writable(skb, skb->len)) {
			return -3;
		}
		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_encode);
	}
	if (tcpopt->header.encryption || NTCAP_TCPOPT_TYPE(tcpopt->header.type) != NATCAP_TCPOPT_TYPE_NONE) {
		skb_rcsum_tcpudp(skb);
	}

	return 0;
}

int natcap_tcp_decode(struct nf_conn *ct, struct sk_buff *skb, struct natcap_TCPOPT *tcpopt, int dir)
{
	struct natcap_session *ns = natcap_session_get(ct);
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_TCPOPT *opt;
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	tcpopt->header.opcode = 0;
	tcpopt->header.opsize = 0;
	tcpopt->header.type = NATCAP_TCPOPT_TYPE_NONE;
	opt = natcap_tcp_decode_header(tcph);
	if (opt == NULL) {
		goto do_decode;
	}

	memcpy((void *)tcpopt, (void *)opt, opt->header.opsize);
	if (mode == FORWARD_MODE || NTCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_CONFUSION) {
		goto done;
	}
	if ((tcpopt->header.type & NATCAP_TCPOPT_SYN)) {
		tcph->seq = TCPOPT_NATCAP;
		tcph->ack_seq = TCPOPT_NATCAP;
		goto do_decode;
	}
	if ((tcpopt->header.type & NATCAP_TCPOPT_CONFUSION) && ns) {
		int add_len = ntohl(get_byte4((unsigned char *)tcpopt + tcpopt->header.opsize - sizeof(unsigned int)));
		if (dir == IP_CT_DIR_ORIGINAL) {
			if (ns->tcp_seq_offset == 0) {
				ns->tcp_seq_offset = add_len;
			}
		} else {
			if (ns->tcp_ack_offset == 0) {
				ns->tcp_ack_offset = add_len;
			}
		}
	}

	offlen = skb_tail_pointer(skb) - (unsigned char *)((void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize);
	BUG_ON(offlen < 0);
	memmove((void *)tcph + sizeof(struct tcphdr), (void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize, offlen);

	tcph->doff = (tcph->doff * 4 - tcpopt->header.opsize) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) - tcpopt->header.opsize);
	skb->len -= tcpopt->header.opsize;
	skb->tail -= tcpopt->header.opsize;

do_decode:
	if (ns) {
		if (dir == IP_CT_DIR_ORIGINAL) {
			if (ns->tcp_seq_offset) {
				spin_lock_bh(&ct->lock);
				if (ct->proto.tcp.last_seq == 0 || ct->proto.tcp.last_seq == ntohl(tcph->seq)) {
					ct->proto.tcp.seen[0].td_end += ns->tcp_seq_offset;
					ct->proto.tcp.seen[0].td_maxend += ns->tcp_seq_offset;
				}
				spin_unlock_bh(&ct->lock);
				tcph->seq = htonl(ntohl(tcph->seq) + ns->tcp_seq_offset);
			}
			if (ns->tcp_ack_offset) {
				tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + ns->tcp_ack_offset);
			}
		} else {
			if (ns->tcp_ack_offset) {
				spin_lock_bh(&ct->lock);
				if (ct->proto.tcp.last_seq == 0 || ct->proto.tcp.last_seq == ntohl(tcph->seq)) {
					ct->proto.tcp.seen[1].td_end += ns->tcp_ack_offset;
					ct->proto.tcp.seen[1].td_maxend += ns->tcp_ack_offset;
				}
				spin_unlock_bh(&ct->lock);
				tcph->seq = htonl(ntohl(tcph->seq) + ns->tcp_ack_offset);
			}
			if (ns->tcp_seq_offset) {
				tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + ns->tcp_seq_offset);
			}
		}
	}

	if (tcpopt->header.encryption) {
		if (!skb_make_writable(skb, skb->len)) {
			return -3;
		}
		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_decode);
	}
	if (tcpopt->header.encryption || NTCAP_TCPOPT_TYPE(tcpopt->header.type) != NATCAP_TCPOPT_TYPE_NONE) {
		skb_rcsum_tcpudp(skb);
	}
done:
	return 0;
}

int natcap_tcp_encode_fwdupdate(struct sk_buff *skb, struct tcphdr *tcph, const struct tuple *server)
{
	struct natcap_TCPOPT *tcpopt;
	__be32 target_ip = 0;
	u16 oldopt, newopt;

	tcpopt = natcap_tcp_decode_header(tcph);
	if (tcpopt == NULL) {
		return -1;
	}

	if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_ALL) {
		target_ip = tcpopt->all.data.ip;
	} else if (NTCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_DST) {
		target_ip = tcpopt->dst.data.ip;
	} else {
		return -1;
	}

	oldopt = (tcpopt->header.type << 8) | tcpopt->header.encryption;

	if (target_ip == server->ip) {
		tcpopt->header.type |= NATCAP_TCPOPT_TARGET;
	} else {
		tcpopt->header.type &= ~NATCAP_TCPOPT_TARGET;
	}

	newopt = (tcpopt->header.type << 8) | tcpopt->header.encryption;

	if (oldopt != newopt) {
		inet_proto_csum_replace2(&tcph->check, skb, htons(oldopt), htons(newopt), false);
		return 1;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_add_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_add_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_del_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_del_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_src_mac(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_UNSPEC;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATCAP_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

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

#define __ALIGN_64BITS 8

int natcap_session_init(struct nf_conn *ct, gfp_t gfp)
{
	struct natcap_session *ns;
	struct nf_ct_ext *old, *new;
	struct nf_conn_nat *nat = NULL;
	unsigned int newoff, newlen = 0;
	size_t alloc_size;
	size_t var_alloc_len = ALIGN(sizeof(struct natcap_session), __ALIGN_64BITS);

	if (natcap_session_get(ct) != NULL) {
		return 0;
	}

	if (nf_ct_is_confirmed(ct)) {
		return -1;
	}
	if (ct->ext && !!ct->ext->offset[NF_CT_EXT_NAT]) {
		return -1;
	}

	if (ct->ext) {
		old = ct->ext;
		newoff = ALIGN(old->len, __ALIGN_64BITS);
		newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
		alloc_size = ALIGN(newlen + sizeof(struct nf_conn_nat), __ALIGN_64BITS);

		if (newlen > 255u) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "ct->ext no space left (old->len=%u, newlen=%u)\n", DEBUG_ARG_PREFIX, old->len, newlen);
			return -1;
		}

		new = __krealloc(old, alloc_size, gfp);
		if (!new) {
			return -1;
		}
		new->len = newlen;
		memset((void *)new + newoff, 0, newlen - newoff);

		if (new != old) {
			kfree_rcu(old, rcu);
			rcu_assign_pointer(ct->ext, new);
		}

		nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, gfp);
		if (nat == NULL) {
			return -1;
		}
	} else {
		newoff = ALIGN(sizeof(struct nf_ct_ext), __ALIGN_64BITS);
		newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
		alloc_size = ALIGN(newlen + sizeof(struct nf_conn_nat), __ALIGN_64BITS);

		new = kzalloc(alloc_size, gfp);
		if (!new) {
			return -1;
		}
		new->len = newlen;
		ct->ext = new;

		nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, gfp);
		if (nat == NULL) {
			return -1;
		}
	}

	ns = (struct natcap_session *)((void *)nat - ALIGN(sizeof(struct natcap_session), __ALIGN_64BITS));
	ns->magic = NATCAP_MAGIC;

	return 0;
}

struct natcap_session *natcap_session_get(struct nf_conn *ct)
{
	struct nf_conn_nat *nat;
	struct natcap_session *ns = NULL;

	nat = nfct_nat(ct);
	if (!nat) {
		return NULL;
	}

	ns = (struct natcap_session *)((void *)nat - ALIGN(sizeof(struct natcap_session), __ALIGN_64BITS));
	if (ns->magic != NATCAP_MAGIC)
		return NULL;

	return ns;
}

int natcap_udp_to_tcp_pack(struct sk_buff *skb, struct natcap_session *ns, int m)
{
	struct iphdr *iph;
	void *l4;

	iph = ip_hdr(skb);

	if (!ns) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "ns is NULL\n", DEBUG_ARG_PREFIX);
		return -EINVAL;
	}

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "skb_make_writable failed\n", DEBUG_ARG_PREFIX);
		return -ENOMEM;
	}

	if (skb_tailroom(skb) < sizeof(struct tcphdr) - sizeof(struct udphdr) && pskb_expand_head(skb, 0, sizeof(struct tcphdr) - sizeof(struct udphdr), GFP_ATOMIC)) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "pskb_expand_head failed\n", DEBUG_ARG_PREFIX);
		return -ENOMEM;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	memmove((void *)UDPH(l4) + sizeof(struct tcphdr), (void *)UDPH(l4) + sizeof(struct udphdr), skb_tail_pointer(skb) - (unsigned char *)UDPH(l4) - sizeof(struct udphdr));
	iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct tcphdr) - sizeof(struct udphdr));
	skb->len += sizeof(struct tcphdr) - sizeof(struct udphdr);
	skb->tail += sizeof(struct tcphdr) - sizeof(struct udphdr);
	iph->protocol = IPPROTO_TCP;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	TCPH(l4)->seq = ns->current_seq == 0 ? htonl(jiffies) : htonl(ns->current_seq);
	TCPH(l4)->ack_seq = (m == 0 && ns->current_seq == 0) ? 0 : htonl(ns->foreign_seq);
	TCPH(l4)->res1 = 0;
	TCPH(l4)->doff = 5;
	TCPH(l4)->syn = ns->current_seq == 0 ? 1 : 0;
	TCPH(l4)->rst = 0;
	TCPH(l4)->psh = 0;
	TCPH(l4)->ack = (m == 0 && ns->current_seq == 0) ? 0 : 1;
	TCPH(l4)->fin = 0;
	TCPH(l4)->urg = 0;
	TCPH(l4)->ece = 0;
	TCPH(l4)->cwr = 0;
	TCPH(l4)->window = htons(ntohs(iph->id) ^ (ntohl(TCPH(l4)->seq) & 0xffff) ^ (ntohl(TCPH(l4)->ack_seq) & 0xffff));
	TCPH(l4)->check = 0;
	TCPH(l4)->urg_ptr = 0;

	skb_rcsum_tcpudp(skb);

	ns->current_seq = ntohl(TCPH(l4)->seq) + ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct tcphdr);
	return 0;
}

struct cone_nat_session *cone_nat_array = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_common_cone_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_common_cone_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_common_cone_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_common_cone_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct cone_nat_session cns;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}
	if ((IPS_NATCAP & ct->status)) {
		return NF_ACCEPT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	if (nf_nat_initialized(ct, IP_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
#else
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
#endif

	if (cone_nat_array && IP_SET_test_dst_ip(state, in, out, skb, "natcap_wan_ip") > 0) {
		memcpy(&cns, &cone_nat_array[ntohs(UDPH(l4)->dest)], sizeof(cns));
		if (cns.ip != 0 && cns.port != 0) {
			if (natcap_dnat_setup(ct, cns.ip, cns.port) != NF_ACCEPT) {
				NATCAP_ERROR("(CCI)" DEBUG_UDP_FMT ": do mapping failed, target=%pI4:%u @port=%u\n", DEBUG_UDP_ARG(iph,l4), &cns.ip, ntohs(cns.port), ntohs(UDPH(l4)->dest));
			}
			NATCAP_INFO("(CCI)" DEBUG_UDP_FMT ": do mapping, target=%pI4:%u @port=%u\n", DEBUG_UDP_ARG(iph,l4), &cns.ip, ntohs(cns.port), ntohs(UDPH(l4)->dest));
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_common_cone_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_common_cone_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_common_cone_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_common_cone_out_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct cone_nat_session cns;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (cone_nat_array &&
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53) &&
			ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53) &&
			((IPS_NATCAP & ct->status) ||
			 (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip != iph->saddr &&
			  IP_SET_test_src_ip(state, in, out, skb, "natcap_wan_ip") > 0))) {

		memcpy(&cns, &cone_nat_array[ntohs(UDPH(l4)->source)], sizeof(cns));
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != cns.ip ||
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port != cns.port) {

			NATCAP_INFO("(CCO)" DEBUG_UDP_FMT ": update mapping from %pI4:%u to %pI4:%u @port=%u\n", DEBUG_UDP_ARG(iph,l4),
					&cns.ip, ntohs(cns.port),
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
					ntohs(UDPH(l4)->source));

			cns.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			cns.port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
			memcpy(&cone_nat_array[ntohs(UDPH(l4)->source)], &cns, sizeof(cns));
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops common_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_common_cone_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natcap_common_cone_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 1,
	},
};

int natcap_common_init(void)
{
	int ret = 0;

	dnatcap_map_init();
	cone_nat_array = vmalloc(sizeof(struct cone_nat_session) * 65536);
	if (cone_nat_array == NULL) {
		return -ENOMEM;
	}
	memset(cone_nat_array, 0, sizeof(struct cone_nat_session) * 65536);

	need_conntrack();
	ret = nf_register_hooks(common_hooks, ARRAY_SIZE(common_hooks));
	if (ret != 0) {
		vfree(cone_nat_array);
	}
	return ret;
}

void natcap_common_exit(void)
{
	nf_unregister_hooks(common_hooks, ARRAY_SIZE(common_hooks));

	if (cone_nat_array) {
		void *tmp = cone_nat_array;
		cone_nat_array = NULL;
		synchronize_rcu();
		vfree(tmp);
	}
}
