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
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include "natcap_common.h"
#include "natcap_client.h"
#include "natcap_server.h"
#include "natcap_knock.h"
#include "natcap_peer.h"

unsigned short natcap_udp_seq_lock = 0;
unsigned short natcap_ignore_forward = 0;
unsigned int natcap_ignore_mask = 0x00000000;
unsigned int natcap_max_pmtu = 1440;

unsigned int natcap_touch_timeout = 32;

unsigned short natcap_redirect_port = 0;
unsigned short natcap_client_redirect_port = 0;

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
	[MIXING_MODE] = "CLIENT+SERVER",
	[KNOCK_MODE] = "KNOCK",
	[PEER_MODE] = "PEER",
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
#if defined(skb_frag_foreach_page)
			u32 p_off, p_len, copied;
			struct page *p;
			u8 *vaddr;

			if (copy > len)
				copy = len;
			skb_frag_foreach_page(frag,
			                      skb_frag_off(frag) + offset - start,
			                      copy, p, p_off, p_len, copied) {
				vaddr = kmap_atomic(p);
				update(vaddr + p_off, p_len);
				kunmap_atomic(vaddr);
				pos += p_len;
			}
			if (!(len -= copy))
				return;
			offset += copy;
#else
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
#endif
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

	tcpopt->header.subtype = 0;
	if ((status & NATCAP_NEED_ENC))
		tcpopt->header.encryption = 1;
	else
		tcpopt->header.encryption = 0;

	if ((status & NATCAP_CLIENT_MODE)) {
		int add_len = 0;
		//not syn
		if (!(tcph->syn && !tcph->ack)) {
			if ((NS_NATCAP_AUTH & ns->n.status)) {
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
				short_set_bit(NS_NATCAP_AUTH_BIT, &ns->n.status);
				return 0;
			}
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_NONE;
			tcpopt->header.opsize = 0;
			return 0;
		}
		//syn
		if (http_confusion && ns && !(NS_NATCAP_TCPUDPENC & ns->n.status) && (NS_NATCAP_ENC & ns->n.status)) {
			add_len += sizeof(unsigned int);
			if (ns->n.tcp_seq_offset == 0) {
				ns->n.tcp_seq_offset = sizeof(htp_confusion_req) / 2 + jiffies % (sizeof(htp_confusion_req) / 4);
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
				set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->n.tcp_seq_offset));
				tcpopt->header.type |= NATCAP_TCPOPT_CONFUSION;
			}
			short_set_bit(NS_NATCAP_AUTH_BIT, &ns->n.status);
			if (iph->daddr == ip && knock_flood) {
				tcpopt->all.data.ip = PEER_XSYN_MASK_ADDR;
			}
			return 0;
		}
		if (user_mark_natcap_mask != 0) {
			/* we need u_hash in first packet */
			return -1;
		}
		size = ALIGN(sizeof(struct natcap_TCPOPT_header) + sizeof(struct natcap_TCPOPT_dst) + add_len, sizeof(unsigned int));
		if (tcph->doff * 4 + size <= 60) {
			tcpopt->header.type = NATCAP_TCPOPT_TYPE_DST;
			tcpopt->header.opcode = TCPOPT_NATCAP;
			tcpopt->header.opsize = size;
			tcpopt->dst.data.ip = ip;
			tcpopt->dst.data.port = port;
			if (add_len == sizeof(unsigned int)) {
				set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->n.tcp_seq_offset));
				tcpopt->header.type |= NATCAP_TCPOPT_CONFUSION;
			}
			if (iph->daddr == ip && knock_flood) {
				tcpopt->dst.data.ip = PEER_XSYN_MASK_ADDR;
			}
			return 0;
		}
		return -1;
	} else {
		if (ns && (NS_NATCAP_CONFUSION & ns->n.status)) {
			int add_len = 0;
			if (tcph->syn && tcph->ack) {
				add_len += sizeof(unsigned int);
				if (ns->n.tcp_ack_offset == 0) {
					ns->n.tcp_ack_offset = sizeof(htp_confusion_rsp) / 4 + jiffies % (sizeof(htp_confusion_rsp) / 8);
				}
				size = ALIGN(sizeof(struct natcap_TCPOPT_header) + add_len, sizeof(unsigned int));
				tcpopt->header.type = NATCAP_TCPOPT_TYPE_ADD;
				tcpopt->header.opcode = TCPOPT_NATCAP;
				tcpopt->header.opsize = size;
				if (add_len == sizeof(unsigned int)) {
					set_byte4((unsigned char *)tcpopt + size - add_len, htonl(ns->n.tcp_ack_offset));
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
	struct iphdr *iph;
	struct tcphdr *tcph;
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_NONE) {
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
	if (tcpopt->header.encryption) {
		if (!skb_make_writable(skb, skb->len)) {
			return -3;
		}
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_encode);
	}
	if (tcpopt->header.encryption || NATCAP_TCPOPT_TYPE(tcpopt->header.type) != NATCAP_TCPOPT_TYPE_NONE) {
		skb_rcsum_tcpudp(skb);
	}

	return 0;
}

int natcap_tcp_decode(struct nf_conn *ct, struct sk_buff *skb, struct natcap_TCPOPT *tcpopt, int dir)
{
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
	if (NATCAP_TCPOPT_TYPE(opt->header.type) == NATCAP_TCPOPT_TYPE_CONFUSION) {
		goto done;
	}
	if ((tcpopt->header.type & NATCAP_TCPOPT_SYN)) {
		tcph->seq = TCPOPT_NATCAP;
		tcph->ack_seq = TCPOPT_NATCAP;
		goto do_decode;
	}

	offlen = skb_tail_pointer(skb) - (unsigned char *)((void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize);
	BUG_ON(offlen < 0);
	memmove((void *)tcph + sizeof(struct tcphdr), (void *)tcph + sizeof(struct tcphdr) + tcpopt->header.opsize, offlen);

	tcph->doff = (tcph->doff * 4 - tcpopt->header.opsize) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) - tcpopt->header.opsize);
	skb->len -= tcpopt->header.opsize;
	skb->tail -= tcpopt->header.opsize;

do_decode:
	if (tcpopt->header.encryption) {
		if (!skb_make_writable(skb, skb->len)) {
			return -3;
		}
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

		skb_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_decode);
	}
	if (tcpopt->header.encryption || NATCAP_TCPOPT_TYPE(tcpopt->header.type) != NATCAP_TCPOPT_TYPE_NONE) {
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

	if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_ALL) {
		target_ip = tcpopt->all.data.ip;
	} else if (NATCAP_TCPOPT_TYPE(tcpopt->header.type) == NATCAP_TCPOPT_TYPE_DST) {
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
int ip_set_test_src_ipport(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_src_ipport(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
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
	opt.dim = IPSET_DIM_TWO;
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
int __ip_set_test_src_ipport(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name, __be32 *ip_addr, __be32 ip, __be16 *port_addr, __be16 port)
#else
int __ip_set_test_src_ipport(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name, __be32 *ip_addr, __be32 ip, __be16 *port_addr, __be16 port)
#endif
{
	int ret = 0;
	__be32 old_ip = *ip_addr;
	__be16 old_port = *port_addr;
	*port_addr = port;
	*ip_addr = ip;
	ret = IP_SET_test_src_ipport(state, in, out, skb, ip_set_name);
	*port_addr = old_port;
	*ip_addr = old_ip;
	return ret;
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
int ip_set_test_dst_netport(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_dst_netport(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
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
	opt.dim = IPSET_DIM_TWO;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int __ip_set_test_src_port(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name, __be16 *port_addr, __be16 port)
#else
int __ip_set_test_src_port(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name, __be16 *port_addr, __be16 port)
#endif
{
	int ret = 0;
	__be16 old_port = *port_addr;
	*port_addr = port;
	ret = IP_SET_test_src_port(state, in, out, skb, ip_set_name);
	*port_addr = old_port;
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int __ip_set_test_dst_port(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name, __be16 *port_addr, __be16 port)
#else
int __ip_set_test_dst_port(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name, __be16 *port_addr, __be16 port)
#endif
{
	int ret = 0;
	__be16 old_port = *port_addr;
	*port_addr = port;
	ret = IP_SET_test_dst_port(state, in, out, skb, ip_set_name);
	*port_addr = old_port;
	return ret;
}

static unsigned int __natcap_nat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto, int type)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, type == 0 ? IP_NAT_MANIP_DST : IP_NAT_MANIP_SRC)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, type == 0 ? IP_NAT_MANIP_DST : IP_NAT_MANIP_SRC);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct nf_nat_ipv4_range range;
	if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.ip = addr;
	range.max_addr.ip = addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#else
	struct nf_nat_range2 range;
	if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.ip = addr;
	range.max_addr.ip = addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	memset(&range.base_proto, 0, sizeof(range.base_proto));
	return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#endif
}

unsigned int natcap_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
	return __natcap_nat_setup(ct, addr, man_proto, 0);
}

unsigned int natcap_snat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
	return __natcap_nat_setup(ct, addr, man_proto, 1);
}

u32 cone_snat_hash(__be32 ip, __be16 port, __be32 wan_ip)
{
	static u32 cone_snat_hashrnd __read_mostly;

	net_get_random_once(&cone_snat_hashrnd, sizeof(cone_snat_hashrnd));

	return jhash_3words(ip, port, wan_ip, cone_snat_hashrnd);
}

#if defined(nf_ct_ext_add)
void *compat_nf_ct_ext_add(struct nf_conn *ct, int id, gfp_t gfp)
{
	return __nf_ct_ext_add_length(ct, id, 0, gfp);
}
#else
#define compat_nf_ct_ext_add nf_ct_ext_add
#endif

#define NATCAP_MAX_OFF 512u
#define __ALIGN_64BITS 8
#define __ALIGN_64BYTES (__ALIGN_64BITS * 8)
#define NATCAP_FACTOR (__ALIGN_64BITS * 2)

int natcap_session_init(struct nf_conn *ct, gfp_t gfp)
{
	unsigned int i;
	struct nat_key_t *nk = NULL;
	struct nf_ct_ext *old, *new;
	unsigned int nkoff, newoff, newlen = 0;
	size_t alloc_size;
	size_t var_alloc_len = ALIGN(sizeof(struct natcap_session), __ALIGN_64BITS);

	if (nf_ct_is_confirmed(ct)) {
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE((((struct nf_ct_ext *)0)->offset)); i++) {
		if (!nf_ct_ext_exist(ct, i)) compat_nf_ct_ext_add(ct, i, gfp);
	}

	if (!ct->ext) {
		return -1;
	}

	old = ct->ext;
	nkoff = ALIGN(old->len, __ALIGN_64BYTES);
	newoff = ALIGN(nkoff + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS), __ALIGN_64BITS);

	if (old->len * NATCAP_FACTOR <= NATCAP_MAX_OFF) {
		nk = (struct nat_key_t *)((void *)old + old->len * NATCAP_FACTOR);
		if (nk->magic == NATCAP_MAGIC && nk->ext_magic == (((unsigned long)ct) & 0xffffffff)) {
			if (nk->natcap_off) {
				//natcap exist
				return 0;
			}
			nkoff = old->len * NATCAP_FACTOR;
			newoff = ALIGN(nk->len, __ALIGN_64BITS);
		} else {
			nk = NULL;
		}
	}

	if (nkoff > NATCAP_MAX_OFF) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "realloc ct->ext->len > %u not supported!\n", DEBUG_ARG_PREFIX, NATCAP_MAX_OFF);
		return -1;
	}

	newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
	alloc_size = ALIGN(newlen, __ALIGN_64BITS);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
	new = __krealloc(old, alloc_size, gfp);
#else
	new = krealloc(old, alloc_size, gfp);
#endif
	if (!new) {
		NATCAP_ERROR(DEBUG_FMT_PREFIX "__krealloc size=%u failed!\n", DEBUG_ARG_PREFIX, (unsigned int)alloc_size);
		return -1;
	}
	memset((void *)new + newoff, 0, newlen - newoff);
	if (nk == NULL) {
		nk = (struct nat_key_t *)((void *)new + nkoff);
		memset((void *)nk, 0, newoff - nkoff);
	}

	if (new != old) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		kfree_rcu(old, rcu);
		ct->ext = new;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
		kfree_rcu(old, rcu);
		rcu_assign_pointer(ct->ext, new);
#else
		ct->ext = new;
#endif
	}

	new->len = nkoff / NATCAP_FACTOR;
	nk = (struct nat_key_t *)((void *)new + nkoff);
	nk->magic = NATCAP_MAGIC;
	nk->ext_magic = (unsigned long)ct & 0xffffffff;
	nk->len = newlen;
	nk->natcap_off = newoff;

	return 0;
}

struct natcap_session *natcap_session_get(struct nf_conn *ct)
{
	struct nat_key_t *nk;
	struct natcap_session *ns = NULL;

	if (!ct->ext) {
		return NULL;
	}

	if (ct->ext->len * NATCAP_FACTOR > NATCAP_MAX_OFF) {
		return NULL;
	}

	nk = (struct nat_key_t *)((void *)ct->ext + ct->ext->len * NATCAP_FACTOR);
	if (nk->magic != NATCAP_MAGIC || nk->ext_magic != (((unsigned long)ct) & 0xffffffff)) {
		return NULL;
	}

	if (nk->natcap_off == 0) {
		return NULL;
	}

	ns = (struct natcap_session *)((void *)ct->ext + nk->natcap_off);

	return ns;
}

void natcap_clone_timeout(struct nf_conn *dst, struct nf_conn *src)
{
	unsigned long extra_jiffies;
	unsigned long current_jiffies = jiffies;

	if (!nf_ct_is_confirmed(src)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		extra_jiffies = src->timeout.expires;
#else
		extra_jiffies = src->timeout;
#endif
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		extra_jiffies = src->timeout.expires - current_jiffies;
#else
		extra_jiffies = src->timeout - current_jiffies;
#endif
	}

	if (!nf_ct_is_confirmed(dst)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		dst->timeout.expires = extra_jiffies;
#else
		dst->timeout = extra_jiffies;
#endif
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		extra_jiffies += current_jiffies;
		if (extra_jiffies - dst->timeout.expires >= HZ) {
			mod_timer_pending(&dst->timeout, extra_jiffies);
		}
#else
		extra_jiffies += current_jiffies;
		dst->timeout = extra_jiffies;
#endif
	}
}

int natcap_udp_to_tcp_pack(struct sk_buff *skb, struct natcap_session *ns, int m, struct sk_buff **ping_skb)
{
	struct nf_conn *ct, *ct2;
	enum ip_conntrack_info ctinfo;
	int ret = NF_DROP;
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

	TCPH(l4)->seq = ns->n.current_seq == 0 ? htonl(jiffies) : htonl(ns->n.current_seq);
	TCPH(l4)->ack_seq = (m == 0 && ns->n.current_seq == 0) ? 0 : htonl(ns->n.foreign_seq);
	tcp_flag_word(TCPH(l4)) = (ns->n.current_seq == 0 ? TCP_FLAG_SYN : 0) | ((m == 0 && ns->n.current_seq == 0) ? 0 : TCP_FLAG_ACK);
	TCPH(l4)->res1 = 0;
	TCPH(l4)->doff = 5;
	TCPH(l4)->window = htons(ntohs(iph->id) ^ (ntohl(TCPH(l4)->seq) & 0xffff) ^ (ntohl(TCPH(l4)->ack_seq) & 0xffff));
	TCPH(l4)->check = 0;
	TCPH(l4)->urg_ptr = 0;
	if (natcap_udp_seq_lock == 1 && (ns->ping.lock != 2 || TCPH(l4)->syn)) {
		ns->ping.lock = 2;
		TCPH(l4)->urg_ptr = __constant_htons(1);
	}

	if (ns->ping.saddr) {
		iph->saddr = ns->ping.saddr;
		iph->daddr = ns->ping.daddr;
		TCPH(l4)->source = ns->ping.source;
		TCPH(l4)->dest = ns->ping.dest;
	}

	skb_rcsum_tcpudp(skb);

	if (ns->ping.lock == 0 || TCPH(l4)->syn)
		ns->n.current_seq = ntohl(TCPH(l4)->seq) + ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(struct tcphdr);

	ct = nf_ct_get(skb, &ctinfo);
	skb_nfct_reset(skb);
	nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, skb);
	ct2 = nf_ct_get(skb, &ctinfo);
	if (!ct || !ct2) {
		return -EINVAL;
	}
	natcap_clone_timeout(ct2, ct);
	if (!nf_ct_is_confirmed(ct2) && !ct2->master) {
		nf_conntrack_get(&ct->ct_general);
		ct2->master = ct;
	}
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return -EINVAL;
	}

	if (!TCPH(l4)->syn && m == 0 && ping_skb) {
		if (!(((ns->n.current_seq / 1024) % 8 == 0) ||
		        (ns->ping.stage == 0 && uintmindiff(ns->ping.jiffies, jiffies) > 3 * HZ) ||
		        (ns->ping.stage == 1 && uintmindiff(ns->ping.jiffies, jiffies) > 1 * HZ))) {
			return 0;
		}
		if ((ns->ping.stage == 1 && uintmindiff(ns->ping.jiffies, jiffies) > 3 * HZ) || ns->ping.lock == 1) {
			//timeout, ping syn
			int offset, add_len;
			offset = sizeof(struct iphdr) + sizeof(struct tcphdr) + 16 + TCPOLEN_MSS - (skb_headlen(skb) + skb_tailroom(skb));
			add_len = offset < 0 ? 0 : offset;
			offset += skb_tailroom(skb);
			*ping_skb = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_len, GFP_ATOMIC);
			if (!(*ping_skb)) {
				NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
				return 0;
			}
			(*ping_skb)->tail += offset;
			(*ping_skb)->len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 16 + TCPOLEN_MSS;

			iph = ip_hdr(*ping_skb);
			l4 = (void *)iph + iph->ihl * 4;

			iph->tot_len = htons((*ping_skb)->len);
			iph->protocol = IPPROTO_TCP;
			iph->saddr = ns->ping.saddr ? ns->ping.saddr : iph->saddr;
			iph->daddr = ns->ping.saddr ? ns->ping.daddr : iph->daddr;
			iph->ttl = 0x80;
			iph->id = htons(jiffies);
			iph->frag_off = 0x0;

			if (ns->ping.lock == 0) {
				ns->ping.jiffies = jiffies;
				ns->ping.stage = 0;
				ns->ping.lock = 1;
				TCPH(l4)->source = htons(prandom_u32() % (65536 - 1024) + 1024);
			}
			TCPH(l4)->dest = ns->ping.saddr ? ns->ping.dest : TCPH(l4)->dest;

			TCPH(l4)->seq = htonl(ns->n.current_seq - 1);
			TCPH(l4)->ack_seq = 0;
			tcp_flag_word(TCPH(l4)) = TCP_FLAG_SYN;
			TCPH(l4)->res1 = 0;
			TCPH(l4)->doff = (sizeof(struct tcphdr) + 16 + TCPOLEN_MSS) / 4;
			TCPH(l4)->window = htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff))));
			TCPH(l4)->check = 0;
			TCPH(l4)->urg_ptr = 0;

			set_byte1(l4 + sizeof(struct tcphdr), TCPOPT_NATCAP);
			set_byte1(l4 + sizeof(struct tcphdr) + 1, 16);
			set_byte2(l4 + sizeof(struct tcphdr) + 2, 0);
			set_byte4(l4 + sizeof(struct tcphdr) + 4, ns->ping.remote_saddr);
			set_byte4(l4 + sizeof(struct tcphdr) + 4 + 4, ns->ping.remote_daddr);
			set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4, ns->ping.remote_source);
			set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2, ns->ping.remote_dest);
			set_byte1(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2, TCPOPT_MSS);
			set_byte1(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2 + 1, TCPOLEN_MSS);
			set_byte2(l4 + sizeof(struct tcphdr) + 4 + 4 + 4 + 2 + 2 + 1 + 1, ntohs(natcap_max_pmtu - 40));

			//ns->n.current_seq = ntohl(TCPH(l4)->seq);
			ns->ping.saddr = iph->saddr;
			ns->ping.daddr = iph->daddr;
			ns->ping.source = TCPH(l4)->source;
			ns->ping.dest = TCPH(l4)->dest;

			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(*ping_skb);

			NATCAP_WARN(DEBUG_FMT_PREFIX "ping: timeout new syn %pI4:%u->%pI4:%u tuple[%pI4:%u->%pI4:%u]\n", DEBUG_ARG_PREFIX,
			            &iph->saddr, ntohs(TCPH(l4)->source), &iph->daddr, ntohs(TCPH(l4)->dest),
			            &ns->ping.remote_saddr, ntohs(ns->ping.remote_source), &ns->ping.remote_daddr, ntohs(ns->ping.remote_dest));

			skb_nfct_reset(*ping_skb);
			nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, *ping_skb);
			ct2 = nf_ct_get(*ping_skb, &ctinfo);
			if (!ct || !ct2) {
				consume_skb(*ping_skb);
				*ping_skb = NULL;
				return -EINVAL;
			}
			natcap_clone_timeout(ct2, ct);
			if (!nf_ct_is_confirmed(ct2) && !ct2->master) {
				nf_conntrack_get(&ct->ct_general);
				ct2->master = ct;
			}
			ret = nf_conntrack_confirm(*ping_skb);
			if (ret != NF_ACCEPT) {
				consume_skb(*ping_skb);
				*ping_skb = NULL;
				return -EINVAL;
			}
			return 0;
		}

		//ping
		if (ns->ping.stage == 0)
			ns->ping.jiffies = jiffies;
		ns->ping.stage = 1;
		*ping_skb = skb_copy(skb, GFP_ATOMIC);
		if ((*ping_skb) == NULL) {
			NATCAP_ERROR(DEBUG_FMT_PREFIX "alloc_skb fail\n", DEBUG_ARG_PREFIX);
			return 0;
		}

		iph = ip_hdr(*ping_skb);
		l4 = (void *)iph + iph->ihl * 4;
		(*ping_skb)->len -= ntohs(iph->tot_len) - (iph->ihl * 4 + sizeof(struct tcphdr));
		iph->tot_len = ntohs(iph->ihl * 4 + sizeof(struct tcphdr));
		iph->id = jiffies;
		TCPH(l4)->window = htons(~(ntohs(iph->id) ^ ((ntohl(TCPH(l4)->seq) & 0xffff) | (ntohl(TCPH(l4)->ack_seq) & 0xffff))));

		skb_rcsum_tcpudp(*ping_skb);

		NATCAP_INFO(DEBUG_FMT_PREFIX "ping: send %pI4:%u->%pI4:%u\n", DEBUG_ARG_PREFIX,
		            &iph->saddr, ntohs(TCPH(l4)->source), &iph->daddr, ntohs(TCPH(l4)->dest));

	}

	return 0;
}

struct cone_nat_session *cone_nat_array = NULL;
struct cone_snat_session *cone_snat_array = NULL;

void cone_nat_cleanup(void)
{
	if (cone_nat_array)
		memset(cone_nat_array, 0, sizeof(struct cone_nat_session) * 65536);
	if (cone_snat_array)
		memset(cone_snat_array, 0, sizeof(struct cone_snat_session) * 32768);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_common_cone_in_hook(unsigned int hooknum,
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
	struct natcap_session *ns;
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
	if ((IPS_NATCAP_CONE & ct->status)) {
		xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
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
#endif

	if (ipv4_is_loopback(iph->daddr) || ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr) || ipv4_is_zeronet(iph->daddr)) {
		return NF_ACCEPT;
	}

	//alloc natcap_session
	ns = natcap_session_in(ct);
	if (!ns) {
		NATCAP_DEBUG("(CCI)" DEBUG_UDP_FMT ": natcap_session_in failed\n", DEBUG_UDP_ARG(iph,l4));
		return NF_ACCEPT;
	}

	if (cone_nat_array && cone_snat_array &&
	        IP_SET_test_dst_ip(state, in, out, skb, "cone_wan_ip") > 0) {
		if (IP_SET_test_dst_port(state, in, out, skb, "cone_nat_unused_port") > 0 &&
		        !is_natcap_server(iph->saddr)) {
			return NF_ACCEPT;
		}

		memcpy(&cns, &cone_nat_array[ntohs(UDPH(l4)->dest)], sizeof(cns));
		if (cns.ip != 0 && cns.port != 0) {
			if (natcap_dnat_setup(ct, cns.ip, cns.port) != NF_ACCEPT) {
				NATCAP_ERROR("(CCI)" DEBUG_UDP_FMT ": do mapping failed, target=%pI4:%u @port=%u\n",
				             DEBUG_UDP_ARG(iph,l4), &cns.ip, ntohs(cns.port), ntohs(UDPH(l4)->dest));
				return NF_ACCEPT;
			}

			NATCAP_INFO("(CCI)" DEBUG_UDP_FMT ": do mapping, target=%pI4:%u @port=%u\n",
			            DEBUG_UDP_ARG(iph,l4), &cns.ip, ntohs(cns.port), ntohs(UDPH(l4)->dest));

			set_bit(IPS_NATCAP_CONE_BIT, &ct->status);
			xt_mark_natcap_set(XT_MARK_NATCAP, &skb->mark);
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_common_cone_out_hook(unsigned int hooknum,
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
	struct natcap_session *ns;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	struct cone_nat_session cns;
	struct cone_snat_session css;

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
	ns = natcap_session_get(ct);
	if (NULL == ns) {
		return NF_ACCEPT;
	}
	if ((ns->n.status & NS_NATCAP_TCPUDPENC)) {
		return NF_ACCEPT;
	}

	if ((IPS_NATCAP_CONE & ct->status)) {
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			return NF_ACCEPT;
		}
		if ((NS_NATCAP_CONESNAT & ns->n.status)) {
			return NF_ACCEPT;
		}
		if (ns->n.cone_pkts >= 8) { /* we try 8 times but not REPLY just bypass */
			return NF_ACCEPT;
		}
		//store original src ip encode
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip ||
		        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all != ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all) {
			int offlen;
			if (skb_tailroom(skb) < 8 && pskb_expand_head(skb, 0, 8, GFP_ATOMIC)) {
				NATCAP_ERROR("(CCO)" DEBUG_UDP_FMT ": pskb_expand_head failed\n", DEBUG_UDP_ARG(iph,l4));
				consume_skb(skb);
				return NF_STOLEN;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			offlen = skb_tail_pointer(skb) - ((unsigned char *)UDPH(l4) + sizeof(struct udphdr));
			BUG_ON(offlen < 0);
			memmove((void *)UDPH(l4) + sizeof(struct udphdr) + 8, (void *)UDPH(l4) + sizeof(struct udphdr), offlen);
			iph->tot_len = htons(ntohs(iph->tot_len) + 8);
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			UDPH(l4)->check = CSUM_MANGLED_0;
			skb->len += 8;
			skb->tail += 8;
			set_byte2((void *)UDPH(l4) + sizeof(struct udphdr), __constant_htons(0xfe9b));
			set_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 2, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);
			set_byte4((void *)UDPH(l4) + sizeof(struct udphdr) + 4, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			/* count the cone_pkts */
			ns->n.cone_pkts++;
		}
		return NF_ACCEPT;
	}

	if (cone_nat_array && cone_snat_array && ntohs(UDPH(l4)->source) >= 1024 &&
	        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all != __constant_htons(53) &&
	        ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all != __constant_htons(53) &&
	        ((IPS_NATCAP & ct->status) ||
	         (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip != iph->saddr &&
	          IP_SET_test_src_ip(state, in, out, skb, "cone_wan_ip") > 0))) {
		unsigned int idx;

		idx = ntohs(UDPH(l4)->source) % 65536;
		memcpy(&cns, &cone_nat_array[idx], sizeof(cns));
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != cns.ip ||
		        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port != cns.port) {

			NATCAP_INFO("(CCO)" DEBUG_UDP_FMT ": update mapping from %pI4:%u to %pI4:%u @port=%u\n", DEBUG_UDP_ARG(iph,l4),
			            &cns.ip, ntohs(cns.port),
			            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
			            ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
			            idx);

			cns.ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			cns.port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
			memcpy(&cone_nat_array[idx], &cns, sizeof(cns));

			idx = cone_snat_hash(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port, iph->saddr) % 32768;
			memcpy(&css, &cone_snat_array[idx], sizeof(css));
			if ((css.wan_ip != iph->saddr || css.wan_port != UDPH(l4)->source) ||
			        css.lan_ip != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip ||
			        css.lan_port != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port) {

				NATCAP_INFO("(CCO)" DEBUG_UDP_FMT ": update SNAT mapping from %pI4:%u=>%pI4:%u to %pI4:%u=>%pI4:%u\n", DEBUG_UDP_ARG(iph,l4),
				            &css.lan_ip, ntohs(css.lan_port),
				            &css.wan_ip, ntohs(css.wan_port),
				            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port),
				            &iph->saddr, ntohs(UDPH(l4)->source));

				css.wan_ip = iph->saddr;
				css.wan_port = UDPH(l4)->source;
				css.lan_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				css.lan_port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
				memcpy(&cone_snat_array[idx], &css, sizeof(css));
			}
		}
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_common_cone_snat_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_common_cone_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natcap_common_cone_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natcap_common_cone_snat_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *in = state->in;
#endif
	const struct net_device *out = state->out;
#endif
	enum ip_conntrack_info ctinfo;
	struct natcap_session *ns;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;

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
	ns = natcap_session_get(ct);
	if (NULL == ns) {
		return NF_ACCEPT;
	}
	if ((ns->n.status & NS_NATCAP_TCPUDPENC)) {
		return NF_ACCEPT;
	}

	if ((IPS_NATCAP_CONE & ct->status)) {
		//restore original src ip decode && do SNAT
		if ((NS_NATCAP_CONECFM & ns->n.status) && ns->n.cone_pkts >= 32) {
			return NF_ACCEPT;
		}

		if (skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 8) &&
		        get_byte2((void *)UDPH(l4) + sizeof(struct udphdr)) == __constant_htons(0xfe9b)) {
			int ret;
			int offlen;
			__be32 ip;
			__be16 port;
			u_int16_t off;
			__be16 *portptr;
			unsigned int range_size, min, i;
			struct nf_conntrack_tuple tuple;
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			port = get_byte2((void *)UDPH(l4) + sizeof(struct udphdr) + 2);
			ip = get_byte4((void *)UDPH(l4) + sizeof(struct udphdr) + 4);

			offlen = skb_tail_pointer(skb) - ((unsigned char *)UDPH(l4) + sizeof(struct udphdr) + 8);
			BUG_ON(offlen < 0);
			memmove((void *)UDPH(l4) + sizeof(struct udphdr), (void *)UDPH(l4) + sizeof(struct udphdr) + 8, offlen);
			iph->tot_len = htons(ntohs(iph->tot_len) - 8);
			UDPH(l4)->len = htons(ntohs(iph->tot_len) - iph->ihl * 4);
			UDPH(l4)->check = CSUM_MANGLED_0;
			skb->len -= 8;
			skb->tail -= 8;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_rcsum_tcpudp(skb);

			if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

			if (ns->n.cone_pkts != 0) {
				NATCAP_WARN("(CCS)" DEBUG_UDP_FMT ": cone_pkts is %u before, maybe out of order\n", DEBUG_UDP_ARG(iph,l4), ns->n.cone_pkts);
				ns->n.cone_pkts = 0;
			}

			if (nf_ct_is_confirmed(ct)) {
				return NF_ACCEPT;
			}

			memset(&tuple, 0, sizeof(tuple));
			tuple.src.u3.ip = ip;
			tuple.src.u.all = port;
			tuple.src.l3num = AF_INET;
			tuple.dst.u3.ip = iph->daddr;
			tuple.dst.u.all = UDPH(l4)->dest;
			tuple.dst.protonum = IPPROTO_UDP;

			portptr = &tuple.src.u.all;

			min = 1024;
			range_size = 65535 - 1024 + 1;
			off = prandom_u32();

			if (nf_nat_used_tuple(&tuple, ct)) {
				for (i = 0; i != range_size; ++off, ++i) {
					*portptr = htons(min + off % range_size);
					if (nf_nat_used_tuple(&tuple, ct))
						continue;
				}
			}
			port = *portptr;

			NATCAP_INFO("(CCS)" DEBUG_UDP_FMT ": SNAT to %pI4:%u\n", DEBUG_UDP_ARG(iph,l4), &ip, ntohs(port));
			ret = natcap_snat_setup(ct, ip, port);
			if (ret != NF_ACCEPT) {
				NATCAP_WARN("(CCS)" DEBUG_UDP_FMT ": natcap_snat_setup failed\n", DEBUG_UDP_ARG(iph,l4));
			}
			short_set_bit(NS_NATCAP_CONESNAT_BIT, &ns->n.status);

		} else if ((NS_NATCAP_CONESNAT & ns->n.status)) {
			short_set_bit(NS_NATCAP_CONECFM_BIT, &ns->n.status);
			ns->n.cone_pkts++;
		}
		return NF_ACCEPT;
	}

	if (nf_ct_is_confirmed(ct)) {
		return NF_ACCEPT;
	}

	if (cone_nat_array && cone_snat_array && IP_SET_test_src_ipport(state, in, out, skb, "cone_nat_unused_dst") <= 0) {
		int ret;
		unsigned int idx;
		const struct rtable *rt;
		__be32 newsrc, nh;
		struct cone_nat_session cns;
		struct cone_snat_session css;

		rt = skb_rtable(skb);
		nh = rt_nexthop(rt, ip_hdr(skb)->daddr);
		newsrc = inet_select_addr(out, nh, RT_SCOPE_UNIVERSE);
		if (!newsrc) {
			NATCAP_WARN("(CCS)" DEBUG_UDP_FMT ": %s ate my IP address\n", DEBUG_UDP_ARG(iph,l4), out->name);
			return NF_ACCEPT;
		}

		idx = cone_snat_hash(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port, newsrc) % 32768;
		memcpy(&css, &cone_snat_array[idx], sizeof(css));
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == css.lan_ip &&
		        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port == css.lan_port &&
		        css.wan_ip == newsrc && css.wan_port != 0) {
			idx = ntohs(css.wan_port) % 65536;
			memcpy(&cns, &cone_nat_array[idx], sizeof(cns));
			if (__IP_SET_test_src_port(state, in, out, skb, "cone_nat_unused_port", &UDPH(l4)->source, css.wan_port) <= 0 &&
			        cns.ip == css.lan_ip && cns.port == css.lan_port) {
				__be32 oldip;

				oldip = iph->saddr;
				iph->saddr = css.wan_ip;
				if (IP_SET_test_src_ip(state, in, out, skb, "cone_wan_ip") > 0) {
					iph->saddr = oldip;
					NATCAP_INFO("(CCS)" DEBUG_UDP_FMT ": SNAT to %pI4:%u\n", DEBUG_UDP_ARG(iph,l4), &css.wan_ip, ntohs(css.wan_port));
					ret = natcap_snat_setup(ct, css.wan_ip, css.wan_port);
					if (ret != NF_ACCEPT) {
						NATCAP_WARN("(CCS)" DEBUG_UDP_FMT ": natcap_snat_setup failed\n", DEBUG_UDP_ARG(iph,l4));
					}
				} else {
					iph->saddr = oldip;
				}
			}
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
		.hook = natcap_common_cone_snat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC - 6,
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

static struct sk_buff *peer_user_uskbs[NR_CPUS];
struct sk_buff *uskb_of_this_cpu(unsigned int id)
{
	BUG_ON(id >= NR_CPUS);
	if (!peer_user_uskbs[id]) {
		struct ethhdr *eth;
		peer_user_uskbs[id] = __alloc_skb(PEER_USKB_SIZE + sizeof(struct ethhdr), GFP_ATOMIC, 0, numa_node_id());
		skb_reset_mac_header(peer_user_uskbs[id]);
		skb_put(peer_user_uskbs[id], sizeof(struct ethhdr));
		skb_pull(peer_user_uskbs[id], sizeof(struct ethhdr));
		eth = eth_hdr(peer_user_uskbs[id]);
		memset(eth, 0, sizeof(*eth));
		eth->h_proto = __constant_htons(ETH_P_IP);
	}
	return peer_user_uskbs[id];
}

int natcap_common_init(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < NR_CPUS; i++) {
		peer_user_uskbs[i] = NULL;
	}

	dnatcap_map_init();
	cone_nat_array = vmalloc(sizeof(struct cone_nat_session) * 65536);
	if (cone_nat_array == NULL) {
		ret = -ENOMEM;
		goto err_alloc_cone_nat_array;
	}
	memset(cone_nat_array, 0, sizeof(struct cone_nat_session) * 65536);

	cone_snat_array = vmalloc(sizeof(struct cone_snat_session) * 32768);
	if (cone_snat_array == NULL) {
		ret = -ENOMEM;
		goto err_alloc_cone_snat_array;
	}
	memset(cone_snat_array, 0, sizeof(struct cone_snat_session) * 32768);

	need_conntrack();
	ret = nf_register_hooks(common_hooks, ARRAY_SIZE(common_hooks));
	if (ret != 0) {
		goto err_nf_register_hooks;
	}

	return 0;

	nf_unregister_hooks(common_hooks, ARRAY_SIZE(common_hooks));
err_nf_register_hooks:
	vfree(cone_snat_array);
err_alloc_cone_snat_array:
	vfree(cone_nat_array);
err_alloc_cone_nat_array:
	return ret;
}

void natcap_common_exit(void)
{
	int i;
	nf_unregister_hooks(common_hooks, ARRAY_SIZE(common_hooks));

	if (cone_nat_array) {
		void *tmp = cone_nat_array;
		cone_nat_array = NULL;
		synchronize_rcu();
		vfree(tmp);
	}

	if (cone_snat_array) {
		void *tmp = cone_snat_array;
		cone_snat_array = NULL;
		synchronize_rcu();
		vfree(tmp);
	}

	for (i = 0; i < NR_CPUS; i++) {
		if (peer_user_uskbs[i]) {
			kfree(peer_user_uskbs[i]);
			peer_user_uskbs[i] = NULL;
		}
	}
}
