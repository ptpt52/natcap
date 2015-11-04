/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#include "natcap.h"

#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/ip_fib.h>

static int natcap_major = 0;
static int natcap_minor = 0;
static int number_of_devices = 1;
static struct cdev natcap_cdev;
const char *natcap_dev_name = "natcap_ctl";
static struct class *natcap_class;
static struct device *natcap_dev;

static int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,1=fixme,2==debug,4=info,8=warn,16=error,...,31=all)");

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
		dnatcap_map[natcap_map[i]] = i;
	}
}

static void natcap_data_encode(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = natcap_map[buf[i]];
	}
}

static void natcap_data_decode(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = dnatcap_map[buf[i]];
	}
}

static void skb_tcp_data_hook(struct sk_buff *skb, int offset, int len, void (*update)(unsigned char *, int))
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int pos = 0;

	/* Checksum header. */
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
			skb_tcp_data_hook(frag_iter, offset - start, copy, update);
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

#define NATCAP_FIXME(fmt, ...) \
	do { \
		if (debug & 0x1) { \
			printk(KERN_ALERT "fixme: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_DEBUG(fmt, ...) \
	do { \
		if (debug & 0x2) { \
			printk(KERN_ALERT "debug: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_INFO(fmt, ...) \
	do { \
		if (debug & 0x4) { \
			printk(KERN_ALERT "info: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_WARN(fmt, ...) \
	do { \
		if (debug & 0x8) { \
			printk(KERN_ALERT "warning: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATCAP_ERROR(fmt, ...) \
	do { \
		if (debug & 0x16) { \
			printk(KERN_ALERT "error: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define IP_TCP_FMT	"%pI4:%u->%pI4:%u"
#define IP_TCP_ARG(i,t)	&(i)->saddr, ntohs((t)->source), &(i)->daddr, ntohs((t)->dest)
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

#define DEBUG_FMT "[" IP_TCP_FMT "][ID=0x%x,TL=%u][" TCP_ST_FMT "]"
#define DEBUG_ARG(i, t) IP_TCP_ARG(i,t), ntohs((i)->id), ntohs((i)->tot_len), TCP_ST_ARG(t)

#ifdef CONFIG_IP_MULTIPLE_TABLES
static struct fib_table *natcap_fib_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node *node;
#endif
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	head = &net->ipv4.fib_table_hash[h];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry_rcu(tb, node, head, tb_hlist) {
#else
	hlist_for_each_entry_rcu(tb, head, tb_hlist) {
#endif
		if (tb->tb_id == id)
			return tb;
	}
	return NULL;
}
#else
#define natcap_fib_get_table fib_get_table
#endif /* CONFIG_IP_MULTIPLE_TABLES */

bool dst_need_natcap(__be32 daddr, __be16 dport)
{
	u32 tid = NATCAP_WHITELIST_TID;
	struct net *net = &init_net;
	struct flowi4 fl4;
	struct fib_result res;
	struct fib_table *tb;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = daddr;
	fl4.saddr = 0;
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;

	res.tclassid = 0;
	res.fi = NULL;
	res.table = NULL;

	rcu_read_lock();

	tb = natcap_fib_get_table(net, tid);
	if (tb && fib_table_lookup(tb, &fl4, &res, 0) == 0) {
		rcu_read_unlock();
		return true;
	}

	rcu_read_unlock();

	return false;
}

#define MAX_NATCAP_SERVER 256
struct natcap_server_info {
	unsigned int active_index;
	unsigned int server_count[2];
	__be32 server[2][MAX_NATCAP_SERVER];
};

static struct natcap_server_info natcap_server_info;

static inline void natcap_server_init(void)
{
	memset(&natcap_server_info, 0, sizeof(natcap_server_info));
}

static inline int natcap_server_add(__be32 ip)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	if (nsi->server_count[m] == MAX_NATCAP_SERVER)
		return -ENOSPC;

	for (i = 0; i < nsi->server_count[m]; i++) {
		if (nsi->server[m][i] == ip) {
			return -EEXIST;
		}
	}

	/* all ip(s) are stored from MAX to MIN */
	j = 0;
	for (i = 0; i < nsi->server_count[m]; i++) {
		if (ntohl(ip) < ntohl(nsi->server[m][i])) {
			nsi->server[n][j++] = nsi->server[m][i];
		} else {
			nsi->server[n][j++] = ip;
			nsi->server[n][j++] = nsi->server[m][i];
		}
	}
	if (j == i) {
		nsi->server[n][j++] = ip;
	}
	nsi->server_count[n] = j;

	nsi->active_index = n;

	return 0;
}

static inline int natcap_server_delete(__be32 ip)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;
	unsigned int i, j;

	j = 0;
	for (i = 0; i < nsi->server_count[m]; i++) {
		if (nsi->server[m][i] == ip) {
			continue;
		}
		nsi->server[n][j++] = nsi->server[m][i];
	}
	if (j == i)
		return -ENOENT;

	nsi->server_count[n] = j;

	nsi->active_index = n;

	return 0;
}

static inline void natcap_server_cleanup(void)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int n = (m + 1) % 2;

	nsi->server_count[m] = 0;
	nsi->server_count[n] = 0;
	nsi->active_index = n;
}

static inline __be32 natcap_server_select(__be32 ip, __be16 port)
{
	struct natcap_server_info *nsi = &natcap_server_info;
	unsigned int m = nsi->active_index;
	unsigned int count = nsi->server_count[m];
	unsigned int hash;

	if (count == 0)
		return 0;

	hash = (unsigned int)jiffies;
	hash = hash % count;

	return nsi->server[m][hash];
}

static inline void *natcap_server_get(loff_t idx)
{
	if (idx < natcap_server_info.server_count[natcap_server_info.active_index])
		return &natcap_server_info.server[natcap_server_info.active_index][idx];
	return NULL;
}

static void *natcap_start(struct seq_file *m, loff_t *pos)
{
	return natcap_server_get(*pos);
}

static void *natcap_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return natcap_server_get(*pos);
}

static void natcap_stop(struct seq_file *m, void *v)
{
}

static int natcap_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%pI4\n", v);
	return 0;
}

const struct seq_operations natcap_seq_ops = {
	.start = natcap_start,
	.next = natcap_next,
	.stop = natcap_stop,
	.show = natcap_show,
};

static ssize_t natcap_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t natcap_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err;
	int n;
	char data[256];
	int cnt = 256;
	__be32 ip;
	char *handle;

	if (buf_len > cnt)
		return -ENOMEM;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data, buf, cnt) != 0)
		return -EACCES;

	if ((handle = strnstr(data, "clean", cnt)) != NULL) {
		natcap_server_cleanup();
		return cnt;
	}

	if (strncmp(data, "add", 3) == 0) {
		unsigned int a, b, c, d;
		n = sscanf(data, "add %u.%u.%u.%u", &a, &b, &c, &d);
		if (n != 4)
			return -EINVAL;
		ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
		if ((err = natcap_server_add(ip)) != 0)
			return err;
		return cnt;
	} else if (strncmp(data, "delete", 6) == 0) {
		unsigned int a, b, c, d;
		n = sscanf(data, "delete %u.%u.%u.%u", &a, &b, &c, &d);
		if (n != 4)
			return -EINVAL;
		ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
		if ((err = natcap_server_delete(ip)) != 0)
			return err;
		return cnt;
	} else if (strncmp(data, "debug=", 6) == 0) {
		int d;
		n = sscanf(data, "debug=%u", &d);
		if (n != 1)
			return -EINVAL;
		debug = d;
		printk("natcap setting debug=%u\n", debug);
		return cnt;
	}

	return -EINVAL;
}

static int natcap_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &natcap_seq_ops);
}

static int natcap_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations natcap_fops = {
	.owner = THIS_MODULE,
	.open = natcap_open,
	.release = natcap_release,
	.read = natcap_read,
	.write = natcap_write,
	.llseek  = seq_lseek,
};

static inline int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);

	if (skb->len < len)
	{
		return -1;
	}
	else if (len < (iph->ihl * 4))
	{
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP)
	{
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

			skb->ip_summed = CHECKSUM_NONE;
		}
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
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

			skb->ip_summed = CHECKSUM_NONE;
		}
	}
	else
	{
		return -1;
	}

	return 0;
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

			oldmss = (op[i+3] << 8) | op[i+2];
			newmss = htons(ntohs(oldmss) + delta);

			op[i+2] = newmss & 0xFF;
			op[i+3] = (newmss & 0xFF00) >> 8;

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

static inline int natcap_tcp_encode(struct sk_buff *skb, __be32 server_ip, int to_server)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_tcp_option *nto = NULL;
	int ntosz = ALIGN(sizeof(struct natcap_tcp_option), sizeof(unsigned int));
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (skb->len != ntohs(iph->tot_len)) {
		NATCAP_ERROR("(%s)" DEBUG_FMT ": bad skb, SL=%d, TL=%d\n", __FUNCTION__, DEBUG_ARG(iph,tcph), skb->len, ntohs(iph->tot_len));
		return -1;
	}

	if (!tcph->syn || tcph->ack) {
		//not syn packet
		goto do_encode;
	}

	//XXX do use skb_tailroom here!!
	if (skb->end - skb->tail < ntosz && pskb_expand_head(skb, 0, ntosz, GFP_ATOMIC)) {
		/* no memory */
		NATCAP_ERROR("(%s)" DEBUG_FMT ": pskb_expand_head failed\n", __FUNCTION__, DEBUG_ARG(iph,tcph));
		return -2;
	}

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	offlen = skb_tail_pointer(skb) - (unsigned char *)tcph - sizeof(struct tcphdr);
	if (offlen < 0) {
		NATCAP_ERROR("(%s)" DEBUG_FMT ": skb tcp offlen = %d\n", __FUNCTION__, DEBUG_ARG(iph,tcph), offlen);
		return -4;
	}

	nto = (struct natcap_tcp_option *)((void *)tcph + sizeof(struct tcphdr));
	memmove((void *)nto + ntosz, (void *)nto, offlen);

	nto->opcode = TCPOPT_NATCAP;
	nto->opsize = ntosz;
	nto->data.server_port = 0;
	nto->data.server_ip = server_ip;

	tcph->doff = (tcph->doff * 4 + ntosz) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) + ntosz);
	skb->len += ntosz;
	skb->tail += ntosz;

do_encode:
	skb_tcp_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - (iph->ihl * 4 + tcph->doff * 4), natcap_data_encode);

	if (skb_rcsum_tcpudp(skb) != 0)
	{
		return -8;
	}

	return 0;
}

static inline int natcap_tcp_decode(struct sk_buff *skb, __be32 *server_ip)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct natcap_tcp_option *nto = NULL;
	int ntosz = ALIGN(sizeof(struct natcap_tcp_option), sizeof(unsigned int));
	int offlen;

	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (skb->len != ntohs(iph->tot_len)) {
		NATCAP_ERROR("(%s)" DEBUG_FMT ": bad skb, SL=%d, TL=%d\n", __FUNCTION__, DEBUG_ARG(iph,tcph), skb->len, ntohs(iph->tot_len));
		return -1;
	}

	if (!tcph->syn || tcph->ack) {
		//not syn packet
		goto do_decode;
	}

	nto = (struct natcap_tcp_option *)((void *)tcph + sizeof(struct tcphdr));
	if (nto->opcode != TCPOPT_NATCAP ||
			nto->opsize != ntosz) {
		return -2;
	}
	if (tcph->doff * 4 < sizeof(struct tcphdr) + ntosz) {
		return -4;
	}

	offlen = skb_tail_pointer(skb) - (unsigned char *)nto - ntosz;
	if (offlen < 0) {
		NATCAP_ERROR("(%s)" DEBUG_FMT ": skb tcp offlen = %d\n", __FUNCTION__, DEBUG_ARG(iph,tcph), offlen);
		return -8;
	}

	// *server_port = nto->data.server_port;
	*server_ip = nto->data.server_ip;

	memmove((void *)nto, (void *)nto + ntosz, offlen);

	tcph->doff = (tcph->doff * 4 - ntosz) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) - ntosz);
	skb->len -= ntosz;
	skb->tail -= ntosz;

do_decode:
	skb_tcp_data_hook(skb, iph->ihl * 4 + tcph->doff * 4, skb->len - iph->ihl * 4 - tcph->doff * 4, natcap_data_decode);

	if (skb_rcsum_tcpudp(skb) != 0)
	{
		return -32;
	}
	//skb->ip_summed = CHECKSUM_UNNECESSARY;

	return 0;
}

static inline unsigned int natcap_tcp_dnat_setup(struct nf_conn *ct, __be32 ip, __be16 port)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, IP_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = IP_NAT_RANGE_MAP_IPS;
	range.min_ip = ip;
	range.max_ip = ip;
	range.min.tcp.port = port;
	range.max.tcp.port = port;
	return nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct nf_nat_ipv4_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_ip = ip;
	range.max_ip = ip;
	range.min.tcp.port = port;
	range.max.tcp.port = port;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#else
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_addr.ip = ip;
	range.max_addr.ip = ip;
	range.min_proto.tcp.port = port;
	range.max_proto.tcp.port = port;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#endif
}

//*PREROUTING*->POSTROUTING
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_pre_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#else
static unsigned int natcap_pre_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	unsigned int ret;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 server_ip = 0;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) { /* in client side */
		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			skb->mark = XT_MARK_NATCAP;
			NATCAP_DEBUG("(PREROUTING)" DEBUG_FMT ": found\n", DEBUG_ARG(iph,tcph));
		}
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		NATCAP_DEBUG("(PREROUTING)" DEBUG_FMT ": before decode\n", DEBUG_ARG(iph,tcph));
		ret = natcap_tcp_decode(skb, &server_ip);
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);
	} else {
		if (!tcph->syn || tcph->ack) {
			NATCAP_DEBUG("(PREROUTING)" DEBUG_FMT ": first packet in but not syn\n", DEBUG_ARG(iph,tcph));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		ret = natcap_tcp_decode(skb, &server_ip);
		//reload
		iph = ip_hdr(skb);
		tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		//not a natcap packet
		if (ret != 0) {
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}

		if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time */
			NATCAP_INFO("(PREROUTING)" DEBUG_FMT ": new natcaped connection in, after decode server_ip=%pI4\n",
					DEBUG_ARG(iph,tcph), &server_ip);
			if (iph->daddr != server_ip &&
					natcap_tcp_dnat_setup(ct, server_ip, tcph->dest) != NF_ACCEPT) {
				NATCAP_ERROR("(PREROUTING)" DEBUG_FMT ": natcap_tcp_dnat_setup failed, server_ip=%pI4\n",
						DEBUG_ARG(iph,tcph), &server_ip);
				set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
				return NF_DROP;
			}
		}
	}

	if (ret != 0) {
		NATCAP_WARN("(PREROUTING)" DEBUG_FMT ": natcap_tcp_decode ret = %d\n",
			DEBUG_ARG(iph,tcph), ret);
		return NF_DROP;
	}

	skb->mark = XT_MARK_NATCAP;

	NATCAP_DEBUG("(PREROUTING)" DEBUG_FMT ": after decode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

//PREROUTING->*POSTROUTING*
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natcap_post_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#else
static unsigned int natcap_post_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) { /* in client side */
		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			NATCAP_DEBUG("(POSTROUTING)" DEBUG_FMT ": found\n", DEBUG_ARG(iph,tcph));
		}
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		//matched
		NATCAP_DEBUG("(POSTROUTING)" DEBUG_FMT ": before encode\n", DEBUG_ARG(iph,tcph));
	} else {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ret = natcap_tcp_encode(skb, iph->saddr, 0);
	if (ret != 0) {
		NATCAP_ERROR("(POSTROUTING)" DEBUG_FMT ": natcap_tcp_encode@server ret=%d\n",
				DEBUG_ARG(iph,tcph), ret);
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_DROP;
	}

	NATCAP_DEBUG("(POSTROUTING)" DEBUG_FMT ":after encode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

//*OUTPUT*->POSTROUTING
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_local_out_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_local_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#else
static unsigned int natcap_local_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	int ret = 0;
	__be32 server_ip = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) { /* in client side */
		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			NATCAP_DEBUG("(OUTPUT)" DEBUG_FMT ": found\n", DEBUG_ARG(iph,tcph));
		}
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		//matched
		NATCAP_DEBUG("(OUTPUT)" DEBUG_FMT ": before encode\n", DEBUG_ARG(iph,tcph));
	} else if (dst_need_natcap(iph->daddr, tcph->dest) == 0) {
		//server_ip = htonl((108<<24)|(61<<16)|(201<<8)|(222<<0));
		//server_ip = htonl((198<<24)|(199<<16)|(118<<8)|(35<<0));
		server_ip = natcap_server_select(iph->daddr, tcph->dest);
		if (server_ip == 0) {
			NATCAP_DEBUG("(OUTPUT)" DEBUG_FMT ": no server found\n", DEBUG_ARG(iph,tcph));
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_ACCEPT;
		}
		NATCAP_INFO("(OUTPUT)" DEBUG_FMT ": new natcaped connection out, before encode, server_ip=%pI4\n",
				DEBUG_ARG(iph,tcph), &server_ip);
	} else {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	ret = natcap_tcp_encode(skb, iph->daddr, 1);

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (ret != 0) {
		NATCAP_ERROR("(OUTPUT)" DEBUG_FMT ": natcap_tcp_encode@client ret=%d\n",
			DEBUG_ARG(iph,tcph), ret);
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_DROP;
	}

	if (!test_and_set_bit(IPS_NATCAP_BIT, &ct->status)) { /* first time out */
		NATCAP_INFO("(OUTPUT)" DEBUG_FMT ": new natcaped connection out, after encode\n",
				DEBUG_ARG(iph,tcph));
		//setup DNAT
		if (natcap_tcp_dnat_setup(ct, server_ip, tcph->dest) != NF_ACCEPT) {
			NATCAP_ERROR("(OUTPUT)" DEBUG_FMT ": natcap_tcp_dnat_setup failed, server_ip=%pI4\n",
					DEBUG_ARG(iph,tcph), &server_ip);
			set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
			return NF_DROP;
		}
	}

	NATCAP_DEBUG("(OUTPUT)" DEBUG_FMT ": after encode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

//PREROUTING->*INPUT*
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natcap_local_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natcap_local_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#else
static unsigned int natcap_local_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
#endif
{
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 server_ip = 0;

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BYPASS_BIT, &ct->status)) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) { /* in client side */
		if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
			NATCAP_DEBUG("(INPUT)" DEBUG_FMT ": found\n", DEBUG_ARG(iph,tcph));
		}
		return NF_ACCEPT;
	}

	if (test_bit(IPS_NATCAP_BIT, &ct->status)) {
		//matched
		NATCAP_DEBUG("(INPUT)" DEBUG_FMT ": before decode\n", DEBUG_ARG(iph,tcph));
	} else {
		set_bit(IPS_NATCAP_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	ret = natcap_tcp_decode(skb, &server_ip);

	//reload
	iph = ip_hdr(skb);
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

	if (ret != 0) {
		NATCAP_WARN("(INPUT)" DEBUG_FMT ": natcap_tcp_decode ret = %d\n",
			DEBUG_ARG(iph,tcph), ret);
		return NF_DROP;
	}

	NATCAP_DEBUG("(INPUT)" DEBUG_FMT ": after decode\n", DEBUG_ARG(iph,tcph));

	return NF_ACCEPT;
}

static struct nf_hook_ops natcap_pre_in_hook_ops = {
	.owner = THIS_MODULE,
	.hook = natcap_pre_in_hook,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_CONNTRACK + 1,
};

static struct nf_hook_ops natcap_post_out_hook_ops = {
	.owner = THIS_MODULE,
	.hook = natcap_post_out_hook,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_LAST,
};

static struct nf_hook_ops natcap_local_out_hook_ops = {
	.owner = THIS_MODULE,
	.hook = natcap_local_out_hook,
	.hooknum = NF_INET_LOCAL_OUT,
	.pf = PF_INET,
	.priority = NF_IP_PRI_CONNTRACK + 1,
};

static struct nf_hook_ops natcap_local_in_hook_ops = {
	.owner = THIS_MODULE,
	.hook = natcap_local_in_hook,
	.hooknum = NF_INET_LOCAL_IN,
	.pf = PF_INET,
	.priority = NF_IP_PRI_LAST,
};

static int __init natcap_init(void) {
	int retval = 0;
	dev_t devno;

	printk(KERN_ALERT "natcap_init version: " NATCAP_VERSION "\n");

	dnatcap_map_init();
	natcap_server_init();

	if (natcap_major>0) {
		devno = MKDEV(natcap_major, natcap_minor);
		retval = register_chrdev_region(devno, number_of_devices, natcap_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, natcap_minor, number_of_devices, natcap_dev_name);
	}
	if (retval < 0) {
		printk(KERN_WARNING "natcap: alloc_chrdev_region failed\n");
		return retval;
	}
	natcap_major = MAJOR(devno);
	natcap_minor = MINOR(devno);
	printk(KERN_INFO "natcap_major=%d, natcap_minor=%d\n", natcap_major, natcap_minor);

	cdev_init(&natcap_cdev, &natcap_fops);
	natcap_cdev.owner = THIS_MODULE;
	natcap_cdev.ops = &natcap_fops;

	retval = cdev_add(&natcap_cdev, devno, 1);
	if (retval) {
		printk(KERN_NOTICE "error=%d adding chardev\n", retval);
		goto cdev_add_failed;
	}

	natcap_class = class_create(THIS_MODULE,"natcap_class");
	if (IS_ERR(natcap_class)) {
		printk(KERN_NOTICE "failed in creating class\n");
		retval = -EINVAL;
		goto class_create_failed;
	}

	natcap_dev = device_create(natcap_class, NULL, devno, NULL, natcap_dev_name);
	if (!natcap_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	retval = nf_register_hook(&natcap_local_in_hook_ops);
	if (retval != 0)
		goto err0;
	retval = nf_register_hook(&natcap_local_out_hook_ops);
	if (retval != 0)
		goto err1;
	retval = nf_register_hook(&natcap_post_out_hook_ops);
	if (retval != 0)
		goto err2;
	retval = nf_register_hook(&natcap_pre_in_hook_ops);
	if (retval != 0)
		goto err3;

	/* we need nf_conntrack_ipv4 */
	need_conntrack();

	return 0;

	//nf_unregister_hook(&natcap_pre_in_hook_ops);
err3:
	nf_unregister_hook(&natcap_post_out_hook_ops);
err2:
	nf_unregister_hook(&natcap_local_out_hook_ops);
err1:
	nf_unregister_hook(&natcap_local_in_hook_ops);
err0:

	device_destroy(natcap_class, devno);
device_create_failed:
	class_destroy(natcap_class);
class_create_failed:
	cdev_del(&natcap_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

static void __exit natcap_exit(void) {
	dev_t devno;

	printk(KERN_ALERT "natcap_exit\n");

	nf_unregister_hook(&natcap_pre_in_hook_ops);
	nf_unregister_hook(&natcap_post_out_hook_ops);

	nf_unregister_hook(&natcap_local_out_hook_ops);
	nf_unregister_hook(&natcap_local_in_hook_ops);

	devno = MKDEV(natcap_major, natcap_minor);
	device_destroy(natcap_class, devno);
	class_destroy(natcap_class);
	cdev_del(&natcap_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	return;
}

module_init(natcap_init);
module_exit(natcap_exit);

MODULE_AUTHOR("Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=");
MODULE_VERSION(NATCAP_VERSION);
MODULE_DESCRIPTION("Natcap packet to avoid inspection");
MODULE_LICENSE("GPL");
