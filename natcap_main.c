/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
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
#include <linux/vmalloc.h>
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
#include "natcap.h"
#include "natcap_common.h"
#include "natcap_client.h"
#include "natcap_server.h"
#include "natcap_knock.h"
#include "natcap_peer.h"

static int natcap_major = 0;
static int natcap_minor = 0;
static int number_of_devices = 1;
static struct cdev natcap_cdev;
const char *natcap_dev_name = "natcap_ctl";
static struct class *natcap_class;
static struct device *natcap_dev;

static int natcap_ctl_buffer_use = 0;
static char *natcap_ctl_buffer = NULL;
static void *natcap_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(natcap_ctl_buffer,
		             SEQ_PGSZ - 1,
		             "# Version: %s\n"
		             "# Usage:\n"
		             "#    disabled=Number -- set disable/enable\n"
		             "#    debug=Number -- set debug value\n"
		             "#    server [ip]:[port]-[e/o] -- add one server\n"
		             "#    delete [ip]:[port]-[e/o] -- delete one server\n"
		             "#    clean -- remove all existing server(s)\n"
		             "#    change_server -- change current server\n"
		             "#\n"
		             "# Info:\n"
		             "#    mode=%s(%u)\n"
		             "#    current_server0=" TUPLE_FMT "\n"
		             "#    current_server1=" TUPLE_FMT "\n"
		             "#    default_mac_addr=%02x:%02x:%02x:%02x:%02x:%02x\n"
		             "#    u_hash=0x%08x(%u)\n"
		             "#    u_mask=0x%08x\n"
		             "#    si_mask=0x%08x\n"
		             "#    ni_mask=0x%08x\n"
		             "#    ni_forward=%u\n"
		             "#    udp_seq_lock=%u\n"
		             "#    server_flow_stop=%u\n"
		             "#    protocol=%u\n"
		             "#    server_seed=%u\n"
		             "#    auth_enabled=%u\n"
		             "#    tx_speed_limit=%d B/s\n"
		             "#    rx_speed_limit=%d B/s\n"
		             "#    tx_pkts_threshold=%d\n"
		             "#    rx_pkts_threshold=%d\n"
		             "#    http_confusion=%u\n"
		             "#    encode_http_only=%u\n"
		             "#    sproxy=%u\n"
		             "#    knock_port=%u-%c-%c-%c\n"
		             "#    knock_flood=%u\n"
		             "#    natcap_redirect_port=%u\n"
		             "#    natcap_client_redirect_port=%u\n"
		             "#    natcap_max_pmtu=%u\n"
		             "#    natcap_touch_timeout=%u\n"
		             "#    flow_total_tx_bytes=%llu\n"
		             "#    flow_total_rx_bytes=%llu\n"
		             "#    auth_http_redirect_url=%s\n"
		             "#    htp_confusion_host=%s\n"
		             "#    server_persist_lock=%u\n"
		             "#    dns_proxy_drop=%u\n"
		             "#    peer_multipath=%u\n"
		             "#    macfilter=%s(%u)\n"
		             "#    ipfilter=%s(%u)\n"
		             "#    dns_proxy_server=" TUPLE_FMT "\n"
		             "#    server1_use_peer=%u\n"
		             "#    natmap=%u-%u\n"
		             "#\n"
		             "# Reload cmd:\n"
		             "\n"
		             "clean\n"
		             "disabled=%u\n"
		             "debug=%u\n"
		             "server_persist_timeout=%u\n"
		             "cnipwhitelist_mode=%u\n"
		             "dns_server=%pI4:%u\n"
		             "\n",
		             NATCAP_VERSION,
		             mode_str[mode], mode,
		             TUPLE_ARG(natcap_server_info_current(SERVER_GROUP_0)),
		             TUPLE_ARG(natcap_server_info_current(SERVER_GROUP_1)),
		             default_mac_addr[0], default_mac_addr[1], default_mac_addr[2], default_mac_addr[3], default_mac_addr[4], default_mac_addr[5],
		             ntohl(default_u_hash),
		             ntohl(default_u_hash),
		             user_mark_natcap_mask,
		             server_index_natcap_mask,
		             natcap_ignore_mask,
		             natcap_ignore_forward,
		             natcap_udp_seq_lock,
		             server_flow_stop,
		             default_protocol,
		             server_seed, auth_enabled,
		             natcap_tx_speed_get(),
		             natcap_rx_speed_get(),
		             tx_pkts_threshold,
		             rx_pkts_threshold,
		             http_confusion, encode_http_only, sproxy, ntohs(knock_port), knock_encryption ? 'e' : 'o',
		             knock_tcp_encode == TCP_ENCODE ? 'T' : 'U', knock_udp_encode == UDP_ENCODE ? 'U' : 'T',
		             knock_flood,
		             ntohs(natcap_redirect_port), ntohs(natcap_client_redirect_port), natcap_max_pmtu, natcap_touch_timeout,
		             flow_total_tx_bytes, flow_total_rx_bytes,
		             auth_http_redirect_url,
		             htp_confusion_host,
		             server_persist_lock,
		             dns_proxy_drop,
		             peer_multipath,
		             macfilter_acl_str[macfilter], macfilter,
		             ipfilter_acl_str[ipfilter], ipfilter,
		             TUPLE_ARG(dns_proxy_server),
		             natcap_server_use_peer, natmap_start, natmap_end,
		             disabled, debug, server_persist_timeout,
		             cnipwhitelist_mode, &dns_server, ntohs(dns_port));
		natcap_ctl_buffer[n] = 0;
		return natcap_ctl_buffer;
	} else if ((*pos) > 0) {
		struct tuple *dst = NULL;
		int x = 0;

		for (x = SERVER_GROUP_0; x < SERVER_GROUP_MAX; x++) {
			dst = (struct tuple *)natcap_server_info_get(x, (*pos) - 1);
			if (dst) break;
		}

		if (dst) {
			n = snprintf(natcap_ctl_buffer,
			             SEQ_PGSZ - 1,
			             "server %d " TUPLE_FMT "\n",
			             x, TUPLE_ARG(dst));
			natcap_ctl_buffer[n] = 0;
			return natcap_ctl_buffer;
		}
	}

	return NULL;
}

static void *natcap_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return natcap_start(m, pos);
	}
	return NULL;
}

static void natcap_stop(struct seq_file *m, void *v)
{
}

static int natcap_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
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
	int err = 0;
	int n, l, x;
	struct tuple dst;
	int cnt = MAX_IOCTL_LEN;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <=256
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATCAP_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "clean", 5) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			for (x = 0; x < SERVER_GROUP_MAX; x++) {
				natcap_server_info_cleanup(x);
			}
			goto done;
		}
	} else if (strncmp(data, "dns_server=", 11) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int a, b, c, d, e;
			n = sscanf(data, "dns_server=%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
			if ( (n == 5 && e <= 0xffff) &&
			        (((a & 0xff) == a) &&
			         ((b & 0xff) == b) &&
			         ((c & 0xff) == c) &&
			         ((d & 0xff) == d)) ) {
				dns_server = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
				dns_port = htons(e);
				goto done;
			}
		}
	} else if (strncmp(data, "server ", 7) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int a, b, c, d, e;
			char f, g, h;
			n = sscanf(data, "server %u %u.%u.%u.%u:%u-%c-%c-%c", &x, &a, &b, &c, &d, &e, &f, &g, &h);
			if ( (n == 9 && e <= 0xffff) &&
			        (x < SERVER_GROUP_MAX) &&
			        (f == 'e' || f == 'o') &&
			        (g == 'T' || g == 'U') &&
			        (h == 'U' || h == 'T') &&
			        (((a & 0xff) == a) &&
			         ((b & 0xff) == b) &&
			         ((c & 0xff) == c) &&
			         ((d & 0xff) == d)) ) {
				dst.ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
				dst.port = htons(e);
				dst.encryption = !!(f == 'e');
				dst.tcp_encode = g == 'T' ? TCP_ENCODE : UDP_ENCODE;
				dst.udp_encode = h == 'U' ? UDP_ENCODE : TCP_ENCODE;
				if ((err = natcap_server_info_add(x, &dst)) == 0) {
					goto done;
				}
				NATCAP_println("natcap_server_add() failed ret=%d", err);
			}
		}
	} else if (strncmp(data, "dns_proxy_server=", 17) == 0) {
		unsigned int a, b, c, d, e;
		char f, g, h;
		n = sscanf(data, "dns_proxy_server=%u.%u.%u.%u:%u-%c-%c-%c", &a, &b, &c, &d, &e, &f, &g, &h);
		if ( (n == 8 && e <= 0xffff) &&
		        (f == 'e' || f == 'o') &&
		        (g == 'T' || g == 'U') &&
		        (h == 'U' || h == 'T') &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			dst.ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			dst.port = htons(e);
			dst.encryption = !!(f == 'e');
			dst.tcp_encode = g == 'T' ? TCP_ENCODE : UDP_ENCODE;
			dst.udp_encode = h == 'U' ? UDP_ENCODE : TCP_ENCODE;
			tuple_copy(dns_proxy_server, &dst);
			goto done;
		}
	} else if (strncmp(data, "change_server", 13) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			natcap_server_info_change(SERVER_GROUP_0, 1);
			goto done;
		}
	} else if (strncmp(data, "delete", 6) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int a, b, c, d, e;
			char f, g, h;
			n = sscanf(data, "delete %u %u.%u.%u.%u:%u-%c-%c-%c", &x, &a, &b, &c, &d, &e, &f, &g, &h);
			if ( (n == 9 && e <= 0xffff) &&
			        (x < SERVER_GROUP_MAX) &&
			        (f == 'e' || f == 'o') &&
			        (g == 'T' || g == 'U') &&
			        (h == 'U' || h == 'T') &&
			        (((a & 0xff) == a) &&
			         ((b & 0xff) == b) &&
			         ((c & 0xff) == c) &&
			         ((d & 0xff) == d)) ) {
				dst.ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
				dst.port = htons(e);
				dst.encryption = !!(f == 'e');
				dst.tcp_encode = g == 'T' ? TCP_ENCODE : UDP_ENCODE;
				dst.udp_encode = h == 'U' ? UDP_ENCODE : TCP_ENCODE;
				if ((err = natcap_server_info_delete(x, &dst)) == 0) {
					goto done;
				}
				NATCAP_println("natcap_server_delete() failed ret=%d", err);
			}
		}
	} else if (strncmp(data, "server1_use_peer=", 17) == 0) {
		unsigned int d;
		n = sscanf(data, "server1_use_peer=%u", &d);
		if (n == 1) {
			natcap_server_use_peer = d;
			goto done;
		}
	} else if (strncmp(data, "debug=", 6) == 0) {
		int d;
		n = sscanf(data, "debug=%u", &d);
		if (n == 1) {
			debug = d;
			goto done;
		}
	} else if (strncmp(data, "disabled=", 9) == 0) {
		int d;
		n = sscanf(data, "disabled=%u", &d);
		if (n == 1) {
			disabled = d;
			goto done;
		}
	} else if (strncmp(data, "si_mask=", 8) == 0) {
		unsigned int d;
		n = sscanf(data, "si_mask=%u", &d);
		if (n == 1) {
			server_index_natcap_mask = d;
			goto done;
		}
	} else if (strncmp(data, "ni_mask=", 8) == 0) {
		unsigned int d;
		n = sscanf(data, "ni_mask=%u", &d);
		if (n == 1) {
			natcap_ignore_mask = d;
			goto done;
		}
	} else if (strncmp(data, "u_mask=", 7) == 0) {
		unsigned int d;
		n = sscanf(data, "u_mask=%u", &d);
		if (n == 1) {
			user_mark_natcap_mask = d;
			goto done;
		}
	} else if (strncmp(data, "ni_forward=", 11) == 0) {
		unsigned int d;
		n = sscanf(data, "ni_forward=%u", &d);
		if (n == 1) {
			natcap_ignore_forward = d;
			goto done;
		}
	} else if (strncmp(data, "udp_seq_lock=", 13) == 0) {
		unsigned int d;
		n = sscanf(data, "udp_seq_lock=%u", &d);
		if (n == 1) {
			natcap_udp_seq_lock = d;
			goto done;
		}
	} else if (strncmp(data, "u_hash=", 7) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "u_hash=%u", &d);
			if (n == 1) {
				default_u_hash = htonl(d);
				goto done;
			}
		}
	} else if (strncmp(data, "server_flow_stop=", 17) == 0) {
		if (mode == SERVER_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "server_flow_stop=%u", &d);
			if (n == 1) {
				server_flow_stop = d;
				goto done;
			}
		}
	} else if (strncmp(data, "protocol=", 9) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "protocol=%u", &d);
			if (n == 1) {
				default_protocol = d;
				goto done;
			}
		}
	} else if (strncmp(data, "server_persist_timeout=", 23) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "server_persist_timeout=%u", &d);
			if (n == 1) {
				server_persist_timeout = d;
				goto done;
			}
		}
	} else if (strncmp(data, "server_persist_lock=", 20) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "server_persist_lock=%u", &d);
			if (n == 1) {
				server_persist_lock = !!d;
				goto done;
			}
		}
	} else if (strncmp(data, "dns_proxy_drop=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "dns_proxy_drop=%u", &d);
			if (n == 1) {
				dns_proxy_drop = d;
				goto done;
			}
		}
	} else if (strncmp(data, "peer_multipath=", 15) == 0) {
		int d;
		n = sscanf(data, "peer_multipath=%u", &d);
		if (n == 1) {
			peer_multipath = d;
			goto done;
		}
		err = -EINVAL;
	} else if (strncmp(data, "tx_speed_limit=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "tx_speed_limit=%d", &d);
			if (n == 1) {
				natcap_tx_speed_set(d);
				goto done;
			}
		}
	} else if (strncmp(data, "rx_speed_limit=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "rx_speed_limit=%d", &d);
			if (n == 1) {
				natcap_rx_speed_set(d);
				goto done;
			}
		}
	} else if (strncmp(data, "tx_pkts_threshold=", 18) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "tx_pkts_threshold=%u", &d);
			if (n == 1) {
				tx_pkts_threshold = d;
				goto done;
			}
		}
	} else if (strncmp(data, "rx_pkts_threshold=", 18) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "rx_pkts_threshold=%u", &d);
			if (n == 1) {
				rx_pkts_threshold = d;
				goto done;
			}
		}
	} else if (strncmp(data, "http_confusion=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "http_confusion=%u", &d);
			if (n == 1) {
				http_confusion = d;
				goto done;
			}
		}
	} else if (strncmp(data, "cnipwhitelist_mode=", 19) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "cnipwhitelist_mode=%u", &d);
			if (n == 1) {
				cnipwhitelist_mode = d;
				goto done;
			}
		}
	} else if (strncmp(data, "encode_http_only=", 17) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "encode_http_only=%u", &d);
			if (n == 1) {
				encode_http_only = d;
				goto done;
			}
		}
	} else if (strncmp(data, "sproxy=", 7) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "sproxy=%u", &d);
			if (n == 1) {
				sproxy = d;
				goto done;
			}
		}
	} else if (strncmp(data, "macfilter=", 10) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "macfilter=%u", &d);
			if (n == 1) {
				if (d == NATCAP_ACL_NONE || d == NATCAP_ACL_ALLOW || d == NATCAP_ACL_DENY) {
					macfilter = d;
					goto done;
				}
			}
		}
	} else if (strncmp(data, "ipfilter=", 9) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			int d;
			n = sscanf(data, "ipfilter=%u", &d);
			if (n == 1) {
				if (d == NATCAP_ACL_NONE || d == NATCAP_ACL_ALLOW || d == NATCAP_ACL_DENY) {
					ipfilter = d;
					goto done;
				}
			}
		}
	} else if (strncmp(data, "knock_port=", 11) == 0) {
		if (mode == KNOCK_MODE || mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			char e;
			n = sscanf(data, "knock_port=%u", &d);
			if (n == 1 && d <= 65535) {
				knock_port = htons((unsigned short)(d & 0xffff));
				n = sscanf(data, "knock_port=%u-%c", &d, &e);
				if (n == 2 && e == 'e') {
					knock_encryption = 1;
				} else {
					knock_encryption = 0;
				}
				if (n == 2) {
					char g, h;
					n = sscanf(data, "knock_port=%u-%c-%c-%c", &d, &e, &g, &h);
					if (n == 4 && (e == 'e' || e == 'o') && (g == 'T' || g == 'U') && (h == 'U' || h == 'T')) {
						knock_tcp_encode = g == 'T' ? TCP_ENCODE : UDP_ENCODE;
						knock_udp_encode = h == 'U' ? UDP_ENCODE : TCP_ENCODE;
					}
				}
				goto done;
			}
		}
	} else if (strncmp(data, "knock_flood=", 12) == 0) {
		if (mode == KNOCK_MODE || mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "knock_flood=%u", &d);
			if (n == 1) {
				knock_flood = d;
				goto done;
			}
		}
	} else if (strncmp(data, "natcap_redirect_port=", 21) == 0) {
		if (mode == SERVER_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "natcap_redirect_port=%u", &d);
			if (n == 1 && d <= 65535) {
				natcap_redirect_port = htons((unsigned short)(d & 0xffff));
				goto done;
			}
		}
	} else if (strncmp(data, "natcap_client_redirect_port=", 28) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "natcap_client_redirect_port=%u", &d);
			if (n == 1 && d <= 65535) {
				natcap_client_redirect_port = htons((unsigned short)(d & 0xffff));
				goto done;
			}
		}
	} else if (strncmp(data, "natcap_touch_timeout=", 21) == 0) {
		unsigned int d;
		n = sscanf(data, "natcap_touch_timeout=%u", &d);
		if (n == 1) {
			natcap_touch_timeout = d;
			goto done;
		}
	} else if (strncmp(data, "natcap_max_pmtu=", 16) == 0) {
		unsigned int d;
		n = sscanf(data, "natcap_max_pmtu=%u", &d);
		if (n == 1 && d >= NATCAP_MIN_PMTU && d <= NATCAP_MAX_PMTU) {
			natcap_max_pmtu = d;
			goto done;
		}
	} else if (strncmp(data, "auth_http_redirect_url=", 23) == 0) {
		if (mode == SERVER_MODE || mode == MIXING_MODE) {
			char *tmp = NULL;
			tmp = kmalloc(2048, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "auth_http_redirect_url=%s\n", tmp);
			if (n == 1 && memcmp("http", tmp, 4) == 0) {
				void *old = auth_http_redirect_url;
				auth_http_redirect_url = tmp;
				if (old) {
					synchronize_rcu();
					kfree(old);
				}
				goto done;
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "htp_confusion_host=", 19) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char *tmp = NULL;
			tmp = kmalloc(1024, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "htp_confusion_host=%s\n", tmp);
			tmp[1023] = 0;
			if (n == 1 && strlen(tmp) <= 63) {
				strcpy(htp_confusion_host, tmp);
				kfree(tmp);
				sprintf(htp_confusion_req, htp_confusion_req_format, get_random_u32(), htp_confusion_host);
				goto done;
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "cn_domain_dump=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char *tmp = kmalloc(1024, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "cn_domain_dump=%s\n", tmp);
			tmp[1023] = 0;
			if (n == 1) {
				err = cn_domain_dump_path(tmp);
				if (err == 0) {
					kfree(tmp);
					goto done;
				}
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "cn_domain_path=", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char *tmp = kmalloc(1024, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "cn_domain_path=%s\n", tmp);
			tmp[1023] = 0;
			if (n == 1) {
				err = cn_domain_load_from_path(tmp);
				if (err == 0) {
					kfree(tmp);
					goto done;
				}
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "cn_domain_raw=", 14) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char *tmp = kmalloc(1024, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "cn_domain_raw=%s\n", tmp);
			tmp[1023] = 0;
			if (n == 1) {
				err = cn_domain_load_from_raw(tmp);
				if (err == 0) {
					kfree(tmp);
					goto done;
				}
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "cn_domain=", 10) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char tmp[128];
			n = sscanf(data, "cn_domain=%s\n", tmp);
			tmp[127] = 0;
			if (n == 1) {
				err = cn_domain_insert(tmp);
				if (err == 0) {
					goto done;
				}
			}
		}
	} else if (strncmp(data, "cn_domain_clean", 15) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			cn_domain_clean();
			goto done;
		}
	} else if (strncmp(data, "lk_domain=", 10) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			char tmp[128];
			n = sscanf(data, "lk_domain=%s\n", tmp);
			tmp[127] = 0;
			if (n == 1) {
				n = cn_domain_lookup(tmp);
				printk("cn_domain_lookup (%s) ret = %d\n", tmp, n);
				goto done;
			}
		}
	} else if (strncmp(data, "default_mac_addr=", 17) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == PEER_MODE) {
			unsigned int a, b, c, d, e, f;
			n = sscanf(data, "default_mac_addr=%02x:%02x:%02x:%02x:%02x:%02x\n", &a, &b, &c, &d, &e, &f);
			if (n != 6) {
				n = sscanf(data, "default_mac_addr=%02x-%02x-%02x-%02x-%02x-%02x\n", &a, &b, &c, &d, &e, &f);
			}
			if ( n == 6 &&
			        ((a & 0xff) == a) &&
			        ((b & 0xff) == b) &&
			        ((c & 0xff) == c) &&
			        ((d & 0xff) == d) &&
			        ((e & 0xff) == e) &&
			        ((f & 0xff) == f) ) {
				default_mac_addr[0] = a;
				default_mac_addr[1] = b;
				default_mac_addr[2] = c;
				default_mac_addr[3] = d;
				default_mac_addr[4] = e;
				default_mac_addr[5] = f;
				goto done;
			}
		}
	} else if (strncmp(data, "dns_server_node_add=", 20) == 0) {
		if (mode == SERVER_MODE || mode == MIXING_MODE) {
			unsigned int a, b, c, d;
			n = sscanf(data, "dns_server_node_add=%u.%u.%u.%u", &a, &b, &c, &d);
			if ( (n == 4) &&
			        (((a & 0xff) == a) &&
			         ((b & 0xff) == b) &&
			         ((c & 0xff) == c) &&
			         ((d & 0xff) == d)) ) {
				err = dns_server_node_add( htonl((a<<24)|(b<<16)|(c<<8)|(d<<0)) );
				if (err == 0) {
					goto done;
				}
			}
		}
	} else if (strncmp(data, "dns_server_node_clean", 21) == 0) {
		dns_server_node_clean();
		goto done;
	} else if (strncmp(data, "cone_nat_clean", 14) == 0) {
		cone_nat_cleanup();
		goto done;
	} else if (strncmp(data, "cone_nat_drop=", 14) == 0) {
		unsigned int a[10];
		n = sscanf(data, "cone_nat_drop=%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
		           &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7], &a[8], &a[9]);
		if ( (n == 10) &&
		        (((a[0] & 0xff) == a[0]) &&
		         ((a[1] & 0xff) == a[1]) &&
		         ((a[2] & 0xff) == a[2]) &&
		         ((a[3] & 0xff) == a[3]) &&
		         ((a[4] & 0xffff) == a[4]) &&
		         ((a[5] & 0xff) == a[5]) &&
		         ((a[6] & 0xff) == a[6]) &&
		         ((a[7] & 0xff) == a[7]) &&
		         ((a[8] & 0xff) == a[8]) &&
		         ((a[9] & 0xffff) == a[9])) ) {
			__be32 iip = htonl((a[0]<<24)|(a[1]<<16)|(a[2]<<8)|(a[3]<<0));
			__be16 iport = htons(a[4]);
			__be32 eip = htonl((a[5]<<24)|(a[6]<<16)|(a[7]<<8)|(a[8]<<0));
			__be16 eport = htons(a[9]);
			cone_nat_drop(iip, iport, eip, eport);
			goto done;
		}
	} else if (strncmp(data, "natmap_add=", 11) == 0) {
		unsigned int a, b, c, d;
		unsigned int port;
		unsigned int port1;
		n = sscanf(data, "natmap_add=%u-%u.%u.%u.%u", &port, &a, &b, &c, &d);
		if ( (n == 5) && ((port & 0xffff) == port) &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			if (!natmap_dip) {
				natmap_dip = vmalloc(sizeof(__be32) * 65536);
				if (!natmap_dip) {
					return -ENOMEM;
				}
				memset(natmap_dip, 0, sizeof(__be32) * 65536);
			}
			natmap_dip[port] = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			goto done;
		}
		n = sscanf(data, "natmap_add=%u-%u-%u.%u.%u.%u", &port, &port1, &a, &b, &c, &d);
		if ( (n == 6) && ((port & 0xffff) == port) && ((port1 & 0xffff) == port1) && port <= port1 &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			if (!natmap_dip) {
				natmap_dip = vmalloc(sizeof(__be32) * 65536);
				if (!natmap_dip) {
					return -ENOMEM;
				}
				memset(natmap_dip, 0, sizeof(__be32) * 65536);
			}
			natmap_dip[port1] = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			for (; port < port1; port = ((port + 1) & 0xffff))
				natmap_dip[port] = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			goto done;
		}
	} else if (strncmp(data, "natmap_clean", 12) == 0) {
		natmap_start = 0;
		natmap_end = 0;
		synchronize_rcu();
		if (natmap_dip) {
			vfree(natmap_dip);
			natmap_dip = NULL;
		}
		goto done;
	} else if (strncmp(data, "natmap_start=", 13) == 0) {
		unsigned int port;
		n = sscanf(data, "natmap_start=%u", &port);
		if ( (n == 1) && ((port & 0xffff) == port) ) {
			natmap_start = port;
			goto done;
		}
	} else if (strncmp(data, "natmap_end=", 11) == 0) {
		unsigned int port;
		n = sscanf(data, "natmap_end=%u", &port);
		if ( (n == 1) && ((port & 0xffff) == port) ) {
			natmap_end = port;
			goto done;
		}
	}

	NATCAP_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int natcap_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	if (natcap_ctl_buffer_use++ == 0)
	{
		natcap_ctl_buffer = kmalloc(SEQ_PGSZ, GFP_KERNEL);
		if (natcap_ctl_buffer == NULL) {
			natcap_ctl_buffer_use--;
			return -ENOMEM;
		}
	}

	ret = seq_open(file, &natcap_seq_ops);
	if (ret)
		return ret;

	return 0;
}

static int natcap_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);

	if (--natcap_ctl_buffer_use == 0) {
		kfree(natcap_ctl_buffer);
		natcap_ctl_buffer = NULL;
	}

	return ret;
}

static struct file_operations natcap_fops = {
	.owner = THIS_MODULE,
	.open = natcap_open,
	.release = natcap_release,
	.read = natcap_read,
	.write = natcap_write,
	.llseek  = seq_lseek,
};

static int natcap_mode_init(void)
{
	int ret = -1;
	switch (mode) {
	case CLIENT_MODE:
		ret = natcap_client_init();
		if (ret != 0) {
			break;
		}
		ret = natcap_peer_init();
		if (ret != 0) {
			natcap_client_exit();
			break;
		}
		break;
	case SERVER_MODE:
		ret = natcap_server_init();
		if (ret != 0) {
			break;
		}
		ret = natcap_peer_init();
		if (ret != 0) {
			natcap_server_exit();
			break;
		}
		break;
	case MIXING_MODE:
		ret = natcap_client_init();
		if (ret != 0) {
			break;
		}
		ret = natcap_server_init();
		if (ret != 0) {
			natcap_client_exit();
			break;
		}
		ret = natcap_peer_init();
		if (ret != 0) {
			natcap_server_exit();
			natcap_client_exit();
			break;
		}
		break;
	case KNOCK_MODE:
		ret = natcap_knock_init();
		break;
	case PEER_MODE:
		ret = natcap_peer_init();
	default:
		break;
	}
	return ret;
}

static void natcap_mode_exit(void)
{
	switch (mode) {
	case CLIENT_MODE:
		natcap_peer_exit();
		natcap_client_exit();
		break;
	case SERVER_MODE:
		natcap_peer_exit();
		natcap_server_exit();
		break;
	case MIXING_MODE:
		natcap_peer_exit();
		natcap_server_exit();
		natcap_client_exit();
		break;
	case KNOCK_MODE:
		natcap_knock_exit();
		break;
	case PEER_MODE:
		natcap_peer_exit();
	default:
		break;
	}
}

static int __init natcap_init(void) {
	int retval = 0;
	dev_t devno;

	NATCAP_println("version: " NATCAP_VERSION "");

	if (natcap_major>0) {
		devno = MKDEV(natcap_major, natcap_minor);
		retval = register_chrdev_region(devno, number_of_devices, natcap_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, natcap_minor, number_of_devices, natcap_dev_name);
	}
	if (retval < 0) {
		NATCAP_println("alloc_chrdev_region failed!");
		return retval;
	}
	natcap_major = MAJOR(devno);
	natcap_minor = MINOR(devno);
	NATCAP_println("natcap_major=%d, natcap_minor=%d", natcap_major, natcap_minor);

	cdev_init(&natcap_cdev, &natcap_fops);
	natcap_cdev.owner = THIS_MODULE;
	natcap_cdev.ops = &natcap_fops;

	retval = cdev_add(&natcap_cdev, devno, 1);
	if (retval) {
		NATCAP_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	natcap_class = class_create(THIS_MODULE, "natcap_class");
#else
	natcap_class = class_create("natcap_class");
#endif
	if (IS_ERR(natcap_class)) {
		NATCAP_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	natcap_dev = device_create(natcap_class, NULL, devno, NULL, natcap_dev_name);
	if (!natcap_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	retval = natcap_common_init();
	if (retval != 0)
		goto err0;

	retval = natcap_mode_init();
	if (retval != 0)
		goto err1;

	return 0;

	//natcap_mode_exit();
err1:
	natcap_common_exit();
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

	NATCAP_println("removing");

	natcap_mode_exit();
	natcap_common_exit();

	devno = MKDEV(natcap_major, natcap_minor);
	device_destroy(natcap_class, devno);
	class_destroy(natcap_class);
	cdev_del(&natcap_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	NATCAP_println("done");
	return;
}

module_init(natcap_init);
module_exit(natcap_exit);

MODULE_AUTHOR("Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=");
MODULE_VERSION(NATCAP_VERSION);
MODULE_DESCRIPTION("Natcap packet to avoid inspection");
MODULE_LICENSE("GPL");
