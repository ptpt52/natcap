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
#include "natcap_forward.h"
#include "natcap_knock.h"
#include "natcap_peer.h"

static int natcap_major = 0;
static int natcap_minor = 0;
static int number_of_devices = 1;
static struct cdev natcap_cdev;
const char *natcap_dev_name = "natcap_ctl";
static struct class *natcap_class;
static struct device *natcap_dev;

static char natcap_ctl_buffer[PAGE_SIZE];
static void *natcap_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(natcap_ctl_buffer,
				sizeof(natcap_ctl_buffer) - 1,
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
				"#    current_server=" TUPLE_FMT "\n"
				"#    default_mac_addr=%02X:%02X:%02X:%02X:%02X:%02X\n"
				"#    u_hash=%u\n"
				"#    server_seed=%u\n"
				"#    auth_enabled=%u\n"
				"#    tx_speed_limit=%d B/s\n"
				"#    rx_speed_limit=%d B/s\n"
				"#    tx_pkts_threshold=%d\n"
				"#    rx_pkts_threshold=%d\n"
				"#    http_confusion=%u\n"
				"#    encode_http_only=%u\n"
				"#    sproxy=%u\n"
				"#    knock_port=%u\n"
				"#    natcap_redirect_port=%u\n"
				"#    natcap_touch_timeout=%u\n"
				"#    flow_total_tx_bytes=%llu\n"
				"#    flow_total_rx_bytes=%llu\n"
				"#    auth_http_redirect_url=%s\n"
				"#    htp_confusion_host=%s\n"
				"#    server_persist_lock=%u\n"
				"#    macfilter=%s(%u)\n"
				"#    ipfilter=%s(%u)\n"
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
				TUPLE_ARG(natcap_server_info_current()),
				default_mac_addr[0], default_mac_addr[1], default_mac_addr[2], default_mac_addr[3], default_mac_addr[4], default_mac_addr[5],
				ntohl(default_u_hash),
				server_seed, auth_enabled,
				natcap_tx_speed_get(),
				natcap_rx_speed_get(),
				tx_pkts_threshold,
				rx_pkts_threshold,
				http_confusion, encode_http_only, sproxy, ntohs(knock_port),
				ntohs(natcap_redirect_port),natcap_touch_timeout,
				flow_total_tx_bytes, flow_total_rx_bytes,
				auth_http_redirect_url,
				htp_confusion_host,
				server_persist_lock,
				macfilter_acl_str[macfilter], macfilter,
				ipfilter_acl_str[ipfilter], ipfilter,
				disabled, debug, server_persist_timeout,
				cnipwhitelist_mode, &dns_server, ntohs(dns_port));
		natcap_ctl_buffer[n] = 0;
		return natcap_ctl_buffer;
	} else if ((*pos) > 0) {
		struct tuple *dst = (struct tuple *)natcap_server_info_get((*pos) - 1);

		if (dst) {
			n = snprintf(natcap_ctl_buffer,
					sizeof(natcap_ctl_buffer) - 1,
					"server " TUPLE_FMT "\n",
					TUPLE_ARG(dst));
			natcap_ctl_buffer[n] = 0;
			return natcap_ctl_buffer;
		}
	}

	return NULL;
}

static void *natcap_next(struct seq_file *m, void *v, loff_t *pos)
{
	int n;
	struct tuple *dst;

	(*pos)++;
	if ((*pos) > 0) {
		dst = (struct tuple *)natcap_server_info_get((*pos) - 1);
		if (dst) {
			n = snprintf(natcap_ctl_buffer,
					sizeof(natcap_ctl_buffer) - 1,
					"server " TUPLE_FMT "\n",
					TUPLE_ARG(dst));
			natcap_ctl_buffer[n] = 0;
			return natcap_ctl_buffer;
		}
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
	int n, l;
	struct tuple dst;
	int cnt = 256;
	static char data[256];
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
		if (data_left >= 256) {
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
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			natcap_server_info_cleanup();
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
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			unsigned int a, b, c, d, e;
			char f, g, h;
			n = sscanf(data, "server %u.%u.%u.%u:%u-%c-%c-%c", &a, &b, &c, &d, &e, &f, &g, &h);
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
				if ((err = natcap_server_info_add(&dst)) == 0)
				{
					goto done;
				}
				NATCAP_println("natcap_server_add() failed ret=%d", err);
			}
		}
	} else if (strncmp(data, "change_server", 13) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			natcap_server_info_change(1);
			goto done;
		}
	} else if (strncmp(data, "delete", 6) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			unsigned int a, b, c, d, e;
			char f;
			n = sscanf(data, "delete %u.%u.%u.%u:%u-%c", &a, &b, &c, &d, &e, &f);
			if ( (n == 6 && e <= 0xffff) &&
					(f == 'e' || f == 'o') &&
					(((a & 0xff) == a) &&
					 ((b & 0xff) == b) &&
					 ((c & 0xff) == c) &&
					 ((d & 0xff) == d)) ) {
				dst.ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
				dst.port = htons(e);
				dst.encryption = !!(f == 'e');
				if ((err = natcap_server_info_delete(&dst)) == 0)
					goto done;
				NATCAP_println("natcap_server_delete() failed ret=%d", err);
			}
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
	} else if (strncmp(data, "u_hash=", 7) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "u_hash=%u", &d);
			if (n == 1) {
				default_u_hash = htonl(d);
				goto done;
			}
		}
	} else if (strncmp(data, "server_persist_timeout=", 23) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			int d;
			n = sscanf(data, "server_persist_timeout=%u", &d);
			if (n == 1) {
				server_persist_timeout = d;
				goto done;
			}
		}
	} else if (strncmp(data, "server_persist_lock=", 20) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == FORWARD_MODE) {
			int d;
			n = sscanf(data, "server_persist_lock=%u", &d);
			if (n == 1) {
				server_persist_lock = !!d;
				goto done;
			}
		}
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
			n = sscanf(data, "knock_port=%u", &d);
			if (n == 1 && d <= 65535) {
				knock_port = htons((unsigned short)(d & 0xffff));
				goto done;
			}
		}
	} else if (strncmp(data, "natcap_redirect_port=", 21) == 0) {
		if (mode == SERVER_MODE || mode == CLIENT_MODE || mode == MIXING_MODE) {
			unsigned int d;
			n = sscanf(data, "natcap_redirect_port=%u", &d);
			if (n == 1 && d <= 65535) {
				natcap_redirect_port = htons((unsigned short)(d & 0xffff));
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
	} else if (strncmp(data, "auth_http_redirect_url=", 23) == 0) {
		if (mode == SERVER_MODE) {
			char *tmp = NULL;
			tmp = kmalloc(2048, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			n = sscanf(data, "auth_http_redirect_url=%s\n", tmp);
			if (n == 1 && memcmp("http", tmp, 4) == 0) {
				if (auth_http_redirect_url) {
					kfree(auth_http_redirect_url);
				}
				auth_http_redirect_url = tmp;
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
				sprintf(htp_confusion_req, htp_confusion_req_format, prandom_u32(), htp_confusion_host);
				goto done;
			}
			kfree(tmp);
		}
	} else if (strncmp(data, "default_mac_addr=", 17) == 0) {
		if (mode == CLIENT_MODE || mode == MIXING_MODE || mode == PEER_MODE) {
			unsigned int a, b, c, d, e, f;
			n = sscanf(data, "default_mac_addr=%02X:%02X:%02X:%02X:%02X:%02X\n", &a, &b, &c, &d, &e, &f);
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
		if (mode == SERVER_MODE) {
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
	int ret = seq_open(file, &natcap_seq_ops);
	if (ret)
		return ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
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
		case FORWARD_MODE:
			ret = natcap_forward_init();
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
		case FORWARD_MODE:
			natcap_forward_exit();
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

	natcap_class = class_create(THIS_MODULE,"natcap_class");
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
