/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
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
				"# Usage:\n"
				"#    debug=Number -- set debug value\n"
				"#    client_forward_mode=Number -- set client forward mode value\n"
				"#    server [ip]:[port]-[e/o] -- add one server\n"
				"#    delete [ip]:[port]-[e/o] -- delete one server\n"
				"#    clean -- remove all existing server(s)\n"
				"#\n"
				"# Info:\n"
				"#    mode=%s\n"
				"#    default_mac_addr=%02X:%02X:%02X:%02X:%02X:%02X\n"
				"#    default_u_hash=%u\n"
				"#    server_seed=%u\n"
				"#    debug=%u\n"
				"#    client_forward_mode=%u\n"
				"#    server_persist_timeout=%u\n"
				"#\n"
				"# Reload cmd:\n"
				"\n"
				"clean\n"
				"debug=%u\n"
				"u_hash=%u\n"
				"client_forward_mode=%u\n"
				"server_persist_timeout=%u\n"
				"\n",
				mode == 0 ? "client" : "server",
				default_mac_addr[0], default_mac_addr[1], default_mac_addr[2], default_mac_addr[3], default_mac_addr[4], default_mac_addr[5],
				ntohl(default_u_hash),
				server_seed, debug, client_forward_mode, server_persist_timeout,
				debug, ntohl(default_u_hash), client_forward_mode, server_persist_timeout);
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
		natcap_server_info_cleanup();
		goto done;
	} else if (strncmp(data, "server ", 7) == 0) {
		unsigned int a, b, c, d, e;
		char f;
		n = sscanf(data, "server %u.%u.%u.%u:%u-%c", &a, &b, &c, &d, &e, &f);
		if ( (n == 6 && e <= 0xffff) &&
				(f == 'e' || f == 'o') &&
				(((a & 0xff) == a) &&
				 ((b & 0xff) == b) &&
				 ((c & 0xff) == c) &&
				 ((d & 0xff) == d)) ) {
			dst.ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			dst.port = htons(e);
			dst.encryption = !!(f == 'e');
			if ((err = natcap_server_info_add(&dst)) == 0)
				goto done;
			NATCAP_println("natcap_server_add() failed ret=%d", err);
		}
	} else if (strncmp(data, "delete", 6) == 0) {
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
	} else if (strncmp(data, "debug=", 6) == 0) {
		int d;
		n = sscanf(data, "debug=%u", &d);
		if (n == 1) {
			debug = d;
			goto done;
		}
	} else if (strncmp(data, "u_hash=", 7) == 0) {
		unsigned int d;
		n = sscanf(data, "u_hash=%u", &d);
		if (n == 1) {
			default_u_hash = htonl(d);
			goto done;
		}
	} else if (strncmp(data, "client_forward_mode=", 20) == 0) {
		int d;
		n = sscanf(data, "client_forward_mode=%u", &d);
		if (n == 1) {
			client_forward_mode = d;
			goto done;
		}
	} else if (strncmp(data, "server_persist_timeout=", 23) == 0) {
		int d;
		n = sscanf(data, "server_persist_timeout=%u", &d);
		if (n == 1) {
			server_persist_timeout = d;
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
	if (mode == 0) {
		return natcap_client_init();
	}
	return natcap_server_init();
}

static void natcap_mode_exit(void)
{
	if (mode == 0) {
		natcap_client_exit();
		return;
	}
	natcap_server_exit();
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
