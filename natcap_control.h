/* Per-open, newline-delimited control input. */
#ifndef _NATCAP_CONTROL_H_
#define _NATCAP_CONTROL_H_

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "natcap_common.h"

struct natcap_ctl_seq {
	struct mutex input_lock;
	size_t len;
	char data[MAX_IOCTL_LEN];
	/* seq reads must not overwrite an incomplete command. */
	char buffer[PAGE_SIZE];
};

static inline int natcap_ctl_seq_open(struct file *file,
                                      const struct seq_operations *ops)
{
	struct seq_file *m;
	struct natcap_ctl_seq *ctl;
	int ret = seq_open_private(file, ops, sizeof(*ctl));

	if (ret)
		return ret;
	m = file->private_data;
	ctl = m->private;
	mutex_init(&ctl->input_lock);
	ctl->len = 0;
	return 0;
}

static inline int natcap_ctl_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct natcap_ctl_seq *ctl = m->private;

	mutex_destroy(&ctl->input_lock);
	return seq_release_private(inode, file);
}

static inline char *natcap_ctl_seq_buffer(struct seq_file *m)
{
	struct natcap_ctl_seq *ctl = m->private;

	return ctl->buffer;
}

static inline ssize_t natcap_ctl_seq_write(struct file *file,
        const char __user *buf, size_t count, loff_t *offset,
        int (*apply)(char *))
{
	struct seq_file *m = file->private_data;
	struct natcap_ctl_seq *ctl = m->private;
	size_t cnt, n;
	ssize_t ret;

	/* dup/fork share this lock; hold it until the command is applied. */
	mutex_lock(&ctl->input_lock);
	cnt = min_t(size_t, count, sizeof(ctl->data) - ctl->len);
	if (!cnt) {
		ret = 0;
		goto out;
	}
	if (copy_from_user(ctl->data + ctl->len, buf, cnt)) {
		ret = -EACCES;
		goto out;
	}

	n = 0;
	/* Whitespace in a continuation belongs to the pending command. */
	if (!ctl->len) {
		while (n < cnt && (ctl->data[n] == ' ' ||
		                   ctl->data[n] == '\n' || ctl->data[n] == '\t'))
			n++;
	}
	if (n)
		goto consumed;
	while (n < cnt && ctl->data[ctl->len + n] != '\n')
		n++;
	if (n == cnt) {
		ctl->len += n;
		if (ctl->len == sizeof(ctl->data)) {
			NATCAP_println("err: too long a line");
			ctl->len = 0;
			ret = -EINVAL;
			goto out;
		}
		goto consumed;
	}
	ctl->data[ctl->len + n] = '\0';
	ctl->len = 0;
	n++;
	/* An apply error discards the line; retry the complete command. */
	ret = apply(ctl->data);
	if (ret)
		goto out;
consumed:
	*offset += n;
	ret = n;
out:
	mutex_unlock(&ctl->input_lock);
	return ret;
}

#endif
