// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * PowerTCP debugfs interface
 *
 * Implemented by:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */

#include "tcp_powertcp_debugfs.h"

#include <linux/circ_buf.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/wait.h>

#define CSV_STR_LEN (1 << 10)

struct powertcp_debugfs {
	struct dentry *root_dir;

	bool open;

	struct mutex read_lock;
	struct mutex write_lock;
	struct circ_buf fifo;
	wait_queue_head_t fifo_event;
	char csv_str[CSV_STR_LEN];
};

// TODO: Move this as a dynamically allocated member to "struct powertcp"?
static struct powertcp_debugfs dbgfs;

static int powertcp_debugfs_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	mutex_lock(&dbgfs.write_lock);

	if (dbgfs.open) {
		/* Can only be opened by one at a time. */
		ret = -EBUSY;
		goto out;
	}

	dbgfs.open = true;
	ret = nonseekable_open(inode, file);

out:
	mutex_unlock(&dbgfs.write_lock);
	return ret;
}

static ssize_t powertcp_debugfs_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct circ_buf *fifo = &dbgfs.fifo;
	const char *fifo_pos;
	int n = 0;
	ssize_t ret = 0;
	int tail;

	mutex_lock(&dbgfs.read_lock);
	tail = fifo->tail;
	fifo_pos = &fifo->buf[tail];

	ret = wait_event_interruptible(dbgfs.fifo_event,
				       CIRC_CNT(fifo->head, tail,
						sizeof(dbgfs.csv_str)) > 0);
	if (ret) {
		goto out;
	}

	n = min_t(int, count,
		  CIRC_CNT_TO_END(fifo->head, tail, sizeof(dbgfs.csv_str)));
	ret = copy_to_user(user_buf, fifo_pos, n);
	if (ret) {
		goto out;
	}
	smp_store_release(&fifo->tail,
			  (tail + n) & (sizeof(dbgfs.csv_str) - 1));
	*ppos += n;
	ret = n;

	wake_up_all(&dbgfs.fifo_event);

out:
	mutex_unlock(&dbgfs.read_lock);
	return ret;
}

static int powertcp_debugfs_release(struct inode *inode, struct file *file)
{
	dbgfs.open = false;
	wake_up_all(&dbgfs.fifo_event);
	return 0;
}

static const struct file_operations powertcp_debugfs_stats_csv_fileops = {
	.llseek = no_llseek,
	.open = powertcp_debugfs_open,
	.owner = THIS_MODULE,
	.read = powertcp_debugfs_read,
	.release = powertcp_debugfs_release,
};

void powertcp_debugfs_exit(void)
{
	mutex_destroy(&dbgfs.read_lock);
	mutex_destroy(&dbgfs.write_lock);

	debugfs_remove_recursive(dbgfs.root_dir);
	dbgfs.root_dir = NULL;
}

void powertcp_debugfs_init(void)
{
	memset(&dbgfs, 0, sizeof(dbgfs));

	mutex_init(&dbgfs.read_lock);
	mutex_init(&dbgfs.write_lock);
	init_waitqueue_head(&dbgfs.fifo_event);
	dbgfs.fifo.buf = dbgfs.csv_str;

	dbgfs.root_dir = debugfs_create_dir("powertcp", NULL);
	if (IS_ERR(dbgfs.root_dir)) {
		pr_err("failed to create powertcp debugfs root dir\n");
		return;
	}

	debugfs_create_file("stats_csv", S_IFREG | S_IRUGO, dbgfs.root_dir,
			    NULL, &powertcp_debugfs_stats_csv_fileops);
}

void powertcp_debugfs_update(u32 ack_seq, u32 cwnd, unsigned long rate)
{
	const char *str;
	int len;
	int n;
	const char *str_pos;
	struct circ_buf *fifo = &dbgfs.fifo;

	if (!dbgfs.open) {
		return;
	}

	str = kasprintf(GFP_KERNEL, "%u,%u,%lu\n", ack_seq, cwnd, rate);
	if (unlikely(!str)) {
		return;
	}

	mutex_lock(&dbgfs.write_lock);

	for (len = strlen(str), str_pos = str; len > 0;
	     len -= n, str_pos += n) {
		int head = fifo->head;
		char *fifo_pos = &fifo->buf[head];

		wait_event(dbgfs.fifo_event,
			   CIRC_SPACE(head, fifo->tail, sizeof(dbgfs.csv_str)) >
					   0 ||
				   !dbgfs.open);
		if (!dbgfs.open) {
			goto out;
		}

		n = min(len, CIRC_SPACE_TO_END(head, fifo->tail,
					       sizeof(dbgfs.csv_str)));
		memcpy(fifo_pos, str_pos, n);
		smp_store_release(&fifo->head,
				  (head + n) & (sizeof(dbgfs.csv_str) - 1));
		wake_up_all(&dbgfs.fifo_event);
	}

out:
	mutex_unlock(&dbgfs.write_lock);
	kfree(str);
}
