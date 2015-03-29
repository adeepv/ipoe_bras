//-----------------------------------------------------------------------------
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
static const char name_root[] = "term";
static const char name_sess[] = "sessions";
static const char name_subnet[] = "subnet";
//-----------------------------------------------------------------------------
struct proc_dir_entry *term_proc_dir;
struct proc_dir_entry *term_proc_sess;
struct proc_dir_entry *term_proc_subnet;
//-----------------------------------------------------------------------------
static void term_proc_show_start(struct seq_file *seq) {
	seq_puts(seq, "+-------+-------+-------------------+-----------------+--------+----------+--------+--------+--------+\n");
	seq_puts(seq, "| Q-tag | V-tag |     HW-addres     |    IP-addres    | State  | StateChg | Status | Input  |  DHCP  |\n");
	seq_puts(seq, "+-------+-------+-------------------+-----------------+--------+----------+--------+--------+--------+\n");
}
//-----------------------------------------------------------------------------
static int term_proc_show_sess(struct seq_file *seq, void *v) {
	struct term_session * ts;
	u32 i;
	u32 j = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
#endif
	term_proc_show_start(seq);
	for (i = 0; i < ip_buckets; i++) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		hlist_for_each_entry(ts, n, &ip_hash[i], ip_index)
#else
		hlist_for_each_entry(ts, &ip_hash[i], ip_index)
#endif
		{
			j++;
			seq_printf(seq, "| %-5u | %-5u | %pM | %-15pI4 | %6s | %8lu | %6s | %6lu | %6lu |\n",
				ts->info.q, ts->info.v,&ts->info.mac,&ts->info.ip,
				 ((ts->st.flags & TERM_SES_ONLINE)?"Online":""),
				ts->st.lastChgState?(jiffies - ts->st.lastChgState) / HZ:0,
				 ((ts->info.lock)?"Locked":""),
				ts->st.lastOnline?(jiffies - ts->st.lastOnline) / HZ:0,
				ts->st.lastInputDHCP?(jiffies - ts->st.lastInputDHCP) / HZ:0
			);

			if (j % 50 == 0)
				term_proc_show_start(seq);

		}
	}
	seq_puts(seq, "+-------+-------+-------------------+-----------------+--------+----------+--------+--------+--------+\n");
	return 0;
}
//-----------------------------------------------------------------------------
static int term_proc_show_subnet(struct seq_file *seq, void *v) {
	struct term_subnet * sb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
#endif
	seq_puts(seq, "+--------------------+-----------------+-----------------+\n");
	seq_puts(seq, "|       subnet       |    GW-addres    |    BRD-addres   |\n");
	seq_puts(seq, "+--------------------+-----------------+-----------------+\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	hlist_for_each_entry(sb, n, &subnet_list, index)
#else
	hlist_for_each_entry(sb, &subnet_list, index)
#endif
	{
		seq_printf(seq, "| %15pI4/%-2u | %15pI4 | %15pI4 |\n",
			&sb->sb, sb->ml,&sb->gw,&sb->bk
		);
	}
	seq_puts(seq, "+--------------------+-----------------+-----------------+\n");
	return 0;
}
//-----------------------------------------------------------------------------
static int term_seq_open_sess(struct inode *inode, struct file *file) {
	return single_open(file, term_proc_show_sess, NULL);
}
//-----------------------------------------------------------------------------
static const struct file_operations term_fops_sess = {
	.owner   = THIS_MODULE,
	.open    = term_seq_open_sess,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
//-----------------------------------------------------------------------------
static int term_seq_open_subnet(struct inode *inode, struct file *file) {
	return single_open(file, term_proc_show_subnet, NULL);
}
//-----------------------------------------------------------------------------
static const struct file_operations term_fops_subnet = {
	.owner   = THIS_MODULE,
	.open    = term_seq_open_subnet,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
//-----------------------------------------------------------------------------
int term_proc_init(void) {

	term_proc_dir = proc_mkdir(name_root, init_net.proc_net);

	if (!term_proc_dir)
		goto err;

	term_proc_sess = proc_create(name_sess, S_IFREG|S_IRUSR|S_IWUSR, term_proc_dir, &term_fops_sess);

	if (!term_proc_sess)
		goto err;

	term_proc_subnet = proc_create(name_subnet, S_IFREG|S_IRUSR|S_IWUSR, term_proc_dir, &term_fops_subnet);

	if (!term_proc_subnet)
		goto err;

	return 0;

err:
	pr_err("can't create entry in proc filesystem!\n");
	term_proc_cleanup();
	return -ENOBUFS;
}
//-----------------------------------------------------------------------------
void term_proc_cleanup(void) {
	if (term_proc_sess)
		remove_proc_entry(name_sess, term_proc_dir);

	if (term_proc_subnet)
		remove_proc_entry(name_subnet, term_proc_dir);

	if (term_proc_dir)
		remove_proc_entry(name_root, init_net.proc_net);
}
//-----------------------------------------------------------------------------
