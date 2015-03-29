//-----------------------------------------------------------------------------
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <uapi/linux/in.h> //IPPROTO_TCP
#include <linux/ip.h>  //ip_hdr
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
//-----------------------------------------------------------------------------
static int white_buckets = 8192;
static struct list_head * white_hash = NULL;
static unsigned int white_rnd __read_mostly;
static struct task_struct *white_thread; // ��������� ������

/* ���� �� ������� ���� ������� �� ������� ����� ������� ��� ���������� ����������. */
static char whitelist_buf[256] = "/etc/nms/whitelist";
static char *whitelist = whitelist_buf;
module_param(whitelist, charp, 0444);
MODULE_PARM_DESC(whitelist, "captive portal ip addres list file");
//-----------------------------------------------------------------------------
struct white_ips {
	struct rcu_head rcu;
	struct list_head list;
	u32 ip;
	atomic_t delete;
};
//-----------------------------------------------------------------------------
static inline unsigned int get_white_hash (u32 ip) {
	return jhash_1word(ip, white_rnd) & (white_buckets - 1);
}
//-----------------------------------------------------------------------------
static inline void insert_white_hash (struct white_ips * is) {
	unsigned int h = get_white_hash(is->ip);
	list_add_rcu(&is->list, &white_hash[h]);
}
//-----------------------------------------------------------------------------
static inline int ip_match_white(u32 ip) {

	struct white_ips * is;

	unsigned int h = get_white_hash(ip);

	rcu_read_lock();
	list_for_each_entry_rcu(is, &white_hash[h], list)
		if (is->ip == ip) {
			rcu_read_unlock();
			return 1;
		}

	rcu_read_unlock();
	return 0;
}
//-----------------------------------------------------------------------------
static inline int ip_undelete_white(u32 ip) {

	struct white_ips * is;

	unsigned int h = get_white_hash(ip);

	rcu_read_lock();
	list_for_each_entry_rcu(is, &white_hash[h], list)
		if (is->ip == ip) {
			atomic_set(&is->delete, 0);
			rcu_read_unlock();
			return 1;
		}

	rcu_read_unlock();
	return 0;
}
//-----------------------------------------------------------------------------
static void term_white_add(u32 ip) {
	struct white_ips * is;

	/* ��� ���� � ������. */
	if (ip_undelete_white(ip))
		return;

	/* �������� ������ ��� ������� ������. */
	is = kzalloc(sizeof(struct white_ips), GFP_ATOMIC);

	if (!is) {
		if (net_ratelimit())
			printk(KERN_ERR "term: white: \"struct white_https_ips\" allocation failed\n");
		return;
	}

	is->ip = ip;
	atomic_set(&is->delete, 0);

	insert_white_hash(is);
}
//-----------------------------------------------------------------------------
int term_white_match(struct sk_buff *skb) {

	struct iphdr * iph;
	struct tcphdr * tph;
	struct udphdr * uph;

	iph = ip_hdr(skb);

	switch (iph->protocol) {
		case IPPROTO_TCP:

			tph = (struct tcphdr *)(skb->data+(iph->ihl<<2));

			/* input */
			switch (tph->source) {
				case htons(443): // https
				case htons(80):  // http
				case htons(53):  // dns
					if (ip_match_white(iph->saddr))
						return 1;
				break;
			}

			/* output */
			switch (tph->dest) {
				case htons(443): // https
				case htons(80):  // http
				case htons(53):  // dns
					if (ip_match_white(iph->daddr))
						return 1;
				break;
			}
		break;

		case IPPROTO_UDP:

			uph = (struct udphdr *)(skb->data+(iph->ihl<<2));

			/* input */
			if (uph->source == htons(53) // dns
			 && ip_match_white(iph->saddr))
				return 1;

			/* output */
			if (uph->dest == htons(53)  // dns
			 && ip_match_white(iph->daddr))
				return 1;
		break;
	}

	return 0;
}
//-----------------------------------------------------------------------------
static void mark_to_delete(void) {

	struct white_ips * wh;
	int i = 0;

	for (i = 0; i < white_buckets; i++) {
		rcu_read_lock();
		list_for_each_entry_rcu(wh, &white_hash[i], list)
				atomic_set(&wh->delete, 1);
		rcu_read_unlock();
	}

}
//-----------------------------------------------------------------------------
static void delete_marked(void) {

	struct white_ips * wh;
	int i = 0;

	for (i = 0; i < white_buckets; i++) {
		rcu_read_lock();
		list_for_each_entry_rcu(wh, &white_hash[i], list) {
			if (atomic_read(&wh->delete)) {
				list_del_rcu(&wh->list);
				kfree_rcu(wh, rcu);
			}
		}
		rcu_read_unlock();
	}
}
//-----------------------------------------------------------------------------
static __kernel_time_t readfile(__kernel_time_t modifed) {

	struct kstat stat;
	struct file *f;
	size_t n;
	loff_t len;
	loff_t file_offset = 0;
	void * buff;
	char * str;
	char * begin;
	mm_segment_t fs = get_fs();
	set_fs(get_ds());

	/* ��������� ������� �����. */
	if (vfs_stat(whitelist, &stat)) {
		printk("term: white: File not exist: '%s'\n", whitelist);
		goto fail_open;
	}

	/* ��������� ���������� �� ����� ���������� �����. */
	if (stat.mtime.tv_sec == modifed)
		goto fail_open;

	/* ������� ������� ����. */
	f = filp_open(whitelist, O_RDONLY, 0);

	if (IS_ERR(f)) {
		printk("term: white: Failed to open file: '%s'\n", whitelist);
		goto fail_open;
	}

	/* �������� ������ �����. */
	len = vfs_llseek(f, 0L, SEEK_END);
	if (len <= 0)
		goto failure;

	/* �������� ����� ��� ������ ����������� �����. */
	if (NULL == (buff = vmalloc(len)))
		goto failure;

	/* �������� ������� ������� �� ������ �����. */
	vfs_llseek(f, 0L, SEEK_SET);

	/* ������ ���������� ����� � �����. */
	if ((n = vfs_read(f, buff, len, &file_offset)) != len) {
		printk("term: white: Failed to read file '%s'\n", whitelist);
		vfree(buff);
		goto failure;
	}

	*(char*)(buff + n) = '\0';

	/* ��������� ����. */
	filp_close(f, NULL);
	set_fs(fs);

	/* ������������ �������� �� ������ ������. */
	str = (char*)buff;

	/* �������� ��� �������� ������ �� ��������. */
	mark_to_delete();

	/* ���� �� ������� �� ����� ������. */
	while (str < (char*)buff + n) {

		/* ��������� ������� � ������ ������. */
		while (*str == ' ')
			str++;

		/* ���� ������ ������ � ������ ����������� - ���������� ��� ������. */
		if (*str == '#')
			while (*str != '\n' && *str != '\0')
				str++;

		/* ���� ������ - ������. */
		if (*str == '\n') {
			str++;
			continue;
		}

		/* ���� ��������� ����� ���������. */
		if (*str == '\0')
			break;

		/* ��� ��� str ��������� �� ������ ������. */
		begin = str;

		/* �ģ� �� ������ �� ���������� ����� �����, �������� ������, ���� �������. */
		while (*str != '\0' && *str != '\n' && *str != ' ')
			str++;

		/* ���������� ����� ������. */
		*str = '\0';

		/* ������������ ������ � ���� � ������� � ������. */
		term_white_add(in_aton(begin));

		str++;
	}

	/* ����������� �����. */
	vfree(buff);

	/* ������� ���������� �������� ������. */
	delete_marked();

	/* ���������� ����� ������������� ��������� �����. */
	return stat.mtime.tv_sec;

failure:
	filp_close(f, NULL);

fail_open:
	set_fs(fs);
	return modifed;
}
//-----------------------------------------------------------------------------
static int term_white_thread(void * unused) {
	u32 i = 0;
	/* ����� ��������� ����� �� ������� ���� �������. */
	__kernel_time_t modifed = 0;

	while (!kthread_should_stop()) {
		if (++i % 600) {
			msleep(100); // 0.1c
			continue;
		}
		/* ��� � ������ ����������� ������ ��������� �������. */
		modifed = readfile(modifed);
	}

	return 0;
}
//-----------------------------------------------------------------------------
int term_white_init(void) {

	unsigned int i;
	int hsize = 0;

	get_random_bytes(&white_rnd, sizeof(white_rnd));
	hsize = sizeof(struct list_head) * white_buckets;
	white_hash = vmalloc(hsize);

	if (white_hash == NULL)
		return 1;

	for (i = 0; i < white_buckets; i++)
		INIT_LIST_HEAD(&white_hash[i]);

	/* ��������� �����. */
	white_thread = kthread_run(term_white_thread, NULL, "term_isg_white");

	return 0;
}
//-----------------------------------------------------------------------------
void term_white_destroy(void) {

	struct white_ips * wh;
	int i;

	/* ������������� �����. */
	kthread_stop(white_thread);

	/* ��������� �� ���. */
	for (i = 0; i < white_buckets; i++)
		list_for_each_entry(wh, &white_hash[i], list) {
			list_del_rcu(&wh->list);
			kfree_rcu(wh, rcu);
		}

	vfree(white_hash);
}
//-----------------------------------------------------------------------------
