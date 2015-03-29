//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
/* хэш по qinq */
u32 qinq_buckets = 8192;
struct hlist_head * qinq_hash = NULL;
unsigned int qinq_jhash_rnd __read_mostly;
//-----------------------------------------------------------------------------
/* хэш по ip */
u32 ip_buckets = 8192;
struct hlist_head * ip_hash = NULL;
unsigned int ip_jhash_rnd __read_mostly;
//-----------------------------------------------------------------------------
/* хэш по mac */
u32 mac_buckets = 8192;
struct hlist_head * mac_hash = NULL;
unsigned int mac_jhash_rnd __read_mostly;
//-----------------------------------------------------------------------------
void term_cmd_session(void * data) {
	struct term_session_info *ev = (struct term_session_info *)data;
	struct term_session * ts;
	struct term_subnet * sb;

	ts = term_ip_lookup_session_all(ev->ip);
	if (ts) {

		/* Подсеть абонента */
		sb = term_find_subnet(ev->ip);
		if (!sb)
			return;

		spin_lock_bh(&term_lock);

		/* Абонент перепрыгнул в другой порт. */
		if (ts->info.q != ev->q || ts->info.v != ev->v) {
			// Необходимо погасить сессию перед изменением.
			// т.к. после - это уже другая сессия с другими параметрами,
			// и при исчерпании таймера будут пременены уже изменённые данные.
			// возникает состояние залипания включенной сесии, не удаляется маршрут
			// и не уведомляется биллинг.
			term_set_user_inactive(ts);

			/* Очищаем счётчики */
			memset(&ts->st,0,sizeof(struct term_stat));

			hlist_del(&ts->qinq_index);
			ts->info.q = ev->q;
			ts->info.v = ev->v;
			term_insert_qinq_hash(ts);
		}

		/* Абонент сменил MAC. */
		if (!ether_addr_equal(ts->info.mac, ev->mac)) {
			term_set_user_inactive(ts);
			hlist_del(&ts->mac_index);
			memcpy(ts->info.mac, ev->mac, ETH_ALEN);
			term_insert_mac_hash(ts);
		}

		ts->sb.gw = sb->gw;
		ts->sb.mk = sb->mk;
		ts->sb.sb = sb->sb;
		ts->sb.bk = sb->bk;
		ts->info.lock = ev->lock;
		ts->info.multiuser = ev->multiuser;
		spin_unlock_bh(&term_lock);
	} else {

		/* Подсеть абонента */
		sb = term_find_subnet(ev->ip);
		if (!sb)
			return;

		ts = kzalloc(sizeof(struct term_session), GFP_KERNEL);
		if (!ts) {
			printk(KERN_ERR "term: %s session allocation failed\n",__func__);
			return;
		}

		ts->info.q             = ev->q;
		ts->info.v             = ev->v;
		ts->info.ip            = ev->ip;
		ts->sb.gw              = sb->gw;
		ts->sb.mk              = sb->mk;
		ts->sb.sb              = sb->sb;
		ts->sb.bk              = sb->bk;
		memcpy(ts->info.mac, ev->mac, ETH_ALEN);
		ts->info.lock          = ev->lock;
		ts->info.multiuser     = ev->multiuser;

		spin_lock_bh(&term_lock);
		term_insert_ip_hash(ts);
		term_insert_mac_hash(ts);
		term_insert_qinq_hash(ts);
		spin_unlock_bh(&term_lock);

	}
}
//-----------------------------------------------------------------------------
int term_sessions_init(void) {

	int hsize;
	int i;

	/* IP HASHING */
	get_random_bytes(&ip_jhash_rnd, sizeof(ip_jhash_rnd));
	hsize = sizeof(struct hlist_head) * ip_buckets;
	ip_hash = vmalloc(hsize);

	if (!ip_hash) {
		printk(KERN_INFO "term: session: can't allocate hash ip buffers\n");
		return -1;
	}

	for (i = 0; i < ip_buckets; i++)
		INIT_HLIST_HEAD(&ip_hash[i]);

	/* MAC HASHING */
	get_random_bytes(&mac_jhash_rnd, sizeof(mac_jhash_rnd));
	hsize = sizeof(struct hlist_head) * mac_buckets;
	mac_hash = vmalloc(hsize);

	if (!mac_hash) {
		printk(KERN_INFO "term: session: can't allocate hash mac buffers\n");
		goto mac_err;
	}

	for (i = 0; i < mac_buckets; i++)
		INIT_HLIST_HEAD(&mac_hash[i]);

	/* QINQ HASHING */
	get_random_bytes(&qinq_jhash_rnd, sizeof(qinq_jhash_rnd));
	hsize = sizeof(struct hlist_head) * qinq_buckets;
	qinq_hash = vmalloc(hsize);

	if (!qinq_hash) {
		printk(KERN_INFO "term: session: can't allocate hash QinQ buffers\n");
		goto qinq_err;
	}

	for (i = 0; i < qinq_buckets; i++)
		INIT_HLIST_HEAD(&qinq_hash[i]);

	return 0;

qinq_err:
	vfree(mac_hash);
mac_err:
	vfree(ip_hash);

	return -1;
}
//-----------------------------------------------------------------------------
void term_sessions_destroy(void) {
	struct term_session * ts;
	struct hlist_node * t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
#endif
	u32 i;

	/* Очищаем список сессий */
	for (i = 0; i < ip_buckets; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		hlist_for_each_entry_safe(ts, t, n, &ip_hash[i], ip_index)
#else
		hlist_for_each_entry_safe(ts, t, &ip_hash[i], ip_index)
#endif
		{
			hlist_del(&ts->ip_index);
			hlist_del(&ts->mac_index);
			hlist_del(&ts->qinq_index);
			if (ts->st.flags & TERM_SES_ONLINE)
				term_route_del(ts->info.ip);
			kfree(ts);
		}
	}
	vfree(ip_hash);
	vfree(mac_hash);
	vfree(qinq_hash);
}
//-----------------------------------------------------------------------------
