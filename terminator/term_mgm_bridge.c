//-----------------------------------------------------------------------------
#include <linux/if_vlan.h>
#include <linux/jhash.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
#define HASH_SIZE 256
//-----------------------------------------------------------------------------
struct timer_list gc_timer;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//                               BEGIN PORT
//-----------------------------------------------------------------------------
static spinlock_t			port_hash_lock;
static struct hlist_head		port_hash[HASH_SIZE];
static u32				port_salt __read_mostly;
//-----------------------------------------------------------------------------
struct mbr_port {
	struct hlist_node		hlist;
	u16				q_tag;
	u16				v_tag;
};
//-----------------------------------------------------------------------------
static inline u32 mbr_port_hash(u16 q_tag, u16 v_tag) {
	return jhash_2words(q_tag, v_tag, port_salt) & (HASH_SIZE - 1);
}
//-----------------------------------------------------------------------------
static struct mbr_port * mbr_find_port (u16 q_tag, u16 v_tag) {

	struct hlist_head * head;
	struct mbr_port * port;

	head = &port_hash[mbr_port_hash(q_tag, v_tag)];

	hlist_for_each_entry(port, head, hlist)
		if (port->q_tag == q_tag && port->v_tag == v_tag)
			return port;

	return NULL;
}
//-----------------------------------------------------------------------------
static struct mbr_port * mbr_create_port (u16 q_tag, u16 v_tag) {

	struct mbr_port * port;

	port = kzalloc(sizeof(*port), GFP_ATOMIC);
	if (!port) {
		if (net_ratelimit())
			printk(KERN_ERR "term: %s: port allocation failed\n",__func__);
		return NULL;
	}

	port->q_tag = q_tag;
	port->v_tag = v_tag;

	spin_lock_bh(&port_hash_lock);
	hlist_add_head(&port->hlist, &port_hash[mbr_port_hash(q_tag, v_tag)]);
	spin_unlock_bh(&port_hash_lock);

	return port;
}
//-----------------------------------------------------------------------------
//                                 END PORT
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//                                BEGIN MAC
//-----------------------------------------------------------------------------
static spinlock_t				hash_lock;
static struct hlist_head			hash[HASH_SIZE];
static u32					fdb_salt __read_mostly;
//-----------------------------------------------------------------------------
struct fdb_entry {
	struct rcu_head			rcu;
	struct hlist_node		hlist;
	struct mbr_port *		port;

	unsigned long			used;
	u8				mac[ETH_ALEN];
};
//-----------------------------------------------------------------------------
static inline u32 mbr_hash_mac(u8 * mac) {

	u32 a = get_unaligned((u32*)mac);
	u32 b = get_unaligned((u32*)(mac + 2));

	return jhash_2words(a, b, fdb_salt) & (HASH_SIZE - 1);
}
//-----------------------------------------------------------------------------
static struct fdb_entry *fdb_find_rcu(struct hlist_head *head,
				      const u8 *addr,
				      struct mbr_port * port) {

	struct fdb_entry *fdb;

	hlist_for_each_entry_rcu(fdb, head, hlist) {
		if (ether_addr_equal(fdb->mac, addr)) {
			if (port && port != fdb->port) {
				printk(KERN_ERR "term: mbr: mac flipflap: "
					"%pM %u:%u -> %u:%u\n",
					&fdb->mac,
					fdb->port->q_tag,fdb->port->v_tag,
					port->q_tag,port->v_tag);
				fdb->port = port;
			}
			return fdb;
		}
	}

	return NULL;
}
//-----------------------------------------------------------------------------
static struct fdb_entry *fdb_create(struct hlist_head *head,
				    const u8 *mac,
				    struct mbr_port * port) {

	struct fdb_entry *fdb;

	fdb = kzalloc(sizeof(*fdb), GFP_ATOMIC);
	if (!fdb) {
		if (net_ratelimit())
			printk(KERN_ERR "term: %s: fdb_entry allocation failed\n",__func__);
		return NULL;
	}

	memcpy(fdb->mac, mac, ETH_ALEN);
	fdb->port = port;

	hlist_add_head_rcu(&fdb->hlist, head);

	return fdb;
}
//-----------------------------------------------------------------------------
static void fdb_delete(struct fdb_entry *f) {
	hlist_del_rcu(&f->hlist);
	kfree_rcu(f, rcu);
}
//-----------------------------------------------------------------------------
void fdb_cleanup(unsigned long unused) {
	unsigned long delay = 300 * HZ;
	unsigned long next_timer = jiffies + delay;
	int i;

	spin_lock(&hash_lock);
	for (i = 0; i < HASH_SIZE; i++) {
		struct fdb_entry *f;
		struct hlist_node *n;

		hlist_for_each_entry_safe(f, n, &hash[i], hlist) {
			unsigned long this_timer;

			this_timer = f->used + delay;
			if (time_before_eq(this_timer, jiffies))
				fdb_delete(f);
			else if (time_before(this_timer, next_timer)) {
				next_timer = this_timer;
			}
		}
	}
	spin_unlock(&hash_lock);

	mod_timer(&gc_timer, round_jiffies_up(next_timer));
}
//-----------------------------------------------------------------------------
//                                 END MAC
//-----------------------------------------------------------------------------



//-----------------------------------------------------------------------------
//                                BEGIN SEND
//-----------------------------------------------------------------------------
static void mbr_send_single(struct mbr_port * port, struct sk_buff * skb) {

	skb->vlan_tci = 0;
	skb->pkt_type = PACKET_OUTGOING; // пакет - на выход
	skb_forward_csum(skb);

	/* skb->data указывает на начало сетевого уровня (arp, ip, etc...)
	   Но нас интерсуют МАС адреса в этом пакете. VLAN вырезан, но МАС
	   был сохранён и сдвинут вправно (см. vlan_untag) - поэтому просто
	   двигаем указатели в лево. */

	__skb_push(skb, ETH_HLEN);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	if (port->v_tag)
		skb = term_vlan_insert_tag(skb, htons(ETH_P_8021Q), port->v_tag & VLAN_VID_MASK);

	if (unlikely(!skb))
		return;

	if (port->q_tag)
		skb = term_vlan_insert_tag(skb, htons(ETH_P_8021Q), port->q_tag & VLAN_VID_MASK);

	if (unlikely(!skb))
		return;

	/* Отправляем пакет в драйвер */
	dev_queue_xmit(skb);
}
//-----------------------------------------------------------------------------
static void mbr_send_copy(struct mbr_port * port, struct sk_buff * skb) {

	struct sk_buff * skb2;

	skb2 = skb_copy(skb, GFP_ATOMIC);
	if (!skb2)
		return;

	mbr_send_single(port, skb2);
}
//-----------------------------------------------------------------------------
//                                 END SEND
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
void term_mbr(struct sk_buff * skb, u16 q_tag, u16 v_tag) {

	struct hlist_head * head;
	struct fdb_entry * entry;
	struct mbr_port * port;
	struct mbr_port * p = NULL;
	int i;


	/* Шаг первый - найти порт отправителя. */

	port = mbr_find_port(q_tag, v_tag);

	if (!port)
		port = mbr_create_port(q_tag, v_tag);

	if (!port)
		goto free;

	/* Шаг второй - проверить отправителя. */
	head = &hash[mbr_hash_mac(eth_hdr(skb)->h_source)];

	rcu_read_lock();

	entry = fdb_find_rcu(head, eth_hdr(skb)->h_source, port);

	if (unlikely(!entry))
		entry = fdb_create(head, eth_hdr(skb)->h_source, port);

	if (unlikely(!entry)) {
		rcu_read_unlock();
		goto free;
	}

	entry->used = jiffies;

	rcu_read_unlock();

	/* Шаг третий - найти получателя. */
	if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
		for (i = 0; i < HASH_SIZE; i++) {
			spin_lock_bh(&port_hash_lock);
			hlist_for_each_entry(p, &port_hash[i], hlist)
				if (p != port)
					mbr_send_copy(p, skb);
			spin_unlock_bh(&port_hash_lock);
		}
		goto free;
	}

	head = &hash[mbr_hash_mac(eth_hdr(skb)->h_dest)];

	rcu_read_lock();
	entry = fdb_find_rcu(head, eth_hdr(skb)->h_dest, NULL);
	rcu_read_unlock();
	if (likely(entry)) {
		mbr_send_single(entry->port, skb);
		return;
	}

free:
	kfree_skb(skb);
}
//-----------------------------------------------------------------------------
int term_mbr_init(void) {

	int i;

	get_random_bytes(&fdb_salt, sizeof(fdb_salt));
	get_random_bytes(&port_salt, sizeof(port_salt));

	for (i = 0; i < HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&hash[i]);
		INIT_HLIST_HEAD(&port_hash[i]);
	}

	/* Пока не придумал как динамически создавать порты - будем это делать так. */
	for (i = 2001; i < 2100; i++)
		mbr_create_port(i, 7);
		mbr_create_port(0, 7);

	/* Очистка кэша маков. */
	spin_lock_init(&hash_lock);
	setup_timer(&gc_timer, fdb_cleanup, 0);
	mod_timer(&gc_timer, round_jiffies_up(jiffies + HZ * 300));

	return 0;
}
//-----------------------------------------------------------------------------
void term_mbr_destroy(void) {

	int i;
	struct mbr_port * p;
	struct fdb_entry * fdb;
	struct hlist_node * t;

	del_timer_sync(&gc_timer);

	for (i = 0; i < HASH_SIZE; i++) {
		rcu_read_lock();
		hlist_for_each_entry_rcu(fdb, &hash[i], hlist)
			fdb_delete(fdb);
		rcu_read_unlock();
	}

	for (i = 0; i < HASH_SIZE; i++) {
		hlist_for_each_entry_safe(p, t, &port_hash[i], hlist) {
			hlist_del(&p->hlist);
			kfree(p);
		}
	}
}
//-----------------------------------------------------------------------------
