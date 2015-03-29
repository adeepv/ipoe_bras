//-----------------------------------------------------------------------------
#ifndef _IP_TERM_H
#define _IP_TERM_H
//-----------------------------------------------------------------------------
#include <linux/version.h>
#include <linux/if_ether.h> //ETH_ALEN
#include <linux/etherdevice.h> //ether_addr_equal
#include <net/ip.h>
#include <net/inet_common.h>
//-----------------------------------------------------------------------------
#include "../net_proto.h"
//-----------------------------------------------------------------------------
#define TERM_NETLINK_MAIN	30
//-----------------------------------------------------------------------------
/* From Userspace to Kernel */
#define TERM_EVENT_SESSION           0x01
#define TERM_EVENT_SUBNET            0x02
//-----------------------------------------------------------------------------
#define TERM_WORK_MODE_L2            0
#define TERM_WORK_MODE_L3            1
//-----------------------------------------------------------------------------
#define TERM_SES_ONLINE  0x00000001
#define TERM_SES_BAD_MAC 0x00000002
//-----------------------------------------------------------------------------
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#define vlan_tx_tag_get_id(__skb)       ((__skb)->vlan_tci & VLAN_VID_MASK)
#endif
//-----------------------------------------------------------------------------
/* This structure defines an ethernet arp header. */
struct term_arphdr {
	u16 ar_hrd;		/* format of hardware address */
	u16 ar_pro;		/* format of protocol address */
	u8  ar_hln;		/* length of hardware address */
	u8  ar_pln;		/* length of protocol address */
	u16 ar_op;		/* ARP opcode (command)       */
	u8  ar_sha[ETH_ALEN];	/* sender hardware address    */
	u32 ar_sip;		/* sender IP address          */
	u8  ar_tha[ETH_ALEN];	/* target hardware address    */
	u32 ar_tip;		/* target IP address          */
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
struct term_session_info {
	u16 q;			/* 802.1AD vlan_id    */
	u16 v;			/* 802.1Q vlan_id     */
	u32 ip;			/* User's IP-address  */
	 u8 mac[ETH_ALEN];	/* User's MAC-address */
	 u8 lock;		/* Lock the user      */
	 u8 multiuser;		/* Session binding to multiuser port */
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
struct term_subnet {
	struct hlist_node        index;
	u32 sb;
	u32 mk;
	u32 bk;
	u32 gw;
	u32 ml;
};
//-----------------------------------------------------------------------------
struct term_stat {
	u32 flags;
	unsigned long lastOnline;
	unsigned long lastInput;
	unsigned long lastInputDHCP;
	unsigned long lastChgState;
};
//-----------------------------------------------------------------------------
struct __term_subnet {
	u32 sb;			/* User's subnet          */
	u32 mk;			/* User's netmask         */
	u32 bk;			/* User's broadcast       */
	u32 gw;			/* User's dafault gateway */
	u32 ml;			/* User's masklen         */
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
struct term_session {
	u32 last_update;
	struct term_session_info	info;
	struct __term_subnet		sb;
	struct term_stat		st;
	struct hlist_node		ip_index;
	struct hlist_node		mac_index;
	struct hlist_node		qinq_index;
};
//-----------------------------------------------------------------------------
struct term_in_event {
	u32 type;
	u8  data[16];
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
// term.c
extern struct net_device *term_in_dev;
extern struct net_device *term_dev_world;
extern spinlock_t term_lock;
extern spinlock_t term_event_lock;

// term_arp.c
extern int term_arp_input(struct sk_buff *skb, struct term_session *ts);
extern void term_arping(void);
extern void term_update_neighbour(struct term_session *ts);
extern void gratuitous_arp(struct term_session *ts);

// term_dev.c
extern u32 gw_ip;
extern u8 gw_mac[6];
extern int term_dev_create(void);
extern void term_dev_destroy(void);

// term_dhcp.c
extern void term_dhcp(struct sk_buff *skb, struct term_session *ts);

// term_input.c
extern rx_handler_result_t term_user_input(struct sk_buff **pskb);
extern rx_handler_result_t term_world_input(struct sk_buff *skb);

// term_mgm_bridge.c
extern void term_mbr(struct sk_buff *skb, u16 q_tag, u16 v_tag);
extern int term_mbr_init(void);
extern void term_mbr_destroy(void);

// term_netlink.c
extern int term_netlink_init(void);
extern void term_netlink_destroy(void);
extern int term_ip_add(u32 ip, u32 mask);
extern int term_route_add(u32 dst);
extern int term_route_del(u32 dst);

// term_proc.c
extern int term_proc_init(void);
extern void term_proc_cleanup(void);

// term_send.c
extern int term_send_in_filter(struct sk_buff *skb, struct term_session *ts);
extern int term_send_out_filter(struct sk_buff *skb, struct term_session *ts);
extern void term_send_to_user(struct sk_buff *skb, struct term_session *ts, u8 *daddr, u8 *saddr);
extern rx_handler_result_t term_world_send(struct sk_buff *skb, struct term_session *ts);

// term_sessions.c
extern u32 ip_buckets;
extern struct hlist_head * ip_hash;
extern unsigned int ip_jhash_rnd __read_mostly;
extern u32 qinq_buckets;
extern struct hlist_head * qinq_hash;
extern unsigned int qinq_jhash_rnd __read_mostly;
extern u32 mac_buckets;
extern struct hlist_head * mac_hash;
extern unsigned int mac_jhash_rnd __read_mostly;
//---
extern int term_sessions_init(void);
extern void term_sessions_destroy(void);
extern void term_cmd_session(void *);

// term_stat.c
extern void term_set_user_active(struct term_session *ts);
extern void term_set_user_inactive(struct term_session *ts);

// term_vlan.c
extern struct sk_buff *term_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci);
extern struct sk_buff *term_vlan_untag(struct sk_buff *skb);
extern struct sk_buff *term_add_users_tag(struct sk_buff *skb, struct term_session *ts);

// term_white.c
extern int  term_white_match(struct sk_buff *skb);
extern int  term_white_init(void);
extern void term_white_destroy(void);

// term_work.c
extern int term_work_init(void);
extern void term_work_destroy(void);
extern void term_add_work(struct term_session * ts);

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//
//                              IP HASHING
//
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static inline u32 term_get_ip_hash (u32 ip) {
	return jhash_1word(ip, ip_jhash_rnd) & (ip_buckets - 1);
}
//-----------------------------------------------------------------------------
static inline void term_insert_ip_hash (struct term_session * ts) {
	hlist_add_head(&ts->ip_index, &ip_hash[term_get_ip_hash(ts->info.ip)]);
}
//-----------------------------------------------------------------------------
static inline struct term_session *term_ip_lookup_session_all(u32 ip) {
	struct term_session * ts;
	u32 h = term_get_ip_hash(ip);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
	hlist_for_each_entry(ts, n, &ip_hash[h], ip_index)
#else
	hlist_for_each_entry(ts, &ip_hash[h], ip_index)
#endif
		if (ts->info.ip == ip)
			return ts;

	return NULL;
}
//-----------------------------------------------------------------------------
static inline struct term_session *term_ip_lookup_session(u32 ip) {

	struct term_session * ts = term_ip_lookup_session_all(ip);

	if (ts && ts->info.q && ts->info.v)
		return ts;

	return NULL;
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//
//                              QINQ HASHING
//
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static inline u32 term_get_qinq_hash (u16 q, u16 v) {
	return jhash_1word((q << 16 | v), qinq_jhash_rnd) & (qinq_buckets - 1);
}
//-----------------------------------------------------------------------------
static inline void term_insert_qinq_hash (struct term_session * ts) {
	hlist_add_head(&ts->qinq_index, &qinq_hash[term_get_qinq_hash(ts->info.q, ts->info.v)]);
}
//-----------------------------------------------------------------------------
static inline struct term_session *term_lookup_qinq_session(u16 q, u16 v, u8 * mac) {
	struct term_session * ts;
	u32 h = term_get_qinq_hash(q, v);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
	hlist_for_each_entry(ts, n, &qinq_hash[h], qinq_index)
#else
	hlist_for_each_entry(ts, &qinq_hash[h], qinq_index)
#endif
		if (ts->info.q == q && ts->info.v == v) {
			if (ts->info.multiuser && !ether_addr_equal(mac, ts->info.mac))
				continue;
			else
				return ts;
		}

	return NULL;
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//
//                              MAC HASHING
//
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static inline u32 term_get_mac_hash(u8 mac[ETH_ALEN]) {
	u64 m = 0;
	u8 i;
	for (i = ETH_ALEN; i; i--) m |= (mac[i] << (8 * (i-1)));
	return jhash_2words(m >> 16, m & 0xffff, mac_jhash_rnd) & (mac_buckets - 1);
}
//-----------------------------------------------------------------------------
static inline void term_insert_mac_hash (struct term_session * ts) {
	hlist_add_head(&ts->mac_index, &mac_hash[term_get_mac_hash(ts->info.mac)]);
}
//-----------------------------------------------------------------------------
static inline struct term_session *term_term_mac_lookup_session(u8 mac[ETH_ALEN]) {
	struct term_session * ts;
	u32 h = term_get_mac_hash(mac);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
	hlist_for_each_entry(ts, n, &mac_hash[h], mac_index)
#else
	hlist_for_each_entry(ts, &mac_hash[h], mac_index)
#endif
		if (memcmp(ts->info.mac, mac, ETH_ALEN)==0)
			return ts;
	return NULL;
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//
//                  Subnet Support
//
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
extern struct hlist_head subnet_list;
//-----------------------------------------------------------------------------
static inline void term_insert_subnet (struct term_subnet * sb) {
	hlist_add_head(&sb->index, &subnet_list);
}
//-----------------------------------------------------------------------------
static inline struct term_subnet *term_find_subnet (u32 ip) {
	struct term_subnet * sb;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
	hlist_for_each_entry(sb, n, &subnet_list, index)
#else
	hlist_for_each_entry(sb, &subnet_list, index)
#endif
		if ((ip & sb->mk) == sb->sb)
			return sb;
	return NULL;
}
//-----------------------------------------------------------------------------
static inline int term_ip_in_subnet (struct term_subnet *sb, u32 ip) {
	return (ip & sb->mk) == sb->sb;
}
//-----------------------------------------------------------------------------
#endif
//-----------------------------------------------------------------------------
