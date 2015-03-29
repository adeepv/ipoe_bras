//-----------------------------------------------------------------------------
#include <linux/module.h>
#include <linux/if_ether.h> // ETH_P_ALL
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <net/arp.h>
#include <linux/ip.h>
#include <net/genetlink.h>
#include <net/neighbour.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
static void term_arp_send(int type, int ptype, __be32 dest_ip,
           struct net_device *dev, __be32 src_ip,
           const unsigned char *dest_hw,
           const unsigned char *src_hw,
           struct term_session *ts)
{
	struct sk_buff *skb;

	/* ���������� �� ������������ ARP */
	if (dev->flags & IFF_NOARP)
		return;

	/* �������� �������� ����� */
	skb = arp_create(type, ptype, dest_ip, dev, src_ip, dest_hw, src_hw, dest_hw);

	/* ������������ ������� ����� */
	if (!skb)
		return;

	/* �������� ������ �������� */
	if (ts && dev == term_in_dev) {

		/* ������������ ����� � 2 ����� */
		skb = term_add_users_tag(skb, ts);

		/* ��������������� ����� �� �����-�� �������� �� ������� */
		if (unlikely(!skb))
			return;

		/* ���������� ����� � ������� */
		dev_queue_xmit(skb);
//		dev->netdev_ops->ndo_start_xmit(skb, dev);

		return;
	}

//	/* �������� ������ � ������������� */
//	if (!ts && dev == term_dev_world) {
//        /* Before delegating work to the up layer, enter our MAC-address */
//                skb->dev = term_dev_world;
//                skb->vlan_tci = 0;
//                skb->pkt_type = PACKET_HOST;
//		arp_tbl.proxy_redo(skb);
//                skb_forward_csum(skb);
//		skb_reset_network_header(skb);
//		skb_probe_transport_header(skb, 0);
//		skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
//		netif_rx(skb);
//		return;
//	}

//	BUG();
	printk("term: arp: BUG at %s on %s:%u\n",__func__,__FILE__,__LINE__);

}
//-----------------------------------------------------------------------------
/*
 * ��������� ARP ��� �� ���������� ����������������.
 * ������������ ��� ���������� (L2) ������.
 */
void term_update_neighbour(struct term_session *ts) {
	struct neighbour *n;

	if (!ts)
		return;

	/*
	 * ���������� ����� �� ARP ������� ���������� ����������.
	 * � ������ ���������� ������ ������� ţ.
	 */
	n = __neigh_lookup(&arp_tbl, &ts->info.ip, term_dev_world, 1);

	if (n) {
// todo �������� ���������.
		neigh_update(n, ts->info.mac, NUD_PERMANENT, NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE);
		neigh_release(n);
	}

}
//-----------------------------------------------------------------------------
/*
 * ��������� ���������� ARP ��������.
 *
 */
static void term_arp_request(struct sk_buff *skb, struct term_session *ts) {
	struct term_session *ds;
	struct term_arphdr *arp = (struct term_arphdr*)arp_hdr(skb);

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	if (arp->ar_sip == 0) {
//		if (net_ratelimit())
//			printk("term: %s arp->ar_sip == 0, dst_ip = %pI4\n",__func__,&arp->ar_tip);
		// TODO �������� ��� ���, ��� ������������� ��������
		goto free;
	}

	/* Special case: RFC 3927, Gratuitous ARP */
	if (arp->ar_sip == arp->ar_tip) {
//		if (net_ratelimit())
//			printk("term: %s arp->ar_sip(%pI4) == arp->ar_tip(%pI4)\n",__func__,&arp->ar_sip,&arp->ar_tip);
		// TODO �������� ��� ���
		// - �������� ��� � ��������?
		goto free;
	}

	/* ������ �� �������������� */
	if (!ts) {
//		/* ���� - ���� */
//		ds = term_ip_lookup_session(arp->ar_tip);
//		/* �� ������� ���������� ���� */
//		if (!ds)
//			goto free;
//		term_arp_update_neighbor(ds)
//		printk("term: %s %u\n",__func__,__LINE__);
//		term_arp_send(ARPOP_REPLY, ETH_P_ARP, arp->ar_sip, skb->dev, arp->ar_tip, arp->ar_sha, ds->info.mac, NULL);
		goto free;
	}

	/* �� ��������� ��������� IP ��������� */
	if (arp->ar_sip != ts->info.ip) {
		if (net_ratelimit())
			printk("term: arp: arp->ar_sip(%pI4) != ts->info.ip(%pI4)\n",&arp->ar_sip,&ts->info.ip);
		// TODO ���������� � �����������
		goto free;
	}

	/* �������� �������� ��� ��������� */
	term_set_user_active(ts);

	/* ���� �� � ��� �� ������� */
	if ((arp->ar_tip & ts->sb.mk) != ts->sb.sb)
		goto free;

	/* ���� - subnet ��� broadcast ���� ������� */
	if (ts->sb.sb == arp->ar_tip || ts->sb.bk == arp->ar_tip)
		goto free;

	/* ���� - ��������� ���� ������� */
	if (ts->sb.gw == arp->ar_tip)
		goto send;

	/* ���� - ������ ���� */
	ds = term_ip_lookup_session(arp->ar_tip);

	/* �� ������� ���������� ���� */
	if (!ds)
		goto free;

	/* ����������� ��� ���������� ������������, ���� ��������� ���������� */
	if (ts->info.lock || ds->info.lock || !ds->st.flags & TERM_SES_ONLINE)
		goto free;

send:
	term_arp_send(ARPOP_REPLY, ETH_P_ARP, arp->ar_sip, skb->dev, arp->ar_tip, arp->ar_sha, NULL, ts);
free:
	kfree_skb(skb);
}
//-----------------------------------------------------------------------------
/*
 * ��������� ���������� ARP �������.
 *
 * �������� ����� ���� ��� ������ ���������� � ����� �� ������� �����������,
 * ��� � ������ ��������� ��� ��������� ������,
 * ������������ �� ���������� ARP ����.
 *
 */
static void term_arp_reply(struct sk_buff *skb, struct term_session *ts) {

	/* ����� ������������ ��� ���� - ����� �� ��������� */
	if (ts->sb.gw == ((struct term_arphdr *)arp_hdr(skb))->ar_tip)

		/* MAC ����� ����������� ��� MAC ����� � ������ != MAC ������ ������ */
		if (likely(ether_addr_equal(((struct term_arphdr *)arp_hdr(skb))->ar_sha, ts->info.mac)
			&& ether_addr_equal(eth_hdr(skb)->h_source, ts->info.mac)))

			/* �������� �������� ��� ��������� */
			term_set_user_active(ts);

	kfree_skb(skb);
}
//-----------------------------------------------------------------------------
/*
 * ��������� ���������� ��������� ARP.
 *
 */
int term_arp_input(struct sk_buff *skb, struct term_session *ts) {
	struct term_arphdr *arp;
	struct net_device * dev = skb->dev;

	/* ���������� �� ������������ ARP */
	if (dev->flags & IFF_NOARP)
		goto free;

	/* �����������, ��� ��������� ��������� ������������ � kmalloc'd ������� */
	if (!pskb_network_may_pull(skb, sizeof(struct term_arphdr)))
		goto free;

	/* ������� ��������� �� ��������� ������ */
	arp = (struct term_arphdr*)arp_hdr(skb);

	/* ������ ������ ����� �� ��������� ��� � � ���������� - Ethernet 0x0001 */
	if (htons(dev->type) != arp->ar_hrd)
		goto free;

	/* �������� IPv4 0x0800 */
	if (arp->ar_pro != htons(ETH_P_IP))
		goto free;

	/* ����� Ethernet - ������ 6 ���� */
	if (arp->ar_hln != dev->addr_len)
		goto free;

	/* ����� IPv4 ������ 4 ����� */
	if (arp->ar_pln != 4)
		goto free;

	/* MAC ����� ����������� ������ != MAC ������ ����������� � ������� */
	if (unlikely(!ether_addr_equal(arp->ar_sha, eth_hdr(skb)->h_source))) {
		if (net_ratelimit())
			printk("term: arp: Source mac %pM != request mac %pM\n",
				&eth_hdr(skb)->h_source,&arp->ar_sha);
		goto free;
	}

	/*
	 *      Check for bad requests for 127.x.x.x and requests for multicast addresses.
	 *      If this is one such, delete it.
	 */
	if (ipv4_is_multicast(arp->ar_tip) || ipv4_is_loopback(arp->ar_tip))
		goto free;

	/* ���������� �������� */
	if (arp->ar_op == htons(ARPOP_REQUEST)) {
		term_arp_request(skb, ts);
		goto out;
	}

	/* ���������� ������� */
	if (arp->ar_op == htons(ARPOP_REPLY)) {
		term_arp_reply(skb, ts);
		goto out;
	}

free:
	kfree_skb(skb);
out:
	return RX_HANDLER_CONSUMED;
}
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
void term_arping(void) {
	struct term_session * ts;
	u32 i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
#endif

	for (i=0; i<ip_buckets; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		hlist_for_each_entry(ts, n, &ip_hash[i], ip_index)
#else
		hlist_for_each_entry(ts, &ip_hash[i], ip_index)
#endif
		{
			if (ts->info.q && ts->info.v) {

				/* ���� ���� ������� �� �� ������� > 2 ����� - ��������� � ��������� ��������� */
				if (ts->st.flags & TERM_SES_ONLINE && ts->st.lastOnline + HZ * 120 < jiffies)
					term_set_user_inactive(ts);

				term_arp_send(ARPOP_REQUEST, ETH_P_ARP, ts->info.ip, term_in_dev, ts->sb.gw, NULL, NULL, ts);
			}
		}
	}
}
//-----------------------------------------------------------------------------
void gratuitous_arp(struct term_session *ts) {

	struct sk_buff *skb;

	skb = arp_create(ARPOP_REQUEST, ETH_P_ARP, 0xFFFFFFFF, term_in_dev,
				ts->sb.gw, NULL, NULL, term_in_dev->broadcast);

	/* ������������ ������� ����� */
	if (!skb)
		return;

	/* ������������ ����� � 2 ����� */
	skb = term_add_users_tag(skb, ts);

	/* ��������������� ����� �� �����-�� �������� �� ������� */
	if (unlikely(!skb))
		return;

	/* ���������� ����� � ������� */
	dev_queue_xmit(skb);
}
//-----------------------------------------------------------------------------
