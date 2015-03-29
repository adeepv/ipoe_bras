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
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
static rx_handler_result_t term_ip_input (struct sk_buff *skb, struct term_session *ts) {
	/* ���������� ������ */
	struct term_session *ds;

	/* ��������� IP ��������� */
	struct iphdr * iph = NULL;

	/* ��������� UDP ��������� */
	struct udphdr * uh;

	/* �����������, ��� IP-��������� ��������� ������������ � kmalloc'd ������� */
	if (unlikely(!pskb_network_may_pull(skb, sizeof(struct iphdr))))
		goto free;

	iph = ip_hdr(skb);

	/* ��������� ����������� �� ������ ����� */
	if (unlikely(!iph))
		goto free;

	/* ����� ��������� IP-������ � 32-������ ������ */
	if (unlikely(iph->ihl < 5))
		goto free;

	/* ������ IPv4 */
	if (unlikely(iph->version != 4))
		goto free;

	/* �����������, ��� IP-��������� ��������� ������������ � kmalloc'd ������� */
	if (unlikely(!pskb_network_may_pull(skb, iph->ihl*4)))
		goto free;

	iph = ip_hdr(skb);

	/* ��������� ����������� ����� */
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto free;

	/* DHCP �������� */
	if (ts && skb->dev == term_in_dev && iph->protocol == IPPROTO_UDP
		&& (iph->daddr == ts->sb.gw || iph->daddr == ts->sb.bk || iph->daddr == 0xFFFFFFFF)
	) {
		if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct udphdr)))
			goto free;

		uh = (struct udphdr *)(skb->data+(iph->ihl<<2));
		if (uh->source == htons(68) && uh->dest == htons(67)) {
			term_dhcp(skb, ts);
			goto out;
		}
	}

	/*
	 *      Check for bad requests for 127.x.x.x and requests for multicast
	 *      addresses.  If this is one such, delete it.
	 */
	if (ipv4_is_multicast(iph->daddr) || ipv4_is_loopback(iph->daddr))
		goto free;

	/* ���������� ������ - ��� ������� */
	ds = term_ip_lookup_session(iph->daddr);

	/* �������� ������ */
	/* ����������� - �� ������ */
	if (likely(!ts)) {
		/* �������� ������ ��� ������������ �������� */
		if (!ds)
			goto free;

		/* ��������� �������. */
		if (!term_send_in_filter(skb, ds))
			goto free;

		/* ��������� � �������� ������ */
		term_send_to_user(skb, ds, ds->info.mac, NULL);
		goto out;
	}

	/* ��������� ��� �������������� ������ */

	/* ��������� ����������� �������������� � �������� IP-������ */
	if (iph->saddr != ts->info.ip)
		goto free;

	/* �������� �������� ��� ��������� */
	term_set_user_active(ts);

	/* ��������� ������. */
	if (likely(!ds))
		if (term_send_out_filter(skb, ts))
			return term_world_send(skb, ts);

	/* ������ ����� ���������� */
	if (likely(ds)) {
		/* ����������� ��� ���������� ������������, ���� ��������� ���������� */
		if (ts->info.lock || ds->info.lock || !(ds->st.flags & TERM_SES_ONLINE))
			goto free;

		/* ��������� � �������� ������ */
		term_send_to_user(skb, ds, ds->info.mac, NULL);
		goto out;
	}

free:
	kfree_skb(skb);
out:
	return RX_HANDLER_CONSUMED;
}
//-----------------------------------------------------------------------------
/*
 * ������� ��������� QinQ ������,
 * ��������� ��������� single vlan � �������������� ������
 */
rx_handler_result_t term_user_input (struct sk_buff **pskb) {
	// ���� ����� �������� � ���������� ������ ���������� vlan_hdr
	// � ���������� ����� skb->vlan_tci
	// skb->protocol ����� ���������� �� ������ vlan ������������.
	u16 q_tag = 0;
	u16 v_tag = 0;
	struct term_session *ts;

	struct sk_buff *skb = *pskb;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		goto free;

	/* ������ �������������� ����� */
	if (unlikely(!vlan_tx_tag_present(skb)))
		goto pass;

	/* Outer tag */
	q_tag = vlan_tx_tag_get_id(skb);

	/* ������ �� Q-in-Q ���� */
	if (unlikely(skb->protocol != cpu_to_be16(ETH_P_8021Q))) {
		/* ���� ���������� �������������. */
		if (q_tag == 7) {
			term_mbr(skb, 0, q_tag);
			goto consumed;
		}

		/* Single tagged sync vlan */
		if (q_tag == 123) {
//			term_sync_queue(skb);
			goto consumed;
		}

		goto pass;
	}

	skb->vlan_tci = 0;

	/* ���������� ��� ������� ������ ��� ����������� */
	if (unlikely(!is_valid_ether_addr(eth_hdr(skb)->h_source)))
		goto free;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto consumed;

	if (unlikely(!skb->dev))
		goto free;

	/* Inner tag */
	skb = term_vlan_untag(skb);
	if (unlikely(!skb))
		goto consumed;

	/* ���������� ��� �� �������� */
	if (unlikely(!vlan_tx_tag_present(skb)))
		goto free;

	v_tag = vlan_tx_tag_get_id(skb);

	/* ���� ���������� �������������. */
	if (unlikely(v_tag == 7)) {
		term_mbr(skb, q_tag, v_tag);
		goto consumed;
	}

	skb->vlan_tci = 0;

	/* ���� ������ �� ������� ������ */
	ts = term_lookup_qinq_session(q_tag, v_tag, eth_hdr(skb)->h_source);

	/* ������ �� ������� */
	if (unlikely(!ts))
		goto free;
// todo ���� ������ �� ������ �� ������� ��:
// 1. �������� ���������� � ������ ����/ ��������� ����� ����������/���������� ������ - ���� �������� �� ����� � ���� ���� �� ��������� �� ������, ���� ��������� �� ���� ���� ������������� �� ���� � ���������� ����������������.
// 2. �� ����� ���� ���� - ��� ����� �������. ������� ������. ���� ����� ����. ������� �� ���� ��� �����������.
// 3. 
//

	/* MAC ����� ����������� ������ != MAC ������ ������ */
	if (unlikely(!ether_addr_equal(eth_hdr(skb)->h_source, ts->info.mac))) {
//		if (net_ratelimit()) printk("term: user_input: ses:%u:%u source %pM != user %pM\n",
//			q_tag,v_tag,&eth_hdr(skb)->h_source,&ts->info.mac
//		);
		goto free;
//		ts->st.flags |= TERM_SES_BAD_MAC;
	}

	/* ��������� ���������� */
	ts->st.lastInput = jiffies;

	/* ��������� ���������� ARP ��������� */
	if (skb->protocol == cpu_to_be16(ETH_P_ARP))
		return term_arp_input(skb, ts);

	/* ��������� ���������� IP ��������� */
	if (skb->protocol == cpu_to_be16(ETH_P_IP))
		return term_ip_input(skb, ts);

free:
	kfree_skb(skb);
consumed:
	return RX_HANDLER_CONSUMED;
pass:
	return RX_HANDLER_PASS;
}
//-----------------------------------------------------------------------------
rx_handler_result_t term_world_input (struct sk_buff *skb) {
//	/* ��������� ���������� ARP ��������� */
//	if (skb->protocol == cpu_to_be16(ETH_P_ARP))
//		return term_arp_input(skb, NULL);

	/* ��������� ���������� IP ��������� */
	if (likely(skb->protocol == cpu_to_be16(ETH_P_IP)))
		return term_ip_input(skb, NULL);

	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}
//-----------------------------------------------------------------------------
