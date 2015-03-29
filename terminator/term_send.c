//-----------------------------------------------------------------------------
#include <linux/if_ether.h> // ETH_P_ALL
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <net/arp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
int term_send_in_filter(struct sk_buff *skb, struct term_session *ts) {
	/* ������ �� ����������� ��������. */
	if (unlikely(!(ts->st.flags & TERM_SES_ONLINE)))
		return 0;

	/* ������ �� ����������� ��������. */
	if (unlikely(ts->info.lock))
		return term_white_match(skb);

	/* � ��������� ������� ���������� ������. */
	return 1;
}
//-----------------------------------------------------------------------------
int term_send_out_filter(struct sk_buff *skb, struct term_session *ts) {

	/* ������ �� ����������� ��������. */
	if (unlikely(ts->info.lock))
		return term_white_match(skb);

	/* � ��������� ������� ���������� ������. */
	return 1;
}
//-----------------------------------------------------------------------------
void term_send_to_user(struct sk_buff *skb,
			struct term_session *ts,
			u8 *daddr,
			u8 *saddr) {
	/* Before delegating work to the lower layer, enter our MAC-address */
	skb->dev = term_in_dev;
	if (saddr == NULL)
		saddr = skb->dev->dev_addr;

	if (daddr == NULL)
		daddr = ts->info.mac;

	skb->vlan_tci = 0;
	skb->pkt_type = PACKET_OUTGOING; // ����� - �� �����
	skb_forward_csum(skb);

	/* �������� ��������� ethrenet */
	dev_hard_header(skb, skb->dev, htons(skb->protocol), daddr, saddr, 0);

	/* ������������ ����� � 2 ����� */
	skb = term_add_users_tag(skb, ts);

	/* ��������������� ����� �� �����-�� �������� �� ������� */
	if (unlikely(!skb))
		return;

	/* ���������� ����� � ������� */
	dev_queue_xmit(skb);
}
//-----------------------------------------------------------------------------
rx_handler_result_t term_world_send(struct sk_buff *skb, struct term_session *ts) {

	/* Before delegating work to the up layer, enter our MAC-address */
	skb->dev = term_dev_world;
	skb->vlan_tci = 0;
	skb->pkt_type = PACKET_HOST;

	/* � �������� ��� ���������� - ��� ����������� �������. */
	memcpy(&eth_hdr(skb)->h_dest, skb->dev->dev_addr, ETH_ALEN);

	/* � �������� ��� ����������� - ��� ������������ �������. */
	memcpy(&eth_hdr(skb)->h_source, gw_mac, ETH_ALEN);

	return RX_HANDLER_ANOTHER;

}
//-----------------------------------------------------------------------------
