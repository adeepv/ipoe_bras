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
	/* Трафик на офлайнового абонента. */
	if (unlikely(!(ts->st.flags & TERM_SES_ONLINE)))
		return 0;

	/* Трафик на залоченного абонента. */
	if (unlikely(ts->info.lock))
		return term_white_match(skb);

	/* В остальных случаях пропускаем трафик. */
	return 1;
}
//-----------------------------------------------------------------------------
int term_send_out_filter(struct sk_buff *skb, struct term_session *ts) {

	/* Трафик от залоченного абонента. */
	if (unlikely(ts->info.lock))
		return term_white_match(skb);

	/* В остальных случаях пропускаем трафик. */
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
	skb->pkt_type = PACKET_OUTGOING; // пакет - на выход
	skb_forward_csum(skb);

	/* Собираем заголовок ethrenet */
	dev_hard_header(skb, skb->dev, htons(skb->protocol), daddr, saddr, 0);

	/* Заворачиваем пакет в 2 влана */
	skb = term_add_users_tag(skb, ts);

	/* Инкапсулировать пакет по каким-то причинам не удалось */
	if (unlikely(!skb))
		return;

	/* Отправляем пакет в драйвер */
	dev_queue_xmit(skb);
}
//-----------------------------------------------------------------------------
rx_handler_result_t term_world_send(struct sk_buff *skb, struct term_session *ts) {

	/* Before delegating work to the up layer, enter our MAC-address */
	skb->dev = term_dev_world;
	skb->vlan_tci = 0;
	skb->pkt_type = PACKET_HOST;

	/* В качестве МАС получатеял - МАС виртуальной сетевой. */
	memcpy(&eth_hdr(skb)->h_dest, skb->dev->dev_addr, ETH_ALEN);

	/* В качестве МАС отправителя - МАС виртуального роутера. */
	memcpy(&eth_hdr(skb)->h_source, gw_mac, ETH_ALEN);

	return RX_HANDLER_ANOTHER;

}
//-----------------------------------------------------------------------------
