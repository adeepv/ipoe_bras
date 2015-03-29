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
	/* Получатель пакета */
	struct term_session *ds;

	/* Заголовок IP протокола */
	struct iphdr * iph = NULL;

	/* Заголовок UDP протокола */
	struct udphdr * uh;

	/* Гарантирует, что IP-заголовок полностью присутствует в kmalloc'd области */
	if (unlikely(!pskb_network_may_pull(skb, sizeof(struct iphdr))))
		goto free;

	iph = ip_hdr(skb);

	/* Заголовок отсутствует на нужном месте */
	if (unlikely(!iph))
		goto free;

	/* Длина заголовка IP-пакета в 32-битных словах */
	if (unlikely(iph->ihl < 5))
		goto free;

	/* Только IPv4 */
	if (unlikely(iph->version != 4))
		goto free;

	/* Гарантирует, что IP-заголовок полностью присутствует в kmalloc'd области */
	if (unlikely(!pskb_network_may_pull(skb, iph->ihl*4)))
		goto free;

	iph = ip_hdr(skb);

	/* Проверяем контрольную сумму */
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto free;

	/* DHCP протокол */
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

	/* Получатель пакета - наш абонент */
	ds = term_ip_lookup_session(iph->daddr);

	/* Входящий трафик */
	/* Отправитель - не абонет */
	if (likely(!ts)) {
		/* Входящий трафик для неизвестного абонента */
		if (!ds)
			goto free;

		/* Применяем фильтра. */
		if (!term_send_in_filter(skb, ds))
			goto free;

		/* Переходим к отправке пакета */
		term_send_to_user(skb, ds, ds->info.mac, NULL);
		goto out;
	}

	/* Исходящий или межабонентский трафик */

	/* Проверяем коректность установленного у абонента IP-адреса */
	if (iph->saddr != ts->info.ip)
		goto free;

	/* Помечаем абонента как активного */
	term_set_user_active(ts);

	/* Исходящий трафик. */
	if (likely(!ds))
		if (term_send_out_filter(skb, ts))
			return term_world_send(skb, ts);

	/* Трафик между абонентами */
	if (likely(ds)) {
		/* Отправитель или получатель заблокирован, либо плучатель недоступен */
		if (ts->info.lock || ds->info.lock || !(ds->st.flags & TERM_SES_ONLINE))
			goto free;

		/* Переходим к отправке пакета */
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
 * Функция поглощает QinQ транки,
 * прозрачно пропуская single vlan и нетегированные пакеты
 */
rx_handler_result_t term_user_input (struct sk_buff **pskb) {
	// сюда пакет прилетит с вырезанным первой структурой vlan_hdr
	// и заполенным полем skb->vlan_tci
	// skb->protocol будет показывать на вторую vlan инкапсуляцию.
	u16 q_tag = 0;
	u16 v_tag = 0;
	struct term_session *ts;

	struct sk_buff *skb = *pskb;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		goto free;

	/* Прибыл нетегированный пакет */
	if (unlikely(!vlan_tx_tag_present(skb)))
		goto pass;

	/* Outer tag */
	q_tag = vlan_tx_tag_get_id(skb);

	/* Прибыл не Q-in-Q влан */
	if (unlikely(skb->protocol != cpu_to_be16(ETH_P_8021Q))) {
		/* Влан управления коммутаторами. */
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

	/* Мультикаст или забитый нулями мак отправителя */
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

	/* Внутренний тег не заполнен */
	if (unlikely(!vlan_tx_tag_present(skb)))
		goto free;

	v_tag = vlan_tx_tag_get_id(skb);

	/* Влан управления коммутаторами. */
	if (unlikely(v_tag == 7)) {
		term_mbr(skb, q_tag, v_tag);
		goto consumed;
	}

	skb->vlan_tci = 0;

	/* Ищем сессию по номерам вланов */
	ts = term_lookup_qinq_session(q_tag, v_tag, eth_hdr(skb)->h_source);

	/* Сессия не найдена */
	if (unlikely(!ts))
		goto free;
// todo если сессия по вланам не найдена то:
// 1. абонента переткнули в другой порт/ поставили новый комутатора/переварили оптику - надо поискать по макам и если есть то проверить ту сессию, если неактивна то дать ойпи перенаправить на сайт и предложить авторизироваться.
// 2. по макам тоже нету - это новый абонент. создать сессию. дать новый ойпи. пустить на сайт для авторизации.
// 3. 
//

	/* MAC адрес отправителя пакета != MAC адресу сессии */
	if (unlikely(!ether_addr_equal(eth_hdr(skb)->h_source, ts->info.mac))) {
//		if (net_ratelimit()) printk("term: user_input: ses:%u:%u source %pM != user %pM\n",
//			q_tag,v_tag,&eth_hdr(skb)->h_source,&ts->info.mac
//		);
		goto free;
//		ts->st.flags |= TERM_SES_BAD_MAC;
	}

	/* Обновляем статистику */
	ts->st.lastInput = jiffies;

	/* Локальный обработчик ARP протокола */
	if (skb->protocol == cpu_to_be16(ETH_P_ARP))
		return term_arp_input(skb, ts);

	/* Локальный обработчик IP протокола */
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
//	/* Локальный обработчик ARP протокола */
//	if (skb->protocol == cpu_to_be16(ETH_P_ARP))
//		return term_arp_input(skb, NULL);

	/* Локальный обработчик IP протокола */
	if (likely(skb->protocol == cpu_to_be16(ETH_P_IP)))
		return term_ip_input(skb, NULL);

	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}
//-----------------------------------------------------------------------------
