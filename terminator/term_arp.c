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

	/* Устройство не поддерживает ARP */
	if (dev->flags & IFF_NOARP)
		return;

	/* Собираем ответный пакет */
	skb = arp_create(type, ptype, dest_ip, dev, src_ip, dest_hw, src_hw, dest_hw);

	/* Неполучилось собрать пакет */
	if (!skb)
		return;

	/* Отправка пакета абоненту */
	if (ts && dev == term_in_dev) {

		/* Заворачиваем пакет в 2 влана */
		skb = term_add_users_tag(skb, ts);

		/* Инкапсулировать пакет по каким-то причинам не удалось */
		if (unlikely(!skb))
			return;

		/* Отправляем пакет в драйвер */
		dev_queue_xmit(skb);
//		dev->netdev_ops->ndo_start_xmit(skb, dev);

		return;
	}

//	/* Отправка пакета в маршрутизатор */
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
 * Обновляет ARP кэш на интерфейсе маршрутеризатора.
 * Используется при прозрачном (L2) режиме.
 */
void term_update_neighbour(struct term_session *ts) {
	struct neighbour *n;

	if (!ts)
		return;

	/*
	 * Производим поиск по ARP таблице указанного интерфейса.
	 * В случие отсутсивия записи создаём её.
	 */
	n = __neigh_lookup(&arp_tbl, &ts->info.ip, term_dev_world, 1);

	if (n) {
// todo почитать проверить.
		neigh_update(n, ts->info.mac, NUD_PERMANENT, NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE);
		neigh_release(n);
	}

}
//-----------------------------------------------------------------------------
/*
 * Локальный обработчик ARP запросов.
 *
 */
static void term_arp_request(struct sk_buff *skb, struct term_session *ts) {
	struct term_session *ds;
	struct term_arphdr *arp = (struct term_arphdr*)arp_hdr(skb);

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	if (arp->ar_sip == 0) {
//		if (net_ratelimit())
//			printk("term: %s arp->ar_sip == 0, dst_ip = %pI4\n",__func__,&arp->ar_tip);
		// TODO обновить арп кэш, при необходимости ответить
		goto free;
	}

	/* Special case: RFC 3927, Gratuitous ARP */
	if (arp->ar_sip == arp->ar_tip) {
//		if (net_ratelimit())
//			printk("term: %s arp->ar_sip(%pI4) == arp->ar_tip(%pI4)\n",__func__,&arp->ar_sip,&arp->ar_tip);
		// TODO обновить арп кэш
		// - поменять мак в биллинге?
		goto free;
	}

	/* Запрос от маршрутизатора */
	if (!ts) {
//		/* Цель - юзер */
//		ds = term_ip_lookup_session(arp->ar_tip);
//		/* Не удалось определить Цель */
//		if (!ds)
//			goto free;
//		term_arp_update_neighbor(ds)
//		printk("term: %s %u\n",__func__,__LINE__);
//		term_arp_send(ARPOP_REPLY, ETH_P_ARP, arp->ar_sip, skb->dev, arp->ar_tip, arp->ar_sha, ds->info.mac, NULL);
		goto free;
	}

	/* Не корретная настройка IP протокола */
	if (arp->ar_sip != ts->info.ip) {
		if (net_ratelimit())
			printk("term: arp: arp->ar_sip(%pI4) != ts->info.ip(%pI4)\n",&arp->ar_sip,&ts->info.ip);
		// TODO отобразить в мониторинге
		goto free;
	}

	/* Помечаем абонента как активного */
	term_set_user_active(ts);

	/* Цель не в той же подсети */
	if ((arp->ar_tip & ts->sb.mk) != ts->sb.sb)
		goto free;

	/* Цель - subnet или broadcast ойпи подсети */
	if (ts->sb.sb == arp->ar_tip || ts->sb.bk == arp->ar_tip)
		goto free;

	/* Цель - локальный ойпи подсети */
	if (ts->sb.gw == arp->ar_tip)
		goto send;

	/* Цель - другой юзер */
	ds = term_ip_lookup_session(arp->ar_tip);

	/* Не удалось определить Цель */
	if (!ds)
		goto free;

	/* Отправитель или получатель заблокирован, дибо плучатель недоступен */
	if (ts->info.lock || ds->info.lock || !ds->st.flags & TERM_SES_ONLINE)
		goto free;

send:
	term_arp_send(ARPOP_REPLY, ETH_P_ARP, arp->ar_sip, skb->dev, arp->ar_tip, arp->ar_sha, NULL, ts);
free:
	kfree_skb(skb);
}
//-----------------------------------------------------------------------------
/*
 * Локальный обработчик ARP Ответов.
 *
 * Ответами могут быть как пакеты присланные в ответ на запросы мониотринга,
 * так и ложные сообщения при различных атаках,
 * направленных на отравление ARP кэша.
 *
 */
static void term_arp_reply(struct sk_buff *skb, struct term_session *ts) {

	/* Ответ предназначен для ойпи - шлюза по умолчанию */
	if (ts->sb.gw == ((struct term_arphdr *)arp_hdr(skb))->ar_tip)

		/* MAC адрес отправителя или MAC адрес в пакете != MAC адресу сессии */
		if (likely(ether_addr_equal(((struct term_arphdr *)arp_hdr(skb))->ar_sha, ts->info.mac)
			&& ether_addr_equal(eth_hdr(skb)->h_source, ts->info.mac)))

			/* Помечаем абонента как активного */
			term_set_user_active(ts);

	kfree_skb(skb);
}
//-----------------------------------------------------------------------------
/*
 * Локальный обработчик протокола ARP.
 *
 */
int term_arp_input(struct sk_buff *skb, struct term_session *ts) {
	struct term_arphdr *arp;
	struct net_device * dev = skb->dev;

	/* Устройство не поддерживает ARP */
	if (dev->flags & IFF_NOARP)
		goto free;

	/* Гарантирует, что структура полностью присутствует в kmalloc'd области */
	if (!pskb_network_may_pull(skb, sizeof(struct term_arphdr)))
		goto free;

	/* Получам указатель на структуру данных */
	arp = (struct term_arphdr*)arp_hdr(skb);

	/* Внутри пакета такой же заголовок как и в устройстве - Ethernet 0x0001 */
	if (htons(dev->type) != arp->ar_hrd)
		goto free;

	/* Протокол IPv4 0x0800 */
	if (arp->ar_pro != htons(ETH_P_IP))
		goto free;

	/* Адрес Ethernet - длинна 6 байт */
	if (arp->ar_hln != dev->addr_len)
		goto free;

	/* Длина IPv4 адреса 4 байта */
	if (arp->ar_pln != 4)
		goto free;

	/* MAC адрес отправителя пакета != MAC адресу отправителя в запросе */
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

	/* Обработчик запросов */
	if (arp->ar_op == htons(ARPOP_REQUEST)) {
		term_arp_request(skb, ts);
		goto out;
	}

	/* Обработчик ответов */
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

				/* Если хост активен но не отвечал > 2 минут - переводем в состояние неактивен */
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

	/* Неполучилось собрать пакет */
	if (!skb)
		return;

	/* Заворачиваем пакет в 2 влана */
	skb = term_add_users_tag(skb, ts);

	/* Инкапсулировать пакет по каким-то причинам не удалось */
	if (unlikely(!skb))
		return;

	/* Отправляем пакет в драйвер */
	dev_queue_xmit(skb);
}
//-----------------------------------------------------------------------------
