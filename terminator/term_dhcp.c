//----------------------------------------------------------------
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <net/udp.h>
//----------------------------------------------------------------
#include "term.h"
//----------------------------------------------------------------
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)
// BOOTP (rfc951) message types
#define DHCP_BOOTREQUEST     1
#define DHCP_BOOTREPLY       2
//----------------------------------------------------------------
// DHCP message code.
/* http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xml */
#define DHCPDISCOVER         1               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPOFFER            2               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPREQUEST          3               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPDECLINE          4               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPACK              5               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPNAK              6               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPRELEASE          7               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPINFORM           8               /* http://tools.ietf.org/html/rfc2132 */
#define DHCPFORCERENEW       9               /* http://tools.ietf.org/html/rfc3203 */
#define DHCPLEASEQUERY      10               /* http://tools.ietf.org/html/rfc4388 */
#define DHCPLEASEUNASSIGNED 11               /* http://tools.ietf.org/html/rfc4388 */
#define DHCPLEASEUNKNOWN    12               /* http://tools.ietf.org/html/rfc4388 */
#define DHCPLEASEACTIVE     13               /* http://tools.ietf.org/html/rfc4388 */

/*
#define DHCP_MAX_MTU      1500
#define BOOTREQUEST          1
#define BOOTREPLY            2
#define DHLEN (sizeof(struct packet_header) + sizeof(struct dhcp_header)) + 1
#define DNS_COUNT            2
#define MAX_ID_LEN          20
#define DHCPS               67
#define DHCPC               68
*/

//----------------------------------------------------------------
// Relay Agent Information option subtypes:
#define RAI_CIRCUIT_ID  1
#define RAI_REMOTE_ID   2
#define RAI_AGENT_ID    3
//----------------------------------------------------------------
// Possible values for flags field...
#define BOOTP_BROADCAST 32768L
//----------------------------------------------------------------
// DHCP Option codes:
#define DHO_PAD                         0
#define DHO_SUBNET_MASK                 1
#define DHO_TIME_OFFSET                 2
#define DHO_ROUTERS                     3
#define DHO_TIME_SERVERS                4
#define DHO_NAME_SERVERS                5
#define DHO_DOMAIN_NAME_SERVERS         6
#define DHO_LOG_SERVERS                 7
#define DHO_COOKIE_SERVERS              8
#define DHO_LPR_SERVERS                 9
#define DHO_IMPRESS_SERVERS             10
#define DHO_RESOURCE_LOCATION_SERVERS   11
#define DHO_HOST_NAME                   12
#define DHO_BOOT_SIZE                   13
#define DHO_MERIT_DUMP                  14
#define DHO_DOMAIN_NAME                 15
#define DHO_SWAP_SERVER                 16
#define DHO_ROOT_PATH                   17
#define DHO_EXTENSIONS_PATH             18
#define DHO_IP_FORWARDING               19
#define DHO_NON_LOCAL_SOURCE_ROUTING    20
#define DHO_POLICY_FILTER               21
#define DHO_MAX_DGRAM_REASSEMBLY        22
#define DHO_DEFAULT_IP_TTL              23
#define DHO_PATH_MTU_AGING_TIMEOUT      24
#define DHO_PATH_MTU_PLATEAU_TABLE      25
#define DHO_INTERFACE_MTU               26
#define DHO_ALL_SUBNETS_LOCAL           27
#define DHO_BROADCAST_ADDRESS           28
#define DHO_PERFORM_MASK_DISCOVERY      29
#define DHO_MASK_SUPPLIER               30
#define DHO_ROUTER_DISCOVERY            31
#define DHO_ROUTER_SOLICITATION_ADDRESS 32
#define DHO_STATIC_ROUTES               33
#define DHO_TRAILER_ENCAPSULATION       34
#define DHO_ARP_CACHE_TIMEOUT           35
#define DHO_IEEE802_3_ENCAPSULATION     36
#define DHO_DEFAULT_TCP_TTL             37
#define DHO_TCP_KEEPALIVE_INTERVAL      38
#define DHO_TCP_KEEPALIVE_GARBAGE       39
#define DHO_NIS_DOMAIN                  40
#define DHO_NIS_SERVERS                 41
#define DHO_NTP_SERVERS                 42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS 43
#define DHO_NETBIOS_NAME_SERVERS        44
#define DHO_NETBIOS_DD_SERVER           45
#define DHO_NETBIOS_NODE_TYPE           46
#define DHO_NETBIOS_SCOPE               47
#define DHO_FONT_SERVERS                48
#define DHO_X_DISPLAY_MANAGER           49
#define DHO_DHCP_REQUESTED_ADDRESS      50
#define DHO_DHCP_LEASE_TIME             51
#define DHO_DHCP_OPTION_OVERLOAD        52
#define DHO_DHCP_MESSAGE_TYPE           53
#define DHO_DHCP_SERVER_IDENTIFIER      54
#define DHO_DHCP_PARAMETER_REQUEST_LIST 55
#define DHO_DHCP_MESSAGE                56
#define DHO_DHCP_MAX_MESSAGE_SIZE       57
#define DHO_DHCP_RENEWAL_TIME           58
#define DHO_DHCP_REBINDING_TIME         59
#define DHO_VENDOR_CLASS_IDENTIFIER     60
#define DHO_DHCP_CLIENT_IDENTIFIER      61
#define DHO_NWIP_DOMAIN_NAME            62
#define DHO_NWIP_SUBOPTIONS             63
#define DHO_USER_CLASS                  77
#define DHO_FQDN                        81
#define DHO_DHCP_AGENT_OPTIONS          82
#define DHO_SUBNET_SELECTION            118 /* RFC3011! */
/* The DHO_AUTHENTICATE option is not a standard yet, so I've
   allocated an option out of the "local" option space for it on a
   temporary basis.  Once an option code number is assigned, I will
   immediately and shamelessly break this, so don't count on it
   continuing to work. */
#define DHO_AUTHENTICATE                210
#define DHO_END                         255
//----------------------------------------------------------------
/*
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		ACK
 */
//----------------------------------------------------------------
#define DHCP_UDP_OVERHEAD       (20 + 8)  // IP header + UDP header
#define DHCP_CHADDR_LEN         16
#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN           128
#define DHCP_FIXED_NON_UDP      236
#define DHCP_FIXED_LEN          (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD) // Everything but options.


#define DHCP_MTU_MAX            1500
#define DHCP_MTU_MIN            576

#define MAGIC_NUMBER_LEN        4

#define DHCP_MAX_OPTION_LEN     (DHCP_MTU_MAX - DHCP_FIXED_LEN - MAGIC_NUMBER_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN - MAGIC_NUMBER_LEN)

#define MAC_ADDR_LEN        6
// Possible values for hardware type (htype) field...
#define HTYPE_ETHER         1       // Ethernet 10Mbps

//----------------------------------------------------------------
/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 +---------------+---------------+---------------+---------------+
 |                            xid (4)                            |
 +-------------------------------+-------------------------------+
 |           secs (2)            |           flags (2)           |
 +-------------------------------+-------------------------------+
 |                          ciaddr  (4)                          |
 +---------------------------------------------------------------+
 |                          yiaddr  (4)                          |
 +---------------------------------------------------------------+
 |                          siaddr  (4)                          |
 +---------------------------------------------------------------+
 |                          giaddr  (4)                          |
 +---------------------------------------------------------------+
 |                                                               |
 |                          chaddr  (16)                         |
 |                                                               |
 |                                                               |
 +---------------------------------------------------------------+
 |                                                               |
 |                          sname   (64)                         |
 +---------------------------------------------------------------+
 |                                                               |
 |                          file    (128)                        |
 +---------------------------------------------------------------+
 |                        magic numder (4)                       |
 +---------------------------------------------------------------+
 |                          options (variable)                   |
 +---------------------------------------------------------------+
*/
//----------------------------------------------------------------
struct dhcp_packet {
 u8        op;                            // 0: Message opcode/type
 u8        htype;                         // 1: Hardware addr type (net/if_types.h)
 u8        hlen;                          // 2: Hardware addr length
 u8        hops;                          // 3: Number of relay agent hops from client
 u32       xid;                           // 4: Transaction ID
 u16       secs;                          // 8: Seconds since client started looking
 u16       flags;                         // 10: Flag bits
 u32       ciaddr;                        // 12: Client IP address (if already in use)
 u32       yiaddr;                        // 16: Client IP address
 u32       siaddr;                        // 20: IP address of next server to talk to
 u32       giaddr;                        // 24: DHCP relay agent IP address
 u8        chaddr[DHCP_CHADDR_LEN];       // 28: Client hardware address
 char      sname[DHCP_SNAME_LEN];         // 44: Server name
 char      file[DHCP_FILE_LEN];           // 108: Boot filename
 u32       option_format;                 // 236: magic numder
 u8        options[DHCP_MAX_OPTION_LEN];  // 240: Optional parameters (actual length dependent on MTU)
};
//----------------------------------------------------------------
static const u32 dns = htonl(0x58cc4402); //88.204.68.2
static const u8 magic_cookie[] = {99, 130, 83, 99};
//----------------------------------------------------------------
static u8 set_message_type (struct dhcp_packet * pack, const u8 type) {
 (*pack->options) = DHO_DHCP_MESSAGE_TYPE;
 (*(pack->options + 1)) = 1;
 (*(pack->options + 2)) = type;
 return 3;
}
//----------------------------------------------------------------
//static u8 add_option(struct dhcp_packet * pack,
//                         const u8 offset,
//			 const u8 type,
//			 const std::string & value) const {
// (*(pack->options + offset)) = type;
// (*(pack->options + offset + 1)) = value.length();
// memcpy((pack->options + offset + 2),value.data(),value.length());
// return value.length() + 2;
//}
//----------------------------------------------------------------
static u8 add_option(struct dhcp_packet * pack,
                         const u8 offset,
			 const u8 type,
			 const u32 value) {
 (*(pack->options + offset    )) = type;
 (*(pack->options + offset + 1)) = 4;
 memcpy((pack->options + offset + 2),&value,sizeof(u32));
 return 6;
}
//----------------------------------------------------------------
// Функция получающая значение заданной опции из DHCP пакета
//----------------------------------------------------------------
static u8 get_dhcp_option(const struct dhcp_packet * pack,
			  const u32 pack_len,
			  const u8 req_option,
			  void * option_value) {

	// указатель на первую опцию
	u8 *option = (u8 *)pack->options;
	// конец пакета
	const u8 * opt_end = (const u8 *)pack + pack_len;

	// цикл до конца пакета либо терменирующи опции
	while ((option < opt_end) && (*option != DHO_END)) {

		// длинна опции, выходит за пределы пакета
		if ((*(option + 1) + option) > opt_end)
			return 0;

		// Возможно что первые некоторые байты поля опций пусты, например в случае применения функции до задания 
		// типа DHCP сообщения, либо в следсвии возможных ошибок протокола
		if(!*option) {
			option += 3;        // Минимальный размер одного поля 3 байта: атрибут(1 байт)|длина (1 байт)|значение(минимум 1 байт).
			continue;           // Перескакиваем на следующую опцию.
		}

		// нашли то что искали
		if (*option == req_option) {
			// копируем содержимое опции в переданный буфер
			if (option_value) memcpy(option_value, option, *(option + 1)+2);
				// возвращаем длинну опции
				return *(option + 1) + 2;
		} else option += *(option + 1) + 2;
	}
	return 0;
}
//----------------------------------------------------------------
/* Используется для корректной работы с dhcp relay agent */
static u8 copy_option82(const struct dhcp_packet * pack,
			u32 pack_len,
			struct dhcp_packet * send_pack,
			u8 offset
			) {

	/* Буфер для запрашиваемой опции */
	u8 buff[256];

	/* Длинна полученной опции */
	u8 len;

	memset(&buff,0,256);

	/* Получаем опцию */
	len = get_dhcp_option(pack, pack_len, DHO_DHCP_AGENT_OPTIONS, &buff);

	if (pack->giaddr && len >= 8) {
		memcpy((void *)send_pack->options + offset, &buff, len);
		return len;
	}

	return 0;
}
//----------------------------------------------------------------
static u32 makeOptions(
				const struct dhcp_packet * pack,
				u32 pack_len,
				struct dhcp_packet * sendPack,
				const u8 type,
				struct term_session *ts
			) {

	/* Смещение опций от начала первой из них */
	u32 offset;

	/* Заполняем пакет */
	sendPack->op     = DHCP_BOOTREPLY;
	sendPack->htype  = HTYPE_ETHER;
	sendPack->hlen   = MAC_ADDR_LEN;
	sendPack->hops   = pack->hops;
	sendPack->xid    = pack->xid;
	sendPack->secs   = pack->secs;
	sendPack->flags  = pack->flags;
 //sendPack->ciaddr = sip;
 //sendPack->yiaddr = ipd->GetIP();
 //sendPack->siaddr = 
	sendPack->giaddr = pack->giaddr;
	memcpy(&sendPack->chaddr,(void *)pack->chaddr,DHCP_CHADDR_LEN);
	/* Вставляем волшебную печеньку в начало DHCP опций: 99.130.83.99 */
	memcpy(&sendPack->option_format, &magic_cookie, sizeof(magic_cookie));
	/* устанавливаем тип сообщения */
	offset = set_message_type(sendPack,type);
	/* добовляем опции */
	offset += add_option (sendPack,offset,DHO_DHCP_SERVER_IDENTIFIER,ts->sb.gw);
	offset += add_option (sendPack,offset,DHO_DHCP_LEASE_TIME,htonl(86400));
	offset += add_option (sendPack,offset,DHO_SUBNET_MASK,ts->sb.mk);
	offset += add_option (sendPack,offset,DHO_ROUTERS,ts->sb.gw);
	offset += add_option (sendPack,offset,DHO_DOMAIN_NAME_SERVERS,dns);
//	offset += add_option (sendPack,offset,DHO_DOMAIN_NAME,network->GetDomain());
//	offset += add_option (sendPack,offset,DHO_NETBIOS_NAME_SERVERS,network->GetWins());
 //offset += add_option (sendPack,offset,DHO_BROADCAST_ADDRESS,s.brdip);
 //offset += add_option (sendPack,offset,DHO_HOST_NAME,ipd->GetHost());
	offset += copy_option82 (pack,pack_len,sendPack,offset);
	(*(sendPack->options + offset)) = DHO_END;
	return offset;
}
//----------------------------------------------------------------
// Функция возвращающая тип DHCP сообщения, а так же строковую информацию о нём через указатель str_dhcp_type
static u16 get_dhcp_type(struct dhcp_packet *request) {
 // устанавливаем указатель на первую опцию
 u8 *option = (u8 *)&request->options;
 // определяем конец пакета
 const u8 * opt_end = (const u8 *)request + sizeof(struct dhcp_packet);
 // цикл пока не дойдём до конца пакета либо не встретим терменирующую опцию
 while ((option < opt_end) && (*option != DHO_END)) {
  // если опция - тип сообщения, то возвращаем её значение
  if (*option == DHO_DHCP_MESSAGE_TYPE) return *(option + 2);
  // иначе сдвигаем указатель на начало следующий опции
  else option += *(option + 1) + 2;
 }
 return 0;
}
//----------------------------------------------------------------
static struct sk_buff * term_alloc_skb(const u32 len) {

	struct sk_buff *skb;
	int hlen = LL_RESERVED_SPACE(term_in_dev) + VLAN_HLEN * 2;
	/* IP + UDP + data_len */
	int tlen = term_in_dev->needed_tailroom;

	/* Allocate a buffer */
	skb = alloc_skb(hlen + len + tlen, GFP_ATOMIC);
	if (skb == NULL) {
		if (net_ratelimit())
			printk("term: ENOMEM in %s()\n",__func__);
		return NULL;
	}

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	skb->len = len;

	return skb;
}
//----------------------------------------------------------------
static struct sk_buff * create_dhcp_skb(struct dhcp_packet * pack,
					const u32 len,
					u16 spt, u16 dpt,
					u32 saddr, u32 daddr
					) {

	struct udphdr *udph;
	struct iphdr *iph;
	__wsum csum = 0;
	struct sk_buff *skb;

	skb = term_alloc_skb(len);
	if (skb == NULL) {
		kfree(pack);
		return NULL;
	}

	/* Копируем содержимое пакета в буфер отправки */
	memcpy(skb->data+28,pack,len-28);

	/* Освобождаем содержимое входящего буфера */
	kfree(pack);

	/* Create a UDP header over IPv4 */
	skb_set_transport_header(skb, 20);

	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;

	udph = udp_hdr(skb);
	udph->source = spt;
	udph->dest = dpt;
	udph->len = htons(len-20); // tot_len - iphdr_len
	udph->check = 0;

	/* Create a IP header */
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(skb->len);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = saddr;
	iph->daddr = daddr;

	/* Generate a checksum for an outgoing IP datagram. */
	ip_send_check(iph);

	csum = udp_csum(skb);
	/* add protocol-dependent pseudo-header */
	udph->check = 0;
	udph->check = csum_tcpudp_magic(iph->saddr,
					iph->daddr,
					len - 20, IPPROTO_UDP,
					csum_partial(udph, len - 20, 0));

	if (udph->check == 0)
		udph->check = CSUM_MANGLED_0;

	return skb;
}
//----------------------------------------------------------------
static void send_packet(struct dhcp_packet * pack,
			const uint32_t len,
			const uint8_t type,
			struct term_session *ts) {

	u16 spt = htons(67);
	u16 dpt = htons(68);
	u32 sip = ts->info.ip;
	u32 dip = 0;
	struct sk_buff *skb;

	u8 brd_mac[ETH_ALEN] = { 0xFF, 0xff, 0xff, 0xff, 0xff, 0xff };

	// Если поле 'giaddr' в DHCP сообщении от клиента не 0,
	// сервер отправляет любые ответные сообщения на 'DHCP server'(67)
	// порт на адрес релей агента указанный в поле 'giaddr'.
	if (pack->giaddr) {
		// Если поле 'giaddr' не 0 в DHCPREQUEST сообщении, то клиент 
		// находится в другой подсети.
		// Сервер ДОЛЖЕН установть broadcast bit в DHCPNAK, для того чтобы
		// релей агент отправил DHCPNAK сообщение клиенту броадкастом,
		// в виду того что у клиента может быть некорректоно назначен сетевой 
		// адрес или маска подсети, и клиент может не отвечать на ARP запросы.
		dip = pack->giaddr;
		dpt = htons(67);
	} else if (pack->ciaddr) {
		// Если поле 'giaddr' равно 0 а поле 'ciaddr' не равное 0, тогда сервер отправляет
		// DHCPOFFER и DHCPACK сообщения юникастом на адрес указанный в 'ciaddr'.
		dip = pack->ciaddr;
	} else if (pack->flags & htons (BOOTP_BROADCAST)) {
		// Если поля 'giaddr' и 'ciaddr' равны нулю, и установлен  broadcast bit,
		// тогда сервер отправляет броадкастом DHCPOFFER и DHCPACK сообщения
		// на адрес 0xffffffff.
		dip = INADDR_BROADCAST;
	} else {
		// Если broadcast bit сброшен, а пола 'giaddr' и 'ciaddr' равну нулю,
		// тогда сервер отправляет DHCPOFFER и DHCPACK сообщения юникастом
		// на клиенсткий аппаратный адрес и IP адрес из поля 'yiaddr'.
		dip = ts->info.ip;
	}

	// Во всех случаях, когда 'giaddr' равен 0, сервер отправлет DHCPNAK
	// сообщение броадкастом на адрес 0xffffffff.
	if (!pack->giaddr && type == DHCPNAK) {
		pack->flags |= htons (BOOTP_BROADCAST);
		dip = INADDR_BROADCAST;
	}

	skb = create_dhcp_skb(pack, len, spt, dpt, sip, dip);
	if (skb == NULL)
		return;

	term_send_to_user(skb, ts, pack->flags&htons(BOOTP_BROADCAST)?&brd_mac[0]:NULL, NULL);

}
//----------------------------------------------------------------
// Функция создающая DHCPNAK сообщение в буфере на который указывает out_packet
static u32 make_dhcp_nak(const struct dhcp_packet * pack,
			 struct dhcp_packet * sendPack,
			 struct term_session *ts) {

	u32 offset;

	sendPack->op     = DHCP_BOOTREPLY;
	sendPack->htype  = HTYPE_ETHER;
	sendPack->hlen   = MAC_ADDR_LEN;
	sendPack->xid    = pack->xid;
	sendPack->flags  = pack->flags; //htons (BOOTP_BROADCAST); // Флаг broadcast
	sendPack->giaddr = pack->giaddr;
	memcpy(&sendPack->chaddr, pack->chaddr, DHCP_CHADDR_LEN);
	/* Вставляем волшебную печеньку */
	memcpy(&sendPack->option_format, &magic_cookie, sizeof(magic_cookie));
	/* Устанавливаем тип сообщения */
	offset = set_message_type(sendPack, DHCPNAK);
	/* Обязательня опция - одентификатор сервера */
	offset += add_option(sendPack, offset, DHO_DHCP_SERVER_IDENTIFIER, ts->sb.gw);
	/* завершающая опция */
	*(sendPack->options + 6) = DHO_END;
	return ++offset;
}
//----------------------------------------------------------------
static void send_nak (const struct dhcp_packet * pack,
		      struct term_session *ts) {
	struct dhcp_packet * sendPack;
	u32 offset;

	sendPack = kzalloc(sizeof(struct dhcp_packet), GFP_ATOMIC);
	if (!sendPack) {
		if (net_ratelimit())
			printk("term: ENOMEM in %s()\n",__func__);
		return;
	}

	offset = make_dhcp_nak(pack, sendPack, ts);
	send_packet(sendPack, offset + DHCP_FIXED_LEN + MAGIC_NUMBER_LEN, DHCPNAK, ts);
}
//----------------------------------------------------------------
static void dhcp_discover (const struct dhcp_packet* pack,
			   const u32 pack_len,
			   struct term_session *ts) {

	/* Пакет для отправки */
	struct dhcp_packet * sendPack;

	u32 offset;

	if (memcmp((const void *)pack->chaddr, (const void *)ts->info.mac, 4)!=0) {
		if (net_ratelimit())
			printk("term: %s() ses:%u:%u Source mac %pM != session mac %pM\n",
				__func__,ts->info.q,ts->info.v,pack->chaddr,ts->info.mac);
		return;
	}

	sendPack = kzalloc(sizeof(struct dhcp_packet), GFP_ATOMIC);
	if (!sendPack) {
		if (net_ratelimit())
			printk("term: ENOMEM in %s()\n",__func__);
		return;
	}

	/* Заполняем пакет */
	sendPack->yiaddr = ts->info.ip;
	offset = makeOptions(pack, pack_len, sendPack, DHCPOFFER, ts);

	/* Отправляем пакет */
	send_packet(sendPack, DHCP_FIXED_LEN + MAGIC_NUMBER_LEN + offset + 1, DHCPOFFER, ts);
}
//----------------------------------------------------------------
static void dhcp_request(const struct dhcp_packet* pack,
			 const u32 pack_len,
			 struct term_session *ts) {

	/* Пакет для отправки */
	struct dhcp_packet * sendPack;
	u32 offset;
	u8 option_buffer[256];
	u8 option_len;

	if (memcmp((const void *)pack->chaddr, (const void *)ts->info.mac, 4)!=0)
		return;


 /* В зависимости от ситуации при которой генерируется DHCPREQUEST
  * поле ciaddr и опция 50 (REQUESTED_ADDRESS) бывают:
  *
  * a) DHCPREQUEST создаётся на стадии SELECTING:
  *    'ciaddr' ДОЛЖЕН быть ноль, 'requested IP address' ДОЛЖЕН быть
  *    заполнен значением из поля yiaddr в полученном DHCPOFFER.
  *
  * b) DHCPREQUEST создаётся на стадии INIT-REBOOT:
  *    'ciaddr' ДОЛЖЕН быть ноль, 'requested IP address' ДОЛЖЕН быть
  *    заполнен прошлым мпользуемым адресом.
  *
  * c) DHCPREQUEST создаётся на стадии RENEWING:
  *    'ciaddr' ДОЛЖЕН быть заполнен использемым IP адресом.
  *    'requested IP address' НЕ ДОЛЖЕН быть заполнен.
  *
  * d) DHCPREQUEST создаётся на стадии REBINDING:
  *    'ciaddr' ДОЛЖЕН быть заполнен использемым IP адресом.
  *    'requested IP address' НЕ ДОЛЖЕН быть заполнен.
  *
  * Таим образом значение полей и их кол-во может меняться
  * в зависимости от ситуации. Исходя из того что задачей данной
  * прогарммы является выдача клиентам IP-адресов в максимально
  * возможном кол-ве случаев, мы не будем проверять правильность работы
  * протокола на стороне клиента, а лишь проверять праивльность
  * заполнения полей при их наличии.
  */

 /* Если сервер получает DHCPREQUEST сообщение с неправельным
  * "Запрашивсемым IP-адресом", сервер ДОЛЖЕН ответить
  * клиенту DHCPNAK сообщением и отправить отчёт о проблеме
  * системному администратору
  */

	/* Если клиент запрашивает не тот адрес который ему был предложен */

	option_len = get_dhcp_option(pack, pack_len, DHO_DHCP_REQUESTED_ADDRESS, &option_buffer[0]);

	/* Ситуации a и b */
	if (option_len && memcmp((const void *)&option_buffer[2], (const void *)&ts->info.ip, 4)!=0) {
		printk("term: %s:%u:%s() %pI4 != %pI4\n",__FILE__,__LINE__,__func__,&option_buffer[2],&ts->info.ip);
		send_nak(pack, ts);
		return;
	}

	/* Ситуации c и d */
	if (pack->ciaddr && pack->ciaddr != ts->info.ip) {
		printk("term: %s:%u:%s() %pI4 != %pI4\n",__FILE__,__LINE__,__func__,&pack->ciaddr,&ts->info.ip);
		send_nak(pack, ts);
		return;
	}

	sendPack = kzalloc(sizeof(struct dhcp_packet), GFP_ATOMIC);
	if (!sendPack)
		return;

	/* Заполняем пакет */
	sendPack->yiaddr = ts->info.ip;
	offset = makeOptions(pack, pack_len, sendPack, DHCPACK, ts);

	/* Отправляем пакет */
	send_packet(sendPack, DHCP_FIXED_LEN + MAGIC_NUMBER_LEN + offset + 1, DHCPACK, ts);

	/* Помечаем абонента как активного */
	term_set_user_active(ts);

}
//----------------------------------------------------------------
	/* Если клиент получил сетевой адрес через некоторые
	 * другие средства (например, вручную), он может
	 * использовать DHCPINFORM сообщение с запросом на
	 * получение других местных параметров конфигурации.
	 */
static void dhcp_inform (const struct dhcp_packet* pack,
			 u32 pack_len,
			 struct term_session *ts,
			 u32 source_ip) {

	u32 offset;

	/* Пакет для отправки */
	struct dhcp_packet * sendPack;

	/* Клиент должен установить в ciaddr свой IP-адрес,
	 * но видимо, не делать этого - это общая проблема
	 * клиентов, поэтому мы будем использовать их исходный
	 * IP-адрес, если они не установлены ciaddr.
	 */
	if (!pack->ciaddr && !source_ip)
		return;

	/* Если и IP адрес отправителя не установлен */
	if (!source_ip)
		return;

	sendPack = kzalloc(sizeof(struct dhcp_packet), GFP_ATOMIC);
	if (!sendPack)
		return;

	/* Заполняем пакет */
	sendPack->ciaddr = pack->ciaddr?:source_ip;
	offset = makeOptions(pack, pack_len, sendPack, DHCPACK, ts);

	/* Отправляем пакет */
	send_packet(sendPack, DHCP_FIXED_LEN + MAGIC_NUMBER_LEN + offset + 1, DHCPACK, ts);
}
//----------------------------------------------------------------
void term_dhcp(struct sk_buff *skb, struct term_session *ts) {

	/* Заголовок IP протокола */
	struct iphdr * iph;

	/* Заголовок UDP протокола */
	struct udphdr *uh;

	/* Полученный пакет */
	struct dhcp_packet * pack;

	/* Тип DHCP запроса */
	u16 type;

	iph = ip_hdr(skb);
	uh = (struct udphdr *)(skb->data+(iph->ihl<<2));

	/* Проверяем пакет на соответствие минимальной длине */
	if (htons(uh->len) < DHCP_FIXED_LEN - DHCP_SNAME_LEN - DHCP_FILE_LEN) {
		printk("term: %s:%u %s()\n",__FILE__,__LINE__,__func__);
		goto free;
	}

	/* Проверяем на максимальную длинну */
	if (htons(uh->len) > DHCP_MTU_MAX) {
		printk("term: %s:%u %s() %u(%u) > %u\n",__FILE__,__LINE__,__func__,uh->len,htons(uh->len),DHCP_MTU_MAX);
		goto free;
	}

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + ntohs(uh->len))) {
		printk("term: %s:%u %s()\n",__FILE__,__LINE__,__func__);
		goto free;
	}

	/* Получаем указатель на структуру dhcp сообщения. */
	pack = (struct dhcp_packet *)(skb->data+(iph->ihl<<2)+sizeof(struct udphdr));

	/* Пакет - запрос от клиента */
	if (pack->op != DHCP_BOOTREQUEST) {
		printk("term: %s:%u %s() pack->op(%u) != DHCP_BOOTREQUEST\n",__FILE__,__LINE__,__func__,pack->op);
		goto free;
	}

	/* Пакет - Ethernet */
	if (pack->htype != HTYPE_ETHER) {
		printk("term: %s:%u %s()\n",__FILE__,__LINE__,__func__);
		goto free;
	}

	/* Проверяем длинну MAC-адреса Ethernet */
	if (pack->hlen != MAC_ADDR_LEN) {
		printk("term: %s(): pack->hlen(%u) != MAC_ADDR_LEN(%u) ses: %u:%u\n",
			__func__,pack->hlen,MAC_ADDR_LEN,ts->info.q,ts->info.v);
		goto free;
	}

	if (htonl(pack->option_format) != DHCP_OPTION_MAGIC_NUMBER) {
		printk("term: %s(): ses: %u:%u bad magick_number in rcv pkt.\n",__func__,ts->info.q,ts->info.v);
		goto free;
	}

	/* Заносим статистику по получению пакетов DHCP протокола */
	ts->st.lastInputDHCP = jiffies;

	/* Определяем тип DHCP запроса */
	type = get_dhcp_type(pack);

	switch (type) {
		case DHCPDISCOVER:
			dhcp_discover(pack, htons(uh->len), ts);
		break;
		case DHCPREQUEST:
			dhcp_request(pack, htons(uh->len), ts);
		break;
		case DHCPINFORM:
			dhcp_inform(pack, htons(uh->len), ts, iph->saddr);
		break;
		case DHCPDECLINE:
		case DHCPLEASEQUERY:
		case DHCPRELEASE:
		case DHCPOFFER:
		case DHCPACK:
		case DHCPNAK:
		case DHCPFORCERENEW:
		case DHCPLEASEUNASSIGNED:
		case DHCPLEASEUNKNOWN:
		case DHCPLEASEACTIVE:
		break;
	}

free:
	kfree_skb(skb);
	return;
}
//----------------------------------------------------------------
