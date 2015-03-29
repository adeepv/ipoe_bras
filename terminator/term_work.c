//-----------------------------------------------------------------------------
#include <linux/workqueue.h>
#include <linux/rculist.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
// Отложенная обработка событий.
// Верхняя половина может вызываться из прерываний при обработке пакетов
// Устанавливает статусы, прописывает ARP и добавляет маршруты.

//-----------------------------------------------------------------------------
/* Очереди задач */
static LIST_HEAD(term_work_list);
struct term_work_struct {
	struct rcu_head rcu;
	struct list_head list;
	struct term_session * ts;
};
struct work_struct term_work_tasklet;
static struct socket * sock;
//-----------------------------------------------------------------------------
static void term_session_send_notify (struct term_session *ts) {
	struct nms_message_header * h;
	struct nms_message_session_notify * n;
	struct kvec iov;
	void * msg;
	struct msghdr buff = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };

	int msg_len = sizeof(struct nms_message_header)
		    + sizeof(struct nms_message_session_notify);

	msg = kzalloc(msg_len, GFP_ATOMIC);
	if (!msg)
		return;

	h = (struct nms_message_header *) msg;
	h->code = NMS_MESS_CODE_NOTYFY;
	h->type = NMS_MESS_TYPE_SESSION;
	h->len  = msg_len;

	n = (struct nms_message_session_notify *) ++h;
	n->q     = ts->info.q;
	n->v     = ts->info.v;
	n->ip    = ts->info.ip;
	memcpy(n->mac, ts->info.mac, ETH_ALEN);
	n->flags = ts->st.flags;

	iov.iov_base = msg;
	iov.iov_len  = (size_t)msg_len;
	kernel_sendmsg(sock, &buff, &iov, 1, (size_t)msg_len);
}
//-----------------------------------------------------------------------------
/* Верхняя половина. */
void term_add_work(struct term_session * ts) {

	struct term_work_struct * tws = kzalloc(sizeof(*tws), GFP_ATOMIC);
	if (!tws)
		return;

	tws->ts = ts;

	list_add_rcu(&tws->list, &term_work_list);

	schedule_work(&term_work_tasklet);
}
//-----------------------------------------------------------------------------
/* Нижняя половина. */
static void term_do_tasklet (void) {

	struct term_work_struct * tws;

	while (!list_empty(&term_work_list)) {
		tws = list_entry_rcu(term_work_list.next, struct term_work_struct, list);

		if (tws->ts->st.flags & TERM_SES_ONLINE)
			term_route_add(tws->ts->info.ip);
		else
			term_route_del(tws->ts->info.ip);

		term_session_send_notify(tws->ts);

		list_del_rcu(&tws->list);
		kfree_rcu(tws, rcu);

	}

}
//-----------------------------------------------------------------------------
static struct socket *usock_alloc(__be32 ipaddr, unsigned short port) {

	struct sockaddr_in sin;
	struct socket *sock;
	int error;

	if ((error = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
		printk(KERN_ERR "term: work: sock_create_kern error %d\n", error);
		return NULL;
	}
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(ipaddr);
	sin.sin_port        = htons(port);
	if ((error = sock->ops->connect(sock, (struct sockaddr *)&sin, sizeof(sin), 0)) < 0) {
		printk(KERN_ERR "term: work: error connecting UDP socket %d\n", error);
		sock_release(sock);
		return NULL;
	}
	return sock;
}
//-----------------------------------------------------------------------------



// Простая реализация потока. Запускается через каждые 50 секунд.
//-----------------------------------------------------------------------------
/* Отложенная работа */
static void term_work_fn(struct work_struct *dummy);
DECLARE_DELAYED_WORK(term_work, term_work_fn);
//-----------------------------------------------------------------------------
static void term_work_fn(struct work_struct *dummy) {
	term_arping();
	/* Таймаут 50 секунд */
	schedule_delayed_work(&term_work, HZ * 50);
}
//-----------------------------------------------------------------------------




//-----------------------------------------------------------------------------
int term_work_init(void) {
			//  ip		port
			// todo to mod param
	sock = usock_alloc(0x00112233, 1234);
	if (!sock)
		return 1;

	INIT_WORK(&term_work_tasklet, (void *)term_do_tasklet);

	/* Первый запуск через 10 секунд */
	schedule_delayed_work(&term_work, HZ * 10);

	return 0;
}
//-----------------------------------------------------------------------------
void term_work_destroy(void) {
	/* Отменяем отложенную работу */
	cancel_delayed_work(&term_work);
	flush_scheduled_work();

	if (sock)
		sock_release(sock);
}
//-----------------------------------------------------------------------------
