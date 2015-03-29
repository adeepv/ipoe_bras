//-----------------------------------------------------------------------------
#include <linux/module.h>
#include <linux/if_ether.h> // ETH_P_ALL
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <net/arp.h>
#include <linux/ip.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
/* netlink сокет */
static struct sock * sknl;
//-----------------------------------------------------------------------------
static inline void sk_add_addr(struct sockaddr *addr, __be32 ip) {
	((struct sockaddr_in *) addr)->sin_addr.s_addr = ip;
	addr->sa_family = AF_INET;
}
//-----------------------------------------------------------------------------
static int term_call_ioctl(unsigned int cmd, void * arg) {
	int err;
	struct sock sk;
	struct socket sock;
	mm_segment_t oldfs;

	sk.sk_net = &init_net;
	sock.sk = &sk;

	oldfs = get_fs();
	set_fs(get_ds());
	err = inet_ioctl(&sock, cmd, (long unsigned int)arg);
	set_fs(oldfs);

	return err;
}
//-----------------------------------------------------------------------------
int term_route_add(u32 dst) {

	int err;
	struct rtentry rt;

	memset(&rt, 0, sizeof(rt));
	sk_add_addr(&rt.rt_dst, dst);
	sk_add_addr(&rt.rt_gateway, gw_ip);
	rt.rt_flags |= RTF_HOST | RTF_GATEWAY;
	rt.rt_metric = 0;
	rt.rt_dev = term_dev_world->name;

	err = term_call_ioctl(SIOCADDRT, (void*) &rt);
	if (err  < 0)
		printk(KERN_ERR "term: route_add: Unable to add route (%d)\n",err);

	return err;
}
//-----------------------------------------------------------------------------
int term_route_del(u32 dst) {

	int err;
	struct rtentry rt;

	memset(&rt, 0, sizeof(rt));
	sk_add_addr(&rt.rt_dst, dst);
	sk_add_addr(&rt.rt_gateway, gw_ip);
	rt.rt_flags |= RTF_HOST | RTF_GATEWAY;
	rt.rt_metric = 0;
	rt.rt_dev = term_dev_world->name;

	err = term_call_ioctl(SIOCDELRT, (void*) &rt);
	if (err  < 0)
		printk(KERN_ERR "term: route_del: Unable to del route (%d)\n",err);

	return err;
}
//-----------------------------------------------------------------------------
int term_ip_add(u32 ip, u32 mask) {

	int err;
	struct ifreq ir;

	memset(&ir, 0, sizeof(ir));

	if (!term_dev_world) {
		printk(KERN_ERR "term: ip_add: Device pointer is not set\n");
		return -1;
	}

	strncpy(ir.ifr_name, term_dev_world->name, IFNAMSIZ);

	sk_add_addr(&ir.ifr_addr, ip);
	if ((err = term_call_ioctl(SIOCSIFADDR, (void*) &ir)) < 0) {
		printk(KERN_ERR "term: ip_add: Unable to set interface address (%d)\n",err);
		return err;
	}

	sk_add_addr(&ir.ifr_addr, mask);
	if ((err = term_call_ioctl(SIOCSIFNETMASK, (void*) &ir)) < 0) {
		printk(KERN_ERR "term: ip_add: Unable to set interface netmask (%d)\n",err);
		return err;
	}

	sk_add_addr(&ir.ifr_addr, ip | ~mask);
	if ((err = term_call_ioctl(SIOCSIFBRDADDR, (void*) &ir)) < 0) {
		printk(KERN_ERR "term: ip_add: Unable to set interface broadcast address (%d)\n",err);
		return err;
	}

	return 0;
}
//-----------------------------------------------------------------------------
static void term_cmd_subnet(void * data) {
	struct __term_subnet *ev = (struct __term_subnet *)data;
	struct term_subnet *sb;
//	u64 now = ktime_to_ns(ktime_get());
//	spin_lock_bh(&term_lock);
	sb = term_find_subnet(ev->sb);
	if (sb) {
		//printk(KERN_ERR "ipt_ISG: isg_update_session()\n");
		sb->mk = ev->mk;
		sb->bk = ev->bk;
		sb->gw = ev->gw;
		sb->ml = ev->ml;
	} else {
//		printk(KERN_ERR "term: subnet lookup failed - create it\n");
		sb = kzalloc(sizeof(struct term_subnet), GFP_ATOMIC);
		if (!sb) {
//			spin_unlock_bh(&term_lock);
			printk(KERN_ERR "term: subnet allocation failed\n");
			return;
		}
		sb->sb = ev->sb;
		sb->mk = ev->mk;
		sb->bk = ev->bk;
		sb->gw = ev->gw;
		sb->ml = ev->ml;
//		printk(KERN_ERR "term: create_subnet: sb=%u mk=%u bk=%u gw=%u\n", sb->sb, sb->mk, sb->bk, sb->gw);
		term_insert_subnet(sb);
	}

//	spin_unlock_bh(&term_lock);
	return;
}
//-----------------------------------------------------------------------------
static void term_nl_receive_main(struct sk_buff *skb) {

	/* Извлекаем netlink сообщение из сетевого пакета */
	struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;

	/* Извлекаем данные из netlink пакета */
	struct term_in_event *ev = (struct term_in_event *) NLMSG_DATA(nlh);

	spin_lock_bh(&term_event_lock);
	switch (ev->type) {
		case TERM_EVENT_SESSION:
			term_cmd_session((void*)&ev->data);
		break;
		case TERM_EVENT_SUBNET:
			term_cmd_subnet((void*)&ev->data);
		break;
	}
	spin_unlock_bh(&term_event_lock);
}
//-----------------------------------------------------------------------------
int term_netlink_init(void) {
	struct netlink_kernel_cfg cfg;

	/* Регистрируем Netlink сокет */
	memset(&cfg, 0, sizeof(struct netlink_kernel_cfg));
	cfg.input = term_nl_receive_main;

	sknl = netlink_kernel_create(&init_net, TERM_NETLINK_MAIN, &cfg);
	if (!sknl) {
		printk(KERN_ERR "term: Can't create TERM_NETLINK_MAIN socket\n");
		return -ENOMEM;
	}

	return 0;
}
//-----------------------------------------------------------------------------
void term_netlink_destroy(void) {
	/* Освобождаем Netlink сокет */
	netlink_kernel_release(sknl);
}
//-----------------------------------------------------------------------------
