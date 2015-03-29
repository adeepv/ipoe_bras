//-----------------------------------------------------------------------------
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/rtnetlink.h>
#include <net/arp.h>
#include <linux/etherdevice.h>
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
u32 gw_ip;
u8  gw_mac[ETH_ALEN];
//-----------------------------------------------------------------------------
static void term_free_netdev(struct net_device *dev) {

}
//-----------------------------------------------------------------------------
static void term_dev_setup(struct net_device *dev) {
	dev->destructor = term_free_netdev;
}
//-----------------------------------------------------------------------------
/* Trivial set of netlink ops to allow deleting device with netlink. */
static int term_dev_validate(struct nlattr *tb[], struct nlattr *data[]) {
	return -EINVAL;
}
//-----------------------------------------------------------------------------
static struct rtnl_link_ops term_link_ops __read_mostly = {
	.kind           = "IPoE",
	.priv_size      = 0,//sizeof(struct tun_struct),
	.setup          = term_dev_setup,
	.validate       = term_dev_validate,
};
//-----------------------------------------------------------------------------
/* Net device detach from fd. */
static void term_dev_net_uninit(struct net_device *dev) {

}
//-----------------------------------------------------------------------------
/* Net device open. */
static int term_dev_net_open(struct net_device *dev) {
	netif_tx_start_all_queues(dev);
	return 0;
}
//-----------------------------------------------------------------------------
/* Net device close. */
static int term_dev_net_close(struct net_device *dev) {
	netif_tx_stop_all_queues(dev);
	return 0;
}
//-----------------------------------------------------------------------------
/* Net device start xmit */
static netdev_tx_t term_dev_net_xmit(struct sk_buff *skb, struct net_device *dev) {

	skb->mac_header += ETH_HLEN;
	skb->data += ETH_HLEN;
	skb->len -= ETH_HLEN;

	skb_reset_network_header(skb); //skb->network_header = skb->data - skb->head;
	skb_reset_transport_header(skb); //skb->transport_header = skb->data - skb->head;
	skb_reset_mac_len(skb); //   skb->mac_len = skb->network_header - skb->mac_header;

	term_world_input(skb);
	return NETDEV_TX_OK;
}
//-----------------------------------------------------------------------------
static void term_dev_net_mclist(struct net_device *dev) {
	/*
	 * This callback is supposed to deal with mc filter in
	 * _rx_ path and has nothing to do with the _tx_ path.
	 * In rx path we always accept everything userspace gives us.
	 */
}
//-----------------------------------------------------------------------------
#define MIN_MTU 68
#define MAX_MTU 65535
//-----------------------------------------------------------------------------
static int term_dev_net_change_mtu(struct net_device *dev, int new_mtu) {
	if (new_mtu < MIN_MTU || new_mtu + dev->hard_header_len > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}
//-----------------------------------------------------------------------------
static netdev_features_t term_dev_net_fix_features(struct net_device *dev, netdev_features_t features) {
//	struct tun_struct *tun = netdev_priv(dev);
	return 0;//(features & tun->set_features) | (features & ~TUN_USER_FEATURES);
}
//-----------------------------------------------------------------------------
#ifdef CONFIG_NET_POLL_CONTROLLER
static void term_dev_poll_controller(struct net_device *dev) {
	/*
	 * Tun only receives frames when:
	 * 1) the char device endpoint gets data from user space
	 * 2) the tun socket gets a sendmsg call from user space
	 * Since both of those are syncronous operations, we are guaranteed
	 * never to have pending data when we poll for it
	 * so theres nothing to do here but return.
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
	return;
}
#endif
//-----------------------------------------------------------------------------
static u16 term_dev_select_queue(struct net_device *dev,
				 struct sk_buff *skb
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,13,6)
				 , void *accel_priv
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,14,3)
				, select_queue_fallback_t fallback
#endif
				) {
	return 1;
}
//-----------------------------------------------------------------------------
static const struct net_device_ops term_dev_netdev_ops = {
	.ndo_uninit		= term_dev_net_uninit,
	.ndo_open		= term_dev_net_open,
	.ndo_stop		= term_dev_net_close,
	.ndo_start_xmit		= term_dev_net_xmit,
	.ndo_change_mtu		= term_dev_net_change_mtu,
	.ndo_fix_features	= term_dev_net_fix_features,
	.ndo_set_rx_mode	= term_dev_net_mclist,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_select_queue	= term_dev_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= term_dev_poll_controller,
#endif
};
//-----------------------------------------------------------------------------
/* Initialize net device. */
static void term_dev_net_init(struct net_device *dev) {
	dev->netdev_ops = &term_dev_netdev_ops;
	ether_setup(dev);
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	eth_hw_addr_random(dev);
//	dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
}
//-----------------------------------------------------------------------------
int term_dev_create (void) {
	struct net_device *dev;
	const char * name = "IPoE";
	int err = 0;
	struct neighbour *n;

	u32 up1_mk = htonl(~((1U << (32 - 30)) - 1));
	u32 up1_ip = htonl(0x11223345);
// todo
	gw_ip = htonl(0x11223344);

	gw_mac[0] = 0x00;
	gw_mac[1] = 0xaa;
	gw_mac[2] = 0xbb;
	gw_mac[3] = 0xcc;
	gw_mac[4] = 0xdd;
	gw_mac[5] = 0xef;

	dev = __dev_get_by_name(&init_net, name);
	if (dev)
		return -EBUSY;

	dev = alloc_netdev(0, name, term_dev_setup);
//	dev = alloc_netdev(sizeof(struct tun_struct), name, term_dev_setup);

	if (!dev)
		return -ENOMEM;

	dev_net_set(dev, &init_net);
	dev->rtnl_link_ops = &term_link_ops;

	term_dev_net_init(dev);

	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features = dev->hw_features;
	dev->vlan_features = dev->features;

	rtnl_lock();
	err = register_netdevice(dev);
	rtnl_unlock();
	if (err < 0)
		goto err_free_netdev;

//	if (device_create_file(&tun->dev->dev, &dev_attr_tun_flags) ||
//	    device_create_file(&tun->dev->dev, &dev_attr_owner) ||
//	    device_create_file(&tun->dev->dev, &dev_attr_group))
//	    pr_err("Failed to create tun sysfs files\n");
//	}

	rtnl_lock();
	err = dev_open(dev);
	rtnl_unlock();
	if (err)
		goto err_dev_unregister;

	netif_carrier_on(dev);

//        if (netif_running(dev))
//		netif_tx_wake_all_queues(dev);

	/* Устанавливаем оновоной указатель на созданное устройство */
	term_dev_world = dev;

	/* Устанавливаем IP адрес на созданное устройство. */
	term_ip_add(up1_ip, up1_mk);

	/* Указываем MAC-адрес виртуального шлюза. */
	n = __neigh_lookup(&arp_tbl, &gw_ip, dev, 1);
	if (n) {
		neigh_update(n, gw_mac, NUD_PERMANENT, NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE);
		neigh_release(n);
	}

	return 0;

err_dev_unregister:
	unregister_netdevice(dev);
err_free_netdev:
	free_netdev(dev);
	return err;
}
//-----------------------------------------------------------------------------
void term_dev_destroy (void) {
	struct net_device *dev;
	const char * name = "IPoE";

	dev = __dev_get_by_name(&init_net, name);
	if (dev) {
		if (netif_carrier_ok(dev))
			netif_carrier_off(dev);
		rtnl_lock();
		dev_close(dev);
		unregister_netdevice(dev);
		rtnl_unlock();
		free_netdev(dev);
	}

	return;
}
//-----------------------------------------------------------------------------

