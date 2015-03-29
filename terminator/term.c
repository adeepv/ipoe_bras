//-----------------------------------------------------------------------------
#include <linux/module.h>
#include <linux/if_ether.h> // ETH_P_ALL
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <linux/workqueue.h>
#include <linux/ip.h>
//-----------------------------------------------------------------------------
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Svarovskiy A. N. aka VVSina <VVSina@gmail.com>");
MODULE_DESCRIPTION("Term: Linux QinQ IPoE Terminator");
//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
spinlock_t term_lock;
spinlock_t term_event_lock;

/* ��������� ����������� ������� ����� ������� ������������� ������ */
struct net_device *term_in_dev = NULL;
struct net_device *term_dev_world = NULL;

/* ������� */
struct hlist_head subnet_list;

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//
//                           MAIN MODULE REGISTER
//
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static int __init term_init(void) {

	spin_lock_init(&term_lock);
	spin_lock_init(&term_event_lock);

	/* �������� ������� ����� ������� ������������� ������ */
	term_in_dev = dev_get_by_name(&init_net, "enp11s0f0"); // users
	if (!term_in_dev) {
		printk(KERN_INFO "term: can't find device\n");
		goto out;
	}

	// SUBNET
	INIT_HLIST_HEAD(&subnet_list);

	if (term_dev_create()) {
		printk(KERN_INFO "term: can't create virtual device\n");
		goto dev_err;
	}

	/* �������� ������ ��� ������ ������.*/
	if (term_sessions_init())
		goto sessions_err;

	/* ������������ ����� ������. */
	if (term_white_init())
		goto white_err;

	/* ������������ Netlink ����� */
	if (term_netlink_init())
		goto netlink_err;

	/* �������������� � proc */
	if (term_proc_init())
		goto proc_err;

	/* ������������ ���������� ������ */
	if (term_work_init())
		goto work_err;

	/* �������� �������������. */
//	if (term_sync_init())
//		goto sync_err;

	/* �������� bridge �� ����������� �����.*/
	if (term_mbr_init())
		goto mbr_err;

	/* ������ � ������������ ������ */
	rtnl_lock();

	call_netdevice_notifiers(NETDEV_JOIN, term_in_dev);

	if (netdev_master_upper_dev_link(term_in_dev, term_dev_world)) {
		rtnl_unlock();
		goto dev_master_err;
	}

	if (netdev_rx_handler_register(term_in_dev, &term_user_input, NULL)) {
		rtnl_unlock();
		printk(KERN_INFO "term: can't register rx handler by dev %s\n",term_in_dev->name);
		goto rx_hanler_err;
	}

	if (dev_set_promiscuity(term_in_dev, 1)) {
		printk(KERN_INFO "term: can't set promisc mode on dev %s\n",term_in_dev->name);
		goto promisc_err;
	}

	dev_disable_lro(term_in_dev);

	dev_set_mtu(term_in_dev, 1526);

	/* ������� �� ������������ ������ */
	rtnl_unlock();

	printk(KERN_INFO "term: loaded\n");

	return 0;

promisc_err:
	dev_set_promiscuity(term_in_dev, -1);
rx_hanler_err:
	netdev_upper_dev_unlink(term_in_dev, term_dev_world);
dev_master_err:
	term_mbr_destroy();
mbr_err:
//	term_sync_destroy();
//sync_err:
	term_work_destroy();
work_err:
	term_proc_cleanup();
proc_err:
	term_netlink_destroy();
netlink_err:
	term_white_destroy();
white_err:
	term_sessions_destroy();
sessions_err:
	term_dev_destroy();
dev_err:


out:
	return -1;
}
//-----------------------------------------------------------------------------
static void __exit term_exit(void) {
	struct term_subnet * sb;
	struct hlist_node * t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct hlist_node * n;
#endif

	/* ������ � ������������ ������ */
	rtnl_lock();

	dev_set_promiscuity(term_in_dev, -1);

	/* ���������� ���������� */
	netdev_rx_handler_unregister(term_in_dev);

	netdev_upper_dev_unlink(term_in_dev, term_dev_world);

	dev_set_mtu(term_in_dev, 1500);

	/* ������� �� ������������ ������ */
	rtnl_unlock();

	/* ���������� ���������� ��������� �������. */
	rcu_barrier();

	/* ��������� bridge �� ����������� �����.*/
	term_mbr_destroy();

	/* ��������� �������������. */
//	term_sync_destroy();

	/* �������� ���������� ������. */
	term_work_destroy();

	/* ������� proc. */
	term_proc_cleanup();

	/* ����������� Netlink ����� */
	term_netlink_destroy();

	/* ������� ����� ������. */
	term_white_destroy();

	/* ������� ������ ������. */
	term_sessions_destroy();

	/* ������� ����������� ���������� */
	term_dev_destroy();

	synchronize_rcu();

	spin_lock_bh(&term_lock);

	/* ������� ������ �������� */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	hlist_for_each_entry_safe(sb, t, n, &subnet_list, index)
#else
	hlist_for_each_entry_safe(sb, t, &subnet_list, index)
#endif
	{
		hlist_del(&sb->index);
		kfree(sb);
	}

	spin_unlock_bh(&term_lock);

	printk(KERN_INFO "term: Unloaded\n");
}
//-----------------------------------------------------------------------------
module_init(term_init);
module_exit(term_exit);
//-----------------------------------------------------------------------------
