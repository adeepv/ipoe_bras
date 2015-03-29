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
inline struct sk_buff *term_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci) {
	struct vlan_ethhdr *veth;

	if (skb_cow_head(skb, VLAN_HLEN) < 0) {
		kfree_skb(skb);
		return NULL;
	}

	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
	skb->mac_header -= VLAN_HLEN;

	/* first, the ethernet type */
	veth->h_vlan_proto = vlan_proto;

	/* now, the TCI */
	veth->h_vlan_TCI = htons(vlan_tci);

	skb->protocol = htons(ETH_P_8021Q);

	return skb;
}
//-----------------------------------------------------------------------------
struct sk_buff *term_vlan_untag(struct sk_buff *skb) {
	struct vlan_hdr *vhdr;
	u16 vlan_tci;

	if (unlikely(vlan_tx_tag_present(skb)))
		return skb;

	skb = skb_share_check(skb, GFP_ATOMIC);

	if (unlikely(!skb))
		return NULL;

	if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
		goto free;

	vhdr = (struct vlan_hdr *) skb->data;
	vlan_tci = ntohs(vhdr->h_vlan_TCI);
	skb->vlan_tci = VLAN_TAG_PRESENT | vlan_tci;
	skb_pull_rcsum(skb, VLAN_HLEN);
	skb->protocol = vhdr->h_vlan_encapsulated_proto;

	if (unlikely(skb_cow(skb, skb_headroom(skb)) < 0))
		goto free;

	memmove(skb->data - ETH_HLEN, skb->data - VLAN_ETH_HLEN, 2 * ETH_ALEN);
	skb->mac_header += VLAN_HLEN;

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);
	return skb;

free:
	kfree_skb(skb);
	return NULL;
}
//-----------------------------------------------------------------------------
struct sk_buff * term_add_users_tag(struct sk_buff *skb, struct term_session *ts) {
	/* Inner tag - 8021Q 0x8100 */
	skb = term_vlan_insert_tag(skb, htons(ETH_P_8021Q), ts->info.v & VLAN_VID_MASK);

	if (unlikely(!skb))
		return NULL;

	/* Outer tag - QinQ 0x8100 */
	skb = term_vlan_insert_tag(skb, htons(ETH_P_8021Q), ts->info.q & VLAN_VID_MASK);

	if (unlikely(!skb))
		return NULL;

	return skb;
}
//-----------------------------------------------------------------------------
