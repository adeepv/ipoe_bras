//-----------------------------------------------------------------------------
#ifndef NL_H
#define NL_H
//-----------------------------------------------------------------------------
#define TERM_NETLINK_MAIN       30
//-----------------------------------------------------------------------------
/* From Userspace to Kernel */
#define TERM_EVENT_SESSION           0x01
#define TERM_EVENT_SUBNET            0x02
//-----------------------------------------------------------------------------
#include <linux/netlink.h>
#include <linux/if_ether.h>
//-----------------------------------------------------------------------------
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
//-----------------------------------------------------------------------------
struct term_session_info {
	u16 q;                 /* 802.1AD vlan_id */
	u16 v;                 /* 802.1Q vlan_id */
	u32 ip;                /* User's IP-address */
	u8 mac[ETH_ALEN];      /* User's MAC-address */
	u8 lock;               /* Lock the user */
	u8 multiuser;		/* User binding to multiuser port */
	u32 pad1;
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
struct term_subnet {
	u32 sb;
	u32 mk;
	u32 bk;
	u32 gw;
	u32 ml;
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
struct term_nl_event {
	u32	type;
	u8	data[20];
} __attribute__ ((packed));
//-----------------------------------------------------------------------------
extern int nl_send (struct term_nl_event * m);
extern int nl_init(void);
extern void nl_destroy();
//-----------------------------------------------------------------------------
#endif
//-----------------------------------------------------------------------------
