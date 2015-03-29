
KDIR = /lib/modules/$(shell uname -r)/build

TARGET = termit

termit-objs := term.o term_arp.o term_dev.o term_dhcp.o term_input.o term_mgm_bridge.o \
		term_netlink.o term_proc.o term_send.o term_sessions.o term_stat.o \
		term_vlan.o term_white.o term_work.o

obj-m += $(TARGET).o

default:
	make -C $(KDIR) M=$(CURDIR) modules

install: | $(TARGET).ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

clean:
	make -C $(KDIR) M=$(CURDIR) clean
