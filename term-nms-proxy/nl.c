//-----------------------------------------------------------------------------
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/netlink.h>
#include <memory.h>
#include <unistd.h>
//-----------------------------------------------------------------------------
#include "nl.h"
//-----------------------------------------------------------------------------
static struct msghdr msg;
static struct sockaddr_nl dst_addr;
static struct iovec iov;
static struct sockaddr_nl src_addr;
static int sock_fd; // netlink socket
static struct nlmsghdr *nlh; // netlink messages
//-----------------------------------------------------------------------------
int nl_init () {

	/* ������� Netlink �����, ��������� ����������� ��������� (NETLINK_ISG) */
	if ((sock_fd = socket(PF_NETLINK, SOCK_RAW, TERM_NETLINK_MAIN)) < 0) {
		printf("NL: socket failed. %s\n",strerror(errno));
		return -1;
	}

	/* ��������� � ������ ��� ������������� �������� � ��������� ����� � ������� */
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
		printf("INP: Bind failed. %s.\n", strerror(errno));
		return -1;
	}

	/* ��������� ����� ��� �������� ��������� ������ ���� */
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = 0; /* For Linux Kernel */
	dst_addr.nl_groups = 0; /* unicast */

	/* �������� ������ ��� ��������� netlink ��������� � ������������ ������ */
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct term_nl_event)));
	if (nlh == NULL) {
		printf("NL::NL No space avilable.\n");
		return -1;
	}

	/* ��������� ��������� netlink �������� */
	memset(nlh, 0, NLMSG_SPACE(sizeof(struct term_nl_event)));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct term_nl_event));
	nlh->nlmsg_pid = getpid(); // �����������
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NLMSG_DONE; // ��������� ���������. (������ ����������� ��� ���������� ��������� �� �����)
	nlh->nlmsg_seq = 0; // ���������� ����� ���������. (������������ ��� ��������� ����������)

	/* ��������� iovec ��� ��������� msghdr */
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	/* ��������� ���������: ���������, ���� ��������� � ��� ��������� */
	msg.msg_name = (void *)&dst_addr;
	msg.msg_namelen = sizeof(dst_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return 0;
}
//-----------------------------------------------------------------------------
void nl_destroy () {
	close(sock_fd);
};
//-----------------------------------------------------------------------------
int nl_send (struct term_nl_event * m) {

	int err;

	/* ���������� ������������ ������ */
	memcpy(NLMSG_DATA(nlh), m, sizeof(struct term_nl_event));

	/* ���������� ��������� ������ */
	err = sendmsg(sock_fd, &msg, 0);

	if (err == -1)
		syslog(LOG_ERR | LOG_LOCAL0,"INP:Send %s.", strerror(errno));

	return err;
}
//-----------------------------------------------------------------------------
