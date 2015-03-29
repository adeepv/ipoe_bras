//-----------------------------------------------------------------------------
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <arpa/inet.h>
//-----------------------------------------------------------------------------
#include "nl.h"
#include "netunit.h"
//-----------------------------------------------------------------------------
#define DEBUG 1
//-----------------------------------------------------------------------------
int main () {

	int err;

	if (getuid()) {
		printf("You must be root. Exit.\n");
		exit(1);
	}

	if (chdir("/")!=0) //переходим на рут, чтоб не блокировать файловые системы
		syslog(LOG_ERR | LOG_LOCAL0,"chdir('/') return error");

	close(0); //так как демон ничего не собирается выводить на экран, то закрываем stdout, stdin, stderr
	close(1);
	close(2);
	int p;

	switch ((p=fork())) { //форкаемся
		case -1: // laja
			exit(1);
		break;
		case 0: // potomok
			setsid(); // отрываемся от управляющего терминала и переходим в фоновый режим
		break;
		default: // osn. proches
			exit(0);
		break;
	}

	err = nl_init();
	if (err) {
		printf("Err in create nl socket. Exit.\n");
		close(1);
	}

	const char * ts = "subnet\aGetTermList";
	const char * ti = "ip\aGetTermList";

	uint32_t ip;
	inet_aton("123.456.789.123",(struct in_addr*)&ip);
	nt_SetIP(ip);
	nt_SetPort(1234);
	nt_SetLogin("login");
	nt_SetPassword("passwd");

	while (1) {
		if (nt_Connect())
			continue;

		nt_Transact(ts);
		nt_Transact(ti);
		nt_Disconnect();
		sleep(30);
	}

	nl_destroy();

	exit(0);
}
//-----------------------------------------------------------------------------
