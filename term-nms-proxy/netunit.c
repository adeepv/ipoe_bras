//---------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
//---------------------------------------------------------------------------
#include "netunit.h"
#include "base64.h"
#include "blowfish.h"
#include "nl.h"
//---------------------------------------------------------------------------
static uint32_t               ip;
static uint16_t               port;
static char                   login[32];
static char                   password[32];
static int                    outerSocket;
static struct sockaddr_in     outerAddr;
static struct sockaddr_in     localAddr;
static struct term_nl_event   ev;
//---------------------------------------------------------------------------
static void EnDecryptInit(const char * passwd, int len, BLOWFISH_CTX *ctx) {

	unsigned char * keyL;

	keyL = (unsigned char *)malloc(sizeof(char[len]));
	if (keyL == NULL)
		return;

	memset(keyL, 0, len);
	strncpy((char *)keyL, passwd, len);
	Blowfish_Init(ctx, keyL, len);
	free(keyL);
}
//-----------------------------------------------------------------------------
static uint32_t bytes2block(const char * c) {
	uint32_t t = (unsigned char)(*c++);
	t += (unsigned char)(*c++) << 8;
	t += (unsigned char)(*c++) << 16;
	t += (unsigned char)(*c) << 24;
	return t;
}
//-----------------------------------------------------------------------------
static void block2bytes(uint32_t t, char * c) {
 *c++ = t & 0x000000FF;
 *c++ = t >> 8 & 0x000000FF;
 *c++ = t >> 16 & 0x000000FF;
 *c = t >> 24 & 0x000000FF;
}
//-----------------------------------------------------------------------------
static void DecodeString(char * d, const char * s, BLOWFISH_CTX *ctx) {
 uint32_t a = bytes2block(s);
 uint32_t b = bytes2block(s + 4);
 Blowfish_Decrypt(ctx, &a, &b);
 block2bytes(a, d);
 block2bytes(b, d + 4);
}
//-----------------------------------------------------------------------------
static void EncodeString(char * d, const char * s, BLOWFISH_CTX *ctx) {
 uint32_t a = bytes2block(s);
 uint32_t b = bytes2block(s + 4);
 Blowfish_Encrypt(ctx, &a, &b);
 block2bytes(a, d);
 block2bytes(b, d + 4);
}
//-----------------------------------------------------------------------------
int nt_Connect() {
 outerSocket = socket(PF_INET, SOCK_STREAM, 0);
 if (outerSocket < 0) return 1;
 memset(&outerAddr, 0, sizeof(outerAddr));
 memset(&localAddr, 0, sizeof(localAddr));
 outerAddr.sin_family = AF_INET;
 outerAddr.sin_port = htons(port);
 outerAddr.sin_addr.s_addr = ip;
 if (connect(outerSocket, (struct sockaddr*)&outerAddr, sizeof(outerAddr)) < 0) {
  close(outerSocket);
  return 1;
 }
 return 0;
}
//---------------------------------------------------------------------------
static int TxHeader() {
 if (send(outerSocket, STG_HEADER, strlen(STG_HEADER), 0) <= 0) return 1;
 return 0;
}
//---------------------------------------------------------------------------
static int RxHeaderAnswer() {
 char buffer[sizeof(STG_HEADER)+1];
 if (recv(outerSocket, buffer, strlen(OK_HEADER), 0) <= 0) return 1;
 if (strncmp(OK_HEADER, buffer, strlen(OK_HEADER)) == 0) return 0;
 else return 1;
}
//---------------------------------------------------------------------------
static int TxLogin() {
 char loginZ[32];
 memset(loginZ, 0, 32);
 strncpy(loginZ, login, 32);
 if (send(outerSocket, loginZ, 32, 0) <= 0) return 1;
 return 0;
}
//---------------------------------------------------------------------------
static int RxLoginAnswer() {
 char buffer[sizeof(OK_LOGIN)+1];
 if (recv(outerSocket, buffer, strlen(OK_LOGIN), 0) <= 0) return 1;
 if (strncmp(OK_LOGIN, buffer, strlen(OK_LOGIN)) == 0) return 0;
 else return 1;
}
//---------------------------------------------------------------------------
static int TxLoginS() {
	int j;
	char loginZ[32];
	char ct[8];
	memset(loginZ, 0, 32);
	strncpy(loginZ, login, 32);
	BLOWFISH_CTX ctx;
	EnDecryptInit(password, 32, &ctx);

	for (j = 0; j < 4; j++) {
		EncodeString(ct, loginZ + j*8, &ctx);
		if (send(outerSocket, ct, 8, 0) <= 0)
			return 1;
	}

	return 0;
}
//---------------------------------------------------------------------------
static int RxLoginSAnswer() {
	char buffer[sizeof(OK_LOGINS)+1];

	if (recv(outerSocket, buffer, strlen(OK_LOGINS), 0) <= 0)
		return 1;

	if (strncmp(OK_LOGINS, buffer, strlen(OK_LOGINS)) == 0)
		return 0;
	else
		return 1;
}
//---------------------------------------------------------------------------
static int TxData(const char * get) {

 char encode[128] = {0};
 base64_encode(get,strlen(get),encode,sizeof(encode));

 char textZ[9];
 char ct[8];
 int j;
 int n = strlen(encode) / 8;
 int r = strlen(encode) % 8;
 BLOWFISH_CTX ctx;
 EnDecryptInit(password, 32, &ctx);
 for (j = 0; j < n; j++) {
  strncpy(textZ, encode + j*8, 8);
  EncodeString(ct, textZ, &ctx);
  if (send(outerSocket, ct, 8, 0) <= 0) return 1;
 }
 memset(textZ, 0, 8);
 if (r) strncpy(textZ, encode + j*8, 8);
 EnDecryptInit(password, 32, &ctx);
 EncodeString(ct, textZ, &ctx);
 if (send(outerSocket, ct, 8, 0) <= 0) return 1;
 return 0;
}
//---------------------------------------------------------------------------
static int RxDataAnswer() {
 int j, n = 0;
 char bufferS[8];
 char buffer[8 + 1];
 BLOWFISH_CTX ctx;
 EnDecryptInit(password, 32, &ctx);
 char res[256];
 char decode[256];
 int k = 0;
 while (1) {
  if (recv(outerSocket, &bufferS[n++], 1, 0) <= 0) return 1;
  if (n == 8) {
   n = 0;
   DecodeString(buffer, bufferS, &ctx);
   for (j = 0; j < 8; j++) {
    if (buffer[j] != 0 && buffer[j] != '\n') {
     res[k++] = buffer[j];
    } else {
     if (k==0) return 0;
     res[k++] = 0;
     base64_decode((unsigned char*)&res,k,(unsigned char *)decode); // разворачиваем упакованное в mod_econf
     memset(&ev,0,sizeof(struct term_nl_event));
     base64_decode((unsigned char*)decode,strlen(decode),(unsigned char*)&ev);
//#if DEBUG
//     if (ev.type == 1) {
//      struct term_session_info * sf = (struct term_session_info *) ev.data;
//      printf("%u q=%u v=%u ip=%u mac=%02x%02x.%02x%02x.%02x%02x lock=%u \n",ev.type,sf->q,sf->v,sf->ip,sf->mac[0],sf->mac[1],sf->mac[2],sf->mac[3],sf->mac[4],sf->mac[5],sf->lock);
//     }
//#endif
     k = 0;
     nl_send(&ev);
    }
   }
  }
 }
 return 0;
}
//---------------------------------------------------------------------------
void nt_SetLogin(const char * l) {
 strncpy(login, l, 32);
}
//---------------------------------------------------------------------------
void nt_SetPassword(const char * p) {
 strncpy(password, p, 32);
}
//---------------------------------------------------------------------------
void nt_SetIP(uint32_t i) {
 ip = i;
}
//---------------------------------------------------------------------------
void nt_SetPort(uint16_t p) {
 port=p;
}
//---------------------------------------------------------------------------
void nt_Disconnect() {
 close(outerSocket);
}
//-----------------------------------------------------------------------------
int nt_Transact(const char * get) {
 if (TxHeader())       return 1;
 if (RxHeaderAnswer()) return 1;
 if (TxLogin())        return 1;
 if (RxLoginAnswer())  return 1;
 if (TxLoginS())       return 1;
 if (RxLoginSAnswer()) return 1;
 if (TxData(get))      return 1;
 if (RxDataAnswer())   return 1;
 return 0;
}
//---------------------------------------------------------------------------
