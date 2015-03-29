/*
 * Author     :  Paul Kocher
 * E-mail     :  pck@netcom.com
 * Date       :  1997
 * Description:  C implementation of the Blowfish algorithm.
 */

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

#define MAXKEYBYTES 56          /* 448 bits */

typedef struct {
  uint32_t P[16 + 2];
  uint32_t S[4][256];
} BLOWFISH_CTX;

extern void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
extern void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
extern void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);

#endif

