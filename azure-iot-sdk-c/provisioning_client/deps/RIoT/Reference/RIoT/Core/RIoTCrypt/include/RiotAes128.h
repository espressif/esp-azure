#ifndef _RIOT_CRYPTO_AES128_H
#define _RIOT_CRYPTO_AES128_H
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

//
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT)
//
#include "RiotTarget.h"
#include "RiotStatus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define     AES_CTR_MODE    YES
#define     AES_CBC_MODE    NO
#define     AES_ECB_MODE    YES

#define AES128_ENCRYPT_SCHEDULE_LEN 48

#define AES_BLOCK_SIZE  16

typedef uint32_t aes128EncryptKey_t[AES128_ENCRYPT_SCHEDULE_LEN];

//
// Enable AES allocating any resources required
//
// @param key  The key in case this is required
//
void RIOT_AES128_Enable(const uint8_t *key, aes128EncryptKey_t *aes128EncryptKey);

//
// Disable AES freeing any resources that were allocated
//
void RIOT_AES128_Disable(aes128EncryptKey_t *aes128EncryptKey);

//
// AES counter mode encryption/decryption. Note that in
// CTR mode encryption is its own inverse. This function uses the key
// schedule created by RIOT_AES128_Enable()
//
// @param in   The data to encrypt
// @param out  The encrypted data
// @param len  The length of the input data, must be multiple of 16
// @param ctr  Pointer to a 16 uint8_t counter block
//
void RIOT_AES_CTR_128(const aes128EncryptKey_t *aes128EncryptKey, const uint8_t *in,
                      uint8_t *out, uint32_t len, uint8_t *ctr);

void RIOT_AES_CBC_128_ENCRYPT(const aes128EncryptKey_t *aes128EncryptKey,
                              const uint8_t *in, uint8_t *out, uint32_t len,
                              uint8_t *iv);

void RIOT_AES_ECB_128_ENCRYPT(const aes128EncryptKey_t *aes128EncryptKey,
                              const uint8_t *in, uint8_t *out, size_t size);


#ifdef __cplusplus
}
#endif
#endif
