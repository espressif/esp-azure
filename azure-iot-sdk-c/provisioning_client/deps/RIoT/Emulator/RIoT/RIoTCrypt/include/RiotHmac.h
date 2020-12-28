#ifndef _RIOT_CRYPTO_SHA2_H
#define _RIOT_CRYPTO_SHA2_H
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT).
//
#include "RiotTarget.h"
#include "RiotStatus.h"
#include "RiotSha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HMAC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define HMAC_SHA256_BLOCK_LENGTH  64

typedef struct _RIOT_HMAC_SHA256_CTX {
    RIOT_SHA256_CONTEXT hashCtx;
    uint8_t opad[HMAC_SHA256_BLOCK_LENGTH];
} RIOT_HMAC_SHA256_CTX;

//
// Initialize the HMAC context
// @param ctx the HMAC context
// @param key the key
// @param keyLen the length of the key
//
void RIOT_HMAC_SHA256_Init(RIOT_HMAC_SHA256_CTX *ctx, const uint8_t *key, size_t keyLen);

//
// Update the hash with data
// @param ctx the HMAC context
// @param data the data
// @param dataLen the length of the data
// @return
//
void RIOT_HMAC_SHA256_Update(RIOT_HMAC_SHA256_CTX *ctx, const uint8_t *data, size_t dataLen);

//
// Retrieve the final digest for the HMAC
// @param ctx the HMAC context
// @param digest the buffer to hold the digest.  Must be of size SHA256_DIGEST_LENGTH
//
void RIOT_HMAC_SHA256_Final(RIOT_HMAC_SHA256_CTX *ctx, uint8_t *digest);

#ifdef __cplusplus
}
#endif
#endif
