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
#include "RiotHmac.h"

void
RIOT_HMAC_SHA256_Init(
    RIOT_HMAC_SHA256_CTX *ctx,
    const uint8_t *key,
    size_t keyLen
)
{
    size_t cnt;

    assert(ctx && key);

    // if keyLen > 64, hash it and use it as key
    if (keyLen > HMAC_SHA256_BLOCK_LENGTH) {
        RIOT_SHA256_Block_ctx(&ctx->hashCtx, key, keyLen, ctx->opad);
        keyLen = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(ctx->opad, key, keyLen);
    }
    //
    // the HMAC_SHA256 process
    //
    // SHA256((K XOR opad) || SHA256((K XOR ipad) || msg))
    //
    // K is the key
    // ipad is filled with 0x36
    // opad is filled with 0x5c
    // msg is the message
    //

    //
    // prepare inner hash SHA256((K XOR ipad) || msg)
    // K XOR ipad
    //
    for (cnt = 0; cnt < keyLen; cnt++) {
        ctx->opad[cnt] ^= 0x36;
    }
    memset(&ctx->opad[keyLen], 0x36, sizeof(ctx->opad) - keyLen);

    RIOT_SHA256_Init(&ctx->hashCtx);
    RIOT_SHA256_Update(&ctx->hashCtx, ctx->opad, HMAC_SHA256_BLOCK_LENGTH);

    // Turn ipad into opad
    for (cnt = 0; cnt < sizeof(ctx->opad); cnt++) {
        ctx->opad[cnt] ^= (0x5c ^ 0x36);
    }
}

void
RIOT_HMAC_SHA256_Update(
    RIOT_HMAC_SHA256_CTX *ctx,
    const uint8_t *data,
    size_t dataLen
)
{
    RIOT_SHA256_Update(&ctx->hashCtx, data, dataLen);
    return;
}

void
RIOT_HMAC_SHA256_Final(
    RIOT_HMAC_SHA256_CTX *ctx,
    uint8_t *digest
)
{
    // complete inner hash SHA256(K XOR ipad, msg)
    RIOT_SHA256_Final(&ctx->hashCtx, digest);

    // perform outer hash SHA256(K XOR opad, SHA256(K XOR ipad, msg))
    RIOT_SHA256_Init(&ctx->hashCtx);
    RIOT_SHA256_Update(&ctx->hashCtx, ctx->opad, HMAC_SHA256_BLOCK_LENGTH);
    RIOT_SHA256_Update(&ctx->hashCtx, digest, SHA256_DIGEST_LENGTH);
    RIOT_SHA256_Final(&ctx->hashCtx, digest);
    return;
}

