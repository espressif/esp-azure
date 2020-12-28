#ifndef _RIOT_CRYPTO_KDF_SHA256_H_
#define _RIOT_CRYPTO_KDF_SHA256_H_
/******************************************************************************
* Copyright (c) 2013, AllSeen Alliance. All rights reserved.
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

#include "RiotHmac.h"

#ifdef __cplusplus
extern "C" {
#endif

// *
// Create the fixed content for a KDF
// @param fixed  buffer to receive the fixed content
// @param fixedSize  indicates the available space in fixed
// @param label the label parameter (optional)
// @param labelSize
// @param context the context value (optional)
// @param contextSize
// @param numberOfBits the number of bits to be produced
//
size_t RIOT_KDF_FIXED(
    uint8_t         *fixed,
    size_t          fixedSize,
    const uint8_t   *label,
    size_t          labelSize,
    const uint8_t   *context,
    size_t          contextSize,
    uint32_t        numberOfBits
);

//
// Do KDF from SP800-108 -- HMAC based counter mode. This function does a single
// iteration
// @param out the output digest of a single iteration (a SHA256 digest)
// @param key the HMAC key
// @param keySize
// @param counter the running counter value (may be NULL)
// @param fixed the label parameter (optional)
// @param fixedSize
//
void RIOT_KDF_SHA256(
    uint8_t         *out,
    const uint8_t   *key,
    size_t          keySize,
    uint32_t        *counter,
    const uint8_t   *fixed,
    size_t          fixedSize
);

#ifdef __cplusplus
}
#endif
#endif
