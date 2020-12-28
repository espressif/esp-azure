#ifndef _RIOT_CRYPTO_ECC_H
#define _RIOT_CRYPTO_ECC_H
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

#ifdef __cplusplus
extern "C" {
#endif

#define     ECDSA_SIGN      YES
#define     ECDSA_VERIFY    YES
#define     ECDH_IN         NO
#define     ECDH_OUT        YES

#if ECDSA_SIGN || ECDH_OUT
#define USES_EPHEMERAL      YES
#else
#define USES_EPHEMERAL      NO
#endif

#define BIGLEN 9
//
// For P256 bigval_t types hold 288-bit 2's complement numbers (9
// 32-bit words).  For P192 they hold 224-bit 2's complement numbers
// (7 32-bit words).
//
// The representation is little endian by word and native endian
// within each word.
// The least significant word of the value is in the 0th word and there is an
// extra word of zero at the top.
//
#define RIOT_ECC_PRIVATE_BYTES  (4 * (BIGLEN - 1))
#define RIOT_ECC_COORD_BYTES    RIOT_ECC_PRIVATE_BYTES
//
// 4 is in lieu of sizeof(uint32_t), so that the macro is usable in #if conditions
//
typedef struct {
    uint32_t data[BIGLEN];
} bigval_t;


typedef struct {
    bigval_t x;
    bigval_t y;
    uint32_t infinity;
} affine_point_t;

typedef struct {
    bigval_t r;
    bigval_t s;
} ECDSA_sig_t;

typedef bigval_t ecc_privatekey;
typedef affine_point_t ecc_publickey;
typedef affine_point_t ecc_secret;
typedef ECDSA_sig_t ecc_signature;

//
// Convert a number from big endian by uint8_t to bigval_t. If the
// size of the input number is larger than the initialization size
// of a bigval_t ((BIGLEN - 1) * 4), it will be quietly truncated.
//
// @param out  pointer to the bigval_t to be produced
// @param in   pointer to the big-endian value to convert
// @param inSize  number of bytes in the big-endian value
//
void
BigIntToBigVal(bigval_t *tgt, const void *in, size_t inSize);

//
// Convert a number from bigval_t to big endian by uint8_t.
// The conversion will stop after the first (BIGLEN - 1) words have been converted.
// The output size must be (BIGLEN = 1) * 4 bytes long.
//
// @param out  pointer to the big endian value to be produced
// @param in   pointer to the bigval_t to convert
//
void
BigValToBigInt(void *out, const bigval_t *tgt);

//
// Generates the Ephemeral Diffie-Hellman key pair.
//
// @param publicKey The output public key
// @param privateKey The output private key
//
// @return  - RIOT_SUCCESS if the key pair is successfully generated.
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateDHKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey);

//
// Generates the Diffie-Hellman share secret.
//
// @param peerPublicKey The peer's public key
// @param privateKey The private key
// @param secret The output share secret
//
// @return  - RIOT_SUCCESS if the share secret is successfully generated.
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateShareSecret(ecc_publickey *peerPublicKey,
                                     ecc_privatekey *privateKey,
                                     ecc_secret *secret);
//
// Generates the DSA key pair.
//
// @param publicKey The output public key
// @param privateKey The output private key
// @return  - RIOT_SUCCESS if the key pair is successfully generated
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateDSAKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey);

// *
// Derives a DSA key pair from the supplied value and label
//
// @param publicKey  OUT: public key
// @param privateKey OUT: output private key
// @param srcVal     IN: Source value for derivation
// @param label      IN: Label for derivation.
// @param labelSize  IN: Label size. Should not exceed RIOT_ECC_PRIVATE_bytes.
// @return  - RIOT_SUCCESS
//
RIOT_STATUS
RIOT_DeriveDsaKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey,
                      bigval_t *srcVal, const uint8_t *label, size_t labelSize);

//
// Sign a digest using the DSA key
// @param digest The digest to sign
// @param signingPrivateKey The signing private key
// @param sig The output signature
// @return  - RIOT_SUCCESS if the signing process succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSASignDigest(const uint8_t *digest, const ecc_privatekey *signingPrivateKey, ecc_signature *sig);

//
// Sign a buffer using the DSA key
// @param buf The buffer to sign
// @param len The buffer len
// @param signingPrivateKey The signing private key
// @param sig The output signature
// @return  - RIOT_SUCCESS if the signing process succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSASign(const uint8_t *buf, uint16_t len, const ecc_privatekey *signingPrivateKey, ecc_signature *sig);

//
// Verify DSA signature of a digest
// @param digest The digest to sign
// @param sig The signature
// @param pubKey The signing public key
// @return  - RIOT_SUCCESS if the signature verification succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSAVerifyDigest(const uint8_t *digest, const ecc_signature *sig, const ecc_publickey *pubKey);

//
// Verify DSA signature of a buffer
// @param buf The buffer to sign
// @param len The buffer len
// @param sig The signature
// @param pubKey The signing public key
// @return  - RIOT_SUCCESS if the signature verification succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSAVerify(const uint8_t *buf, uint16_t len, const ecc_signature *sig, const ecc_publickey *pubKey);

#ifdef __cplusplus
}
#endif

#endif
