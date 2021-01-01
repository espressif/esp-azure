/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

//
// This source implements the interface between the RIoT framework and
// its cryptographic functions.
//

#ifndef _RIOT_CRYPTO_H
#define _RIOT_CRYPTO_H
#ifdef __cplusplus
extern "C" {
#endif

//
// As the RIoT framework is minimalistic, it will normally support only one
// flavor of each cryptographic operation, i.e., one key strength, one digest
// size, etc.
//
// Macro definitions and typedefs in this header provide the level of
// indirection to allow changing cryptographic primitives, parameters,
// and/or underlying crypto libraries with no or minimal impact on the
// reference code.
//

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <RiotStatus.h>

// Definitions

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(X)       (void)(X)
#endif

// AES
#define RIOT_AES_KEYBITS                128
#define RIOT_AES_KEYBYTES               ((RIOT_AES_KEYBITS) >> 3)
#define RIOT_NCTR_LENGTH                RIOT_AES_KEYBYTES
#define RIOT_SYM_KEY_LENGTH             (RIOT_AES_KEYBYTES + (RIOT_NCTR_LENGTH))

// Digest alg and sizes, in bytes, (not defined by mbed-crypto)
#define RIOT_DIGEST_ALG                 MBEDTLS_MD_SHA256
#define SHA1_DIGEST_LENGTH              0x14
#define SHA256_DIGEST_LENGTH            0x20

// Size, in bytes, of a RIoT digest using the chosen hash algorithm.
#define RIOT_DIGEST_LENGTH              SHA256_DIGEST_LENGTH

// Size, in bytes, of a RIoT HMAC.
#define RIOT_HMAC_LENGTH                RIOT_DIGEST_LENGTH

// Size, in bytes, of encoded RIoT Key length
#define RIOT_ENCODED_BUFFER_MAX         (0x80)

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_CONTEXT_LENGTH     RIOT_DIGEST_LENGTH

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_LABEL_LENGTH       RIOT_DIGEST_LENGTH

// Maximal number of bytes in a RIOT_AIK certificate
#define RIOT_MAX_CERT_LENGTH            2048

// ECC typedefs
typedef mbedtls_ecp_point               RIOT_ECC_PUBLIC;
typedef mbedtls_mpi                     RIOT_ECC_PRIVATE;
typedef struct {
    mbedtls_mpi r;
    mbedtls_mpi s;
} RIOT_ECC_SIGNATURE;

// Enable ECDH and define maximum encoding lengths for MPIs.
#define RIOT_ECDH
#define RIOT_MAX_EBLEN                  MBEDTLS_MPI_MAX_SIZE

// Select a supported curve if one wasn't chosen in the build
#if !defined(RIOTSECP256R1) && !defined(RIOTSECP384R1) && !defined(RIOTSECP521R1)
//#define RIOTSECP256R1
#define RIOTSECP384R1
//#define RIOTSECP521R1
#endif

// Any one of the following curves are supported (see config.h):
//      #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
//      #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
//      #define MBEDTLS_ECP_DP_SECP521R1_ENABLED
// Note that to further reduce code size, consider removing (commenting)
// all but the MBEDTLS_ECP_DP_xx symbol coresponding to the selected
// RIOT_SECPxx curve in config.h.
#if defined(RIOTSECP256R1)
#define RIOT_ECP_GRPID                  MBEDTLS_ECP_DP_SECP256R1
#define RIOT_COORDMAX                   0x20 // Max we expect to see
#elif defined(RIOTSECP384R1)
#define RIOT_ECP_GRPID                  MBEDTLS_ECP_DP_SECP384R1
#define RIOT_COORDMAX                   0x30 // Max we expect to see
#elif defined(RIOTSECP521R1)
#define RIOT_ECP_GRPID                  MBEDTLS_ECP_DP_SECP521R1
#define RIOT_COORDMAX                   0x42 // Max we expect to see
#else
#error "Must define one of RIOTSECP256R1, RIOTSECP384R1, RIOTSECP521R1"
#endif

// Prototypes

RIOT_STATUS
RiotCrypt_SeedDRBG(
    const uint8_t       *bytes,     // IN: Pointer to byte buffer for DRBG Seed
    size_t               size,      // IN: Size of buffer in bytes
    const unsigned char *label,     // IN: Label (personalization string)
    size_t               labelSize  // IN: Label length in bytes
);

RIOT_STATUS
RiotCrypt_Random(
    unsigned char  *output,         // OUT: Buffer to receive random bytes
    size_t          length          // IN:  Number of requested bytes
);

RIOT_STATUS
RiotCrypt_Kdf(
    uint8_t        *result,         // OUT: Buffer to receive the derived bytes
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const uint8_t  *source,         // IN:  Initial data for derivation
    size_t          sourceSize,     // IN:  Size of the source data in bytes
    const uint8_t  *context,        // IN:  Derivation context (may be NULL)
    size_t          contextSize,    // IN:  Size of the context in bytes
    const uint8_t  *label,          // IN:  Label for derivation (may be NULL)
    size_t          labelSize,      // IN:  Size of the label in bytes
    uint32_t        bytesToDerive   // IN:  Number of bytes to be produced
);

RIOT_STATUS
RiotCrypt_Hash(
    uint8_t        *result,         // OUT: Buffer to receive the digest
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to hash
    size_t          dataSize        // IN:  Data size in bytes
);

RIOT_STATUS
RiotCrypt_Hash2(
    uint8_t        *result,         // OUT: Buffer to receive the digest
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const void     *data1,          // IN:  1st operand to hash
    size_t          data1Size,      // IN:  1st operand size in bytes
    const void     *data2,          // IN:  2nd operand to hash
    size_t          data2Size       // IN:  2nd operand size in bytes
);

RIOT_STATUS
RiotCrypt_Hmac(
    uint8_t        *result,         // OUT: Buffer to receive the HMAC
    size_t          resultCapacity, // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to HMAC
    size_t          dataSize,       // IN:  Data size in bytes
    const uint8_t  *key,            // IN:  HMAK key
    size_t          keySize         // IN:  HMAC key size in bytes
);

RIOT_STATUS
RiotCrypt_Hmac2(
    uint8_t        *result,         // OUT: Buffer to receive the HMAK
    size_t          resultCapacity, // IN:  Capacity of the result buffer
    const void     *data1,          // IN:  1st operand to HMAC
    size_t          data1Size,      // IN:  1st operand size in bytes
    const void     *data2,          // IN:  2nd operand to HMAC
    size_t          data2Size,      // IN:  2nd operand size in bytes
    const uint8_t  *key,            // IN:  HMAK key
    size_t          keySize         // IN:  HMAC key size in bytes
);

RIOT_STATUS
RiotCrypt_DeriveEccKey(
    RIOT_ECC_PUBLIC    *publicPart,     // OUT: Derived public key
    RIOT_ECC_PRIVATE   *privatePart,    // OUT: Derived private key
    const void         *srcData,        // IN:  Initial data for derivation
    size_t              srcDataSize,    // IN:  Size of the source data in bytes
    const uint8_t      *label,          // IN:  Label for derivation (may be NULL)
    size_t              labelSize       // IN:  Size of the label in bytes
);

int
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a,     // IN:  ECC Public Key to export
    uint8_t             *b,     // OUT: Buffer to receive the public key
    uint32_t            *s      // OUT: Pointer to receive the buffer size (may be NULL)
);

RIOT_STATUS
RiotCrypt_Sign(
    RIOT_ECC_SIGNATURE     *sig,        // OUT: Signature of data
    const void             *data,       // IN:  Data to sign
    size_t                  dataSize,   // IN:  Data size in bytes
    const RIOT_ECC_PRIVATE *key         // IN:  Signing key
);

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig,            // OUT: Signature of digest
    const uint8_t          *digest,         // IN:  Digest to sign
    size_t                  digestSize,     // IN:  Size of the digest in bytes
    const RIOT_ECC_PRIVATE *key             // IN:  Signing key
);

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data,       // IN: Data to verify signature of
    size_t                      dataSize,   // IN: Size of data in bytes
    const RIOT_ECC_SIGNATURE   *sig,        // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key         // IN: ECC public key of signer
);

RIOT_STATUS
RiotCrypt_VerifyDigest(
    const uint8_t              *digest,     // IN: Digest to verify signature of
    size_t                      digestSize, // IN: Size of the digest
    const RIOT_ECC_SIGNATURE   *sig,        // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key         // IN: ECC public key of signer
);

RIOT_STATUS
RiotCrypt_EccEncrypt(
    uint8_t                *result,         // OUT: Buffer to receive encrypted data
    size_t                  resultCapacity, // IN:  Capacity of the result buffer
    RIOT_ECC_PUBLIC        *ephKey,         // OUT: Ephemeral key to produce
    const void             *data,           // IN:  Data to encrypt
    size_t                  dataSize,       // IN:  Data size in bytes
    const RIOT_ECC_PUBLIC  *key             // IN:  Encryption key
);

RIOT_STATUS
RiotCrypt_EccDecrypt(
    uint8_t                *result,         // OUT: Buffer to receive decrypted data
    size_t                  resultCapacity, // IN:  Capacity of the result buffer
    const void             *data,           // IN:  Data to decrypt
    size_t                  dataSize,       // IN:  Data size in bytes
    RIOT_ECC_PUBLIC        *ephKey,         // IN:  Ephemeral key to produce
    const RIOT_ECC_PRIVATE *key             // IN:  Decryption key
);

RIOT_STATUS
RiotCrypt_SymEncryptDecrypt(
    void       *outData,                  // OUT: Output data
    size_t      outSize,                  // IN:  Size of output data
    const void *inData,                   // IN:  Input data
    size_t      inSize,                   // IN:  Size of input data
    uint8_t     key[RIOT_SYM_KEY_LENGTH]  // IN/OUT: Symmetric key & IV
);

#ifdef __cplusplus
}
#endif
#endif
