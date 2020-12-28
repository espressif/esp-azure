/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/

//
// This source implements the interface between the RIoT framework and
// its cryptographic functions.
//

#ifndef _RIOT_CRYPTO_H
#define _RIOT_CRYPTO_H

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
#include <stdbool.h>
#include "RiotSha256.h"
#include "RiotAes128.h"
#include "RiotHmac.h"
#include "RiotKdf.h"
#include "RiotEcc.h"
#include "RiotBase64.h"

// Size, in bytes, of a RIoT digest using the chosen hash algorithm.
#define RIOT_DIGEST_LENGTH      SHA256_DIGEST_LENGTH

// Size, in bytes, of a RIoT HMAC.
#define RIOT_HMAC_LENGTH        RIOT_DIGEST_LENGTH

// Size, in bytes, of internal keys used by the RIoT framework.
// NOTE:    This number of bytes is used for key derivation.
#define RIOT_KEY_LENGTH         RIOT_DIGEST_LENGTH

// Number of bits in internal symmetric keys used by the RIoT framework.
// NOTE:    This number of bits is used for key derivation. The symmetric
//          algorithm implemenbted by the RIoT framework may use only a
//          subset of these bytes for encryption.
#define RIOT_KEY_BITS           (RIOT_KEY_LENGTH * 8)

// Number of bytes in symmetric encryption keys used by the RIoT framework.
// This number also includes IV/Counter bytes.
#define RIOT_SYM_KEY_LENGTH             (16 + 16)

// Size, in bytes, of encoded RIoT Key length
#define RIOT_ENCODED_BUFFER_MAX         (0x80)

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_CONTEXT_LENGTH     RIOT_DIGEST_LENGTH

// Maximal number of bytes in a label/context passed to the RIoT KDF routine.
#define RIOT_MAX_KDF_LABEL_LENGTH       RIOT_DIGEST_LENGTH

// Maximal number of bytes in a RIOT_AIK certificate
#define RIOT_MAX_CERT_LENGTH        2048

typedef ecc_publickey           RIOT_ECC_PUBLIC;
typedef ecc_privatekey          RIOT_ECC_PRIVATE;
typedef ecc_signature           RIOT_ECC_SIGNATURE;

typedef enum {
    RIOT_ENCRYPT,
    RIOT_DECRYPT
} RIOT_CRYPT_OP_TYPE;

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
    RIOT_ECC_PUBLIC    *publicPart,     // OUT: TODO
    RIOT_ECC_PRIVATE   *privatePart,    // OUT: TODO
    const void         *srcData,        // IN:  TODO
    size_t              srcDataSize,    // IN:  TODO
    const uint8_t      *label,          // IN:  TODO
    size_t              labelSize       // IN:  TODO
);

void
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a,     // IN:  TODO
    uint8_t             *b,     // OUT: TODO
    uint32_t            *s      // OUT: TODO
);

RIOT_STATUS
RiotCrypt_Sign(
    RIOT_ECC_SIGNATURE     *sig,        // OUT: TODO
    const void             *data,       // IN:  TODO
    size_t                  dataSize,   // IN:  TODO
    const RIOT_ECC_PRIVATE *key         // IN:  TODO
);

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig,            // OUT: TODO
    const uint8_t          *digest,         // IN:  TODO
    size_t                  digestSize,     // IN:  TODO
    const RIOT_ECC_PRIVATE *key             // IN:  TODO
);

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data,       // IN: TODO
    size_t                      dataSize,   // IN: TODO
    const RIOT_ECC_SIGNATURE   *sig,        // IN: TODO
    const RIOT_ECC_PUBLIC      *key         // IN: TODO
);

RIOT_STATUS
RiotCrypt_VerifyDigest(
    const uint8_t              *digest,     // IN: TODO
    size_t                      digestSize, // IN: TODO
    const RIOT_ECC_SIGNATURE   *sig,        // IN: TODO
    const RIOT_ECC_PUBLIC      *key         // IN: TODO
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

#endif
