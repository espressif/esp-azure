/*(Copyright)

Microsoft Copyright 2017
Confidential Information

*/
#include "RiotCrypt.h"

#define RIOT_MAX_KDF_FIXED_SIZE     RIOT_MAX_KDF_CONTEXT_LENGTH + \
                                    RIOT_MAX_KDF_LABEL_LENGTH   + 5

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
    uint32_t        bytesToDerive   // IN:  Number of bytesto be produced
)
{
    uint8_t  fixed[RIOT_MAX_KDF_FIXED_SIZE];
    size_t   fixedSize = sizeof(fixed);
    uint32_t counter = 0;

    if (contextSize > RIOT_MAX_KDF_CONTEXT_LENGTH ||
        labelSize > RIOT_MAX_KDF_LABEL_LENGTH ||
        bytesToDerive > resultSize ||
        bytesToDerive % RIOT_KEY_LENGTH != 0) {
        return RIOT_INVALID_PARAMETER;
    }

    fixedSize = RIOT_KDF_FIXED(fixed, fixedSize, context, contextSize,
                               label, labelSize, bytesToDerive * 8);

    while (counter < (bytesToDerive / (RIOT_KEY_LENGTH))) {

        RIOT_KDF_SHA256(result + (counter * (RIOT_KEY_LENGTH)),
                        source, sourceSize, &counter,
                        fixed, fixedSize);
    }

    return RIOT_SUCCESS;
}

typedef RIOT_SHA256_CONTEXT     RIOT_HASH_CONTEXT;

#define RiotCrypt_HashInit      RIOT_SHA256_Init
#define RiotCrypt_HashUpdate    RIOT_SHA256_Update
#define RiotCrypt_HashFinal     RIOT_SHA256_Final

RIOT_STATUS
RiotCrypt_Hash(
    uint8_t        *result,         // OUT: Buffer to receive the digest
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to hash
    size_t          dataSize        // IN:  Data size in bytes
)
{
    RIOT_HASH_CONTEXT ctx;

    if (resultSize < RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    RiotCrypt_HashInit(&ctx);
    RiotCrypt_HashUpdate(&ctx, data, dataSize);
    RiotCrypt_HashFinal(&ctx, result);

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Hash2(
    uint8_t        *result,         // OUT: Buffer to receive the digest
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const void     *data1,          // IN:  1st operand to hash
    size_t          data1Size,      // IN:  1st operand size in bytes
    const void     *data2,          // IN:  2nd operand to hash
    size_t          data2Size       // IN:  2nd operand size in bytes
)
{
    RIOT_HASH_CONTEXT ctx;

    if (resultSize < RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    RiotCrypt_HashInit(&ctx);
    RiotCrypt_HashUpdate(&ctx, data1, data1Size);
    RiotCrypt_HashUpdate(&ctx, data2, data2Size);
    RiotCrypt_HashFinal(&ctx, result);

    return RIOT_SUCCESS;
}

typedef RIOT_HMAC_SHA256_CTX    RIOT_HMAC_CONTEXT;

#define RiotCrypt_HmacInit      RIOT_HMAC_SHA256_Init
#define RiotCrypt_HmacUpdate    RIOT_HMAC_SHA256_Update
#define RiotCrypt_HmacFinal     RIOT_HMAC_SHA256_Final

RIOT_STATUS
RiotCrypt_Hmac(
    uint8_t        *result,         // OUT: Buffer to receive the HMAC
    size_t          resultCapacity, // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to HMAC
    size_t          dataSize,       // IN:  Data size in bytes
    const uint8_t  *key,            // IN:  HMAK key
    size_t          keySize         // IN:  HMAC key size in bytes
)
{
    RIOT_HMAC_CONTEXT ctx;

    if (resultCapacity < RIOT_HMAC_LENGTH ||
        keySize != RIOT_HMAC_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    RiotCrypt_HmacInit(&ctx, key, keySize);
    RiotCrypt_HmacUpdate(&ctx, data, dataSize);
    RiotCrypt_HmacFinal(&ctx, result);

    return RIOT_SUCCESS;
}

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
)
{
    RIOT_HMAC_CONTEXT ctx;

    if (resultCapacity < RIOT_HMAC_LENGTH ||
        keySize != RIOT_HMAC_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    RiotCrypt_HmacInit(&ctx, key, keySize);
    RiotCrypt_HmacUpdate(&ctx, data1, data1Size);
    RiotCrypt_HmacUpdate(&ctx, data2, data2Size);
    RiotCrypt_HmacFinal(&ctx, result);

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_DeriveEccKey(
    RIOT_ECC_PUBLIC    *publicPart,     // OUT: TODO
    RIOT_ECC_PRIVATE   *privatePart,    // OUT: TODO
    const void         *srcData,        // IN:  TODO
    size_t              srcDataSize,    // IN:  TODO
    const uint8_t      *label,          // IN:  TODO
    size_t              labelSize       // IN:  TODO
)
{
    bigval_t    srcVal  = { 0 };
    bigval_t   *pSrcVal = NULL;

    if (srcDataSize > sizeof(bigval_t)) {
        return RIOT_INVALID_PARAMETER;
    }

    if (srcDataSize == sizeof(bigval_t)) {
        pSrcVal = (bigval_t *)srcData;
    } else {
        memcpy(&srcVal, srcData, srcDataSize);
        pSrcVal = &srcVal;
    }

    return RIOT_DeriveDsaKeyPair(publicPart, privatePart,
                                 pSrcVal, label, labelSize);
}

void
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a,     // IN:  TODO
    uint8_t             *b,     // OUT: TODO
    uint32_t            *s      // OUT: TODO
)
{
    *b++ = 0x04;
    BigValToBigInt(b, &a->x);
    b += RIOT_ECC_COORD_BYTES;
    BigValToBigInt(b, &a->y);
    if (s) {
        *s = 1 + 2 * RIOT_ECC_COORD_BYTES;
    }
}


RIOT_STATUS
RiotCrypt_Sign(
    RIOT_ECC_SIGNATURE     *sig,        // OUT: TODO
    const void             *data,       // IN:  TODO
    size_t                  dataSize,   // IN:  TODO
    const RIOT_ECC_PRIVATE *key         // IN:  TODO
)
{
    uint8_t digest[RIOT_DIGEST_LENGTH];

    RiotCrypt_Hash(digest, sizeof(digest), data, dataSize);

    return RIOT_DSASignDigest(digest, key, sig);
}

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig,            // OUT: TODO
    const uint8_t          *digest,         // IN:  TODO
    size_t                  digestSize,     // IN:  TODO
    const RIOT_ECC_PRIVATE *key             // IN:  TODO
)
{
    if (digestSize != RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    return RIOT_DSASignDigest(digest, key, sig);
}

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data,       // IN: TODO
    size_t                      dataSize,   // IN: TODO
    const RIOT_ECC_SIGNATURE   *sig,        // IN: TODO
    const RIOT_ECC_PUBLIC      *key         // IN: TODO
)
{
    uint8_t digest[RIOT_DIGEST_LENGTH];

    RiotCrypt_Hash(digest, sizeof(digest), data, dataSize);

    return RIOT_DSAVerifyDigest(digest, sig, key);
}

RIOT_STATUS
RiotCrypt_VerifyDigest(
    const uint8_t              *digest,     // IN: TODO
    size_t                      digestSize, // IN: TODO
    const RIOT_ECC_SIGNATURE   *sig,        // IN: TODO
    const RIOT_ECC_PUBLIC      *key         // IN: TODO
)
{
    if (digestSize != RIOT_DIGEST_LENGTH) {
        return RIOT_INVALID_PARAMETER;
    }

    return RIOT_DSAVerifyDigest(digest, sig, key);
}

#if USES_EPHEMERAL
#define RIOT_LABEL_EXCHANGE     "Exchange"
RIOT_STATUS
RiotCrypt_EccEncrypt(
    uint8_t                *result,         // OUT: Buffer to receive encrypted data
    size_t                  resultCapacity, // IN:  Capacity of the result buffer
    RIOT_ECC_PUBLIC        *ephKey,         // OUT: Ephemeral key to produce
    const void             *data,           // IN:  Data to encrypt
    size_t                  dataSize,       // IN:  Data size in bytes
    const RIOT_ECC_PUBLIC  *key             // IN:  Encryption key
)
{
    ecc_privatekey  ephPriv;
    ecc_secret      secret;
    uint8_t         exchKey[RIOT_KEY_LENGTH];
    RIOT_STATUS     status;

    status = RIOT_GenerateDHKeyPair(ephKey, &ephPriv);

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RIOT_GenerateShareSecret((RIOT_ECC_PUBLIC *)key, &ephPriv, &secret);

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_Kdf(exchKey, sizeof(exchKey),
                           (uint8_t *)&secret, sizeof(secret),
                           NULL, 0, (const uint8_t*)RIOT_LABEL_EXCHANGE,
                           (sizeof(RIOT_LABEL_EXCHANGE) - 1),
                           sizeof(exchKey));

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_SymEncryptDecrypt(result, resultCapacity,
                                         data, dataSize, exchKey);
    return status;
}

RIOT_STATUS
RiotCrypt_EccDecrypt(
    uint8_t                *result,         // OUT: Buffer to receive decrypted data
    size_t                  resultCapacity, // IN:  Capacity of the result buffer
    const void             *data,           // IN:  Data to decrypt
    size_t                  dataSize,       // IN:  Data size in bytes
    RIOT_ECC_PUBLIC        *ephKey,         // IN:  Ephemeral key to produce
    const RIOT_ECC_PRIVATE *key             // IN:  Decryption key
)
{
    ecc_secret      secret;
    uint8_t         exchKey[RIOT_KEY_LENGTH];
    RIOT_STATUS     status;

    status = RIOT_GenerateShareSecret(ephKey, (RIOT_ECC_PRIVATE *)key, &secret);

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_Kdf(exchKey, sizeof(exchKey),
                           (uint8_t *)&secret, sizeof(secret),
                           NULL, 0, (const uint8_t*)RIOT_LABEL_EXCHANGE,
                           (sizeof(RIOT_LABEL_EXCHANGE) - 1),
                           sizeof(exchKey));

    if (status != RIOT_SUCCESS) {
        return status;
    }

    status = RiotCrypt_SymEncryptDecrypt(result, resultCapacity,
                                         data, dataSize, exchKey);
    return status;
}
#endif

RIOT_STATUS
RiotCrypt_SymEncryptDecrypt(
    void       *outData,                  // OUT: Output data
    size_t      outSize,                  // IN:  Size of output data
    const void *inData,                   // IN:  Input data
    size_t      inSize,                   // IN:  Size of input data
    uint8_t     key[RIOT_SYM_KEY_LENGTH]  // IN/OUT: Symmetric key & IV
)
{
    uint8_t             *iv = key + 16;
    aes128EncryptKey_t  aesKey;

    if (outSize < inSize) {
        return RIOT_INVALID_PARAMETER;
    }

    RIOT_AES128_Enable(key, &aesKey);
    RIOT_AES_CTR_128((const aes128EncryptKey_t*) &aesKey, inData, outData, (uint32_t)inSize, iv);
    RIOT_AES128_Disable(&aesKey);

    return RIOT_SUCCESS;
}
