/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <RiotCrypt.h>
#include <stdio.h>

#ifdef _MSC_VER
#pragma warning(disable : 4127) // conditional expressionn is constant
#pragma warning(disable : 4706) // assignment within conditional expression
#endif

// Obviously not thread safe...
static mbedtls_hmac_drbg_context hmac_drbg_ctx = { 0 };

static int
GetRandomBytes(
    void           *rngState,
    unsigned char  *output,
    size_t          length
)
{
    UNREFERENCED_PARAMETER(rngState);
    for (; length; length--)
        *output++ = (uint8_t)rand();

    return 0;
}

RIOT_STATUS
RiotCrypt_SeedDRBG(
    const uint8_t       *bytes,
    size_t               length,
    const unsigned char *label,
    size_t               labelSize
)
{
    const mbedtls_md_info_t *md_sha256;
    int status = RIOT_SUCCESS;
    unsigned int i, val;

    // Use entropy_len to determine if we need to re-init
    if (hmac_drbg_ctx.entropy_len)
    {
        mbedtls_hmac_drbg_free(&hmac_drbg_ctx);
    }

    // [Re-]Seed
    if (bytes)
    {
        val = 0;
        for (i = 0; i < length; i++) {
            val += ~(bytes[i]);
        }
        srand(~val);
    }

    // Init
    mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

    if(!(md_sha256 = mbedtls_md_info_from_type(RIOT_DIGEST_ALG)))
    {
        status = RIOT_INVALID_STATE;
        goto Cleanup;
    }

    if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha256, GetRandomBytes,
                               NULL, label, labelSize))
    {
        status = RIOT_FAILURE;
        goto Cleanup;
    }

Cleanup:
    if (status != RIOT_SUCCESS)
    {
        mbedtls_hmac_drbg_free(&hmac_drbg_ctx);
    }

    return status;
}

RIOT_STATUS
RiotCrypt_Random(
    unsigned char  *output,
    size_t          length
)
{
    mbedtls_hmac_drbg_random(&hmac_drbg_ctx, output, length);
    return RIOT_SUCCESS;
}

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
    const mbedtls_md_info_t *md_sha256;

    // Parameter validation
    if (!result || !source || (resultSize < bytesToDerive) || !sourceSize ||
       (!context && contextSize) || (!label && labelSize))
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Get md_info
    if (!(md_sha256 = mbedtls_md_info_from_type(RIOT_DIGEST_ALG)))
    {
        return RIOT_INVALID_STATE;
    }

    // We don't expect return on error from mbed-crypto so return general failure
    if (mbedtls_hkdf(md_sha256, context, contextSize, source, sourceSize,
                     label, labelSize, result, resultSize))
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Hash(
    uint8_t        *result,         // OUT: Buffer to receive the digest
    size_t          resultSize,     // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to hash
    size_t          dataSize        // IN:  Data size in bytes
)
{
    if (!(data)   || !(dataSize) ||
        !(result) || (resultSize < RIOT_DIGEST_LENGTH))
    {
        return RIOT_INVALID_PARAMETER;
    }

    // We do not expect to return on internal library error
    mbedtls_sha256_ret(data, dataSize, result, 0);

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
    mbedtls_sha256_context ctx;
    int status = RIOT_SUCCESS;

    // Validate parameters
    if (!(result) || !(data1) || !(data2) || !(data1Size) ||
        (resultSize < RIOT_DIGEST_LENGTH) || !(data2Size))
    {
        return RIOT_INVALID_PARAMETER;
    }

    mbedtls_sha256_init(&ctx);

    // We don't expect return on error from mbed-crypto so return general failure
    if ((status = mbedtls_sha256_starts_ret(&ctx, 0)))
    {
        goto Cleanup;
    }

    if ((status = mbedtls_sha256_update_ret(&ctx, data1, data1Size)))
    {
        goto Cleanup;
    }

    if ((status = mbedtls_sha256_update_ret(&ctx, data2, data2Size)))
    {
        goto Cleanup;
    }

    if ((status = mbedtls_sha256_finish_ret(&ctx, result)))
    {
        goto Cleanup;
    }

Cleanup:
    mbedtls_sha256_free(&ctx);

    if (status)
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Hmac(
    uint8_t        *result,         // OUT: Buffer to receive the HMAC
    size_t          resultCapacity, // IN:  Capacity of the result buffer
    const void     *data,           // IN:  Data to HMAC
    size_t          dataSize,       // IN:  Data size in bytes
    const uint8_t  *key,            // IN:  HMAC key
    size_t          keySize         // IN:  HMAC key size in bytes
)
{
    const mbedtls_md_info_t *md_sha256;

    // Parameter validation
    if (!result || !data || !key || !dataSize || !keySize ||
        (resultCapacity < RIOT_DIGEST_LENGTH))
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Get md_info
    if (!(md_sha256 = mbedtls_md_info_from_type(RIOT_DIGEST_ALG)))
    {
        return RIOT_INVALID_STATE;
    }

    // We don't expect return on error from mbed-crypto so return general failure
    if( mbedtls_md_hmac(md_sha256, key, keySize, data, dataSize, result))
    {
        return RIOT_FAILURE;
    }

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
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_sha256;
    int status;

    // Parameter validation
    if (!result || !data1 || !data2 || !key || !data1Size || !data2Size ||
        !keySize || (resultCapacity < RIOT_DIGEST_LENGTH))
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Get md_info
    if (!(md_sha256 = mbedtls_md_info_from_type(RIOT_DIGEST_ALG)))
    {
        return RIOT_INVALID_STATE;
    }

    mbedtls_md_init( &ctx );

    if ((status = mbedtls_md_setup(&ctx, md_sha256, 1)))
    {
        goto cleanup;
    }

    if ((status = mbedtls_md_hmac_starts( &ctx, key, keySize)))
    {
        goto cleanup;
    }

    if ((status = mbedtls_md_hmac_update( &ctx, data1, data1Size)))
    {
        goto cleanup;
    }

    if ((status = mbedtls_md_hmac_update( &ctx, data2, data2Size)))
    {
        goto cleanup;
    }

    if ((status = mbedtls_md_hmac_finish( &ctx, result)))
    {
        goto cleanup;
    }

cleanup:
    mbedtls_md_free(&ctx);

    if (status)
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

mbedtls_ecp_group ecp_grp_internal = { 0 };

RIOT_STATUS
RiotCrypt_DeriveEccKey(
    RIOT_ECC_PUBLIC    *publicPart,     // OUT: Derived public key
    RIOT_ECC_PRIVATE   *privatePart,    // OUT: Derived private key
    const void         *srcData,        // IN:  Initial data for derivation
    size_t              srcDataSize,    // IN:  Size of the source data in bytes
    const uint8_t      *label,          // IN:  Label for derivation (may be NULL)
    size_t              labelSize       // IN:  Size of the label in bytes
)
{
    if (!publicPart || !privatePart || !srcData || !srcDataSize)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // [Re-]Seed DRBG with source data for this key
    RiotCrypt_SeedDRBG(srcData, srcDataSize, label, labelSize);

    // Init group id, if necessary
    if (ecp_grp_internal.id == MBEDTLS_ECP_DP_NONE)
    {
        if (mbedtls_ecp_group_load(&ecp_grp_internal, RIOT_ECP_GRPID))
        {
            return RIOT_INVALID_STATE;
        }
    }

    // mbedtls_ecp_gen_keypair cannot handle uninitialized mpi values
    mbedtls_mpi_init(privatePart);
    mbedtls_mpi_init(&publicPart->X);
    mbedtls_mpi_init(&publicPart->Y);
    mbedtls_mpi_init(&publicPart->Z);

    // Generate keypair
    if(mbedtls_ecp_gen_keypair(&ecp_grp_internal, privatePart, publicPart,
                               mbedtls_hmac_drbg_random, &hmac_drbg_ctx))
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

int
RiotCrypt_ExportEccPub(
    RIOT_ECC_PUBLIC     *a,     // IN:  ECC Public Key to export
    uint8_t             *b,     // OUT: Buffer to receive the public key bytes
    uint32_t            *s      // IN/OUT: Pointer to receive the buffer size
)
// Note: On success size is always RIOT_COORDMAX * 2 + 1.
// Note2: This function is called from x509bldr and is not otherwise referenced;
// hence the inconsistent return values, < 0 is expected by CHK macro in x509bldr
{
    size_t len = RIOT_COORDMAX;

    // Parameter validation
    if (!a || !b || !s || *s < (len * 2 + 1))
    {
        return -1;
    }

    // Essentially an assert, make sure x y fit into expected lengths
    if ((mbedtls_mpi_size(&a->X) > len) ||
        (mbedtls_mpi_size(&a->Y) > len))
    {
        return -1;
    }

    *b++ = 0x04;

    // Write X
    if (mbedtls_mpi_write_binary(&a->X, b, len))
    {
        return -1;
    }

    // Update byte ptr
    b += len;

    // Write Y (and we know (b + lenX) leaves at least lenY bytes free)
    if (mbedtls_mpi_write_binary(&a->Y, b, len))
    {
        return -1;
    }

    // Output bytes written
    *s = 1 + (len * 2);
    return 0;
}

RIOT_STATUS
RiotCrypt_Sign(
    RIOT_ECC_SIGNATURE     *sig,        // OUT: Signature of data
    const void             *data,       // IN:  Data to sign
    size_t                  dataSize,   // IN:  Data size in bytes
    const RIOT_ECC_PRIVATE *key         // IN:  Signing key
)
{
    uint8_t digest[RIOT_DIGEST_LENGTH];

    // Parameter validation
    if (!sig || !data || !dataSize || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Produce digest to be signed
    if(RiotCrypt_Hash(digest, sizeof(digest), data, dataSize))
    {
        return RIOT_INVALID_STATE;
    }

    // Sign digest
    return RiotCrypt_SignDigest(sig, digest, sizeof(digest), key);
}

RIOT_STATUS
RiotCrypt_SignDigest(
    RIOT_ECC_SIGNATURE     *sig,            // OUT: Signature of digest
    const uint8_t          *digest,         // IN:  Digest to sign
    size_t                  digestSize,     // IN:  Size of the digest in bytes
    const RIOT_ECC_PRIVATE *key             // IN:  Signing key
)
{
    int status;

    // Parameter validation
    if (!sig || !digest || (digestSize != RIOT_DIGEST_LENGTH) || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Init group id, if necessary
    if (ecp_grp_internal.id == MBEDTLS_ECP_DP_NONE)
    {
        if (mbedtls_ecp_group_load(&ecp_grp_internal, RIOT_ECP_GRPID))
        {
            return RIOT_INVALID_STATE;
        }
    }

    // need to init dst mpi values
    mbedtls_mpi_free(&sig->r);
    mbedtls_mpi_free(&sig->s);

    // Sign digest
    status = mbedtls_ecdsa_sign(&ecp_grp_internal, &sig->r, &sig->s, key, digest, digestSize,
                                mbedtls_hmac_drbg_random, &hmac_drbg_ctx);
    if(status)
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

RIOT_STATUS
RiotCrypt_Verify(
    const void                 *data,       // IN: Data to verify signature of
    size_t                      dataSize,   // IN: Size of data in bytes
    const RIOT_ECC_SIGNATURE   *sig,        // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key         // IN: ECC public key of signer
)
{
    uint8_t digest[RIOT_DIGEST_LENGTH];

    // Parameter validation
    if (!data || !dataSize || !sig || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Produce digest to be signed
    if(RiotCrypt_Hash(digest, sizeof(digest), data, dataSize))
    {
        return RIOT_INVALID_STATE;
    }

    // Verify against digest
    return RiotCrypt_VerifyDigest(digest, sizeof(digest), sig, key);
}

RIOT_STATUS
RiotCrypt_VerifyDigest(
    const uint8_t              *digest,     // IN: Digest to verify signature of
    size_t                      digestSize, // IN: Size of the digest
    const RIOT_ECC_SIGNATURE   *sig,        // IN: Signature to verify
    const RIOT_ECC_PUBLIC      *key         // IN: ECC public key of signer
)
{
    // Parameter validation
    if (!digest || (digestSize != RIOT_DIGEST_LENGTH) || !sig || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Init group id, if necessary
    if (ecp_grp_internal.id == MBEDTLS_ECP_DP_NONE)
    {
        if (mbedtls_ecp_group_load(&ecp_grp_internal, RIOT_ECP_GRPID))
        {
            return RIOT_INVALID_STATE;
        }
    }

    // Verify signature
    if(mbedtls_ecdsa_verify(&ecp_grp_internal, digest, digestSize, key, &sig->r, &sig->s))
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}

#ifdef RIOT_ECDH
RIOT_STATUS
RiotCrypt_EccEncrypt(
    uint8_t                *result,         // OUT: Buffer to receive encrypted data
    size_t                  resultCapacity, // IN:  Capacity of the result buffer
    RIOT_ECC_PUBLIC        *ephKey,         // OUT: Ephemeral key to produce
    const void             *data,           // IN:  Data to encrypt
    size_t                  dataSize,       // IN:  Data size in bytes
    const RIOT_ECC_PUBLIC  *key             // IN:  Encryption key
)
// NOTE: Caller is responsible for seeding hmac_drbg prior to call
{
    uint8_t zBytes[RIOT_COORDMAX];
    unsigned char exchKey[RIOT_SYM_KEY_LENGTH];
    RIOT_ECC_PRIVATE d;
    RIOT_ECC_PRIVATE z;

    // Parameter validation
    if (!result || !resultCapacity || !ephKey || !data || !dataSize || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Init group id, if necessary
    if (ecp_grp_internal.id == MBEDTLS_ECP_DP_NONE)
    {
        if (mbedtls_ecp_group_load(&ecp_grp_internal, RIOT_ECP_GRPID))
        {
            return RIOT_INVALID_STATE;
        }
    }

    mbedtls_mpi_init(&d);
    if(mbedtls_ecdh_gen_public(&ecp_grp_internal, &d, ephKey,
                               mbedtls_hmac_drbg_random, &hmac_drbg_ctx))
    {
        return RIOT_FAILURE;
    }

    mbedtls_mpi_init(&z);
    if(mbedtls_ecdh_compute_shared(&ecp_grp_internal, &z, key, &d,
                                   mbedtls_hmac_drbg_random, &hmac_drbg_ctx))
    {
        return RIOT_FAILURE;
    }

    if(mbedtls_mpi_write_binary(&z, zBytes, sizeof(zBytes)))
    {
        return RIOT_FAILURE;
    }

    if(RiotCrypt_Kdf(exchKey, sizeof(exchKey), zBytes, sizeof(zBytes),
                     NULL, 0, (const uint8_t *)"EXCHANGE", 8, RIOT_SYM_KEY_LENGTH))
    {
        return RIOT_FAILURE;
    }

    if(RiotCrypt_SymEncryptDecrypt(result, resultCapacity, data, dataSize, exchKey))
    {
        return RIOT_FAILURE;
    }   

    return RIOT_SUCCESS;
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
    uint8_t zBytes[RIOT_COORDMAX];
    unsigned char exchKey[RIOT_SYM_KEY_LENGTH];
    RIOT_ECC_PRIVATE z;

    // Parameter validation
    if (!result || !resultCapacity || !data || !dataSize || !ephKey || !key)
    {
        return RIOT_INVALID_PARAMETER;
    }

    // Init group id, if necessary
    if (ecp_grp_internal.id == MBEDTLS_ECP_DP_NONE)
    {
        if (mbedtls_ecp_group_load(&ecp_grp_internal, RIOT_ECP_GRPID))
        {
            return RIOT_INVALID_STATE;
        }
    }

    mbedtls_mpi_init(&z);
    mbedtls_ecdh_compute_shared(&ecp_grp_internal, &z, ephKey, key,
                                mbedtls_hmac_drbg_random, &hmac_drbg_ctx);

    mbedtls_mpi_write_binary(&z, zBytes, sizeof(zBytes));

    RiotCrypt_Kdf(exchKey, sizeof(exchKey), zBytes, sizeof(zBytes),
                  NULL, 0, (const uint8_t *)"EXCHANGE", 8, RIOT_SYM_KEY_LENGTH);

    RiotCrypt_SymEncryptDecrypt(result, resultCapacity, data, dataSize, exchKey);
    
    return RIOT_SUCCESS;
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
    mbedtls_aes_context ctx;
    unsigned char nonceCtr[RIOT_NCTR_LENGTH];
    unsigned char stmBlk[RIOT_NCTR_LENGTH] = { 0 };
    size_t ncOffset = 0;

    // Parameter validation
    if (!outData || !inData || !outSize || !inSize)
    {
        return RIOT_INVALID_PARAMETER;
    }

    mbedtls_aes_init(&ctx);

    // Sanity check on sizes
    if(RIOT_SYM_KEY_LENGTH < (RIOT_AES_KEYBYTES + RIOT_NCTR_LENGTH))
    {
        return RIOT_INVALID_STATE;
    }

    // Init nonce counter value
    memcpy(nonceCtr, &(key[RIOT_AES_KEYBYTES]), RIOT_NCTR_LENGTH);

    // Set key (same for enc/dec)
    if(mbedtls_aes_setkey_enc(&ctx, key, RIOT_AES_KEYBITS))
    {
        return RIOT_FAILURE;
    }

    // Perform enc/dec
    if(mbedtls_aes_crypt_ctr(&ctx, inSize, &ncOffset, nonceCtr, stmBlk, inData, outData))
    {
        return RIOT_FAILURE;
    }

    return RIOT_SUCCESS;
}
