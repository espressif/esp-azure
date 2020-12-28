// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>

#include "azure_c_shared_utility/platform.h"

#include "azure_utpm_c/tpm_codec.h"
#include "azure_utpm_c/Marshal_fp.h"

static TPM2B_AUTH NullAuth = { 0 };
static TSS_SESSION NullPwSession;
static const UINT32 TPM_20_SRK_HANDLE = HR_PERSISTENT | 0x00000001;
static const UINT32 TPM_20_EK_HANDLE = HR_PERSISTENT | 0x00010001;

static TPMS_RSA_PARMS  RsaStorageParams = {
    { TPM_ALG_AES, 128, TPM_ALG_CFB },      // TPMT_SYM_DEF_OBJECT  symmetric
    { TPM_ALG_NULL },                       // TPMT_RSA_SCHEME      scheme
    2048,                                   // TPMI_RSA_KEY_BITS    keyBits
    0                                       // UINT32               exponent
};

static TPM2B_PUBLIC* GetEkTemplate()
{
    static TPM2B_PUBLIC EkTemplate = { 0,   // size will be computed during marshaling
    {
        TPM_ALG_RSA,                    // TPMI_ALG_PUBLIC      type
        TPM_ALG_SHA256,                 // TPMI_ALG_HASH        nameAlg
        { 0 },                          // TPMA_OBJECT  objectAttributes (set below)
        { 32,
        { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
        0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
        0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
        0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa }
        },                              // TPM2B_DIGEST         authPolicy
        { 0 },                          // TPMU_PUBLIC_PARMS    parameters (set below)
        { 0 }                           // TPMU_PUBLIC_ID       unique
    } };
    EkTemplate.publicArea.objectAttributes = ToTpmaObject(
        Restricted | Decrypt | FixedTPM | FixedParent | AdminWithPolicy | SensitiveDataOrigin);
    EkTemplate.publicArea.parameters.rsaDetail = RsaStorageParams;
    return &EkTemplate;
}

static TPM2B_PUBLIC* GetSrkTemplate()
{
    static TPM2B_PUBLIC SrkTemplate = { 0,  // size will be computed during marshaling
    {
        TPM_ALG_RSA,                // TPMI_ALG_PUBLIC      type
        TPM_ALG_SHA256,             // TPMI_ALG_HASH        nameAlg
        { 0 },                      // TPMA_OBJECT  objectAttributes (set below)
        { 0 },                      // TPM2B_DIGEST         authPolicy
        { 0 },                      // TPMU_PUBLIC_PARMS    parameters (set before use)
        { 0 }                       // TPMU_PUBLIC_ID       unique
    } };
    SrkTemplate.publicArea.objectAttributes = ToTpmaObject(
        Restricted | Decrypt | FixedTPM | FixedParent | NoDA | UserWithAuth | SensitiveDataOrigin);
    SrkTemplate.publicArea.parameters.rsaDetail = RsaStorageParams;
    return &SrkTemplate;
}

typedef struct TPM_SAMPLE_INFO_TAG
{
    TSS_DEVICE tpm_device;
    TPM2B_PUBLIC ek_pub;
    TPM2B_PUBLIC srk_pub;

    TPM_HANDLE tpm_handle;

} TPM_SAMPLE_INFO;

typedef struct HTTP_SAMPLE_INFO_TAG
{
    int stop_running;
} HTTP_SAMPLE_INFO;

static int load_key(TPM_SAMPLE_INFO* tpm_info, TPM_HANDLE request_handle, TPMI_DH_OBJECT hierarchy, TPM2B_PUBLIC* inPub, TPM2B_PUBLIC* outPub)
{
    int result;
    TPM_RC tpm_result;
    TPM2B_NAME name;
    TPM2B_NAME qName;

    tpm_result = TPM2_ReadPublic(&tpm_info->tpm_device, request_handle, outPub, &name, &qName);
    if (tpm_result == TPM_RC_SUCCESS)
    {
        tpm_info->tpm_handle = request_handle;
        result = 0;
    }
    else if (tpm_result != TPM_RC_HANDLE)
    {
        (void)printf("Failed calling TPM2_ReadPublic 0%x", tpm_result);
        result = MU_FAILURE;
    }
    else
    {
        if (TSS_CreatePrimary(&tpm_info->tpm_device, &NullPwSession, hierarchy, inPub, &tpm_info->tpm_handle, outPub) != TPM_RC_SUCCESS)
        {
            (void)printf("Failed calling TSS_CreatePrimary");
            result = MU_FAILURE;
        }
        else
        {
            if (TPM2_EvictControl(&tpm_info->tpm_device, &NullPwSession, TPM_RH_OWNER, tpm_info->tpm_handle, request_handle) != TPM_RC_SUCCESS)
            {
                (void)printf("Failed calling TSS_CreatePrimary");
                result = MU_FAILURE;
            }
            else if (TPM2_FlushContext(&tpm_info->tpm_device, tpm_info->tpm_handle) != TPM_RC_SUCCESS)
            {
                (void)printf("Failed calling TSS_CreatePrimary");
                result = MU_FAILURE;
            }
            else
            {
                tpm_info->tpm_handle = request_handle;
                result = 0;
            }
        }
    }
    return result;
}

static bool initialize_tpm(TPM_SAMPLE_INFO* tpm_info)
{
    bool result;
    if (TSS_CreatePwAuthSession(&NullAuth, &NullPwSession) != TPM_RC_SUCCESS)
    {
        (void)printf("Failure initializing TPM codec\r\n");
        result = false;
    }
    else if (Initialize_TPM_Codec(&tpm_info->tpm_device) != TPM_RC_SUCCESS)
    {
        (void)printf("Failure initializing TPM codec\r\n");
        result = false;
    }
    else if (load_key(tpm_info, TPM_20_EK_HANDLE, TPM_RH_ENDORSEMENT, GetEkTemplate(), &tpm_info->ek_pub) != 0)
    {
        (void)printf("Failure loading endorsement key\r\n");
        result = false;
    }
    else if (load_key(tpm_info, TPM_20_SRK_HANDLE, TPM_RH_OWNER, GetSrkTemplate(), &tpm_info->srk_pub) != 0)
    {
        (void)printf("Failure loading endorsement key\r\n");
        result = false;
    }
    else
    {
        result = true;
    }

    return result;
}

static void print_bytes(const char* text, const unsigned char* bytes, size_t len)
{
    (void)printf("%s", text);
    for (uint32_t index = 0; index < len; index++)
    {
        (void)printf("%x", bytes[index]);
    }
    (void)printf("\r\n\r\n");
}

static void read_key_info(TPM2B_PUBLIC* pub_key_type, const char* key_name)
{
    unsigned char data_bytes[1024];
    unsigned char* data_pos = data_bytes;
    uint32_t data_length = TPM2B_PUBLIC_Marshal(pub_key_type, &data_pos, NULL);
    print_bytes(key_name, data_bytes, data_length);
}

static void write_sign_data(TPM_SAMPLE_INFO* tpm_info, const char* data)
{
    size_t data_len = strlen(data);
    unsigned char* data_copy = (unsigned char*)data;
    BYTE data_signature[1024];
    uint32_t sign_len = SignData(&tpm_info->tpm_device, &NullPwSession, data_copy, (uint32_t)data_len, data_signature, (uint32_t)sizeof(data_signature));
    if (sign_len == 0)
    {
        printf("Failed to sign data with tpm\r\n");
    }
    else
    {
        print_bytes("Sign Data: ", data_signature, sign_len);
    }
}

static void retrieve_random_bytes()
{
    BYTE random_bytes[32];
    TSS_RandomBytes(random_bytes, 32);
    print_bytes("Random bytes: ", random_bytes, 32);
}

int main(void)
{
    int result;

    TPM_SAMPLE_INFO tpm_info = { 0 };
    if (platform_init() != 0)
    {
        (void)printf("platform_init failed\r\n");
        result = __LINE__;
    }
    else if (initialize_tpm(&tpm_info) )
    {
        read_key_info(&tpm_info.ek_pub, "Endorsement Key: ");
        read_key_info(&tpm_info.srk_pub, "Storage Root Key: ");

        write_sign_data(&tpm_info, "Data to be signed by tpm");

        retrieve_random_bytes();

        Deinit_TPM_Codec(&tpm_info.tpm_device);

        result = 0;
    }
    else
    {
        result = __LINE__;
    }

    platform_deinit();

    (void)getchar();
    return result;
}
