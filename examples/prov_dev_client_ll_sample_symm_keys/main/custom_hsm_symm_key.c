// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sdkconfig.h>
#include "hsm_client_data.h"

typedef struct CUSTOM_HSM_SAMPLE_INFO_TAG
{
    const char* certificate;
    const char* common_name;
    const char* key;
    const unsigned char* endorsment_key;
    size_t ek_length;
    const unsigned char* storage_root_key;
    size_t srk_len;
    char* symm_key;
    char* registration_name;
} CUSTOM_HSM_SAMPLE_INFO;

HSM_CLIENT_HANDLE custom_hsm_create()
{
    HSM_CLIENT_HANDLE result;
    CUSTOM_HSM_SAMPLE_INFO* hsm_info = malloc(sizeof(CUSTOM_HSM_SAMPLE_INFO));
    if (hsm_info == NULL)
    {
        (void)printf("Failued allocating hsm info\r\n");
        result = NULL;
    }
    else
    {
        // TODO: initialize any variables here
        hsm_info->symm_key = NULL;
        hsm_info->registration_name = NULL;
        result = hsm_info;
    }
    return result;
}

void custom_hsm_destroy(HSM_CLIENT_HANDLE handle)
{
    if (handle != NULL)
    {
        CUSTOM_HSM_SAMPLE_INFO* hsm_info = (CUSTOM_HSM_SAMPLE_INFO*)handle;
        // Free anything that has been allocated in this module
        free(hsm_info);
    }
}

char* custom_hsm_symm_key(HSM_CLIENT_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified\r\n");
        result = NULL;
    }
    else
    {
        // TODO: Malloc the symmetric key for the iothub 
        // The SDK will call free() this value
        CUSTOM_HSM_SAMPLE_INFO* hsm_info = (CUSTOM_HSM_SAMPLE_INFO*)handle;
        size_t len = strlen(hsm_info->symm_key);
        if ((result = (char*)malloc(len + 1)) == NULL)
        {
            (void)printf("Failure allocating certificate\r\n");
            result = NULL;
        }
        else
        {
            strcpy(result, hsm_info->symm_key);
        }
    }
    return result;
}

char* custom_hsm_get_registration_name(HSM_CLIENT_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified\r\n");
        result = NULL;
    }
    else
    {
        // TODO: Malloc the registration name for the iothub 
        // The SDK will call free() this value
        CUSTOM_HSM_SAMPLE_INFO* hsm_info = (CUSTOM_HSM_SAMPLE_INFO*)handle;
        size_t len = strlen(hsm_info->registration_name);
        if ((result = (char*)malloc(len + 1)) == NULL)
        {
            (void)printf("Failure allocating certificate\r\n");
            result = NULL;
        }
        else
        {
            strcpy(result, hsm_info->registration_name);
        }
    }
    return result;
}

int custom_hsm_set_symm_key_info(HSM_CLIENT_HANDLE handle, const char* reg_name, const char* symm_key)
{
    int result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified\r\n");
        result = __LINE__;
    }
    else
    {
        // TODO: Malloc the symmetric key for the iothub 
        // The SDK will call free() this value
        CUSTOM_HSM_SAMPLE_INFO* hsm_info = (CUSTOM_HSM_SAMPLE_INFO*)handle;
        size_t reg_len = strlen(reg_name);
        size_t symm_len = strlen(symm_key);
        if ((hsm_info->registration_name = (char*)malloc(reg_len + 1)) == NULL)
        {
            (void)printf("Failure allocating registration name\r\n");
            result = __LINE__;
        }
        else if ((hsm_info->symm_key = (char*)malloc(symm_len + 1)) == NULL)
        {
            (void)printf("Failure allocating symm key\r\n");
            free(hsm_info->registration_name);
            result = __LINE__;
        }
        else
        {
            strcpy(hsm_info->registration_name, reg_name);
            strcpy(hsm_info->symm_key, symm_key);
            result = 0;
        }
    }
    return result;
}

static const HSM_CLIENT_KEY_INTERFACE symm_key_interface =
{
    custom_hsm_create,
    custom_hsm_destroy,
    custom_hsm_symm_key,
    custom_hsm_get_registration_name,
    custom_hsm_set_symm_key_info,
};

const HSM_CLIENT_KEY_INTERFACE* hsm_client_key_interface()
{
    return &symm_key_interface;
}
