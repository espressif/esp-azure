// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TPM_COMM_H
#define TPM_COMM_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif /* __cplusplus */

#include "umock_c/umock_c_prod.h"

#define TPM_COMM_TYPE_VALUES    \
    TPM_COMM_TYPE_EMULATOR,     \
    TPM_COMM_TYPE_WINDOW,       \
    TPM_COMM_TYPE_LINUX

MU_DEFINE_ENUM(TPM_COMM_TYPE, TPM_COMM_TYPE_VALUES);

typedef struct TPM_COMM_INFO_TAG* TPM_COMM_HANDLE;

MOCKABLE_FUNCTION(, TPM_COMM_HANDLE, tpm_comm_create, const char*, endpoint);
MOCKABLE_FUNCTION(, void, tpm_comm_destroy, TPM_COMM_HANDLE, handle);

MOCKABLE_FUNCTION(, TPM_COMM_TYPE, tpm_comm_get_type, TPM_COMM_HANDLE, handle);
MOCKABLE_FUNCTION(, int, tpm_comm_submit_command, TPM_COMM_HANDLE, handle, const unsigned char*, cmd_bytes, uint32_t, bytes_len, unsigned char*, response, uint32_t*, resp_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // TPM_COMM_H