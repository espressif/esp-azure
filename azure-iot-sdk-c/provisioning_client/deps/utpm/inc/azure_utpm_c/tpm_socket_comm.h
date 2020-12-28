// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TPM_SOCKET_COMM_H
#define TPM_SOCKET_COMM_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif /* __cplusplus */

#include "umock_c/umock_c_prod.h"

typedef struct TPM_SOCKET_INFO_TAG* TPM_SOCKET_HANDLE;

MOCKABLE_FUNCTION(, TPM_SOCKET_HANDLE, tpm_socket_create, const char*, address, unsigned short, port);
MOCKABLE_FUNCTION(, void, tpm_socket_destroy, TPM_SOCKET_HANDLE, handle);

MOCKABLE_FUNCTION(, int, tpm_socket_read, TPM_SOCKET_HANDLE, handle, unsigned char*, tpm_bytes, uint32_t, bytes_len);
MOCKABLE_FUNCTION(, int, tpm_socket_send, TPM_SOCKET_HANDLE, handle, const unsigned char*, cmd_val, uint32_t, byte_len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // TPM_SOCKET_COMM_H