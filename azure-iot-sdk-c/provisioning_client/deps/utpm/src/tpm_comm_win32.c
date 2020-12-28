// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/buffer_.h"

#include "azure_utpm_c/tpm_comm.h"
#include <Tbs.h>

typedef struct TPM_COMM_INFO_TAG
{
    TBS_HCONTEXT tbs_context;
} TPM_COMM_INFO;

static const char* get_tbsi_error_msg(TBS_RESULT tbs_res)
{
    switch (tbs_res)
    {
        case TBS_SUCCESS:
            return "The function was successful";

        case TBS_E_BAD_PARAMETER:
            return "One or more parameter values are not valid.";

        case TBS_E_INTERNAL_ERROR:
            return "An internal software error occurred.";

        case TBS_E_INVALID_CONTEXT_PARAM:
            return "A context parameter that is not valid was passed when attempting to create a TBS context.";

        case TBS_E_INVALID_CONTEXT:
            return "The specified context handle does not refer to a valid context.";

        case TBS_E_INVALID_OUTPUT_POINTER:
            return "A specified output pointer is not valid.";

        case TBS_E_BUFFER_TOO_LARGE:
            return "The input or output buffer is too large.";

        case TBS_E_SERVICE_DISABLED:
            return "The TBS service has been disabled.";

        case TBS_E_SERVICE_NOT_RUNNING:
            return "The TBS service is not running and could not be started.";

        case TBS_E_SERVICE_START_PENDING:
            return "The TBS service has been started but is not yet running.";

        case TBS_E_TOO_MANY_TBS_CONTEXTS:
            return "A new context could not be created because there are too many open contexts.";

        case TBS_E_INSUFFICIENT_BUFFER:
            return "The specified output buffer is too small.";

        case TBS_E_TPM_NOT_FOUND:
            return "A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.";

        case TBS_E_IOERROR:
            return "An error occurred while communicating with the TPM.";

    }
    return "Unknown tbsi error found";
}

static void cleanup_memory(TPM_COMM_INFO* tpm_info)
{
    if (tpm_info->tbs_context != NULL)
    {
        (void)Tbsip_Context_Close(tpm_info->tbs_context);
    }
    free(tpm_info);
}

TPM_COMM_HANDLE tpm_comm_create(const char* endpoint)
{
    TPM_COMM_INFO* result;
    (void)endpoint;
    if ((result = malloc(sizeof(TPM_COMM_INFO))) == NULL)
    {
        LogError("Failure: malloc tpm communication info.");
    }
    else
    {
        TBS_RESULT tbs_res;
        TBS_CONTEXT_PARAMS2 parms = { TBS_CONTEXT_VERSION_TWO };
        TPM_DEVICE_INFO device_info = { 1, 0 };

        parms.includeTpm20 = TRUE;

        memset(result, 0, sizeof(TPM_COMM_INFO));
        tbs_res = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&parms, &result->tbs_context);
        if (tbs_res != TBS_SUCCESS)
        {
            LogError("Failure: Tbsi_Context_Create %s.", get_tbsi_error_msg(tbs_res));
            free(result);
            result = NULL;
        }
        else
        {
            tbs_res = Tbsi_GetDeviceInfo(sizeof(device_info), &device_info);
            if (tbs_res != TBS_SUCCESS)
            {
                LogError("Failure getting device tpm information %s.", get_tbsi_error_msg(tbs_res));
                cleanup_memory(result);
                result = NULL;
            }
            else if (device_info.tpmVersion != TPM_VERSION_20)
            {
                LogError("Failure Invalid tpm version specified.  Requires 2.0.");
                cleanup_memory(result);
                result = NULL;
            }
        }
    }
    return result;
}

void tpm_comm_destroy(TPM_COMM_HANDLE handle)
{
    if (handle)
    {
        cleanup_memory(handle);
    }
}

TPM_COMM_TYPE tpm_comm_get_type(TPM_COMM_HANDLE handle)
{
    (void)handle;
    return TPM_COMM_TYPE_WINDOW;
}

int tpm_comm_submit_command(TPM_COMM_HANDLE handle, const unsigned char* cmd_bytes, uint32_t bytes_len, unsigned char* response, uint32_t* resp_len)
{
    int result;
    if (handle == NULL || cmd_bytes == NULL || response == NULL || resp_len == NULL)
    {
        LogError("Invalid argument specified handle: %p, cmd_bytes: %p, response: %p, resp_len: %p.", handle, cmd_bytes, response, resp_len);
        result = MU_FAILURE;
    }
    else
    {
        TBS_RESULT tbs_res;
        tbs_res = Tbsip_Submit_Command(handle->tbs_context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
            cmd_bytes, bytes_len, response, resp_len);
        if (tbs_res != TBS_SUCCESS)
        {
            LogError("Failure sending command to tpm %s.", get_tbsi_error_msg(tbs_res));
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}
