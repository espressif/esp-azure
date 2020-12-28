// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/crt_abstractions.h"

#include "azure_utpm_c/tpm_comm.h"
#include "azure_utpm_c/tpm_socket_comm.h"

#ifdef WIN32
    #include <Winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#define TPM_SIMULATOR_PORT              2321
#define TPM_SIMULATOR_PLATFORM_PORT     2322

#define REMOTE_SIGNAL_POWER_ON_CMD      1
#define REMOTE_SEND_COMMAND             8
#define REMOTE_SIGNAL_NV_ON_CMD         11
#define REMOTE_HANDSHAKE_CMD            15
#define REMOTE_SESSION_END_CMD          20
#define MAX_DATA_RECV                   1024

static const char* TPM_SIMULATOR_ADDRESS = "127.0.0.1";

typedef struct TPM_COMM_INFO_TAG
{
    TPM_SOCKET_HANDLE socket_conn;
    unsigned char* recv_bytes;
    size_t recv_length;
    char* socket_ip;
} TPM_COMM_INFO;

enum TpmSimCommands
{
    Remote_SignalPowerOn = 1,
    //SignalPowerOff = 2,
    Remote_SendCommand = 8,
    Remote_SignalNvOn = 11,
    //SignalNvOff = 12,
    Remote_Handshake = 15,
    Remote_SessionEnd = 20,
    Remote_Stop = 21,
};


static int read_sync_bytes(TPM_COMM_INFO* comm_info, unsigned char* tpm_bytes, uint32_t* bytes_len)
{
    return tpm_socket_read(comm_info->socket_conn, tpm_bytes, *bytes_len);
}

static int read_sync_cmd(TPM_COMM_INFO* tpm_comm_info, uint32_t* tpm_bytes)
{
    int result;
    uint32_t bytes_len = sizeof(uint32_t);
    result = read_sync_bytes(tpm_comm_info, (unsigned char*)tpm_bytes, &bytes_len);
    if (result == 0)
    {
        int j = htonl(*tpm_bytes);
        *tpm_bytes = j;
    }
    return result;
}

static bool is_ack_ok(TPM_COMM_INFO* tpm_comm_info)
{
    uint32_t end_tag;
    return (read_sync_cmd(tpm_comm_info, &end_tag) == 0 && end_tag == 0);
}

static int send_sync_bytes(TPM_COMM_INFO* comm_info, const unsigned char* cmd_val, size_t byte_len)
{
    return tpm_socket_send(comm_info->socket_conn, cmd_val, (uint32_t)byte_len);
}

static int send_sync_cmd(TPM_COMM_INFO* tpm_comm_info, uint32_t cmd_val)
{
    uint32_t net_bytes = htonl(cmd_val);
    return send_sync_bytes(tpm_comm_info, (const unsigned char*)&net_bytes, sizeof(uint32_t) );
}

static void close_simulator(TPM_COMM_INFO* tpm_comm_info)
{
    (void)send_sync_cmd(tpm_comm_info, REMOTE_SESSION_END_CMD);
}

static int power_on_simulator(TPM_COMM_INFO* tpm_comm_info)
{
    int result;
    TPM_SOCKET_HANDLE platform_conn;

    if ((platform_conn = tpm_socket_create(tpm_comm_info->socket_ip, TPM_SIMULATOR_PLATFORM_PORT) ) == NULL)
    {
        LogError("Failure: connecting to tpm simulator platform interface.");
        result = MU_FAILURE;
    }
    else
    {
        uint32_t power_on_cmd = htonl(REMOTE_SIGNAL_POWER_ON_CMD);
        uint32_t signal_nv_cmd = htonl(REMOTE_SIGNAL_NV_ON_CMD);

        if (tpm_socket_send(platform_conn, (const unsigned char*)&power_on_cmd, sizeof(power_on_cmd) ) != 0)
        {
            LogError("Failure sending remote handshake.");
            result = MU_FAILURE;
        }
        else
        {
            uint32_t ack_value;
            if (tpm_socket_read(platform_conn, (unsigned char*)&ack_value, sizeof(uint32_t)) != 0)
            {
                LogError("Failure sending remote handshake.");
                result = MU_FAILURE;
            }
            else
            {
                if (htonl(ack_value) != 0)
                {
                    LogError("Failure reading cmd sync.");
                    result = MU_FAILURE;
                }
                else
                {
                    if (tpm_socket_send(platform_conn, (const unsigned char*)&signal_nv_cmd, sizeof(signal_nv_cmd) ) != 0)
                    {
                        LogError("Failure sending remote handshake.");
                        result = MU_FAILURE;
                    }
                    else
                    {
                        if (tpm_socket_read(platform_conn, (unsigned char*)&ack_value, sizeof(uint32_t)) != 0)
                        {
                            LogError("Failure sending remote handshake.");
                            result = MU_FAILURE;
                        }
                        else
                        {
                            if (htonl(ack_value) != 0)
                            {
                                LogError("Failure reading cmd sync.");
                                result = MU_FAILURE;
                            }
                            else
                            {
                                result = 0;
                            }
                        }
                    }
                }
            }
        }
        tpm_socket_destroy(platform_conn);
    }
    return result;
}

static int execute_simulator_setup(TPM_COMM_INFO* tpm_comm_info)
{
    int result;
    uint32_t tmp_client_version = 1;
    uint32_t tmp_server_version = 1;
    uint32_t tpm_info;

    // Send the handshake request
    if (send_sync_cmd(tpm_comm_info, REMOTE_HANDSHAKE_CMD) != 0)
    {
        LogError("Failure sending remote handshake.");
        result = MU_FAILURE;
    }
    // Send desired protocol version
    else if (send_sync_cmd(tpm_comm_info, tmp_client_version) != 0)
    {
        LogError("Failure sending client version.");
        result = MU_FAILURE;
    }
    else if (read_sync_cmd(tpm_comm_info, &tmp_server_version) != 0)
    {
        LogError("Failure reading cmd sync.");
        result = MU_FAILURE;
    }
    else if (tmp_client_version != tmp_server_version)
    {
        LogError("Failure client and server version does not match.");
        result = MU_FAILURE;
    }
    else if (read_sync_cmd(tpm_comm_info, &tpm_info) != 0)
    {
        LogError("Failure reading cmd sync.");
        result = MU_FAILURE;
    }
    // GetAck
    else if (!is_ack_ok(tpm_comm_info))
    {
        LogError("Failure ack byte from tpm is invalid.");
        result = MU_FAILURE;
    }
    else if (power_on_simulator(tpm_comm_info) != 0)
    {
        LogError("Failure powering on simulator.");
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

TPM_COMM_HANDLE tpm_comm_create(const char* endpoint)
{
    TPM_COMM_INFO* result;
    if ((result = malloc(sizeof(TPM_COMM_INFO))) == NULL)
    {
        LogError("Failure: malloc tpm communication info.");
    }
    else
    {
        memset(result, 0, sizeof(TPM_COMM_INFO));
        int cpy_res;
        if (endpoint != NULL)
        {
            cpy_res = mallocAndStrcpy_s(&result->socket_ip, endpoint);
        }
        else
        {
            cpy_res = mallocAndStrcpy_s(&result->socket_ip, TPM_SIMULATOR_ADDRESS);
        }
        if (cpy_res != 0)
        {
            LogError("Failure: to copy endpoint");
            free(result);
            result = NULL;
        }
        else if ((result->socket_conn = tpm_socket_create(result->socket_ip, TPM_SIMULATOR_PORT)) == NULL)
        {
            LogError("Failure: connecting to tpm simulator.");
            free(result->socket_ip);
            free(result);
            result = NULL;
        }
        else if (execute_simulator_setup(result) != 0)
        {
            LogError("Failure: connecting to tpm simulator.");
            tpm_socket_destroy(result->socket_conn);
            free(result->socket_ip);
            free(result);
            result = NULL;
        }
    }
    return result;
}

void tpm_comm_destroy(TPM_COMM_HANDLE handle)
{
    if (handle)
    {
        close_simulator(handle);
        tpm_socket_destroy(handle->socket_conn);
        free(handle->socket_ip);
        free(handle);
    }
}

TPM_COMM_TYPE tpm_comm_get_type(TPM_COMM_HANDLE handle)
{
    (void)handle;
    return TPM_COMM_TYPE_EMULATOR;
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
        // Send to TPM
        unsigned char locality = 0;
        if (send_sync_cmd(handle, Remote_SendCommand) != 0)
        {
            LogError("Failure preparing sending Remote Command");
            result = MU_FAILURE;
        }
        else if (send_sync_bytes(handle, (const unsigned char*)&locality, 1) != 0)
        {
            LogError("Failure setting locality to TPM");
            result = MU_FAILURE;
        }
        else if (send_sync_cmd(handle, bytes_len) != 0)
        {
            LogError("Failure writing command bit to tpm");
            result = MU_FAILURE;
        }
        else if (send_sync_bytes(handle, cmd_bytes, bytes_len))
        {
            LogError("Failure writing data to tpm");
            result = MU_FAILURE;
        }
        else
        {
            uint32_t length_byte;

            if (read_sync_cmd(handle, &length_byte) != 0)
            {
                LogError("Failure reading length data from tpm");
                result = MU_FAILURE;
            }
            else if (length_byte > *resp_len)
            {
                LogError("Bytes read are greater then bytes expected len_bytes:%u expected: %u", length_byte, *resp_len);
                result = MU_FAILURE;
            }
            else
            {
                *resp_len = length_byte;
                if (read_sync_bytes(handle, response, &length_byte) != 0)
                {
                    LogError("Failure reading bytes");
                    result = MU_FAILURE;
                }
                else
                {
                    // check the Ack
                    uint32_t ack_cmd;
                    if (read_sync_cmd(handle, &ack_cmd) != 0 || ack_cmd != 0)
                    {
                        LogError("Failure reading tpm ack");
                        result = MU_FAILURE;
                    }
                    else
                    {
                        result = 0;
                    }
                }
            }
        }
    }
    return result;
}
