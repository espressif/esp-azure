// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"

#include "azure_utpm_c/tpm_socket_comm.h"

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SOCKET              int
#define INVALID_SOCKET      -1
#define SOCKET_ERROR        -1
#endif

#define MAX_DATA_RECV                   1024

typedef struct TPM_SOCKET_INFO_TAG
{
    SOCKET socket_conn;
    unsigned char* recv_bytes;
    size_t recv_length;
} TPM_SOCKET_INFO;

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

static int add_to_buffer(TPM_SOCKET_INFO* socket_info, const unsigned char* bytes, size_t length)
{
    int result;
    unsigned char* new_buff;
    if (socket_info->recv_bytes == NULL)
    {
        new_buff = (unsigned char*)malloc(length);
    }
    else
    {
        new_buff = (unsigned char*)realloc(socket_info->recv_bytes, socket_info->recv_length + length);
}
    if (new_buff == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        socket_info->recv_bytes = new_buff;
        memcpy(socket_info->recv_bytes + socket_info->recv_length, bytes, length);
        socket_info->recv_length += length;
        result = 0;
    }
    return result;
}

static void remove_from_buffer(TPM_SOCKET_INFO* socket_info, size_t length)
{
    if (socket_info->recv_length == length)
    {
        free(socket_info->recv_bytes);
        socket_info->recv_bytes = NULL;
        socket_info->recv_length = 0;
    }
    else
    {
        unsigned char* new_buff = (unsigned char*)malloc(socket_info->recv_length - length);
        memcpy(new_buff, &socket_info->recv_bytes[length], socket_info->recv_length - length);
        free(socket_info->recv_bytes);
        socket_info->recv_bytes = new_buff;
        socket_info->recv_length -= length;
    }
}

static int send_socket_bytes(TPM_SOCKET_INFO* socket_info, const unsigned char* cmd_val, size_t byte_len)
{
    int result;

#if SHOW_TRACE
    printf("<- ");
    for (size_t index = 0; index < byte_len; index++)
    {
        printf("%x", cmd_val[index]);
    }
    printf("\r\n");
#endif
    int sent_bytes = 0;
    int send_amt = (int)byte_len;
    const char* pIterator = (const char*)cmd_val;
    while (send_amt > 0)
    {
        sent_bytes = send(socket_info->socket_conn, pIterator, (int)send_amt, 0);
        if (sent_bytes <= 0)
        {
            LogError("Failure sending packet.");
            break;
        }
        pIterator += sent_bytes;
        send_amt -= sent_bytes;
    }
    if (sent_bytes < (int)byte_len)
    {
        LogError("sent byte amoutn is less than desired send amount.");
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int read_socket_bytes(TPM_SOCKET_INFO* socket_info)
{
    int result;
    char read_data[MAX_DATA_RECV];
    int data_len = recv(socket_info->socket_conn, read_data, MAX_DATA_RECV, 0);
    if (data_len == -1)
    {
        LogError("Failure received bytes timed out.");
        result = MU_FAILURE;
    }
    else
    {
#if SHOW_TRACE
        printf("-> ");
        for (size_t index = 0; index < size; index++)
        {
            printf("%x", buffer[index]);
        }
        printf("\r\n");
#endif
        if (add_to_buffer(socket_info, (const unsigned char*)read_data, data_len) != 0)
        {
            LogError("Failure: adding bytes to buffer.");
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

static void close_socket(SOCKET socket_obj)
{
#ifdef WIN32
    closesocket(socket_obj);
#else
    (void)shutdown(socket_obj, SHUT_RDWR);
    close(socket_obj);
#endif
}


TPM_SOCKET_HANDLE tpm_socket_create(const char* address, unsigned short port)
{
    TPM_SOCKET_INFO* result;
    if ((result = malloc(sizeof(TPM_SOCKET_INFO))) == NULL)
    {
        LogError("Failure: malloc socket communication info.");
    }
    else
    {
#ifdef WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif

        memset(result, 0, sizeof(TPM_SOCKET_INFO));

        if ((result->socket_conn = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            LogError("Failure: connecting to tpm simulator.");
            free(result);
            result = NULL;
        }
        else
        {
            struct sockaddr_in SockAddr;
            memset(&SockAddr, 0, sizeof(SockAddr));
            SockAddr.sin_family = AF_INET;
            SockAddr.sin_port = htons(port);
            SockAddr.sin_addr.s_addr = inet_addr(address);

            if (connect(result->socket_conn, (struct sockaddr*)&SockAddr, sizeof(SockAddr)) < 0)
            {
                LogError("Failure: connecting to tpm simulator.");
                close_socket(result->socket_conn);
                free(result);
                result = NULL;
            }
        }
    }
    return result;
}

void tpm_socket_destroy(TPM_SOCKET_HANDLE handle)
{
    if (handle)
    {
        close_socket(handle->socket_conn);
        free(handle->recv_bytes);
        free(handle);
    }
}

int tpm_socket_read(TPM_SOCKET_HANDLE handle, unsigned char* tpm_bytes, uint32_t bytes_len)
{
    int result;
    if (handle == NULL || tpm_bytes == NULL || bytes_len == 0)
    {
        LogError("Invalid argument specified handle: %p, tpm_bytes: %p, bytes_len: %d", handle, tpm_bytes, bytes_len);
        result = MU_FAILURE;
    }
    else
    {
        // Do we have enough bytes cached
        result = MU_FAILURE;
        for (size_t index = 0; index < 2; index++)
        {
            if (handle->recv_length >= bytes_len)
            {
                memcpy(tpm_bytes, handle->recv_bytes, bytes_len);
                remove_from_buffer(handle, bytes_len);
                result = 0;
                break;
            }
            else
            {
                if (read_socket_bytes(handle))
                {
                    LogError("Failure reading socket bytes.");
                    result = MU_FAILURE;
                    break;
                }
            }
        }
    }
    return result;
}

int tpm_socket_send(TPM_SOCKET_HANDLE handle, const unsigned char* tpm_bytes, uint32_t bytes_len)
{
    int result;
    if (handle == NULL || tpm_bytes == NULL || bytes_len == 0)
    {
        LogError("Invalid argument specified handle: %p, tpm_bytes: %p, bytes_len: %d", handle, tpm_bytes, bytes_len);
        result = MU_FAILURE;
    }
    else
    {
        result = send_socket_bytes(handle, tpm_bytes, bytes_len);
    }
    return result;
}
