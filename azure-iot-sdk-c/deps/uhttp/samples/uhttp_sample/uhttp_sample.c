// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_uhttp_c/uhttp.h"

#define HTTP_PORT_NUM       80
#define HTTPS_PORT_NUM      443

typedef struct HTTP_SAMPLE_INFO_TAG
{
    int stop_running;
} HTTP_SAMPLE_INFO;

static void on_http_connected(void* callback_ctx, HTTP_CALLBACK_REASON connect_result)
{
    (void)callback_ctx;
    if (connect_result == HTTP_CALLBACK_REASON_OK)
    {
        (void)printf ("HTTP Connected\r\n");
    }
    else
    {
        (void)printf ("HTTP Connection FAILED\r\n");
    }
}

static void on_http_recv(void* callback_ctx, HTTP_CALLBACK_REASON request_result, const unsigned char* content, size_t content_len, unsigned int statusCode, HTTP_HEADERS_HANDLE responseHeadersHandle)
{
    (void)responseHeadersHandle;
    (void)request_result;
    (void)content_len;
    (void)statusCode;
    (void)content;
    if (callback_ctx != NULL)
    {
        HTTP_SAMPLE_INFO* http_info = (HTTP_SAMPLE_INFO*)callback_ctx;
        http_info->stop_running = 1;
    }
    else
    {
        (void)printf("callback_ctx is NULL!!!!!\r\n");
    }
}

static void on_error(void* callback_ctx, HTTP_CALLBACK_REASON error_result)
{
    (void)callback_ctx;
    (void)error_result;
    printf("HTTP client Error Called\r\n");
}

static void on_closed_callback(void* callback_ctx)
{
    (void)callback_ctx;
    printf("Connection closed callback\r\n");
}

static HTTP_CLIENT_HANDLE create_uhttp_client_handle(HTTP_SAMPLE_INFO* sample_info, const char* host_name, int port_num)
{
    SOCKETIO_CONFIG config;
    TLSIO_CONFIG tls_io_config;
    const void* xio_param;
    const IO_INTERFACE_DESCRIPTION* interface_desc;
    if (port_num == HTTPS_PORT_NUM)
    {
        tls_io_config.hostname = host_name;
        tls_io_config.port = port_num;
        tls_io_config.underlying_io_interface = NULL;
        tls_io_config.underlying_io_parameters = NULL;
        xio_param = &tls_io_config;
        // Get the TLS definition
        interface_desc = platform_get_default_tlsio();
    }
    else
    {
        config.accepted_socket = NULL;
        config.hostname = host_name;
        config.port = port_num;
        xio_param = &config;
        // Get the socket definition
        interface_desc = socketio_get_interface_description();
    }
    return uhttp_client_create(interface_desc, xio_param, on_error, sample_info);
}

static void test_http_get(void)
{
    const char* host_name = "httpbin.org";
    int port_num = HTTP_PORT_NUM;
    HTTP_SAMPLE_INFO sample_info;
    sample_info.stop_running = 0;

    HTTP_CLIENT_HANDLE http_handle = create_uhttp_client_handle(&sample_info, host_name, port_num);
    if (http_handle == NULL)
    {
        (void)printf("FAILED HERE\r\n");
    }
    else
    {
        (void)uhttp_client_set_trace(http_handle, true, true);
        if (uhttp_client_open(http_handle, host_name, port_num, on_http_connected, &sample_info) != HTTP_CLIENT_OK)
        {
            (void)printf("FAILED MORE HERE\r\n");
        }
        else
        {
            if (uhttp_client_execute_request(http_handle, HTTP_CLIENT_REQUEST_GET, "/get", NULL, NULL, 0, on_http_recv, &sample_info) != HTTP_CLIENT_OK)
            {
                (void)printf("FAILED FURTHER HERE\r\n");
            }
            else
            {
                do
                {
                    uhttp_client_dowork(http_handle);
                } while (sample_info.stop_running == 0);
            }
            uhttp_client_close(http_handle, on_closed_callback, NULL);
        }
        uhttp_client_destroy(http_handle);
    }
}

void test_http_post(void)
{
    const char* host_name = "httpbin.org";
    int port_num = HTTP_PORT_NUM;
    HTTP_SAMPLE_INFO sample_info;
    sample_info.stop_running = 0;

    HTTP_CLIENT_HANDLE http_handle = create_uhttp_client_handle(&sample_info, host_name, port_num);
    if (http_handle == NULL)
    {
        (void)printf("FAILED MORE HERE\r\n");
    }
    else
    {
        (void)uhttp_client_set_trace(http_handle, true, true);
        if (uhttp_client_open(http_handle, host_name, port_num, on_http_connected, &sample_info) != HTTP_CLIENT_OK)
        {
            (void)printf("FAILED MORE HERE\r\n");
        }
        else
        {
            HTTP_HEADERS_HANDLE http_headers = HTTPHeaders_Alloc();
            if (http_headers == NULL)
            {
                (void)printf("http alloc failed\r\n");
            }
            else
            {
                HTTPHeaders_AddHeaderNameValuePair(http_headers, "User-Agent", "uhttp/1.0");
                HTTPHeaders_AddHeaderNameValuePair(http_headers, "Content-Type", "application/json");

                const char* post_data = "{ \"encryptedData\": { \"authKey\": \"xxxxxxx\", \"secondaryAuthKey\": \"xxxxxxx\", nonce: \"blah\" }, correlationId: \"ASDDSA\"  }";
                size_t len = strlen(post_data);
                if (uhttp_client_execute_request(http_handle, HTTP_CLIENT_REQUEST_POST, "/post", http_headers, (const unsigned char*)post_data, len, on_http_recv, &sample_info) != HTTP_CLIENT_OK)
                {
                    (void)printf("FAILED FURTHER HERE\r\n");
                }
                else
                {
                    do
                    {
                        uhttp_client_dowork(http_handle);
                    } while (sample_info.stop_running == 0);
                }
                HTTPHeaders_Free(http_headers);
            }
            uhttp_client_close(http_handle, on_closed_callback, NULL);
        }
        uhttp_client_destroy(http_handle);
    }
}

int main(void)
{
    int result;

    if (platform_init() != 0)
    {
        (void)printf("platform_init\r\n");
        result = __LINE__;
    }
    else
    {
        result = 0;

        (void)printf("\r\nSending HTTP GET\r\n\r\n");
        test_http_get();

        (void)printf("\r\nSending HTTP POST\r\n\r\n");
        test_http_post();

        platform_deinit();
    }

    (void)printf("Press any key to continue:");
    (void)getchar();
    return result;
}
