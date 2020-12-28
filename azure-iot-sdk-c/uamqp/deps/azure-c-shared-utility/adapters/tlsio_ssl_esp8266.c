// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef FREERTOS_ARCH_ESP8266
#include "openssl/ssl.h"
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

#else
//mock header
#include "esp8266_mock.h"
#include "azure_c_shared_utility/gballoc.h"
#endif

#include <stdio.h>
#include <stdbool.h>
#include "azure_c_shared_utility/lock.h"
/* Codes_SRS_TLSIO_SSL_ESP8266_99_001: [ The tlsio_ssl_esp8266 shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ]*/
/* Codes_SRS_TLSIO_SSL_ESP8266_99_002: [ The tlsio_ssl_esp8266 shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h.]*/
/* Codes_SRS_TLSIO_SSL_ESP8266_99_003: [ The tlsio_ssl_esp8266 shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h. ]*/
/* Codes_SRS_TLSIO_SSL_ESP8266_99_004: [ The tlsio_ssl_esp8266 shall call the callbacks functions defined in the xio.h. ]*/
#include "azure_c_shared_utility/tlsio_openssl.h"
/* Codes_SRS_TLSIO_SSL_ESP8266_99_005: [ The tlsio_ssl_esp8266 shall received the connection information using the TLSIO_CONFIG structure defined in tlsio.h. ]*/
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/crt_abstractions.h"

#define OPENSSL_FRAGMENT_SIZE 5120
#define OPENSSL_LOCAL_TCP_PORT 1000
/* Codes_SSRS_TLSIO_SSL_ESP8266_99_027: [ The tlsio_openssl_open shall set the tlsio to try to open the connection for MAX_RETRY times before assuming that connection failed. ]*/
#define MAX_RETRY 20
#define RETRY_DELAY 1000 * 1000 * 10 // 10s
#define RECEIVE_BUFFER_SIZE 1024
#define OPENSSL_SELECT_TIMEOUT 20

struct timeval timeout = { OPENSSL_SELECT_TIMEOUT, 0 };

typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE;

typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    SSL* ssl;
    SSL_CTX* ssl_context;
    TLSIO_STATE tlsio_state;
    char* hostname;
    int port;
    char* certificate;
    const char* x509certificate;
    const char* x509privatekey;
    int sock;
    ip_addr_t target_ip;
} TLS_IO_INSTANCE;

/*this function destroys an option previously created*/
static void tlsio_openssl_DestroyOption(const char* name, const void* value)
{
    /*since all options for this layer are actually string copies, disposing of one is just calling free*/
    if (
        (name == NULL) || (value == NULL)
        )
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
    }
    else
    {
        if (
            (strcmp(name, "TrustedCerts") == 0) ||
            (strcmp(name, "x509certificate") == 0) ||
            (strcmp(name, "x509privatekey") == 0)
        )
        {
            free((void*)value);
        }
        else
        {
            LogError("not handled option : %s", name);
        }
    }
}


/* Codes_SRS_TLSIO_SSL_ESP8266_99_078: [ The tlsio_openssl_retrieveoptions shall not do anything, and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tlsio_handle)
{
    (void)(tlsio_handle);

    (void)tlsio_openssl_DestroyOption;
    /* Not implementing any options */
    return NULL;
}

static const IO_INTERFACE_DESCRIPTION tlsio_openssl_interface_description =
{
    tlsio_openssl_retrieveoptions,
    tlsio_openssl_create,
    tlsio_openssl_destroy,
    tlsio_openssl_open,
    tlsio_openssl_close,
    tlsio_openssl_send,
    tlsio_openssl_dowork,
    tlsio_openssl_setoption
};

static void indicate_open_complete(TLS_IO_INSTANCE* tls_io_instance, IO_OPEN_RESULT open_result)
{
    if (tls_io_instance->on_io_open_complete == NULL)
    {
        LogError("NULL on_io_open_complete.");
    }
    else
    {
        /* Codes_TLSIO_SSL_ESP8266_99_002: [ The tlsio_ssl_esp8266 shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h.]*/
        tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, open_result);
    }
}


static int lwip_net_errno(int fd)
{
    int sock_errno = 0;
    u32_t optlen = sizeof(sock_errno);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
    return sock_errno;
}

static void lwip_set_non_block(int fd)
{
  int flags = -1;
  int error = 0;

  while((void)1,1){
      flags = fcntl(fd, F_GETFL, 0);
      if (flags == -1){
          error = lwip_net_errno(fd);
          if (error != EINTR){
              break;
          }
      } else{
          break;
      }
  }

  fcntl(fd, F_SETFL, O_NONBLOCK);

}

LOCAL int openssl_thread_LWIP_CONNECTION(TLS_IO_INSTANCE* p)
{
    //LogInfo("openssl_thread_LWIP_CONNECTION begin: %d", system_get_free_heap_size());
    //system_show_malloc();

    int result = 0;
    int ret = 0;
    int sock;

    struct sockaddr_in sock_addr;
    fd_set readset;
    fd_set writeset;
    fd_set errset;
    SSL_CTX *ctx;
    SSL *ssl;

    TLS_IO_INSTANCE* tls_io_instance = p;

    LogInfo("OpenSSL thread start...");

    {
        LogInfo("create SSL context");
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_085: [ If SSL_CTX_new failed, the tlsio_openssl_open shall return __LINE__. ] */
        ctx = SSL_CTX_new(TLSv1_client_method());
        if (ctx == NULL) {
            result = __LINE__;
            LogError("create new SSL CTX failed");
        }
        else
        {
            tls_io_instance->ssl_context = ctx;
            LogInfo("set SSL context read buffer size");
            SSL_CTX_set_default_read_buffer_len(ctx, OPENSSL_FRAGMENT_SIZE);
            // LogInfo("create socket ......");
            // LogInfo("size before creating socket: %d", system_get_free_heap_size());
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_080: [ If socket failed, the tlsio_openssl_open shall return __LINE__. ] */
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                result = __LINE__;
                LogError("create socket failed");
            }
            else
            {
                int keepAlive = 1; //enable keepalive
                int keepIdle = 20; //20s
                int keepInterval = 2; //2s
                int keepCount = 3; //retry # of times

                tls_io_instance->sock = sock;
                LogInfo("sock: %d", sock);
                LogInfo("create socket OK");

                LogInfo("set socket keep-alive ");

                ret = 0;
                ret = ret || setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
                ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
                ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
                ret = ret || setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

                if (ret != 0){
                    result = __LINE__;
                    LogError("set socket keep-alive failed, ret = %d ", ret);
                }
                else
                {
                    LogInfo("set socket keep-alive OK");

                    lwip_set_non_block(sock);

                    LogInfo("bind socket ......");
                    memset(&sock_addr, 0, sizeof(sock_addr));
                    sock_addr.sin_family = AF_INET;
                    sock_addr.sin_addr.s_addr = 0;
                    sock_addr.sin_port = 0; // random local port
                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_082: [ If bind failed, the tlsio_openssl_open shall return __LINE__. ] */
                    ret = bind(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

                    // LogInfo("bind return: %d", ret);
                    if (ret != 0) {
                        result = __LINE__;
                        LogError("bind socket failed");
                    }
                    else
                    {
                        LogInfo("bind socket OK");

                        memset(&sock_addr, 0, sizeof(sock_addr));
                        sock_addr.sin_family = AF_INET;
                        sock_addr.sin_addr.s_addr = tls_io_instance->target_ip.addr;
                        sock_addr.sin_port = (in_port_t)htons(tls_io_instance->port);

                        ret = connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
                        //LogInfo("connect return: %d %s", ret, ip_ntoa(&tls_io_instance->target_ip));
                        //LogInfo("EINPROGRESS: %d", EINPROGRESS);
                        if (ret == -1) {
                            ret = lwip_net_errno(sock);
                            LogInfo("lwip_net_errno ret: %d", ret);
                            /* Codes_SRS_TLSIO_SSL_ESP8266_99_083: [ If connect and getsockopt failed, the tlsio_openssl_open shall return __LINE__. ] */
                            if (ret != 115) { // EINPROGRESS
                                result = __LINE__;
                                ret = -1;
                                LogError("socket connect failed, not EINPROGRESS %s", tls_io_instance->hostname);
                            }
                        }

                        if(ret != -1)
                        {
                            FD_ZERO(&readset);
                            FD_ZERO(&writeset);
                            FD_ZERO(&errset);

                            FD_SET(sock, &readset);
                            FD_SET(sock, &writeset);
                            FD_SET(sock, &errset);

                            ret = lwip_select(sock + 1, NULL, &writeset, &errset, NULL);
                            if (ret <= 0) {
                                result = __LINE__;
                                LogError("select failed: %d", lwip_net_errno(sock));
                            } else
                            {
                                if (!FD_ISSET(sock, &writeset) || FD_ISSET(sock, &errset)) {
                                    result = __LINE__;
                                    LogError("socket Error: %d", lwip_net_errno(sock));
                                }else
                                {
                                    {
                                        LogInfo("Socket Connect OK");
                                        /* Codes_SRS_TLSIO_SSL_ESP8266_99_087: [ If SSL_new failed, the tlsio_openssl_open shall return __LINE__. ] */
                                        ssl = SSL_new(ctx);
                                        //LogInfo("after ssl new");
                                        if (ssl == NULL) {
                                            result = __LINE__;
                                            LogError("create ssl failed");
                                        }
                                        else
                                        {

                                            tls_io_instance->ssl = ssl;
                                            // LogInfo("SSL set fd");
                                            /* Codes_SRS_TLSIO_SSL_ESP8266_99_088: [ If SSL_set_fd failed, the tlsio_openssl_open shall return __LINE__. ] */
                                            ret = SSL_set_fd(ssl, sock);
                                            LogInfo("SSL_set_fd ret:%d", ret);
                                            if (ret != 1){
                                                result = __LINE__;
                                                LogError("SSL_set_fd failed");
                                            }
                                            else{
                                                int retry_connect = 0;
                                                int connect_succeeded = false;

                                                LogInfo("SSL connect... ");

                                                FD_ZERO(&readset);
                                                FD_SET(sock, &readset);
                                                FD_ZERO(&writeset);
                                                FD_SET(sock, &writeset);
                                                FD_ZERO(&errset);
                                                FD_SET(sock, &errset);

                                                /* Codes_SRS_TLSIO_SSL_ESP8266_99_027: [ The tlsio_openssl_open shall set the tlsio to try to open the connection for MAX_RETRY times before assuming that connection failed. ]*/
                                                while (retry_connect < MAX_RETRY)
                                                {
                                                    int ssl_state;

                                                    ret = lwip_select(sock + 1, &readset, &writeset, &errset, &timeout);

                                                    if (ret == 0) {
                                                        result = __LINE__;
                                                        LogInfo("SSL connect timeout");
                                                        break;
                                                    }
                                                    if (FD_ISSET(sock, &errset)) {
                                                        unsigned int len;
                                                        result = __LINE__;
                                                        LogInfo("error return : %d", lwip_net_errno(sock));
                                                        len = (unsigned int) sizeof( int );
                                                        if (0 != getsockopt (sock, SOL_SOCKET, SO_ERROR, &ret, &len))
                                                            LogInfo("SSL error ret : %d", ret);   // socket is in error state
                                                        break;
                                                    }

                                                    ret = SSL_connect(ssl);
                                                    if (ret == 1) { // ssl connect success
                                                        connect_succeeded = true;
                                                        break;
                                                    }

                                                    FD_ZERO(&readset);
                                                    FD_ZERO(&writeset);
                                                    FD_ZERO(&errset);
                                                    FD_SET(sock, &errset);

                                                    ssl_state = SSL_get_error(ssl, ret);
                                                    if (ssl_state == SSL_ERROR_WANT_READ) {
                                                        FD_SET(sock, &readset);
                                                    } else if(ssl_state == SSL_ERROR_WANT_WRITE) {
                                                        FD_SET(sock, &writeset);
                                                    } else {
                                                        LogInfo("SSL state:%d", ssl_state);
                                                        result = __LINE__;
                                                        break;
                                                    }

                                                    retry_connect = retry_connect + 1;
                                                    //LogInfo("SSL connect retry: %d", retry_connect);
                                                    os_delay_us(RETRY_DELAY);
                                                }

                                                /* Codes_SRS_TLSIO_SSL_ESP8266_99_089: [ If SSL_connect failed, the tlsio_openssl_open shall return __LINE__. ] */
                                                if (connect_succeeded == false)
                                                {
                                                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_042: [ If the tlsio_openssl_open retry SSL_connect to open more than MAX_RETRY times without success, it shall return __LINE__. ]*/
                                                    result = __LINE__;
                                                    LogError("SSL_connect failed");
                                                }else{
                                                    LogInfo("SSL connect ok");
                                                    result = 0;
                                                }
                                            }
                                        }
                                    }

                                }
                            }
                        }
                    }

                }
            }

        }
    }
    //LogInfo("openssl_thread_LWIP_CONNECTION end: %d", system_get_free_heap_size());

    if(result!=0){
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
    }
    return result;
}

static int decode_ssl_received_bytes(TLS_IO_INSTANCE* tls_io_instance)
{
    int result;
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_075: [ The tlsio_openssl_dowork shall create a buffer to store the data received from the ssl client. ]*/
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_076: [ The tlsio_openssl_dowork shall delete the buffer to store the data received from the ssl client. ]*/
    unsigned char buffer[RECEIVE_BUFFER_SIZE];
    int rcv_bytes;

    rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
    // LogInfo("ssl_read: rcv_bytes %d", rcv_bytes);
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_071: [ If there are no received data in the ssl client, the tlsio_openssl_dowork shall do nothing. ]*/
    if (rcv_bytes >= 0)
    {
        result = 0;
        if (tls_io_instance->on_bytes_received == NULL)
        {
            LogError("NULL on_bytes_received.");
        }
        else
        {
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_070: [ If there are received data in the ssl client, the tlsio_openssl_dowork shall read this data and call the on_bytes_received with the pointer to the buffer with the data. ]*/
            tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
        }
    }
    else{
        result = __LINE__;
    }

    return result;
}

static int destroy_openssl_instance(TLS_IO_INSTANCE* tls_io_instance)
{
    int result = 0;
    //LogInfo("destroy openssl begin: %d", system_get_free_heap_size());
    if (tls_io_instance != NULL)
    {
        if (tls_io_instance->ssl != NULL)
        {
            SSL_free(tls_io_instance->ssl);
            tls_io_instance->ssl = NULL;
            LogInfo("SSL_free");
        }
        if (tls_io_instance->sock >= 0)
        {
            int close_ret = close(tls_io_instance->sock);
            if (close_ret != 0){
                result = __LINE__;;
                LogError("close socket failed");
            }
            LogInfo("close socket");
        }
        if (tls_io_instance->ssl_context != NULL)
        {
            SSL_CTX_free(tls_io_instance->ssl_context);
            tls_io_instance->ssl_context = NULL;
            LogInfo("SSL_ctx_free");
        }

        //LogInfo("destroy end: %d", system_get_free_heap_size());
    }

    return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_005: [ The tlsio_ssl_esp8266 shall received the connection information using the TLSIO_CONFIG structure defined in tlsio.h. ]*/
/* Codes_SRS_TLSIO_SSL_ESP8266_99_009: [ The tlsio_openssl_create shall create a new instance of the tlsio for esp8266. ]*/
/* Codes_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
    //LogInfo("tlsio_openssl_create begin: %d", system_get_free_heap_size());
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_005: [ The tlsio_ssl_esp8266 shall received the connection information using the TLSIO_CONFIG structure defined in tlsio.h. ]*/
    /* Codes_SRS_TLSIO_SSL_ESP8266_99_017: [ The tlsio_openssl_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
    TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
    TLS_IO_INSTANCE* result;

    /* Codes_SRS_TLSIO_SSL_ESP8266_99_013: [ The tlsio_openssl_create shall return NULL when io_create_parameters is NULL. ]*/
    if (tls_io_config == NULL)
    {
        result = NULL;
        LogError("NULL tls_io_config.");
    }
    else
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_011: [ The tlsio_openssl_create shall allocate memory to control the tlsio instance. ]*/
        result = (TLS_IO_INSTANCE*) malloc(sizeof(TLS_IO_INSTANCE));

        if (result == NULL)
        {
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_012: [ If there is not enough memory to create the tlsio, the tlsio_openssl_create shall return NULL as the handle. ]*/
            LogError("Failed allocating TLSIO instance.");
        }
        else
        {
            memset(result, 0, sizeof(TLS_IO_INSTANCE));
            mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
            result->port = (int)tls_io_config->port;
            result->ssl_context = NULL;
            result->ssl = NULL;
            result->certificate = NULL;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_016: [ The tlsio_openssl_create shall initialize all callback pointers as NULL. ]*/
            result->on_bytes_received = NULL;
            result->on_bytes_received_context = NULL;

            result->on_io_open_complete = NULL;
            result->on_io_open_complete_context = NULL;

            result->on_io_close_complete = NULL;
            result->on_io_close_complete_context = NULL;

            result->on_io_error = NULL;
            result->on_io_error_context = NULL;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_020: [ If tlsio_openssl_create get success to create the tlsio instance, it shall set the tlsio state as TLSIO_STATE_NOT_OPEN. ]*/
            result->tlsio_state = TLSIO_STATE_NOT_OPEN;

            result->x509certificate = NULL;
            result->x509privatekey = NULL;
        }
    }

    /* Codes_SRS_TLSIO_SSL_ESP8266_99_010: [ The tlsio_openssl_create shall return a non-NULL handle on success. ]*/
    return (CONCRETE_IO_HANDLE)result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_021: [ The tlsio_openssl_destroy shall destroy a created instance of the tlsio for esp8266 identified by the CONCRETE_IO_HANDLE. ]*/
void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

    /* Codes_SRS_TLSIO_SSL_ESP8266_99_024: [ If the tlsio_handle is NULL, the tlsio_openssl_destroy shall not do anything. ]*/
    if (tls_io == NULL)
    {
        LogError("NULL tls_io.");
    }
    else
    {

        /* Codes_SRS_TLSIO_SSL_ESP8266_99_025: [ If the tlsio state is TLSIO_STATE_OPENING, TLSIO_STATE_OPEN, or TLSIO_STATE_CLOSING, the tlsio_openssl_destroy shall destroy the tlsio, but log an error. ]*/
        if ((tls_io_instance->tlsio_state == TLSIO_STATE_OPENING) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING))
        {
            LogError("TLS destroyed with a SSL connection still active.");
        }
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_022: [ The tlsio_openssl_destroy shall free all memory allocated for tlsio_instance. ]*/
        if (tls_io_instance->certificate != NULL)
        {
            free(tls_io_instance->certificate);
        }
        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }
        if (tls_io_instance->x509certificate != NULL)
        {
            free((void*)tls_io_instance->x509certificate);
        }
        if (tls_io_instance->x509privatekey != NULL)
        {
            free((void*)tls_io_instance->x509privatekey);
        }
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_021: [ The tlsio_openssl_destroy shall destroy a created instance of the tlsio for esp8266 identified by the CONCRETE_IO_HANDLE. ]*/
        free(tls_io_instance);
    }
    //LogInfo("tlsio_openssl_destroy end: %d", system_get_free_heap_size());
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_026: [ The tlsio_openssl_open shall start the process to open the ssl connection with the host provided in the tlsio_openssl_create. ]*/
int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    //LogInfo("tlsio_openssl_open begin: %d", system_get_free_heap_size());
    int result;

    if (tls_io == NULL)
    {
        /* Codes_TLSIO_SSL_ESP8266_99_036: [ If the tls_io handle is NULL, the tlsio_openssl_open shall not do anything, and return _LINE_. ]*/
        result = __LINE__;
        LogError("NULL tls_io.");
    }
    else
    {

        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        /* Codes_SRS_TLSIO_SSL_ESP8266_99_035: [ If the tlsio state is not TLSIO_STATE_NOT_OPEN and not TLSIO_STATE_ERROR, then tlsio_openssl_open shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_. ]*/
        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN && tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            result = __LINE__;
            LogError("Invalid tlsio_state for open. Expected state is TLSIO_STATE_NOT_OPEN or TLSIO_STATE_ERROR.");
            if (tls_io_instance->on_io_error != NULL)
            {
                tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
            }
        }
        else
        {
            int netconn_retry = 0;
            int ret;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_004: [ The tlsio_ssl_esp8266 shall call the callbacks functions defined in the xio.h. ]*/
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_006: [ The tlsio_ssl_esp8266 shall return the status of all async operations using the callbacks. ]*/
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_007: [ If the callback function is set as NULL. The tlsio_ssl_esp8266 shall not call anything. ]*/
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_028: [ The tlsio_openssl_open shall store the provided on_io_open_complete callback function address. ]*/
            tls_io_instance->on_io_open_complete = on_io_open_complete;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_029: [ The tlsio_openssl_open shall store the provided on_io_open_complete_context handle. ]*/
            tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_030: [ The tlsio_openssl_open shall store the provided on_bytes_received callback function address. ]*/
            tls_io_instance->on_bytes_received = on_bytes_received;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_031: [ The tlsio_openssl_open shall store the provided on_bytes_received_context handle. ]*/
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_032: [ The tlsio_openssl_open shall store the provided on_io_error callback function address. ]*/
            tls_io_instance->on_io_error = on_io_error;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_033: [ The tlsio_openssl_open shall store the provided on_io_error_context handle. ]*/
            tls_io_instance->on_io_error_context = on_io_error_context;

            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING;

            do {
                //LogInfo("size before netconn_gethostbyname: %d", system_get_free_heap_size());
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_018: [ The tlsio_openssl_open shall convert the provide hostName to an IP address. ]*/
                ret = netconn_gethostbyname(tls_io_instance->hostname, &tls_io_instance->target_ip);
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_027: [ The tlsio_openssl_open shall set the tlsio to try to open the connection for MAX_RETRY times before assuming that connection failed. ]*/
            } while((ret != 0) && netconn_retry++ < MAX_RETRY);

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_019: [ If the WiFi cannot find the IP for the hostName, the tlsio_openssl_open shall return __LINE__. ]*/
            if (ret != 0 || openssl_thread_LWIP_CONNECTION(tls_io_instance) != 0){
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_039: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_ERROR. ]*/
                indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_037: [ If the ssl client is not connected, the tlsio_openssl_open shall change the state to TLSIO_STATE_ERROR, log the error, and return _LINE_. ]*/
                result = __LINE__;
                LogError("openssl_thread_LWIP_CONNECTION failed.");
                if (tls_io_instance->on_io_error != NULL)
                {
                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_040: [ If the tlsio_openssl_open failed to open the tls connection, and the on_io_error callback was provided, it shall call the on_io_error. ]*/
                    tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
                }
            }else{
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_034: [ If tlsio_openssl_open get success to open the ssl connection, it shall set the tlsio state as TLSIO_STATE_OPEN, and return 0. ]*/
                tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_041: [ If the tlsio_openssl_open get success to open the tls connection, and the on_io_open_complete callback was provided, it shall call the on_io_open_complete with IO_OPEN_OK. ]*/
                indicate_open_complete(tls_io_instance, IO_OPEN_OK);
                result = 0;
                os_delay_us(5000000); //delay added to give reconnect time to send last message
                //LogInfo("tlsio_openssl_open end: %d", system_get_free_heap_size());
            }
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_043: [ The tlsio_openssl_close shall start the process to close the ssl connection. ]*/
int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    //LogInfo("tlsio_openssl_close begin: %d", system_get_free_heap_size());
    LogInfo("tlsio_openssl_close");

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_049: [ If the tlsio_handle is NULL, the tlsio_openssl_close shall not do anything, and return _LINE_. ]*/
        result = __LINE__;
        LogError("NULL tls_io.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_048: [ If the tlsio state is TLSIO_STATE_NOT_OPEN, TLSIO_STATE_OPENING, or TLSIO_STATE_CLOSING, the tlsio_openssl_close shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_. ]*/
        if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_OPENING))
        {
            result = __LINE__;
            tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            LogError("Invalid tlsio_state for close. Expected state is TLSIO_STATE_OPEN or TLSIO_STATE_ERROR.");
        }
        else
        {
            int ret;

            /* Codes_SRS_TLSIO_SSL_ESP8266_99_045: [ The tlsio_openssl_close shall store the provided on_io_close_complete callback function address. ]*/
            tls_io_instance->on_io_close_complete = on_io_close_complete;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_046: [ The tlsio_openssl_close shall store the provided on_io_close_complete_context handle. ]*/
            tls_io_instance->on_io_close_complete_context = callback_context;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_047: [ If tlsio_openssl_close get success to start the process to close the ssl connection, it shall set the tlsio state as TLSIO_STATE_CLOSING, and return 0. ]*/
            tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;

            ret = destroy_openssl_instance(tls_io_instance);
            if (ret != 0)
            {
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_052: [ If tlsio_openssl_close fails to shutdown the ssl connection, it shall set the tlsio state as TLSIO_STATE_ERROR, and return _LINE_, and call on_io_error. ]*/
                result = __LINE__;
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                if (tls_io_instance->on_io_error != NULL)
                {
                    tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
                }
            }
            else
            {

                /* Codes_SRS_TLSIO_SSL_ESP8266_99_050: [ If tlsio_openssl_close successfully destroys the ssl connection, it shall set the tlsio state as TLSIO_STATE_NOT_OPEN, and return 0. ]*/
                tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                result = 0;
                if (tls_io_instance->on_io_close_complete != NULL)
                {
                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_051: [ If tlsio_openssl_close successfully destroys the ssl connection, it shall call on_io_close_complete. ]*/
                    tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
                }
            }
        }
    }
    //LogInfo("tlsio_openssl_close end: %d", system_get_free_heap_size());
    return result;
}
/* Codes_SRS_TLSIO_SSL_ESP8266_99_053: [ The tlsio_openssl_send shall send all bytes in a buffer to the ssl connection. ]*/
int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;

    if ((tls_io == NULL) || (buffer == NULL) || (size == 0))
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_060: [ If the tls_io handle is NULL, the tlsio_openssl_send shall not do anything, and return _LINE_. ]*/
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_061: [ If the buffer is NULL, the tlsio_openssl_send shall not do anything, and return _LINE_. ]*/
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_062: [ If the size is 0, the tlsio_openssl_send shall not do anything, and return _LINE_. ]*/
        result = __LINE__;
        LogError("Invalid parameter.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_059: [ If the tlsio state is not TLSIO_STATE_OPEN, the tlsio_openssl_send shall return _LINE_. ]*/
            result = __LINE__;
            LogError("TLS is not ready to send data. Expected state is TLSIO_STATE_OPEN.");
            //LogInfo("TLS is not ready to send data. Expected state is TLSIO_STATE_OPEN.");
        }
        else
        {
            int total_write = 0;
            int ret = 0;
            int need_sent_bytes = (int)size;

            fd_set writeset;
            fd_set errset;
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_056: [ The ssl will continue to send all data in the buffer until all bytes have been sent. ]*/
            while(need_sent_bytes > 0)
            {
                FD_ZERO(&writeset);
                FD_SET(tls_io_instance->sock, &writeset);
                FD_ZERO(&errset);
                FD_SET(tls_io_instance->sock, &errset);

                ret = lwip_select(tls_io_instance->sock + 1, NULL, &writeset, &errset, &timeout);
                if (ret == 0) {
                    result = __LINE__;
                    LogError("select timeout and no data to be write");
                    break;
                } else if (ret < 0 || FD_ISSET(tls_io_instance->sock, &errset)) {
                    result = __LINE__;
                    LogError("get error %d", lwip_net_errno(tls_io_instance->sock));
                    break;
                }
                ret = SSL_write(tls_io_instance->ssl, ((uint8*)buffer)+total_write, (int)size);
                // LogInfo("SSL_write ret: %d", ret);
                //LogInfo("SSL_write res: %d, size: %d, retry: %d", res, size, retry);
                if(ret > 0){
                    total_write += ret;
                    need_sent_bytes = need_sent_bytes - ret;
                }
                else
                {
                    result = __LINE__;
                    LogError("SSL_write failed.");
                    break;
                }
            }

            if (need_sent_bytes != 0)
            {
                LogInfo("ssl write failed, return [-0x%x]", -ret);

                ret = SSL_shutdown(tls_io_instance->ssl);
                LogInfo("SSL_shutdown ret: %d", ret);

                /* Codes_SRS_TLSIO_SSL_ESP8266_99_054: [ The tlsio_openssl_send shall use the provided on_io_send_complete callback function address. ]*/
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_055: [ The tlsio_openssl_send shall use the provided on_io_send_complete_context handle. ]*/
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_057: [ If the ssl was not able to send all the bytes in the buffer, the tlsio_openssl_send shall call the on_send_complete with IO_SEND_ERROR, and return _LINE_. ]*/
                result = __LINE__;
                if (on_send_complete != NULL)
                {
                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_003: [ The tlsio_ssl_esp8266 shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h. ]*/
                    on_send_complete(callback_context, IO_SEND_ERROR);
                }
            }
            else
            {
                result = 0;
                // LogInfo("SSL Write OK");
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_058: [ If the ssl finish to send all bytes in the buffer, then tlsio_openssl_send shall call the on_send_complete with IO_SEND_OK, and return 0 ]*/
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_054: [ The tlsio_openssl_send shall use the provided on_io_send_complete callback function address. ]*/
                /* Codes_SRS_TLSIO_SSL_ESP8266_99_055: [ The tlsio_openssl_send shall use the provided on_io_send_complete_context handle. ]*/
                if (on_send_complete != NULL)
                {
                    /* Codes_SRS_TLSIO_SSL_ESP8266_99_003: [ The tlsio_ssl_esp8266 shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h. ]*/
                    on_send_complete(callback_context, IO_SEND_OK);
                }
            }

            // LogInfo("total write: %d", total_write);
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_063: [ The tlsio_openssl_dowork shall execute the async jobs for the tlsio. ]*/
void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_SSL_ESP8266_99_074: [ If the tlsio handle is NULL, the tlsio_openssl_dowork shall not do anything. ]*/
        LogError("NULL tls_io.");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            /* Codes_SRS_TLSIO_SSL_ESP8266_99_069: [ If the tlsio state is TLSIO_STATE_OPEN, the tlsio_openssl_dowork shall read data from the ssl client. ]*/
            int ret = decode_ssl_received_bytes(tls_io_instance);
            if (ret != 0)
            {
                ret = SSL_shutdown(tls_io_instance->ssl);
                //LogInfo("SSL_shutdown ret: %d", ret);
            }
        }
        else
        {
            //LogError("Invalid tlsio_state for dowork. Expected state is TLSIO_STATE_OPEN.");
        }
    }

}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_077: [ The tlsio_openssl_setoption shall not do anything, and return 0. ]*/
int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    (void)tls_io, (void)optionName, (void)value;

    /* Not implementing any options */
    return 0;
}

/* Codes_SRS_TLSIO_SSL_ESP8266_99_008: [ The tlsio_openssl_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void)
{
    return &tlsio_openssl_interface_description;
}
