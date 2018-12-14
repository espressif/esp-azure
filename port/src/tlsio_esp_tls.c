// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This component was written to conform to the tlsio_requirements.md specification located
// in the Azure IoT C Utility: 
// https://github.com/Azure/azure-c-shared-utility/blob/master/devdoc/tlsio_requirements.md
// Comments throughout this code refer to requirements in that spec.

#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "tlsio_pal.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/tlsio_options.h"

#include "esp_tls.h"

typedef struct
{
    unsigned char* bytes;
    size_t size;
    size_t unsent_size;
    ON_SEND_COMPLETE on_send_complete;
    void* callback_context;
} PENDING_TRANSMISSION;

#define MAX_VALID_PORT 0xffff

// The TLSIO_RECEIVE_BUFFER_SIZE has very little effect on performance, and is kept small
// to minimize memory consumption.
#define TLSIO_RECEIVE_BUFFER_SIZE 64


typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_CLOSED,
    TLSIO_STATE_INIT,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_ERROR,
} TLSIO_STATE;

bool is_an_opening_state(TLSIO_STATE state)
{
    return state == TLSIO_STATE_INIT;
}

// This structure definition is mirrored in the unit tests, so if you change
typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    ON_IO_OPEN_COMPLETE on_open_complete;
    void* on_bytes_received_context;
    void* on_io_error_context;
    void* on_open_complete_context;
    esp_tls_cfg_t esp_tls_cfg;
    esp_tls_t   *esp_tls_handle;
    TLSIO_STATE tlsio_state;
    uint16_t port;
    char* hostname;
    SINGLYLINKEDLIST_HANDLE pending_transmission_list;
    TLSIO_OPTIONS options;
} TLS_IO_INSTANCE;

/* Codes_SRS_TLSIO_30_005: [ The phrase "enter TLSIO_STATE_EXT_ERROR" means the adapter shall call the on_io_error function and pass the on_io_error_context that was supplied in tlsio_open_async. ]*/
static void enter_tlsio_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

// Return true if a message was available to remove
static bool process_and_destroy_head_message(TLS_IO_INSTANCE* tls_io_instance, IO_SEND_RESULT send_result)
{
    bool result;
    LIST_ITEM_HANDLE head_pending_io;
    if (send_result == IO_SEND_ERROR)
    {
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        enter_tlsio_error_state(tls_io_instance);
    }
    head_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    if (head_pending_io != NULL)
    {
        PENDING_TRANSMISSION* head_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(head_pending_io);
        // Must remove the item from the list before calling the callback because 
        // SRS_TLSIO_30_091: [ If  tlsio_esp_tls_dowork  is able to send all the bytes in an enqueued message, it shall first dequeue the message then call the messages's  on_send_complete  along with its associated  callback_context  and  IO_SEND_OK . ]
        if (singlylinkedlist_remove(tls_io_instance->pending_transmission_list, head_pending_io) != 0)
        {
            // This particular situation is a bizarre and unrecoverable internal error
            /* Codes_SRS_TLSIO_30_094: [ If the send process encounters an internal error or calls on_send_complete with IO_SEND_ERROR due to either failure or timeout, it shall also call on_io_error and pass in the associated on_io_error_context. ]*/
            enter_tlsio_error_state(tls_io_instance);
            LogError("Failed to remove message from list");
        }
        // on_send_complete is checked for NULL during PENDING_TRANSMISSION creation
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        head_message->on_send_complete(head_message->callback_context, send_result);

        free(head_message->bytes);
        free(head_message);
        result = true;
    }
    else
    {
        result = false;
    }
    return result;
}

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
    /* Codes_SRS_TLSIO_30_009: [ The phrase "enter TLSIO_STATE_EXT_CLOSING" means the adapter shall iterate through any unsent messages in the queue and shall delete each message after calling its on_send_complete with the associated callback_context and IO_SEND_CANCELLED. ]*/
    /* Codes_SRS_TLSIO_30_006: [ The phrase "enter TLSIO_STATE_EXT_CLOSED" means the adapter shall forcibly close any existing connections then call the on_io_close_complete function and pass the on_io_close_complete_context that was supplied in tlsio_close_async. ]*/
    /* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EXT_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/

    esp_tls_conn_delete(tls_io_instance->esp_tls_handle);
    while (process_and_destroy_head_message(tls_io_instance, IO_SEND_CANCELLED));
    // singlylinkedlist_destroy gets called in the main destroy

    tls_io_instance->on_bytes_received = NULL;
    tls_io_instance->on_io_error = NULL;
    tls_io_instance->on_bytes_received_context = NULL;
    tls_io_instance->on_io_error_context = NULL;
    tls_io_instance->tlsio_state = TLSIO_STATE_CLOSED;
    tls_io_instance->on_open_complete = NULL;
    tls_io_instance->on_open_complete_context = NULL;
}

static void tlsio_esp_tls_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_020: [ If tlsio_handle is NULL, tlsio_destroy shall do nothing. ]*/
        LogError("NULL tlsio");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
        if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
        {
            /* Codes_SRS_TLSIO_30_022: [ If the adapter is in any state other than TLSIO_STATE_EX_CLOSED when tlsio_destroy is called, the adapter shall enter TLSIO_STATE_EX_CLOSING and then enter TLSIO_STATE_EX_CLOSED before completing the destroy process. ]*/
            LogError("tlsio_esp_tls_destroy called while not in TLSIO_STATE_CLOSED.");
            internal_close(tls_io_instance);
        }
        /* Codes_SRS_TLSIO_30_021: [ The tlsio_destroy shall release all allocated resources and then release tlsio_handle. ]*/
        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }
        
        tlsio_options_release_resources(&tls_io_instance->options);

        if (tls_io_instance->pending_transmission_list != NULL)
        {
            /* Pending messages were cleared in internal_close */
            singlylinkedlist_destroy(tls_io_instance->pending_transmission_list);
        }
        free(tls_io_instance);
    }
}

/* Codes_SRS_TLSIO_30_010: [ The tlsio_esp_tls_create shall allocate and initialize all necessary resources and return an instance of the tlsio_esp_tls. ]*/
static CONCRETE_IO_HANDLE tlsio_esp_tls_create(void* io_create_parameters)
{
    TLS_IO_INSTANCE* result;

    if (io_create_parameters == NULL)
    {
        /* Codes_SRS_TLSIO_30_013: [ If the io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
        LogError("NULL tls_io_config");
        result = NULL;
    }
    else
    {
        /* Codes_SRS_TLSIO_30_012: [ The tlsio_create shall receive the connection configuration as a TLSIO_CONFIG* in io_create_parameters. ]*/
        TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
        if (tls_io_config->hostname == NULL)
        {
            /* Codes_SRS_TLSIO_30_014: [ If the hostname member of io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
            LogError("NULL tls_io_config->hostname");
            result = NULL;
        }
        else if (tls_io_config->port < 0 || tls_io_config->port > MAX_VALID_PORT)
        {
            /* Codes_SRS_TLSIO_30_015: [ If the port member of io_create_parameters value is less than 0 or greater than 0xffff, tlsio_esp_tls_create shall log an error and return NULL. ]*/
            LogError("tls_io_config->port out of range");
            result = NULL;
        }
        else
        {
            result = malloc(sizeof(TLS_IO_INSTANCE));
            if (result == NULL)
            {
                /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_esp_tls_create shall return NULL. ]*/
                LogError("malloc failed");
            }
            else
            {
                int ms_result;
                memset(result, 0, sizeof(TLS_IO_INSTANCE));
                result->port = (uint16_t)tls_io_config->port;
                result->tlsio_state = TLSIO_STATE_CLOSED;
                result->hostname = NULL;

                result->pending_transmission_list = NULL;
                tlsio_options_initialize(&result->options, TLSIO_OPTION_BIT_TRUSTED_CERTS |
                TLSIO_OPTION_BIT_x509_RSA_CERT | TLSIO_OPTION_BIT_x509_ECC_CERT);
                result->esp_tls_handle = calloc(1, sizeof(esp_tls_t));
                if (result->esp_tls_handle == NULL)
                {
                    /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                    LogError("malloc failed");
                    tlsio_esp_tls_destroy(result);
                    result = NULL;
                }

                /* Codes_SRS_TLSIO_30_016: [ tlsio_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
                ms_result = mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
                if (ms_result != 0)
                {
                    /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                    LogError("malloc failed");
                    tlsio_esp_tls_destroy(result);
                    result = NULL;
                }
                else
                {
                    // Create the message queue
                    result->pending_transmission_list = singlylinkedlist_create();
                    if (result->pending_transmission_list == NULL)
                    {
                        /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                        LogError("Failed singlylinkedlist_create");
                        tlsio_esp_tls_destroy(result);
                        result = NULL;
                    }
                }
            }
        }
    }

    return (CONCRETE_IO_HANDLE)result;
}


static int tlsio_esp_tls_open_async(CONCRETE_IO_HANDLE tls_io,
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{

    int result;
    if (on_io_open_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
        LogError("Required parameter on_io_open_complete is NULL");
        result = __FAILURE__;
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_030: [ If the tlsio_handle parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL tlsio");
        }
        else
        {
            if (on_bytes_received == NULL)
            {
                /* Codes_SRS_TLSIO_30_032: [ If the on_bytes_received parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                LogError("Required parameter on_bytes_received is NULL");
                result = __FAILURE__;
            }
            else
            {
                if (on_io_error == NULL)
                {
                    /* Codes_SRS_TLSIO_30_033: [ If the on_io_error parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                    LogError("Required parameter on_io_error is NULL");
                    result = __FAILURE__;
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

                    if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
                    {
                        /* Codes_SRS_TLSIO_30_037: [ If the adapter is in any state other than TLSIO_STATE_EXT_CLOSED when tlsio_open  is called, it shall log an error, and return FAILURE. ]*/
                        LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_CLOSED.");
                        result = __FAILURE__;
                    }
                    else
                    {

                        /* Codes_SRS_TLSIO_30_034: [ The tlsio_open shall store the provided on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context, on_io_open_complete, and on_io_open_complete_context parameters for later use as specified and tested per other line entries in this document. ]*/
                        tls_io_instance->on_bytes_received = on_bytes_received;
                        tls_io_instance->on_bytes_received_context = on_bytes_received_context;

                        tls_io_instance->on_io_error = on_io_error;
                        tls_io_instance->on_io_error_context = on_io_error_context;

                        tls_io_instance->on_open_complete = on_io_open_complete;
                        tls_io_instance->on_open_complete_context = on_io_open_complete_context;

                        tls_io_instance->esp_tls_cfg.non_block = true;
                        if (tls_io_instance->options.x509_key != NULL && tls_io_instance->options.x509_cert != NULL) {
                            tls_io_instance->esp_tls_cfg.clientcert_pem_buf = (unsigned char *)tls_io_instance->options.x509_cert;
                            tls_io_instance->esp_tls_cfg.clientcert_pem_bytes = strlen(tls_io_instance->options.x509_cert) + 1;
                            tls_io_instance->esp_tls_cfg.clientkey_pem_buf = (unsigned char *)tls_io_instance->options.x509_key;
                            tls_io_instance->esp_tls_cfg.clientkey_pem_bytes = strlen(tls_io_instance->options.x509_key) + 1;
                        }
                        if (tls_io_instance->options.trusted_certs != NULL) {
                            tls_io_instance->esp_tls_cfg.cacert_pem_buf = (unsigned char *)tls_io_instance->options.trusted_certs;
                            tls_io_instance->esp_tls_cfg.cacert_pem_bytes = strlen(tls_io_instance->options.trusted_certs) + 1;
                        }

                        tls_io_instance->tlsio_state = TLSIO_STATE_INIT;
                        result = 0;
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_039: [ On failure, tlsio_open_async shall not call on_io_open_complete. ]*/
    }

    return result;
}

// This implementation does not have asynchronous close, but uses the _async name for consistency with the spec
static int tlsio_esp_tls_close_async(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_050: [ If the tlsio_handle parameter is NULL, tlsio_esp_tls_close_async shall log an error and return FAILURE. ]*/
        LogError("NULL tlsio");
        result = __FAILURE__;
    }
    else
    {
        if (on_io_close_complete == NULL)
        {
            /* Codes_SRS_TLSIO_30_055: [ If the on_io_close_complete parameter is NULL, tlsio_esp_tls_close_async shall log an error and return FAILURE. ]*/
            LogError("NULL on_io_close_complete");
            result = __FAILURE__;
        }
        else
        {
            TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

            if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN &&
                tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
            {
                /* Codes_SRS_TLSIO_30_053: [ If the adapter is in any state other than TLSIO_STATE_EXT_OPEN or TLSIO_STATE_EXT_ERROR then tlsio_close_async shall log that tlsio_close_async has been called and then continue normally. ]*/
                // LogInfo rather than LogError because this is an unusual but not erroneous situation
                LogInfo("tlsio_esp_tls_close has been called when in neither TLSIO_STATE_OPEN nor TLSIO_STATE_ERROR.");
            }

            if (is_an_opening_state(tls_io_instance->tlsio_state))
            {
                /* Codes_SRS_TLSIO_30_057: [ On success, if the adapter is in TLSIO_STATE_EXT_OPENING, it shall call on_io_open_complete with the on_io_open_complete_context supplied in tlsio_open_async and IO_OPEN_CANCELLED. This callback shall be made before changing the internal state of the adapter. ]*/
                tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_CANCELLED);
            }
            // This adapter does not support asynchronous closing
            /* Codes_SRS_TLSIO_30_056: [ On success the adapter shall enter TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EX_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_052: [ On success tlsio_close shall return 0. ]*/
            internal_close(tls_io_instance);
            on_io_close_complete(callback_context);
            result = 0;
        }
    }
    /* Codes_SRS_TLSIO_30_054: [ On failure, the adapter shall not call on_io_close_complete. ]*/
    return result;
}

static void dowork_read(TLS_IO_INSTANCE* tls_io_instance)
{
    // TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
    // then the framework just calls dowork repeatedly until it gets everything. So
    // a bigger buffer would just use memory without buying anything.
    // Putting this buffer in a small function also allows it to exist on the stack
    // rather than adding to heap fragmentation.
    unsigned char buffer[TLSIO_RECEIVE_BUFFER_SIZE];
    int rcv_bytes;

    if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
    {
        rcv_bytes = esp_tls_conn_read(tls_io_instance->esp_tls_handle, buffer, sizeof(buffer));
        while (rcv_bytes > 0)
        {
            // tls_io_instance->on_bytes_received was already checked for NULL
            // in the call to tlsio_esp_tls_open_async
            /* Codes_SRS_TLSIO_30_100: [ As long as the TLS connection is able to provide received data, tlsio_dowork shall repeatedly read this data and call on_bytes_received with the pointer to the buffer containing the data, the number of bytes received, and the on_bytes_received_context. ]*/
            tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
            rcv_bytes = esp_tls_conn_read(tls_io_instance->esp_tls_handle, buffer, sizeof(buffer));
        }
        /* Codes_SRS_TLSIO_30_102: [ If the TLS connection receives no data then tlsio_dowork shall not call the on_bytes_received callback. ]*/
    }
}

static void dowork_send(TLS_IO_INSTANCE* tls_io_instance)
{
    LIST_ITEM_HANDLE first_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    if (first_pending_io != NULL)
    {
        PENDING_TRANSMISSION* pending_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(first_pending_io);
        uint8_t* buffer = ((uint8_t*)pending_message->bytes) +
            pending_message->size - pending_message->unsent_size;
        int write_result = esp_tls_conn_write(tls_io_instance->esp_tls_handle, buffer, pending_message->unsent_size);
        if (write_result > 0)
        {
            pending_message->unsent_size -= write_result;
            if (pending_message->unsent_size == 0)
            {
                /* Codes_SRS_TLSIO_30_091: [ If tlsio_esp_tls_dowork is able to send all the bytes in an enqueued message, it shall call the messages's on_send_complete along with its associated callback_context and IO_SEND_OK. ]*/
                // The whole message has been sent successfully
                process_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
            }
            else
            {
                /* Codes_SRS_TLSIO_30_093: [ If the TLS connection was not able to send an entire enqueued message at once, subsequent calls to tlsio_dowork shall continue to send the remaining bytes. ]*/
                // Repeat the send on the next pass with the rest of the message
                // This empty else compiles to nothing but helps readability
            }
        }
        else
        {
            LogInfo("Error from SSL_write: %d", write_result);
        }
    }
    else
    {
        /* Codes_SRS_TLSIO_30_096: [ If there are no enqueued messages available, tlsio_esp_tls_dowork shall do nothing. ]*/
    }
}

static void tlsio_esp_tls_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_070: [ If the tlsio_handle parameter is NULL, tlsio_dowork shall do nothing except log an error. ]*/
        LogError("NULL tlsio");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        // This switch statement handles all of the state transitions during the opening process
        switch (tls_io_instance->tlsio_state)
        {
        case TLSIO_STATE_CLOSED:
            /* Codes_SRS_TLSIO_30_075: [ If the adapter is in TLSIO_STATE_EXT_CLOSED then  tlsio_dowork  shall do nothing. ]*/
            // Waiting to be opened, nothing to do
            break;
        case TLSIO_STATE_INIT:
            {
            int result = esp_tls_conn_new_async(tls_io_instance->hostname, strlen(tls_io_instance->hostname), tls_io_instance->port, &tls_io_instance->esp_tls_cfg, tls_io_instance->esp_tls_handle);
            if (result == 1) {
                tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
                tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_OK);
            } else if (result == -1) {
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
            }
            }
            break;
        case TLSIO_STATE_OPEN:
            dowork_read(tls_io_instance);
            dowork_send(tls_io_instance);
            break;
        case TLSIO_STATE_ERROR:
            /* Codes_SRS_TLSIO_30_071: [ If the adapter is in TLSIO_STATE_EXT_ERROR then tlsio_dowork shall do nothing. ]*/
            // There's nothing valid to do here but wait to be retried
            break;
        default:
            LogError("Unexpected internal tlsio state");
            break;
        }
    }
}

static int tlsio_esp_tls_send_async(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (on_send_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_062: [ If the on_send_complete is NULL, tlsio_esp_tls_send_async shall log the error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError("NULL on_send_complete");
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_060: [ If the tlsio_handle parameter is NULL, tlsio_esp_tls_send_async shall log an error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL tlsio");
        }
        else
        {
            if (buffer == NULL)
            {
                /* Codes_SRS_TLSIO_30_061: [ If the buffer is NULL, tlsio_esp_tls_send_async shall log the error and return FAILURE. ]*/
                result = __FAILURE__;
                LogError("NULL buffer");
            }
            else
            {
                if (size == 0)
                {
                    /* Codes_SRS_TLSIO_30_067: [ If the  size  is 0,  tlsio_send  shall log the error and return FAILURE. ]*/
                    result = __FAILURE__;
                    LogError("0 size");
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
                    if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
                    {
                        result = __FAILURE__;
                        LogError("tlsio_esp_tls_send_async without a prior successful open");
                    }
                    else
                    {
                        PENDING_TRANSMISSION* pending_transmission = (PENDING_TRANSMISSION*)malloc(sizeof(PENDING_TRANSMISSION));
                        if (pending_transmission == NULL)
                        {
                            /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_esp_tls_send shall log an error and return FAILURE. ]*/
                            result = __FAILURE__;
                            LogError("malloc failed");
                        }
                        else
                        {
                            /* Codes_SRS_TLSIO_30_063: [ The tlsio_esp_tls_send_async shall enqueue for transmission the on_send_complete, the callback_context, the size, and the contents of buffer. ]*/
                            pending_transmission->bytes = (unsigned char*)malloc(size);

                            if (pending_transmission->bytes == NULL)
                            {
                                /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_esp_tls_send shall log an error and return FAILURE. ]*/
                                LogError("malloc failed");
                                free(pending_transmission);
                                result = __FAILURE__;
                            }
                            else
                            {
                                pending_transmission->size = size;
                                pending_transmission->unsent_size = size;
                                pending_transmission->on_send_complete = on_send_complete;
                                pending_transmission->callback_context = callback_context;
                                (void)memcpy(pending_transmission->bytes, buffer, size);

                                if (singlylinkedlist_add(tls_io_instance->pending_transmission_list, pending_transmission) == NULL)
                                {
                                    /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_esp_tls_send_async shall log an error and return FAILURE. ]*/
                                    LogError("Unable to add socket to pending list.");
                                    free(pending_transmission->bytes);
                                    free(pending_transmission);
                                    result = __FAILURE__;
                                }
                                else
                                {
                                    /* Codes_SRS_TLSIO_30_063: [ On success, tlsio_esp_tls_send_async shall enqueue for transmission the  on_send_complete , the  callback_context , the  size , and the contents of  buffer  and then return 0. ]*/
                                    dowork_send(tls_io_instance);
                                    result = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_066: [ On failure, on_send_complete shall not be called. ]*/
    }
    return result;
}

static int tlsio_esp_tls_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_120: [ If the tlsio_handle parameter is NULL, tlsio_esp_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
    int result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = __FAILURE__;
    }
    else
    {
        /* Codes_SRS_TLSIO_30_121: [ If the optionName parameter is NULL, tlsio_esp_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
        /* Codes_SRS_TLSIO_30_122: [ If the value parameter is NULL, tlsio_esp_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
        /* Codes_SRS_TLSIO_ESP_TLS_COMPACT_30_520 [ The tlsio_esp_tls_setoption shall do nothing and return FAILURE. ]*/
        TLSIO_OPTIONS_RESULT options_result = tlsio_options_set(&tls_io_instance->options, optionName, value);
        if (options_result != TLSIO_OPTIONS_RESULT_SUCCESS)
        {
            LogError("Failed tlsio_options_set");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_ESP_TLS_COMPACT_30_560: [ The  tlsio_esp_tls_retrieveoptions  shall do nothing and return an empty options handler. ]*/
static OPTIONHANDLER_HANDLE tlsio_esp_tls_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_160: [ If the tlsio_handle parameter is NULL, tlsio_esp_tls_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
    OPTIONHANDLER_HANDLE result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = NULL;
    }
    else
    {
        result = tlsio_options_retrieve_options(&tls_io_instance->options, tlsio_esp_tls_setoption);
    }
    return result;
}

/* Codes_SRS_TLSIO_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
static const IO_INTERFACE_DESCRIPTION tlsio_esp_tls_interface_description =
{
    tlsio_esp_tls_retrieveoptions,
    tlsio_esp_tls_create,
    tlsio_esp_tls_destroy,
    tlsio_esp_tls_open_async,
    tlsio_esp_tls_close_async,
    tlsio_esp_tls_send_async,
    tlsio_esp_tls_dowork,
    tlsio_esp_tls_setoption
};

/* Codes_SRS_TLSIO_30_001: [ The tlsio_esp_tls shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ]*/
const IO_INTERFACE_DESCRIPTION* tlsio_pal_get_interface_description(void)
{
    return &tlsio_esp_tls_interface_description;
}
