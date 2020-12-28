// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <dlfcn.h>
#ifdef WIN32
#include <Winsock2.h>
#else // WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif // WIN32

#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_utpm_c/gbfiledescript.h"

#include "azure_utpm_c/tpm_comm.h"
#include "azure_utpm_c/tpm_socket_comm.h"

static const char* const TPM_DEVICE_NAME = "/dev/tpm0";
static const char* const TPM_RM_DEVICE_NAME = "/dev/tpmrm0";

static const char* const TPM_TABRMD_USERMODE_RESOURCE_MGR = "libtss2-tcti-tabrmd.so";
static const char* const TPM_ABRMD_USERMODE_RESOURCE_MGR = "libtss2-tcti-abrmd.so";
static const char* const TPM_OLD_USERMODE_RESOURCE_MGR_64 = "/usr/lib/x86_64-linux-gnu/libtctisocket.so.0";
static const char* const TPM_OLD_USERMODE_RESOURCE_MGR_32 = "/usr/lib/i386-linux-gnu/libtctisocket.so.0";
static const char* const TPM_OLD_USERMODE_RESOURCE_MGR_ARM = "/usr/lib/arm-linux-gnueabihf/libtctisocket.so.0";
static const char* const TPM_NEW_USERMODE_RESOURCE_MGR_64 = "/usr/lib/x86_64-linux-gnu/libtcti-socket.so.0";
static const char* const TPM_NEW_USERMODE_RESOURCE_MGR_32 = "/usr/lib/i386-linux-gnu/libtcti-socket.so.0";
static const char* const TPM_NEW_USERMODE_RESOURCE_MGR_ARM = "/usr/lib/arm-linux-gnueabihf/libtcti-socket.so.0";

#define MIN_TPM_RESPONSE_LENGTH     10

#define TPM_UM_RM_PORT              2323

#define REMOTE_SEND_COMMAND         8
#define REMOTE_SESSION_END_CMD      20

static const char* const TPM_UM_RM_ADDRESS = "127.0.0.1";

typedef enum
{
    TCI_NONE = 0,
    TCI_SYS_DEV = 1,
    TCI_SOCKET = 2,
    TCI_OLD_UM_TRM = 4,
    TCI_TCTI = 8,
    TCI_TRM = 0x10
} TPM_CONN_INFO;

typedef struct TPM_COMM_INFO_TAG
{
    uint32_t        timeout_value;
    TPM_CONN_INFO   conn_info;
    union
    {
        int                 tpm_device;
        TPM_SOCKET_HANDLE   socket_conn;
        struct {
            void*   ctx_handle;
            void*   dylib;
        }                   tcti;
    } dev_info;
} TPM_COMM_INFO;

typedef uint32_t TCTI_RC;

#define RC_SUCCESS     0

typedef void* TCTI_HANDLE;

typedef uint32_t (*tcti_init_fn)(TCTI_HANDLE *ctx_handle, size_t *size, const char *cfg);

typedef struct {
    uint32_t version;
    const char *name;
    const char *descr;
    const char *help;
    tcti_init_fn init;
} TCTI_PROV_INFO;

typedef const TCTI_PROV_INFO* (*get_tcti_info_fn)(void);

typedef struct {
    uint64_t magic;
    uint32_t version;
    TCTI_RC (*transmit) (TCTI_HANDLE *h, size_t cmd_size, uint8_t const *command);
    TCTI_RC (*receive) (TCTI_HANDLE *h, size_t *resp_size, uint8_t *response, int32_t timeout);
    void (*finalize) (TCTI_HANDLE *h);
    TCTI_RC (*cancel) (TCTI_HANDLE *h);
    TCTI_RC (*getPollHandles) (TCTI_HANDLE *h, void* handles, size_t *num_handles);
    TCTI_RC (*setLocality) (TCTI_HANDLE *h, uint8_t locality);
} TCTI_CTX;

static int write_data_to_tpm(TPM_COMM_INFO* tpm_info, const unsigned char* tpm_bytes, uint32_t bytes_len)
{
    int result;
    int resp_len = write(tpm_info->dev_info.tpm_device, tpm_bytes, bytes_len);
    if (resp_len != (int)bytes_len)
    {
        LogError("Failure writing data to tpm: %d:%s.", errno, strerror(errno));
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int read_data_from_tpm(TPM_COMM_INFO* tpm_info, unsigned char* tpm_bytes, uint32_t* bytes_len)
{
    int result;
    int len_read = read(tpm_info->dev_info.tpm_device, tpm_bytes, *bytes_len);
    if (len_read < MIN_TPM_RESPONSE_LENGTH)
    {
        LogError("Failure reading data from tpm: len: %d - %d:%s.", len_read, errno, strerror(errno));
        result = MU_FAILURE;
    }
    else
    {
        *bytes_len = len_read;
        result = 0;
    }
    return result;
}

static int read_sync_bytes(TPM_COMM_INFO* comm_info, unsigned char* tpm_bytes, uint32_t* bytes_len)
{
    return tpm_socket_read(comm_info->dev_info.socket_conn, tpm_bytes, *bytes_len);
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
    return tpm_socket_send(comm_info->dev_info.socket_conn, cmd_val, (uint32_t)byte_len);
}

static int send_sync_cmd(TPM_COMM_INFO* tpm_comm_info, uint32_t cmd_val)
{
    uint32_t net_bytes = htonl(cmd_val);
    return send_sync_bytes(tpm_comm_info, (const unsigned char*)&net_bytes, sizeof(uint32_t));
}

static void close_simulator(TPM_COMM_INFO* tpm_comm_info)
{
    (void)send_sync_cmd(tpm_comm_info, REMOTE_SESSION_END_CMD);
}

void write_tcti_info(const TCTI_PROV_INFO *tcti_info)
{
    uint32_t ver = tcti_info->version;
    printf("TCTI name: %s\n", tcti_info->name);
    printf("TCTI version: %u.%u.%u.%u\n", ver & 0xFF, (ver >> 8) & 0xFF, (ver >> 16) & 0xFF, ver >> 24);
    printf("TCTI descr: %s\n", tcti_info->descr);
    printf("TCTI config help: %s\n", tcti_info->help);
}

static void* load_abrmd(void** dylib)
{
    void* tcti_ctx = NULL;
    const TCTI_PROV_INFO *tcti_info;
    const char* abrmd_name = TPM_TABRMD_USERMODE_RESOURCE_MGR;
    size_t size = 0;
    TCTI_RC rc = 0;

    *dylib = dlopen (abrmd_name, RTLD_LAZY);
    if (!*dylib)
    {
        abrmd_name = TPM_ABRMD_USERMODE_RESOURCE_MGR;
        *dylib = dlopen (abrmd_name, RTLD_LAZY);
        if (!*dylib)
        {
            return NULL;
        }
    }

    get_tcti_info_fn get_tcti_info = (get_tcti_info_fn)dlsym(*dylib, "Tss2_Tcti_Info");
    if (!get_tcti_info)
    {
        LogError("No Tss2_Tcti_Info() entry point found in %s\n", abrmd_name);
        goto err;
    }

    tcti_info = get_tcti_info();

    rc = tcti_info->init(NULL, &size, NULL);
    if (rc != RC_SUCCESS) {
        LogError("tcti_init(NULL, ...) in %s failed", abrmd_name);
        goto err;
    }
    if (size < sizeof(TCTI_CTX)) {
        LogError("TCTI context size reported by tcti_init() in %s is too small: %lu < %lu", abrmd_name, (long unsigned int)size, (long unsigned int)sizeof(TCTI_CTX));
        goto err;
    }

    tcti_ctx = (TCTI_HANDLE*)malloc(size);
    if (!tcti_ctx)
    {
        LogError("load_abrmd(): malloc failed\n");
        goto err;
    }

    rc = tcti_info->init(tcti_ctx, &size, NULL);
    if (rc != RC_SUCCESS)
    {
        free(tcti_ctx);
        LogError("Tss2_Tcti_Info(ctx, ...) in %s failed", abrmd_name);
        goto err;
    }

    return tcti_ctx;

err:
    dlclose(*dylib);
    *dylib = NULL;
    return NULL;
}

static int tpm_usermode_resmgr_connect(TPM_COMM_INFO* handle)
{
    bool result;
    bool oldTrm, newTrm;

    // First check the presence of the latest user mode TRM variety
    handle->dev_info.tcti.ctx_handle = load_abrmd(&handle->dev_info.tcti.dylib);
    if (handle->dev_info.tcti.ctx_handle) {
        handle->conn_info = TCI_TCTI | TCI_TRM;
        result = 0;
    }
    else
    {
        oldTrm = access(TPM_OLD_USERMODE_RESOURCE_MGR_64, F_OK) != -1
                   || access(TPM_OLD_USERMODE_RESOURCE_MGR_32, F_OK) != -1
                   || access(TPM_OLD_USERMODE_RESOURCE_MGR_ARM, F_OK) != -1;
        newTrm = access(TPM_NEW_USERMODE_RESOURCE_MGR_64, F_OK) != -1
                   || access(TPM_NEW_USERMODE_RESOURCE_MGR_32, F_OK) != -1
                   || access(TPM_NEW_USERMODE_RESOURCE_MGR_ARM, F_OK) != -1;
        if (!(oldTrm || newTrm))
        {
            LogError("Failure: No user mode TRM found.");
            result = MU_FAILURE;
        }
        else if ((handle->dev_info.socket_conn = tpm_socket_create(TPM_UM_RM_ADDRESS, TPM_UM_RM_PORT)) == NULL)
        {
            LogError("Failure: connecting to user mode TRM.");
            result = MU_FAILURE;
        }
        else
        {
            handle->conn_info = TCI_SOCKET | (oldTrm ? TCI_OLD_UM_TRM : TCI_TRM);
            result = 0;
        }
    }
    return result;
}

static int send_old_um_trm_data(TPM_COMM_HANDLE handle)
{
    int result;
    unsigned char debugMsgLevel = 0, commandSent = 1;
    if ((handle->conn_info & TCI_OLD_UM_TRM) == 0)
    {
        // This is not an old TRM. No additional data are expected.
        result = 0;
    }
    else if (send_sync_bytes(handle, (const unsigned char*)&debugMsgLevel, 1) != 0)
    {
        LogError("Failure setting debugMsgLevel to TRM");
        result = MU_FAILURE;
    }
    else if (send_sync_bytes(handle, (const unsigned char*)&commandSent, 1) != 0)
    {
        LogError("Failure setting commandSent status to TRM");
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
    (void)endpoint;
    if ((result = malloc(sizeof(TPM_COMM_INFO))) == NULL)
    {
        LogError("Failure: malloc tpm communication info.");
    }
    else
    {
        memset(result, 0, sizeof(TPM_COMM_INFO));
        // First check if kernel mode TPM Resource Manager is available
        if ((result->dev_info.tpm_device = open(TPM_RM_DEVICE_NAME, O_RDWR)) >= 0)
        {
            result->conn_info = TCI_SYS_DEV | TCI_TRM;
        }
        // If not, connect to the raw TPM device
        else if ((result->dev_info.tpm_device = open(TPM_DEVICE_NAME, O_RDWR)) >= 0)
        {
            result->conn_info = TCI_SYS_DEV;
        }
        // If the system TPM device is unavalable, try connecting to the user mode TPM resource manager
        else if (tpm_usermode_resmgr_connect(result) != 0)
        {
            LogError("Failure: connecting to the TPM device");
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
        if (handle->conn_info & TCI_SYS_DEV)
        {
            (void)close(handle->dev_info.tpm_device);
        }
        else if (handle->conn_info & TCI_SOCKET)
        {
            close_simulator(handle);
            tpm_socket_destroy(handle->dev_info.socket_conn);
        }
        else if (handle->conn_info & TCI_TCTI)
        {
            TCTI_CTX *tcti_ctx = (TCTI_CTX*)handle->dev_info.tcti.ctx_handle;
            tcti_ctx->finalize(handle->dev_info.tcti.ctx_handle);
            dlclose(handle->dev_info.tcti.dylib);
        }
        free(handle);
    }
}

TPM_COMM_TYPE tpm_comm_get_type(TPM_COMM_HANDLE handle)
{
    (void)handle;
    return TPM_COMM_TYPE_LINUX;
}

int tpm_comm_submit_command(TPM_COMM_HANDLE handle, const unsigned char* cmd_bytes, uint32_t bytes_len, unsigned char* response, uint32_t* resp_len)
{
    int result;
    if (handle == NULL || cmd_bytes == NULL || response == NULL || resp_len == NULL)
    {
        LogError("Invalid argument specified handle: %p, cmd_bytes: %p, response: %p, resp_len: %p.", handle, cmd_bytes, response, resp_len);
        result = MU_FAILURE;
    }
    else if (*resp_len < 10)
    {
        LogError("Response buffer must be at least 10 bytes long %d", *resp_len);
        result = MU_FAILURE;
    }
    else if (handle->conn_info & TCI_SYS_DEV)
    {
        // Send to TPM
        if (write_data_to_tpm(handle, (const unsigned char*)cmd_bytes, bytes_len) != 0)
        {
            LogError("Failure setting locality to TPM");
            result = MU_FAILURE;
        }
        else
        {
            if (read_data_from_tpm(handle, response, resp_len) != 0)
            {
                LogError("Failure reading bytes from tpm");
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }
    else if (handle->conn_info & TCI_TCTI)
    {
        void* ctx_handle = handle->dev_info.tcti.ctx_handle;
        TCTI_CTX *tcti_ctx = (TCTI_CTX*)ctx_handle;
        uint32_t rc = tcti_ctx->transmit(ctx_handle, bytes_len, cmd_bytes);
        if (rc != 0)
        {
            LogError("TCTI_CTX::transmit() failed: 0x%08X\n", rc);
            result = MU_FAILURE;
        }
        else
        {
            size_t  bytes_returned = *resp_len;
            // abrmd has a bug of not setting the returned size when the TPM command fails.
            // So we have to look into that actual TPM response buffer.
            memset(response, 0, 10);
            rc = tcti_ctx->receive(ctx_handle, &bytes_returned, response, 5 * 60 * 1000);
            if (rc == 0)
            {
                uint32_t tpm_response_size = ntohl(*((uint32_t*)(response + 2)));
                *resp_len = tpm_response_size < bytes_returned ? tpm_response_size : (uint32_t)bytes_returned;
                result = 0;
            }
            else
            {
                LogError("TCTI_CTX::receive() failed: 0x%08X\n", rc);
                result = MU_FAILURE;
            }
        }
    }
    else if (handle->conn_info & TCI_SOCKET)
    {
        unsigned char locality = 0;
        if (send_sync_cmd(handle, REMOTE_SEND_COMMAND) != 0)
        {
            LogError("Failure preparing sending Remote Command");
            result = MU_FAILURE;
        }
        else if (send_sync_bytes(handle, (const unsigned char*)&locality, 1) != 0)
        {
            LogError("Failure setting locality to TPM");
            result = MU_FAILURE;
        }
        else if (send_old_um_trm_data(handle) != 0)
        {
            LogError("Failure communicating with old user mode TPM");
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
                    if ( !is_ack_ok(handle) )
                    {
                        LogError("Failure reading TRM ack");
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
    else
    {
        LogError("Submitting command to an uninitialized TPM_COMM_HANDLE");
        result = MU_FAILURE;
    }
    return result;
}
