// Copyright 2020 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_H
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/iot/az_iot_provisioning_client.h"
#include "esp_azure_iot.h"

/* Define the MAX status size. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_STATUS_ID_SIZE
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_STATUS_ID_SIZE        30
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_STATUS_ID_SIZE */

/* Define the MAX deviceID size. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_ID_BUFFER_SIZE
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_ID_BUFFER_SIZE        100
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_ID_BUFFER_SIZE */

/* Define the MAX IoT Hub Endpoint size. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_HUB_SIZE
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_HUB_SIZE              100
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_HUB_SIZE */

/* Define the MAX oertation Id of provisioning service. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_REQ_OP_ID_SIZE
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_REQ_OP_ID_SIZE        100
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_MAX_REQ_OP_ID_SIZE */

/* Set the default token expiry in secs.  */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_TOKEN_EXPIRY
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_TOKEN_EXPIRY              (3600)
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_TOKEN_EXPIRY */

/* Set the default timeout for DNS query.  */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_DNS_TIMEOUT
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_DNS_TIMEOUT               (5 * 100)
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_DNS_TIMEOUT */

typedef struct ESP_AZURE_IOT_PROVISIONING_DEVICE_RESPONSE_STRUCT
{
    az_iot_provisioning_client_register_response    register_response;

    ESP_PACKET                                      *packet_ptr;
} ESP_AZURE_IOT_PROVISIONING_RESPONSE;

typedef struct ESP_AZURE_IOT_PROVISIONING_THREAD_LIST_STRUCT
{
    ESP_THRAED                                              *esp_azure_iot_provisioning_thread_ptr;
    struct ESP_AZURE_IOT_PROVISIONING_THREAD_LIST_STRUCT    *esp_azure_iot_provisioning_thread_next;
} ESP_AZURE_IOT_PROVISIONING_THREAD_LIST;

/**
 * @brief Azure IoT Provisining Client struct
 * 
 */
typedef struct ESP_AZURE_IOT_PROVISIONING_CLIENT_STRUCT
{
    ESP_AZURE_IOT                           *esp_azure_iot_ptr;

    uint32_t                                esp_azure_iot_provisioning_client_state;
    ESP_AZURE_IOT_PROVISIONING_THREAD_LIST  *esp_azure_iot_provisioning_client_thread_suspended;

    uint32_t                                esp_azure_iot_provisioning_client_req_timeout;
    ESP_PACKET                              *esp_azure_iot_provisioning_client_last_response;
    uint32_t                                esp_azure_iot_provisioning_client_request_id;
    uint32_t                                esp_azure_iot_provisioning_client_result;
    ESP_AZURE_IOT_PROVISIONING_RESPONSE     esp_azure_iot_provisioning_client_response;
    void (*esp_azure_iot_provisioning_client_on_complete_callback)(struct ESP_AZURE_IOT_PROVISIONING_CLIENT_STRUCT *prov_client_ptr, uint32_t status);

    uint8_t                                 *esp_azure_iot_provisioning_client_endpoint;
    uint32_t                                esp_azure_iot_provisioning_client_endpoint_length;
    uint8_t                                 *esp_azure_iot_provisioning_client_id_scope;
    uint32_t                                esp_azure_iot_provisioning_client_id_scope_length;
    uint8_t                                 *esp_azure_iot_provisioning_client_registration_id;
    uint32_t                                esp_azure_iot_provisioning_client_registration_id_length;
    uint8_t                                 *esp_azure_iot_provisioning_client_symmetric_key;
    uint32_t                                esp_azure_iot_provisioning_client_symmetric_key_length;
    uint8_t                                 *esp_azure_iot_provisioning_client_sas_token;
    uint32_t                                esp_azure_iot_provisioning_client_sas_token_buff_size;

    ESP_AZURE_IOT_RESOURCE                  esp_azure_iot_provisioning_client_resource;
    az_iot_provisioning_client              esp_azure_iot_provisioning_client_core;
} ESP_AZURE_IOT_PROVISIONING_CLIENT;

/**
 * @brief Initialize Azure IoT Provisioning instance
 * @details This routine initializes the device to the IoT provisioning service.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[in] esp_azure_iot_ptr A pointer to a #ESP_AZURE_IOT.
 * @param[in] endpoint A `uint8_t` pointer to IoT Provisioning endpoint. Must be `NULL` terminated.
 * @param[in] endpoint_length Length of `endpoint`. Does not include the `NULL` terminator.
 * @param[in] id_scope A `uint8_t` pointer to ID Scope.
 * @param[in] id_scope_length Length of the `id_scope`. Does not include the `NULL` terminator.
 * @param[in] registration_id A `uint8_t` pointer to registration ID.
 * @param[in] registration_id_length Length of `registration_id`. Does not include the `NULL` terminator.
 * @param[in] trusted_certificate A pointer to `const char`, which are the server side certs.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully initialized to Azure IoT Provisioning Client.
 */
uint32_t esp_azure_iot_provisioning_client_initialize(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                 ESP_AZURE_IOT *esp_azure_iot_ptr,
                                                 uint8_t *endpoint, uint32_t endpoint_length,
                                                 uint8_t *id_scope, uint32_t id_scope_length,
                                                 uint8_t *registration_id, uint32_t registration_id_length,
                                                 const char *trusted_certificate);

/**
 * @brief Cleanup the Azure IoT Provisioning Client.
 * @details This routine de-initializes the Azure IoT Provisioning Client.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully cleaned up AZ IoT Provisioning Client Instance.
 */
uint32_t esp_azure_iot_provisioning_client_deinitialize(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr);

/**
 * @brief Set client certificate.
 * @details This routine sets the device certificate.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[in] x509_cert A pointer to a `const char` client cert.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully add device certs to AZ IoT Provisioning Client Instance.
 */
uint32_t esp_azure_iot_provisioning_client_device_cert_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                      const char *x509_cert);

/**
 * @brief Set symmetric key
 * @details This routine sets symmetric key.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[in] symmetric_key A uint8_t pointer to a symmetric key.
 * @param[in] symmetric_key_length Length of symmetric key.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully set symmetric key to the IoT Provisioning client.
 */
uint32_t esp_azure_iot_provisioning_client_symmetric_key_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                        uint8_t *symmetric_key, uint32_t symmetric_key_length);

/**
 * @brief Register device to Azure IoT Provisioning service.
 * @details This routine registers device to Azure IoT Provisioning service.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[in] wait_option Number of ticks to block for device registration.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully register device to AZ IoT Provisioning.
 *  @retval #ESP_AZURE_IOT_PENDING Successfully started registration of device but not yet completed.
 */
uint32_t esp_azure_iot_provisioning_client_register(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, uint32_t wait_option);

/**
 * @brief Set registration completion callback
 * @details This routine sets the callback for registration completion.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[in] on_complete_callback Registration completion callback.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successful register completion callback.
 */
uint32_t esp_azure_iot_provisioning_client_completion_callback_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                              void (*on_complete_callback)(struct ESP_AZURE_IOT_PROVISIONING_CLIENT_STRUCT *prov_client_ptr, uint32_t status));

/**
 * @brief Get IoTHub device info into user supplied buffer.
 * @details This routine gets the device id and puts it into a user supplied buffer.
 * 
 * @param[in] prov_client_ptr A pointer to a #ESP_AZURE_IOT_PROVISIONING_CLIENT.
 * @param[out] iothub_hostname Buffer pointer that will contain IoTHub hostname.
 * @param[in/out] iothub_hostname_len Pointer to uint32_t that contains size of buffer supplied. On successful return,
 *               it contains bytes copied to the buffer.
 * @param[out] device_id Buffer pointer that will contain IoTHub deviceId.
 * @param[in/out] device_id_len Pointer to uint32_t that contains size of buffer supplied, once successfully return it contains bytes copied to buffer.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS The device info is successfully retrieved to user supplied buffers.
 */
uint32_t esp_azure_iot_provisioning_client_iothub_device_info_get(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                             uint8_t *iothub_hostname, uint32_t *iothub_hostname_len,
                                                             uint8_t *device_id, uint32_t *device_id_len);

#ifdef __cplusplus
}
#endif
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_H */
