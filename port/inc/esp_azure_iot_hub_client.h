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

#ifndef ESP_AZURE_IOT_HUB_CLIENT_H
#define ESP_AZURE_IOT_HUB_CLIENT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/iot/az_iot_hub_client.h"
#include "esp_azure_iot.h"

#define ESP_AZURE_IOT_HUB_NONE                                      0x00000000 /**< Value denoting a message is of "None" type */
#define ESP_AZURE_IOT_HUB_ALL_MESSAGE                               0xFFFFFFFF /**< Value denoting a message is of "all" type */
#define ESP_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE                   0x00000001 /**< Value denoting a message is a cloud-to-device message */
#define ESP_AZURE_IOT_HUB_DIRECT_METHOD                             0x00000002 /**< Value denoting a message is a direct method */
#define ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES                    0x00000004 /**< Value denoting a message is a device twin message */
#define ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES            0x00000008 /**< Value denoting a message is a device twin document patch message */
#define ESP_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE  0x00000010 /**< Value denoting a message is a device reported properties response */ 

/* Set the default timeout for DNS query.  */
#ifndef ESP_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT
#define ESP_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT             (5 * 100)
#endif /* ESP_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT */

/* Set the default token expiry in secs.  */
#ifndef ESP_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY
#define ESP_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY            (3600)
#endif /* ESP_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY */

/* Define AZ IoT Hub Client state.  */
#define ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED    0 /**< The client is not connected */
#define ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING       1 /**< The client is connecting */
#define ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED        2 /**< The client is connected */


typedef struct ESP_AZURE_IOT_THREAD_LIST_STRUCT
{
    ESP_THRAED                                  *esp_azure_iot_thread_ptr;
    struct ESP_AZURE_IOT_THREAD_LIST_STRUCT     *esp_azure_iot_thread_next;

    uint32_t                                    esp_azure_iot_thread_message_type;
    uint32_t                                    esp_azure_iot_thread_expected_id;     /* Used by device twin. */
    uint32_t                                    esp_azure_iot_thread_response_status; /* Used by device twin. */
    ESP_PACKET                                  *esp_azure_iot_thread_received_message;
} ESP_AZURE_IOT_THREAD_LIST;

/* Forward declration*/
struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT;

typedef struct ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA_STRUCT
{
    ESP_PACKET  *esp_azure_iot_hub_client_message_head;
    ESP_PACKET  *esp_azure_iot_hub_client_message_tail;
    void        (*esp_azure_iot_hub_client_message_callback)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, void *args);
    void        *esp_azure_iot_hub_client_message_callback_args;
    uint32_t    (*esp_azure_iot_hub_client_message_process)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                                    ESP_PACKET *packet_ptr, size_t topic_offset, uint16_t topic_length);
} ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA;

/**
 * @brief Azure IoT Hub Client struct
 * 
 */
typedef struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT
{
    ESP_AZURE_IOT                                       *esp_azure_iot_ptr;
    uint32_t                                            esp_azure_iot_hub_client_state;
    ESP_AZURE_IOT_THREAD_LIST                           *esp_azure_iot_hub_client_thread_suspended;
    ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA   esp_azure_iot_hub_client_c2d_message_metadata;
    ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA   esp_azure_iot_hub_client_device_twin_metadata;
    ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA   esp_azure_iot_hub_client_device_twin_desired_properties_metadata;
    ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA   esp_azure_iot_hub_client_direct_method_metadata;

    void                                                (*esp_azure_iot_hub_client_connection_status_callback)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, uint32_t status);
    uint32_t                                            (*esp_azure_iot_hub_client_token_refresh)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                                                                                size_t expiry_time_secs, uint8_t *key, uint32_t key_len,
                                                                                                uint8_t *sas_buffer, uint32_t sas_buffer_len, uint32_t *sas_length);

    void                                                (*esp_azure_iot_hub_client_report_properties_response_callback)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                                                                                uint32_t request_id, uint32_t response_status, void *args);
    void                                                *esp_azure_iot_hub_client_report_properties_response_callback_args;

    uint32_t                                            esp_azure_iot_hub_client_mqtt_subscribed_flags;
    uint32_t                                            esp_azure_iot_hub_client_request_id;
    uint8_t                                             *esp_azure_iot_hub_client_symmetric_key;
    uint32_t                                            esp_azure_iot_hub_client_symmetric_key_length;
    ESP_AZURE_IOT_RESOURCE                              esp_azure_iot_hub_client_resource;

    az_iot_hub_client                                   iot_hub_client_core;
} ESP_AZURE_IOT_HUB_CLIENT;

/**
 * @brief Initialize Azure IoT hub instance
 * 
 * @param[in] hub_client_ptr A pointer to a ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] esp_azure_iot_ptr A pointer to a ESP_AZURE_IOT.
 * @param[in] host_name A `uint8_t` pointer to IoTHub hostname. Must be `NULL` terminated.
 * @param[in] host_name_length Length of `host_name`. Does not include the `NULL` terminator.
 * @param[in] device_id A `uint8_t` pointer to the device ID.
 * @param[in] device_id_length Length of the `device_id`. Does not include the `NULL` terminator.
 * @param[in] module_id A `uint8_t` pointer to the module ID.
 * @param[in] module_id_length Length of the `module_id`. Does not include the `NULL` terminator.
 * @param[in] trusted_certificate A pointer to `const char`, which are the server side certs.
 * @return A `uint32_t` with the result of the API.
 *   @retval ESP_AZURE_IOT_SUCCESS Successfully initialized the Azure IoT hub client.
 */
uint32_t esp_azure_iot_hub_client_initialize(ESP_AZURE_IOT_HUB_CLIENT* hub_client_ptr,
                                        ESP_AZURE_IOT *esp_azure_iot_ptr,
                                        uint8_t *host_name, uint32_t host_name_length,
                                        uint8_t *device_id, uint32_t device_id_length,
                                        uint8_t *module_id, uint32_t module_id_length,
                                        const char *trusted_certificate);

/**
 * @brief Deinitialize the Azure IoT Hub instance.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully de-initialized the Azure IoT hub client.
 */
uint32_t esp_azure_iot_hub_client_deinitialize(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Set the client certificate in the IoT Hub client.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] device_certificate A pointer to a `const char`, which is the device certificate.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully added device certificate to AZ IoT Hub Instance.
 */
uint32_t esp_azure_iot_hub_client_device_cert_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             const char *device_certificate);

/**
 * @brief Set symmetric key in the IoT Hub client.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] symmetric_key A pointer to a symmetric key.
 * @param[in] symmetric_key_length Length of `symmetric_key`.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully set symmetric key to IoTHub client.
 */
uint32_t esp_azure_iot_hub_client_symmetric_key_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               uint8_t *symmetric_key, uint32_t symmetric_key_length);

/**
 * @brief Set Device Twin model id in the IoT Hub client.
 *
 * @warning THIS FUNCTION IS TEMPORARY. IT IS SUBJECT TO CHANGE OR BE REMOVED IN THE FUTURE.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] model_id_ptr A pointer to a model id.
 * @param[in] model_id_length Length of `model id`.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully set model id to IoTHub client.
 *   @retval #ESP_AZURE_IOT_INVALID_PARAMETER Fail to set model id to IoTHub client due to invalid parameter.
 */
uint32_t esp_azure_iot_hub_client_model_id_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                          uint8_t *model_id_ptr, uint32_t model_id_length);
/**
 * @brief Connect to IoT Hub.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] clean_session Can be set to `0` to re-use current session, or `1` to start new session
 * @param[in] wait_option Number of ticks to wait for internal resources to be available.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if connected to Azure IoT Hub.
 */
uint32_t esp_azure_iot_hub_client_connect(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     uint32_t clean_session, uint32_t wait_option);

/**
 * @brief Disconnect from IoT Hub.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if client disconnects.
 */
uint32_t esp_azure_iot_hub_client_disconnect(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Sets connection status callback function
 * @details This routine sets the connection status callback. This callback function is
 *          invoked when IoT Hub status is changed, such as when the client is connected to IoT Hub.
 *          The different statuses include:
 * 
 *          - #ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED
 *          - #ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING
 *          - #ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED
 * 
 *          Setting the callback function to `NULL` disables the callback function.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] connection_status_cb Pointer to a callback function invoked on connection status is changed.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if connection status callback is set.
 */
uint32_t esp_azure_iot_hub_client_connection_status_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            void (*connection_status_cb)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, uint32_t status));

/**
 * @brief Sets receive callback function
 * @details This routine sets the IoT Hub receive callback function. This callback
 *          function is invoked when a message is received from Azure IoT hub. Setting the
 *          callback function to `NULL` disables the callback function. Message types can be:
 * 
 *          - #ESP_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE
 *          - #ESP_AZURE_IOT_HUB_DIRECT_METHOD
 *          - #ESP_AZURE_IOT_HUB_DT_DOCUMENT
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] message_type Message type of callback function.
 * @param[in] callback_ptr Pointer to a callback function invoked if the specified message type is received.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS if callback function is set successfully.
 */
uint32_t esp_azure_iot_hub_client_receive_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  uint32_t message_type,
                                                  void (*callback_ptr)(
                                                        ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        void *args),
                                                  void *callback_args);

/**
 * @brief Creates telemetry message.
 * @details This routine prepares a packet for sending telemetry data. After the packet is properly created,
 *          application can add additional user-defined properties before sending out.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Returned allocated `ESP_PACKET` on success.
 * @param[in] wait_option Ticks to wait if no packet is available.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if a packet is allocated.
 */
uint32_t esp_azure_iot_hub_client_telemetry_message_create(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      ESP_PACKET **packet_pptr,
                                                      uint32_t wait_option);

/**
 * @brief Deletes telemetry message
 * 
 * @param[in] packet_ptr The `ESP_PACKET` to release.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if a packet is deallocated.
 */
uint32_t esp_azure_iot_hub_client_telemetry_message_delete(ESP_PACKET *packet_ptr);

/**
 * @brief Add property to telemetry message
 * @details This routine allows an application to add user-defined properties to a telemetry message
 *          before it is being sent. This routine can be called multiple times to add all the properties to
 *          the message. The properties are stored in the sequence which the routine is being called.
 *          The property must be added after a telemetry packet is created, and before the telemetry
 *          message is being sent.
 * 
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] property_name Pointer to property name.
 * @param[in] property_name_length Length of property name.
 * @param[in] property_value Pointer to property value.
 * @param[in] property_value_length Length of property value.
 * @param[in] wait_option Ticks to wait if packet needs to be expanded.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if property is added.
 */
uint32_t esp_azure_iot_hub_client_telemetry_property_add(ESP_PACKET *packet_ptr,
                                                    uint8_t *property_name, uint16_t property_name_length,
                                                    uint8_t *property_value, uint16_t property_value_length,
                                                    uint32_t wait_option);

/**
 * @brief Sends telemetry message to IoTHub.
 * @details This routine sends telemetry to IoTHub, with `packet_ptr` containing all the properties.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] telemetry_data Pointer to telemetry data.
 * @param[in] data_size Size of telemetry data.
 * @param[in] wait_option Ticks to wait for message to be sent.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if telemetry message is sent out.
 */
uint32_t esp_azure_iot_hub_client_telemetry_send(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET *packet_ptr,
                                            uint8_t *telemetry_data, uint32_t data_size, uint32_t wait_option);

/**
 * @brief Enable receiving C2D message from IoTHub.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if C2D message receiving is enabled.
 */
uint32_t esp_azure_iot_hub_client_cloud_message_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables receiving C2D message from IoTHub
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if C2D message receiving is disabled.
 */
uint32_t esp_azure_iot_hub_client_cloud_message_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Receives C2D message from IoTHub
 * @details This routine receives C2D message from IoT Hub. If there are no messages in the receive
 *          queue, this routine can block.The amount of time it waits for a message is determined
 *          by the `wait_option` parameter.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Return a `ESP_PACKET` pointer with C2D message on success.
 * @param[in] wait_option Ticks to wait for message to arrive.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if C2D message is received.
 */
uint32_t esp_azure_iot_hub_client_cloud_message_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET **packet_pptr, uint32_t wait_option);

/**
 * @brief Retrieve the property with given property name in the C2D message.
 * 
 * @param[in] hub_client_ptr A pointer to a ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] packet_ptr Pointer to ESP_PACKET containing C2D message.
 * @param[in] property_name A `uint8_t` pointer to property name.
 * @param[in] property_name_length Length of `property_name`.
 * @param[out] property_value Pointer to `uint8_t` array that contains property values.
 * @param[out] property_value_length A `uint32_t` pointer to size of `property_value`.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if property is found and copied successfully into user buffer.
 *   @retval #ESP_AZURE_IOT_NOT_FOUND If property is not found.
 */
uint32_t esp_azure_iot_hub_client_cloud_message_property_get(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET *packet_ptr,
                                                        uint8_t *property_name, uint16_t property_name_length,
                                                        uint8_t **property_value, uint16_t *property_value_length);

/**
 * @brief Enables device twin feature
 * @details This routine enables device twin feature.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if device twin feature is enabled.
 */
uint32_t esp_azure_iot_hub_client_device_twin_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables device twin feature
 * @details This routine disables device twin feature.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if device twin feature is disabled.
 */
uint32_t esp_azure_iot_hub_client_device_twin_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Sets reported properties response callback function
 * @details This routine sets the reponse receive callback function for reported properties. This callback
 *          function is invoked when a response is received from Azure IoT hub for reported properties and no
 *          thread is waiting for response. Setting the callback function to `NULL` disables the callback
 *          function.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] callback_ptr Pointer to a callback function invoked.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if callback function is set successfully.
 */
uint32_t esp_azure_iot_hub_client_report_properties_response_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     void (*callback_ptr)(
                                                                           ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           uint32_t request_id,
                                                                           uint32_t response_status,
                                                                           void *args),
                                                                     void *callback_args);

/**
 * @brief Send device twin reported properties to IoT Hub
 * @details This routine sends device twin reported properties to IoT Hub.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] message_buffer JSON document containing the reported properties.
 * @param[in] message_length Length of JSON document.
 * @param[out] request_id_ptr Request Id assigned to the request.
 * @param[out] response_status_ptr Status return for successful send of reported properties.
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if device twin reported properties is sent successfully.
 */
uint32_t esp_azure_iot_hub_client_device_twin_reported_properties_send(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  uint8_t *message_buffer, uint32_t message_length,
                                                                  uint32_t *request_id_ptr, uint32_t *response_status_ptr,
                                                                  uint32_t wait_option);

/**
 * @brief Request complete device twin properties
 * @details This routine requests complete device twin properties.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT
 * @param[in] wait_option Ticks to wait for sending request.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if device twin properties is requested successfully.
 */
uint32_t esp_azure_iot_hub_client_device_twin_properties_request(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            uint32_t wait_option);

/**
 * @brief Receive complete device twin properties
 * @details This routine receives complete device twin properties.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT
 * @param[out] packet_pptr Pointer to #ESP_PACKET* that contains complete twin document.
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if device twin properties is received successfully.
 */
uint32_t esp_azure_iot_hub_client_device_twin_properties_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            ESP_PACKET **packet_pptr, uint32_t wait_option);

/**
 * @brief Receive desired properties form IoTHub
 * @details This routine receives desired properties from IoTHub.
 *
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Pointer to #ESP_PACKET* that contains complete twin document.
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if desired properties is received successfully.
 */
uint32_t esp_azure_iot_hub_client_device_twin_desired_properties_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    ESP_PACKET **packet_pptr, uint32_t wait_option);

/**
 * @brief Enables receiving direct method messages from IoTHub
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if direct method message receiving is enabled.
 */
uint32_t esp_azure_iot_hub_client_direct_method_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables receiving direct method messages from IoTHub
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if direct method message receiving is disabled.
 */
uint32_t esp_azure_iot_hub_client_direct_method_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Receives direct method message from IoTHub
 * @details This routine receives direct method message from IoT Hub. If there are no
 *          messages in the receive queue, this routine can block. The amount of time it waits for a
 *          message is determined by the `wait_option` parameter.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[out] method_name_pptr Return a pointer to method name on success.
 * @param[out] method_name_length_ptr Return length of `method_name_pptr` on success.
 * @param[out] context_pptr Return a pointer to the context pointer on success.
 * @param[out] context_length_ptr Return length of `context` on success.
 * @param[out] packet_pptr Return `ESP_PACKET` containing the method payload on success.
 * @param[in] wait_option Ticks to wait for message to arrive.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if direct method message is received.
 */
uint32_t esp_azure_iot_hub_client_direct_method_message_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           uint8_t **method_name_pptr, uint16_t *method_name_length_ptr,
                                                           void **context_pptr, uint16_t *context_length_ptr,
                                                           ESP_PACKET **packet_pptr, uint32_t wait_option);

/**
 * @brief Return response to direct method message from IoTHub
 * @details This routine returns response to the direct method message from IoT Hub.
 * @note request_id ties the correlation between direct method receive and response.
 * 
 * @param[in] hub_client_ptr A pointer to a #ESP_AZURE_IOT_HUB_CLIENT.
 * @param[in] status_code Status code for direct method.
 * @param[in] context_ptr Pointer to context return from esp_azure_iot_hub_client_direct_method_message_receive().
 * @param[in] context_length Length of context.
 * @param[in] payload  Pointer to `uint8_t` containing the payload for the direct method response. Payload is in JSON format.
 * @param[in] payload_length Length of `payload`
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS  Successful if direct method response is send.
 */
uint32_t esp_azure_iot_hub_client_direct_method_message_response(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            uint32_t status_code, void *context_ptr, uint16_t context_length,
                                                            uint8_t *payload, uint32_t payload_length, uint32_t wait_option);
#ifdef __cplusplus
}
#endif
#endif /* ESP_AZURE_IOT_HUB_CLIENT_H */