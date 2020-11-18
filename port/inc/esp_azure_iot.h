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

#ifndef ESP_AZURE_IOT_H
#define ESP_AZURE_IOT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "esp_azure_iot_mqtt_client.h"

/* Define the LOG LEVEL.  */
#ifndef ESP_AZURE_IOT_LOG_LEVEL
#define ESP_AZURE_IOT_LOG_LEVEL    2
#endif /* ESP_AZURE_IOT_LOG_LEVEL */

/* Define the log function.  */
#ifndef ESP_AZURE_IOT_LOG
#define ESP_AZURE_IOT_LOG          printf
#endif /* ESP_AZURE_IOT_LOG */

/* Define the az iot log function. */
#define LogError(...)
#define LogInfo(...)
#define LogDebug(...)
#define LogOutput(type,...) {ESP_AZURE_IOT_LOG("[" type "]"); ESP_AZURE_IOT_LOG( __VA_ARGS__); ESP_AZURE_IOT_LOG("\r\n");}

#if ESP_AZURE_IOT_LOG_LEVEL > 0
#include <stdio.h>
#undef LogError
#define LogError(...) LogOutput("ERROR", __VA_ARGS__)
#endif /* ESP_AZURE_IOT_LOG_LEVEL > 0 */
#if ESP_AZURE_IOT_LOG_LEVEL > 1
#undef LogInfo
#define LogInfo(...) LogOutput("INFO", __VA_ARGS__)
#endif /* ESP_AZURE_IOT_LOG_LEVEL > 1 */
#if ESP_AZURE_IOT_LOG_LEVEL > 2
#undef LogDebug
#define LogDebug(...) LogOutput("DEBUG", __VA_ARGS__)
#endif /* ESP_AZURE_IOT_LOG_LEVEL > 2 */

#define ESP_AZURE_IOT_MQTT_QOS_0                           0
#define ESP_AZURE_IOT_MQTT_QOS_1                           1

/* Define AZ IoT SDK event flags. These events are processed by the Cloud thread.  */
#define ESP_AZURE_IOT_HUB_CLIENT_CONNECT_EVENT             ((size_t)0x00000001)       /* IoT Hub Client Connect event      */ /* TODO: clean it if there is no need in future.  */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_EVENT    ((size_t)0x00000002)       /* Provisioning Client Connect event */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_SUBSCRIBE_EVENT  ((size_t)0x00000004)       /* Provisioning Client Subscribe event */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_REQUEST_EVENT    ((size_t)0x00000008)       /* Provisioning Client Request event */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_RESPONSE_EVENT   ((size_t)0x00000010)       /* Provisioning Client Response event */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_DISCONNECT_EVENT ((size_t)0x00000020)       /* Provisioning Client Disconnect event */

/* API return values.  */
#define ESP_AZURE_IOT_SUCCESS                              0x0 /**< The operation was successful. */
#define ESP_AZURE_IOT_SDK_CORE_ERROR                       0x20001
#define ESP_AZURE_IOT_INVALID_PARAMETER                    0x20002
#define ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE            0x20003
#define ESP_AZURE_IOT_INVALID_PACKET                       0x20004
#define ESP_AZURE_IOT_NO_PACKET                            0x20005
#define ESP_AZURE_IOT_NOT_FOUND                            0x20006 /**< If the item requested was not found */
#define ESP_AZURE_IOT_NOT_ENABLED                          0x20007
#define ESP_AZURE_IOT_NOT_INITIALIZED                      0x20008
#define ESP_AZURE_IOT_NOT_SUPPORTED                        0x20009
#define ESP_AZURE_IOT_ALREADY_CONNECTED                    0x2000A
#define ESP_AZURE_IOT_CONNECTING                           0x2000B
#define ESP_AZURE_IOT_DISCONNECTED                         0x2000C
#define ESP_AZURE_IOT_PENDING                              0x2000D /**< The operation is pending. */
#define ESP_AZURE_IOT_SERVER_RESPONSE_ERROR                0x2000E
#define ESP_AZURE_IOT_TOPIC_TOO_LONG                       0x2000F
#define ESP_AZURE_IOT_MESSAGE_TOO_LONG                     0x20010
#define ESP_AZURE_IOT_NO_AVAILABLE_CIPHER                  0x20011
#define ESP_AZURE_IOT_WRONG_STATE                          0x20012

#define ESP_IN_PROGRESS 0x37
#define ESP_NO_WAIT     0
#define ESP_WAIT_FOREVER portMAX_DELAY
#define ESP_IP_PERIODIC_RATE 100

/* Define the common events for all modules.  */
#define ESP_AZURE_IOT_EVENT_COMMON_PERIODIC_EVENT                  0x00000001u     /* Periodic event, 1s           */

/* Define the module events.  */
#define ESP_AZURE_IOT_EVENT_GROUP_MQTT_EVENT                      0x00010000u     /* MQTT event                   */
#define ESP_AZURE_IOT_EVENT_GROUP_AZURE_SDK_EVENT                 0x00020000u     /* Azure SDK event              */
#define ESP_AZURE_IOT_EVENT_GROUP_AZURE_OTA_EVENT                 0x00040000u     /* Azure OTA event              */
#define ESP_AZURE_IOT_EVENT_GROUP_AZURE_ASC_EVENT                 0x00080000u     /* Azure ASC event              */

/* Resource type managed by AZ_IOT.  */
#define ESP_AZURE_IOT_RESOURCE_IOT_HUB                     0x1
#define ESP_AZURE_IOT_RESOURCE_IOT_PROVISIONING            0x2

/* Define MQTT keep alive in seconds. 0 means the keep alive is disabled.
   By default, keep alive is 4 minutes. */
#ifndef ESP_AZURE_IOT_MQTT_KEEP_ALIVE
#define ESP_AZURE_IOT_MQTT_KEEP_ALIVE                      (60 * 4)
#endif /* ESP_AZURE_IOT_MQTT_KEEP_ALIVE */

/**
 * @brief Resource struct
 * 
 */
typedef struct ESP_AZURE_IOT_RESOURCE_STRUCT
{
    uint32_t                                    esp_azure_iot_resource_type;
    void                                        *esp_azure_iot_resource_data_ptr;
    ESP_MQTT_CLIENT                             esp_azure_iot_mqtt;
    uint8_t                                     *esp_azure_iot_mqtt_client_id;
    uint32_t                                    esp_azure_iot_mqtt_client_id_length;
    uint8_t                                     *esp_azure_iot_mqtt_user_name;
    uint32_t                                    esp_azure_iot_mqtt_user_name_length;
    uint8_t                                     *esp_azure_iot_mqtt_sas_token;
    uint32_t                                    esp_azure_iot_mqtt_sas_token_length;
    void                                        *esp_azure_iot_mqtt_buffer_context;
    uint32_t                                    esp_azure_iot_mqtt_buffer_size;
    const char                                  *esp_azure_iot_trusted_certificate;
    const char                                  *esp_azure_iot_device_certificate;
    struct ESP_AZURE_IOT_RESOURCE_STRUCT        *esp_azure_iot_resource_next;

} ESP_AZURE_IOT_RESOURCE;

/**
 * @brief Azure IoT Struct
 * 
 */
typedef struct ESP_AZURE_IOT_STRUCT
{
    uint8_t                                     *esp_azure_iot_name;
    ESP_AZURE_IOT_EVENT                         esp_azure_iot_event;
    ESP_AZURE_IOT_EVENT_GROUP                   esp_azure_iot_event_group;
    SemaphoreHandle_t                           esp_azure_iot_mutex_ptr;
    void                                        (*esp_azure_iot_provisioning_client_event_process)(struct ESP_AZURE_IOT_STRUCT *esp_azure_iot_ptr, size_t common_events, size_t module_own_events); /* TODO: consider register DPS module in event.  */
    struct ESP_AZURE_IOT_RESOURCE_STRUCT        *esp_azure_iot_resource_list_header;
    uint32_t                                    (*esp_azure_iot_unix_time_get)(size_t *unix_time);
} ESP_AZURE_IOT;

#ifndef ESP_PARAMETER_NOT_USED
#define ESP_PARAMETER_NOT_USED(p) ((void)(p))
#endif /* ESP_PARAMETER_NOT_USED */

/**
 * @brief Create the Azure IoT subsystem
 * 
 * @details This routine creates the Azure IoT subsystem. An internal thread is created to
 *          manage activities related to Azure IoT services. Only one ESP_AZURE_IOT instance
 *          is needed to manage instances for Azure IoT hub, IoT Central, Device Provisioning
 *          Services (DPS), and Azure Security Center (ASC).
 * 
 * @param[in] esp_azure_iot_ptr A pointer to a #ESP_AZURE_IOT
 * @param[in] name_ptr A pointer to a NULL-terminated string indicating the name of the Azure IoT instance.
 * @param[in] stack_memory_size Size of stack memory area.
 * @param[in] priority Priority of the internal thread.
 * @param[in] unix_time_callback Callback to fetch unix time from platform.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully created the Azure IoT instance.
 */
uint32_t esp_azure_iot_create(ESP_AZURE_IOT *esp_azure_iot_ptr, uint8_t *name_ptr, uint32_t stack_memory_size,
                         uint32_t priority, uint32_t (*unix_time_callback)(size_t *unix_time));

/**
 * @brief Shutdown and cleanup the Azure IoT subsystem.
 * @details This routine stops all Azure services managed by this instance, and cleans up internal resources.
 * 
 * @param[in] esp_azure_iot_ptr A pointer to a #ESP_AZURE_IOT.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully stopped Azure IoT services and cleaned up internal
 *                                    resources instance.
 */
uint32_t esp_azure_iot_delete(ESP_AZURE_IOT *esp_azure_iot_ptr);

/**
 * @brief Get unixtime
 * 
 * @param[in] esp_azure_iot_ptr A pointer to a #ESP_AZURE_IOT.
 * @param[out] unix_time Pointer to `size_t` where unixtime is returned.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successfully return unix time.
 */
uint32_t esp_azure_iot_unix_time_get(ESP_AZURE_IOT *esp_azure_iot_ptr, size_t *unix_time);

/**
 * @brief Allocate a buffer.
 * 
 * @param[in] esp_azure_iot_ptr A pointer to a #ESP_AZURE_IOT.
 * @param[out] buffer_pptr A pointer to allocated buffer.
 * @param[out] buffer_size Size of allocated buffer.
 * @param[out] buffer_context Context returned for allocated buffer.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully allocated buffer.
 */
uint32_t esp_azure_iot_buffer_allocate(ESP_AZURE_IOT *esp_azure_iot_ptr, uint8_t **buffer_pptr,
                                  uint32_t *buffer_size, void **buffer_context);

/**
 * @brief Free allocated buffer
 * 
 * @param[in] buffer_context Context returned from the esp_azure_iot_buffer_allocate() API.
 * @return A `uint32_t` with the result of the API.
 *  @retval #ESP_AZURE_IOT_SUCCESS Successfully deallocated buffer.
 */
uint32_t esp_azure_iot_buffer_free(void *buffer_context);

/* Internal APIs. */
uint32_t esp_azure_iot_resource_add(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_AZURE_IOT_RESOURCE *resource);
uint32_t esp_azure_iot_resource_remove(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_AZURE_IOT_RESOURCE *resource);
ESP_AZURE_IOT_RESOURCE *esp_azure_iot_resource_search(ESP_MQTT_CLIENT *client_ptr);
uint32_t esp_azure_iot_publish_mqtt_packet(ESP_MQTT_CLIENT *client_ptr, ESP_PACKET *packet_ptr, uint32_t qos, uint32_t wait_option);
uint32_t esp_azure_iot_publish_packet_get(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_MQTT_CLIENT *client_ptr, ESP_PACKET **packet_pptr, uint32_t wait_option);
void esp_azure_iot_mqtt_packet_adjust(ESP_PACKET *packet_ptr);
uint32_t esp_azure_iot_url_encoded_hmac_sha256_calculate(ESP_AZURE_IOT_RESOURCE *resource_ptr,
                                                    uint8_t *key_ptr, uint32_t key_size,
                                                    uint8_t *message_ptr, uint32_t message_size,
                                                    uint8_t *buffer_ptr, uint32_t buffer_len,
                                                    uint8_t **output_ptr, uint32_t *output_len);

int esp_azure_iot_time_init(void);

#ifdef __cplusplus
}
#endif
#endif /* ESP_AZURE_IOT_H */
