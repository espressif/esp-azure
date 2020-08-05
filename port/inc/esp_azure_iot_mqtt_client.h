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

#ifndef ESP_AZURE_IOT_MQTT_CLIENT_H
#define ESP_AZURE_IOT_MQTT_CLIENT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "sdkconfig.h"

#include "mbedtls/base64.h"
#include "mqtt_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/ringbuf.h"
#include "freertos/event_groups.h"

/* Define the default MQTT TLS (secure) port number */
#define ESP_AZURE_IOT_MQTT_TLS_PORT                                    8883
#define ESP_AZURE_IOT_MQTT_SUCCESS                                     0

typedef struct ESP_THREAD_STRUCT 
{
    SemaphoreHandle_t            esp_thread_semaphore;
} ESP_THRAED;

typedef struct ESP_PACKET_STRUCT
{
    uint8_t                     *esp_packet_append_ptr;
    uint8_t                     *esp_packet_prepend_ptr;
    uint8_t                     *esp_packet_data_start;
    uint8_t                     *esp_packet_data_end;
    size_t                      esp_packet_length;
    RingbufHandle_t             esp_packet_append_buf;
    struct ESP_PACKET_STRUCT    *esp_packet_next;
} ESP_PACKET;

typedef struct ESP_AZURE_IOT_EVENT_GROUP_STRUCT
{

    /* Define the module name.  */
    const char                                  *esp_event_group_name;

    /* Define the module registered events including common events and module event
       that are processed in event helper thread.  */
    size_t                                      esp_event_group_registered_events;

    /* Define the actual current event flags in this module that are processed
       in module processing routine.  */
    size_t                                      esp_event_group_own_events;

    /* Define the module processing routine.  */
    void                                        (*esp_event_group_process)(void *module_context, size_t common_events, size_t module_own_events);

    /* Define the context that is passed to module processing routine.  */
    void                                        *esp_event_group_context;

    /* Define the next pointer of created module.  */
    struct ESP_AZURE_IOT_EVENT_GROUP_STRUCT     *esp_event_group_next;
    
    /* Define the event pointer associated with the module.  */
    struct ESP_AZURE_IOT_EVENT_STRUCT           *esp_event_ptr;

} ESP_AZURE_IOT_EVENT_GROUP;

typedef struct ESP_AZURE_IOT_EVENT_STRUCT
{
    /* Define the event ID.  */
    size_t                        esp_event_id;

    /* Define the event name.  */
    const char                    *esp_event_name;
    
    /* Define the event flags that are used to stimulate the event helper
       thread.  */
    EventGroupHandle_t            esp_event_events;
    
    /* Define the internal mutex used for protection .  */
    SemaphoreHandle_t             esp_event_mutex;    

    /* Define the head pointer of the created module list.  */
    ESP_AZURE_IOT_EVENT_GROUP     *esp_event_groups_list_header;    

    /* Define the number of created module instances.  */
    size_t                        esp_event_groups_count;

} ESP_AZURE_IOT_EVENT;

typedef struct ESP_MQTT_CLIENT_STRUCT {
    char                     *esp_mqtt_client_id;
    size_t                   esp_mqtt_client_id_length;
    char                     *esp_mqtt_username;
    size_t                   esp_mqtt_username_length;
    char                     *esp_mqtt_password;
    size_t                   esp_mqtt_password_length;
    esp_mqtt_client_handle_t esp_mqtt_client_handle;
    SemaphoreHandle_t        esp_mqtt_client_mutex_ptr;
    EventGroupHandle_t       esp_mqtt_client_event_ptr;
    ESP_PACKET               *message_receive_queue_head;
    ESP_PACKET               *message_receive_queue_tail;
    uint32_t                 message_receive_queue_depth;
    void                     (*esp_mqtt_client_receive_notify)(struct ESP_MQTT_CLIENT_STRUCT *client_ptr, uint32_t message_count);
    void                     (*esp_mqtt_connect_notify)(struct ESP_MQTT_CLIENT_STRUCT *client_ptr, uint32_t status, void *context);
    void                     (*esp_mqtt_disconnect_notify)(struct ESP_MQTT_CLIENT_STRUCT *client_ptr);
    uint32_t                 (*esp_mqtt_packet_receive_notify)(struct ESP_MQTT_CLIENT_STRUCT *client_ptr, ESP_PACKET *packet_ptr, void *context);
    void                     *esp_mqtt_connect_context;
} ESP_MQTT_CLIENT;

uint32_t esp_azure_iot_mqtt_client_create(ESP_MQTT_CLIENT *client_ptr, char *client_name, char *client_id, uint32_t client_id_length, ESP_AZURE_IOT_EVENT *event_ptr);
uint32_t esp_azure_iot_mqtt_client_delete(ESP_MQTT_CLIENT *client_ptr);
uint32_t esp_azure_iot_mqtt_client_receive_notify_set(ESP_MQTT_CLIENT *client_ptr, void (*receive_notify)(ESP_MQTT_CLIENT *client_ptr, uint32_t message_count));
uint32_t esp_azure_iot_mqtt_client_subscribe(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length, uint32_t QoS);
uint32_t esp_azure_iot_mqtt_client_unsubscribe(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length);
uint32_t esp_azure_iot_mqtt_client_publish(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length, char *message, uint32_t message_length, uint32_t retain, uint32_t QoS, size_t wait_option);
uint32_t esp_azure_iot_mqtt_client_connect(ESP_MQTT_CLIENT *client_ptr, size_t *server_ip, uint32_t server_port, uint32_t keepalive, uint32_t clean_session, size_t wait_option);
uint32_t esp_azure_iot_mqtt_client_secure_connect(ESP_MQTT_CLIENT *client_ptr, size_t *server_ip, uint32_t server_port, uint32_t keepalive, uint32_t clean_session, size_t wait_option);
uint32_t esp_azure_iot_mqtt_client_login_set(ESP_MQTT_CLIENT *client_ptr, char *username, uint32_t username_length, char *password, uint32_t password_length);
uint32_t esp_azure_iot_mqtt_client_disconnect(ESP_MQTT_CLIENT *client_ptr);
uint32_t esp_azure_iot_mqtt_client_publish_packet(ESP_MQTT_CLIENT *client_ptr, ESP_PACKET *packet_ptr, uint32_t QoS, size_t wait_option);
uint32_t esp_azure_iot_mqtt_client_packet_process(ESP_PACKET *packet_ptr, size_t *topic_offset, uint16_t *topic_length, size_t *message_offset, size_t *message_length);
uint32_t esp_azure_iot_mqtt_client_send_event(ESP_MQTT_CLIENT *client_ptr, void *msg);
uint32_t esp_azure_iot_mqtt_client_disconnect_notify_set(ESP_MQTT_CLIENT *client_ptr, void (*disconnect_notify)(ESP_MQTT_CLIENT *));

uint32_t esp_azure_iot_packet_allocate(ESP_PACKET **packet_ptr, size_t packet_type, size_t wait_option);
uint32_t esp_azure_iot_packet_release(ESP_PACKET *packet_ptr_ptr);
uint32_t esp_azure_iot_packet_append(ESP_PACKET *packet_ptr, void *data_start, size_t data_size, size_t wait_option);

uint32_t esp_azure_iot_event_group_set(ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr, size_t group_own_event);
uint32_t esp_azure_iot_event_group_register(ESP_AZURE_IOT_EVENT *event_ptr, ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr, const char *group_name, size_t group_event,
                              void (*group_process)(void* group_context, size_t common_events, size_t group_own_events), void *group_context);
uint32_t esp_azure_iot_event_group_deregister(ESP_AZURE_IOT_EVENT *event_ptr, ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr);

uint32_t esp_azure_iot_event_create(ESP_AZURE_IOT_EVENT *event_ptr, const char *event_name, void *memory_ptr, size_t memory_size, uint32_t priority);
uint32_t esp_azure_iot_event_delete(ESP_AZURE_IOT_EVENT *event_ptr);

uint32_t esp_azure_iot_thread_sleep(ESP_THRAED *thread_ptr, size_t wait_option);
uint32_t esp_azure_iot_thread_wait_abort(ESP_THRAED *thread_ptr);
ESP_THRAED *esp_azure_iot_thread_identify(void);
uint32_t esp_azure_iot_thread_preemption(ESP_THRAED *thread_ptr);

uint32_t esp_azure_iot_get_host_by_name(uint8_t *host_name, size_t *host_address_ptr, size_t wait_option, uint32_t lookup_type);

extern void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);

#ifdef __cplusplus
}
#endif
#endif /* ESP_AZURE_IOT_MQTT_CLIENT_H */