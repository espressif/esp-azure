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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <esp_system.h>
#include <esp_log.h>

#include "esp_azure_iot.h"

static const char *TAG = "azure_iot_mqtt";

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
static const int CONNECTED_BIT = BIT0;

static esp_err_t esp_azure_iot_hub_client_mqtt_event(esp_mqtt_event_handle_t event)
{
    ESP_MQTT_CLIENT *client_ptr = event->user_context;

    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            xEventGroupSetBits(client_ptr->esp_mqtt_client_event_ptr, CONNECTED_BIT);
            if (client_ptr->esp_mqtt_connect_notify) {
                client_ptr->esp_mqtt_connect_notify(client_ptr, ESP_AZURE_IOT_MQTT_SUCCESS, client_ptr->esp_mqtt_connect_context);
            }
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            xEventGroupClearBits(client_ptr->esp_mqtt_client_event_ptr, CONNECTED_BIT);
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            if (client_ptr->esp_mqtt_client_receive_notify) {
                ESP_PACKET *packet_topic = NULL;
                esp_azure_iot_packet_allocate(&packet_topic, 0, 0);
                
                packet_topic -> esp_packet_length = event->topic_len;
                
                memcpy(packet_topic->esp_packet_prepend_ptr, event->topic, event->topic_len);
                packet_topic -> esp_packet_append_ptr = packet_topic -> esp_packet_prepend_ptr + event->topic_len;
                
                if (event->data && event->data_len) {
                    memcpy(packet_topic->esp_packet_append_ptr, event->data, event->data_len);
                    packet_topic -> esp_packet_append_ptr = packet_topic -> esp_packet_append_ptr + event->data_len;
                }
                
                client_ptr->message_receive_queue_head = packet_topic;
                client_ptr->esp_mqtt_client_receive_notify(client_ptr, 1);
            }
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            break;
        default:
            break;
    }
    return ESP_OK;
}

uint32_t esp_azure_iot_mqtt_client_create(ESP_MQTT_CLIENT *client_ptr, char *client_name, char *client_id, uint32_t client_id_length, ESP_AZURE_IOT_EVENT *event_ptr)
{
    client_ptr->esp_mqtt_client_id = client_id;
    client_ptr->esp_mqtt_client_id_length = client_id_length;
    client_ptr->esp_mqtt_client_mutex_ptr = xSemaphoreCreateMutex();
    client_ptr->esp_mqtt_client_event_ptr = xEventGroupCreate();

    return ESP_AZURE_IOT_SUCCESS;
}

uint32_t esp_azure_iot_mqtt_client_receive_notify_set(ESP_MQTT_CLIENT *client_ptr, void (*receive_notify)(ESP_MQTT_CLIENT *client_ptr, uint32_t message_count))
{
    xSemaphoreTake(client_ptr -> esp_mqtt_client_mutex_ptr, portMAX_DELAY);

    client_ptr -> esp_mqtt_client_receive_notify = receive_notify;

    xSemaphoreGive(client_ptr -> esp_mqtt_client_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_delete(ESP_MQTT_CLIENT *client_ptr)
{
    if (client_ptr) {
        if (client_ptr->esp_mqtt_client_handle) {
            esp_mqtt_client_destroy(client_ptr->esp_mqtt_client_handle);
            client_ptr->esp_mqtt_client_handle = NULL;
        }

        if (client_ptr->esp_mqtt_client_mutex_ptr) {
            vSemaphoreDelete(client_ptr->esp_mqtt_client_mutex_ptr);
            client_ptr->esp_mqtt_client_mutex_ptr = NULL;
        }

        if (client_ptr->esp_mqtt_client_event_ptr) {
            vEventGroupDelete(client_ptr->esp_mqtt_client_event_ptr);
            client_ptr->esp_mqtt_client_event_ptr = NULL;
        }
    }

    return (ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_subscribe(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length, uint32_t QoS)
{
    int ret = esp_mqtt_client_subscribe(client_ptr->esp_mqtt_client_handle, topic_name, QoS);
    if (ret < 0) {
        ESP_LOGE(TAG, "Error to subscribe topic=%s, qos=%d", topic_name, QoS);
    } else {
        ESP_LOGI(TAG, "Succ to subscribe topic=%s, id=%d", topic_name, ret);
    }

    return (ret < 0) ? ESP_AZURE_IOT_SDK_CORE_ERROR : ESP_AZURE_IOT_SUCCESS;
}

uint32_t esp_azure_iot_mqtt_client_unsubscribe(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length)
{
    int ret = esp_mqtt_client_unsubscribe(client_ptr->esp_mqtt_client_handle, topic_name);
    if (ret < 0) {
        ESP_LOGE(TAG, "Error to unsubscribe topic %s", topic_name);
    } else {
        ESP_LOGI(TAG, "Succ to unsubscribe topic=%s, id=%d", topic_name, ret);
    }

    return (ret < 0) ? ESP_AZURE_IOT_SDK_CORE_ERROR : ESP_AZURE_IOT_SUCCESS;
}

uint32_t esp_azure_iot_mqtt_client_publish(ESP_MQTT_CLIENT *client_ptr, char *topic_name, uint32_t topic_name_length,
                              char *message, uint32_t message_length, uint32_t retain, uint32_t QoS, size_t wait_option)
{
    int ret = esp_mqtt_client_publish(client_ptr->esp_mqtt_client_handle, topic_name, message, message_length, QoS, retain);
    if (ret < 0) {
        ESP_LOGE(TAG, "Error to publish topic %s", topic_name);
    } else {
        ESP_LOGI(TAG, "Succ to publish topic=%.*s, id=%d", topic_name_length, topic_name, ret);
        if (message) {
            ESP_LOGI(TAG, "Publish message %.*s", message_length, message);
        }
    }

    return (ret < 0) ? ESP_AZURE_IOT_SDK_CORE_ERROR : ESP_AZURE_IOT_SUCCESS;
}

uint32_t esp_azure_iot_mqtt_client_connect(ESP_MQTT_CLIENT *client_ptr, size_t *server_ip, uint32_t server_port,
                              uint32_t keepalive, uint32_t clean_session, size_t wait_option)
{
    size_t ip_address = *server_ip;
    char host_string[64] = {0};
    snprintf(host_string, sizeof(host_string), "mqtt://%u.%u.%u.%u:%d",
           (ip_address >> 24),
           (ip_address >> 16 & 0xFF),
           (ip_address >> 8 & 0xFF),
           (ip_address & 0xFF), server_port);
    
    char *clientid = strndup(client_ptr->esp_mqtt_client_id, client_ptr->esp_mqtt_client_id_length);
    char *username = strndup(client_ptr->esp_mqtt_username, client_ptr->esp_mqtt_username_length);
    char *password = strndup(client_ptr->esp_mqtt_password, client_ptr->esp_mqtt_password_length);

    const esp_mqtt_client_config_t mqtt_cfg = {
        .event_handle = esp_azure_iot_hub_client_mqtt_event,
        .uri = host_string,
        .port = server_port,
        .client_id = clientid,
        .username = username,
        .password = password,
        .disable_clean_session = clean_session,
        .keepalive = keepalive,
        .user_context = client_ptr,
    };

    client_ptr->esp_mqtt_client_handle = esp_mqtt_client_init(&mqtt_cfg);
    ESP_LOGI(TAG, "CONNECT | URI: %s | CLLIENTID: %s | USERNAME: %s | PWD: %s", host_string, clientid, username, password);
    
    free(clientid);
    free(username);
    free(password);
    
    esp_mqtt_client_start(client_ptr->esp_mqtt_client_handle);

    xEventGroupWaitBits(client_ptr->esp_mqtt_client_event_ptr, CONNECTED_BIT,
                        false, true, wait_option);
    
    ESP_LOGI(TAG, "connect successful");

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_secure_connect(ESP_MQTT_CLIENT *client_ptr, size_t *server_ip, uint32_t server_port,
                                     uint32_t keepalive, uint32_t clean_session, size_t wait_option)
{
    size_t ip_address = *server_ip;
    char host_string[64] = {0};
    snprintf(host_string, sizeof(host_string), "mqtts://%u.%u.%u.%u:%d",
           (ip_address >> 24),
           (ip_address >> 16 & 0xFF),
           (ip_address >> 8 & 0xFF),
           (ip_address & 0xFF), server_port);
    
    char *clientid = strndup(client_ptr->esp_mqtt_client_id, client_ptr->esp_mqtt_client_id_length);
    char *username = strndup(client_ptr->esp_mqtt_username, client_ptr->esp_mqtt_username_length);
    char *password = strndup(client_ptr->esp_mqtt_password, client_ptr->esp_mqtt_password_length);

    const esp_mqtt_client_config_t mqtt_cfg = {
        .event_handle = esp_azure_iot_hub_client_mqtt_event,
        .uri = host_string,
        .port = server_port,
        .client_id = clientid,
        .username = username,
        .password = password,
        .disable_clean_session = clean_session,
        .keepalive = keepalive,
        .user_context = client_ptr,
    };

    client_ptr->esp_mqtt_client_handle = esp_mqtt_client_init(&mqtt_cfg);
    ESP_LOGI(TAG, "CONNECT | URI: %s | CLLIENTID: %s | USERNAME: %s | PWD: %s", host_string, clientid, username, password);
    
    free(clientid);
    free(username);
    free(password);
    
    esp_mqtt_client_start(client_ptr->esp_mqtt_client_handle);

    xEventGroupWaitBits(client_ptr->esp_mqtt_client_event_ptr, CONNECTED_BIT,
                        false, true, wait_option);
    
    ESP_LOGI(TAG, "secure connect successful");

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_login_set(ESP_MQTT_CLIENT *client_ptr, char *username, uint32_t username_length, char *password, uint32_t password_length)
{
    client_ptr->esp_mqtt_username = username;
    client_ptr->esp_mqtt_username_length = username_length;
    client_ptr->esp_mqtt_password = password;
    client_ptr->esp_mqtt_password_length = password_length;

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_disconnect(ESP_MQTT_CLIENT *client_ptr)
{
    esp_err_t ret = ESP_FAIL; 
    if (client_ptr && client_ptr->esp_mqtt_client_handle)
        ret = esp_mqtt_client_stop(client_ptr->esp_mqtt_client_handle);

    return (ret == ESP_OK) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

static esp_err_t resolve_host_name(const char *host, struct addrinfo **address_info)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char *use_host = strdup(host);
    if (!use_host) {
        return ESP_ERR_NO_MEM;
    }

    if (getaddrinfo(use_host, NULL, &hints, address_info)) {
        ESP_LOGE(TAG, "couldn't get hostname for :%s:", use_host);
        free(use_host);
        return ESP_ERR_NO_MEM;
    }
    free(use_host);
    return ESP_OK;
}

uint32_t esp_azure_iot_get_host_by_name(uint8_t *host_name, size_t *host_address_ptr, size_t wait_option, uint32_t lookup_type)
{
    ESP_LOGI(TAG, "host_name %s", host_name);
    struct addrinfo *addrinfo = NULL;
    resolve_host_name((const char *)host_name, &addrinfo);
    if (addrinfo && addrinfo->ai_family == AF_INET) {
        struct sockaddr_in *p = (struct sockaddr_in *)addrinfo->ai_addr;
        *host_address_ptr = htonl(p->sin_addr.s_addr);
    } else {
        ESP_LOGE(TAG, "Unsupported protocol family %d", addrinfo->ai_family);
    }
    freeaddrinfo(addrinfo);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_packet_allocate(ESP_PACKET **packet_ptr, size_t packet_type, size_t wait_option)
{
    ESP_PACKET *packet = NULL;
    
    packet = calloc(1, sizeof(ESP_PACKET));
    
    packet->esp_packet_data_start = calloc(1, 1536);
    packet->esp_packet_data_end = packet->esp_packet_data_start + 1536;
    packet->esp_packet_append_ptr = packet->esp_packet_prepend_ptr = packet->esp_packet_data_start;
    packet->esp_packet_append_buf = xRingbufferCreate(1536, RINGBUF_TYPE_BYTEBUF);
    
    *packet_ptr = packet;
    
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_packet_release(ESP_PACKET *packet_ptr_ptr)
{
    if (packet_ptr_ptr) {
        if (packet_ptr_ptr->esp_packet_data_start) {
            free(packet_ptr_ptr->esp_packet_data_start);
            packet_ptr_ptr->esp_packet_data_start = NULL;
        }

        if (packet_ptr_ptr->esp_packet_append_buf) {
            vRingbufferDelete(packet_ptr_ptr->esp_packet_append_buf);
            packet_ptr_ptr->esp_packet_append_buf = NULL;
        }

        free(packet_ptr_ptr);
        packet_ptr_ptr = NULL;
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_packet_append(ESP_PACKET *packet_ptr, void *data_start, size_t data_size, size_t wait_option)
{
    ESP_LOGD(TAG, "append data %s %u", (char *)data_start, data_size);

    BaseType_t ret = xRingbufferSend(packet_ptr->esp_packet_append_buf, data_start, data_size, wait_option);

    return (ret == pdTRUE) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

uint32_t esp_azure_iot_mqtt_client_publish_packet(ESP_MQTT_CLIENT *client_ptr, ESP_PACKET *packet_ptr, uint32_t QoS, size_t wait_option)
{
    char *buffer = NULL;
    size_t size = 0;
    
    buffer = xRingbufferReceive(packet_ptr->esp_packet_append_buf, &size, wait_option);
    if (buffer) {
        esp_azure_iot_mqtt_client_publish(client_ptr, (char *)packet_ptr -> esp_packet_prepend_ptr, packet_ptr->esp_packet_length, buffer, size, 0, QoS, wait_option);
        
        vRingbufferReturnItem(packet_ptr->esp_packet_append_buf, buffer);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_packet_process(ESP_PACKET *packet_ptr, size_t *topic_offset, uint16_t *topic_length, size_t *message_offset, size_t *message_length)
{
    *topic_offset = 0;
    *topic_length = packet_ptr -> esp_packet_length;
    *message_offset = packet_ptr -> esp_packet_length;
    *message_length = packet_ptr -> esp_packet_append_ptr - packet_ptr->esp_packet_prepend_ptr - packet_ptr -> esp_packet_length;
    
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_mqtt_client_disconnect_notify_set(ESP_MQTT_CLIENT *client_ptr, void (*disconnect_notify)(ESP_MQTT_CLIENT *))
{
    xSemaphoreTake(client_ptr -> esp_mqtt_client_mutex_ptr, portMAX_DELAY);

    client_ptr -> esp_mqtt_disconnect_notify = disconnect_notify;

    xSemaphoreGive(client_ptr -> esp_mqtt_client_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

/* API return values.  */
#define ESP_AZURE_IOT_EVENT_GROUP_ALREADY_REGISTERED              0xF0
#define ESP_AZURE_IOT_EVENT_GROUP_NOT_REGISTERED                  0xF1
#define ESP_AZURE_IOT_EVENT_GROUP_BOUND                           0xF2
#define ESP_AZURE_IOT_EVENT_GROUP_EVENT_INVALID                   0xF3

#define ESP_AZURE_IOT_EVENT_ALL_EVENTS                             BIT0 | BIT1 | BIT2 | BIT3 | BIT4 | BIT5      /* All event flags.             */

uint32_t esp_azure_iot_event_group_set(ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr, size_t group_own_event)
{
    ESP_AZURE_IOT_EVENT *event_ptr = event_group_ptr->esp_event_ptr;

    xEventGroupSetBits(event_ptr->esp_event_events, group_own_event);
    
    return(ESP_AZURE_IOT_SUCCESS);
}

static void esp_azure_iot_event_task(void *pv)
{
    ESP_AZURE_IOT_EVENT *event_ptr = (ESP_AZURE_IOT_EVENT *) pv;
    ESP_AZURE_IOT_EVENT_GROUP *current_module = event_ptr->esp_event_groups_list_header;
    while (1) {
        EventBits_t uxBits = xEventGroupWaitBits(event_ptr->esp_event_events, ESP_AZURE_IOT_EVENT_ALL_EVENTS, true, false, 100 / portTICK_PERIOD_MS);
        size_t common_events = (uxBits & (ESP_AZURE_IOT_EVENT_ALL_EVENTS)) ? 0 : ESP_AZURE_IOT_EVENT_COMMON_PERIODIC_EVENT;

        current_module->esp_event_group_process(current_module->esp_event_group_context, common_events, uxBits);

        xEventGroupClearBits(event_ptr->esp_event_events, uxBits);
    }
}

uint32_t esp_azure_iot_event_create(ESP_AZURE_IOT_EVENT *event_ptr, const char *event_name, void *memory_ptr, size_t memory_size, uint32_t priority)
{
    event_ptr->esp_event_events = xEventGroupCreate();
    event_ptr->esp_event_mutex = xSemaphoreCreateMutex();

    xTaskCreate(esp_azure_iot_event_task, event_name, memory_size, event_ptr, priority, NULL);
    
    return(ESP_AZURE_IOT_SUCCESS);
}

/* Register/deregister module in event thread.  */
uint32_t esp_azure_iot_event_group_register(ESP_AZURE_IOT_EVENT *event_ptr, ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr, const char* group_name, size_t group_event,
                              void (*group_process)(void* group_context, size_t common_events, size_t group_own_events), void* group_context)
{
    ESP_AZURE_IOT_EVENT_GROUP *current_module;

    /* Get mutex. */
    xSemaphoreTake(event_ptr -> esp_event_mutex, ESP_WAIT_FOREVER);

    /* Perform duplicate module detection.  */
    for (current_module = event_ptr -> esp_event_groups_list_header; current_module; current_module = current_module -> esp_event_group_next)
    {
        
        /* Check if the module is already registered.  */
        if (current_module == event_group_ptr)
        {

            /* Release mutex. */
            xSemaphoreGive(event_ptr -> esp_event_mutex);

            return(ESP_AZURE_IOT_EVENT_GROUP_ALREADY_REGISTERED);
        }
    }

    /* Set module info.  */
    event_group_ptr -> esp_event_group_name = group_name;
    event_group_ptr -> esp_event_group_process = group_process;
    event_group_ptr -> esp_event_group_context = group_context;
    event_group_ptr -> esp_event_ptr = event_ptr;

    /* Update the module list and count.  */
    event_group_ptr -> esp_event_group_next = event_ptr -> esp_event_groups_list_header;
    event_ptr -> esp_event_groups_list_header = event_group_ptr;
    event_ptr -> esp_event_groups_count ++;

    /* Release mutex. */
    xSemaphoreGive(event_ptr -> esp_event_mutex);
    
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_event_group_deregister(ESP_AZURE_IOT_EVENT *event_ptr, ESP_AZURE_IOT_EVENT_GROUP *event_group_ptr)
{
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_event_delete(ESP_AZURE_IOT_EVENT *event_ptr)
{
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_thread_sleep(ESP_THRAED *thread_ptr, size_t wait_option)
{
    BaseType_t ret = pdFALSE;
    
    if (thread_ptr && thread_ptr->esp_thread_semaphore) {
        ret = xSemaphoreTake(thread_ptr->esp_thread_semaphore, wait_option);
    }
    
    return (ret == pdTRUE) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

uint32_t esp_azure_iot_thread_wait_abort(ESP_THRAED *thread_ptr)
{

    BaseType_t ret = pdFALSE;
    
    if (thread_ptr && thread_ptr->esp_thread_semaphore) {
        ret = xSemaphoreGive(thread_ptr->esp_thread_semaphore);
    }
    
    return (ret == pdTRUE) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

ESP_THRAED *esp_azure_iot_thread_identify(void)
{
    ESP_THRAED *thread_ptr;
    thread_ptr = calloc(1, sizeof(ESP_THRAED));
    thread_ptr->esp_thread_semaphore = xSemaphoreCreateBinary();

    return thread_ptr;
}

uint32_t esp_azure_iot_thread_preemption(ESP_THRAED *thread_ptr)
{
    if (thread_ptr) {
        if (thread_ptr->esp_thread_semaphore) {
            vSemaphoreDelete(thread_ptr->esp_thread_semaphore);
            thread_ptr->esp_thread_semaphore = NULL;
        }
        
        free(thread_ptr);
    }

    return ESP_AZURE_IOT_SUCCESS;
}