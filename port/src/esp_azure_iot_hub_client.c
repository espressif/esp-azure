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

#include "esp_azure_iot_hub_client.h"

#define ESP_AZURE_IOT_HUB_CLIENT_EMPTY_JSON                      "{}"
#define ESP_AZURE_IOT_HUB_CLIENT_USER_AGENT                      "os=azure_rtos"

static void esp_azure_iot_hub_client_received_message_cleanup(ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA *message);
static uint32_t esp_azure_iot_hub_client_cloud_message_sub_unsub(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, uint32_t is_subscribe);
static void esp_azure_iot_hub_client_mqtt_receive_callback(ESP_MQTT_CLIENT* client_ptr, uint32_t number_of_messages);
static uint32_t esp_azure_iot_hub_client_c2d_process(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET *packet_ptr, size_t topic_offset, uint16_t topic_length);
static uint32_t esp_azure_iot_hub_client_device_twin_process(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET *packet_ptr, size_t topic_offset, uint16_t topic_length);
static void esp_azure_iot_hub_client_mqtt_connect_notify(ESP_MQTT_CLIENT *client_ptr, uint32_t status, void *context);
static void esp_azure_iot_hub_client_mqtt_disconnect_notify(ESP_MQTT_CLIENT *client_ptr);
void esp_azure_iot_hub_client_event_process(ESP_AZURE_IOT *esp_azure_iot_ptr, size_t common_events, size_t module_own_events);
static void esp_azure_iot_hub_client_thread_dequeue(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr);
static uint32_t esp_azure_iot_hub_client_sas_token_get(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  size_t expiry_time_secs, uint8_t *key, uint32_t key_len,
                                                  uint8_t *sas_buffer, uint32_t sas_buffer_len, uint32_t *sas_length);

uint32_t esp_azure_iot_hub_client_initialize(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                        ESP_AZURE_IOT *esp_azure_iot_ptr,
                                        uint8_t *host_name, uint32_t host_name_length,
                                        uint8_t *device_id, uint32_t device_id_length,
                                        uint8_t *module_id, uint32_t module_id_length,
                                        const char *trusted_certificate)
{
    uint32_t status;
    ESP_AZURE_IOT_RESOURCE *resource_ptr;
    az_span hostname_span = az_span_init(host_name, (int16_t)host_name_length);
    az_span device_id_span = az_span_init(device_id, (int16_t)device_id_length);
    az_iot_hub_client_options options = az_iot_hub_client_options_default();
    az_result core_result;

    if ((esp_azure_iot_ptr == NULL) || (hub_client_ptr == NULL) || (host_name == NULL) ||
        (device_id == NULL))
    {
        LogError("IoTHub client create fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }
    
    memset(hub_client_ptr, 0, sizeof(ESP_AZURE_IOT_HUB_CLIENT));

    hub_client_ptr -> esp_azure_iot_ptr = esp_azure_iot_ptr;
    hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_trusted_certificate = trusted_certificate;
    options.module_id = az_span_init(module_id, (int16_t)module_id_length);
    options.user_agent = AZ_SPAN_FROM_STR(ESP_AZURE_IOT_HUB_CLIENT_USER_AGENT);

    core_result = az_iot_hub_client_init(&hub_client_ptr -> iot_hub_client_core,
                                         hostname_span, device_id_span, &options);
    if (az_failed(core_result))
    {
        LogError("IoTHub client failed initialization with error : 0x%08x", core_result);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    /* Set resource pointer.  */
    resource_ptr = &(hub_client_ptr -> esp_azure_iot_hub_client_resource);

    /* Create MQTT client.  */
    status = esp_azure_iot_mqtt_client_create(&(resource_ptr -> esp_azure_iot_mqtt),
                                           (char *)esp_azure_iot_ptr -> esp_azure_iot_name,
                                           (char *)"", 0,
                                           &esp_azure_iot_ptr -> esp_azure_iot_event);
    if (status)
    {
        LogError("IoTHub client create fail: MQTT CLIENT CREATE FAIL: 0x%02x", status);
        return(status);
    }

    /* Set mqtt receive notify.  */
    status = esp_azure_iot_mqtt_client_receive_notify_set(&(resource_ptr -> esp_azure_iot_mqtt),
                                                esp_azure_iot_hub_client_mqtt_receive_callback);
    if (status)
    {
        LogError("IoTHub client set message callback: 0x%02x", status);
        esp_azure_iot_mqtt_client_delete(&(resource_ptr -> esp_azure_iot_mqtt));
        return(status);
    }

    /* Obtain the mutex.   */
    xSemaphoreTake(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Link the resource. */
    resource_ptr -> esp_azure_iot_resource_data_ptr = (void *)hub_client_ptr;
    resource_ptr -> esp_azure_iot_resource_type = ESP_AZURE_IOT_RESOURCE_IOT_HUB;
    esp_azure_iot_resource_add(esp_azure_iot_ptr, resource_ptr);

    /* Release the mutex.  */
    xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_connection_status_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            void (*connection_status_cb)(struct ESP_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, uint32_t status))
{
    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTHub client connect fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Set callback function for disconnection. */
    esp_azure_iot_mqtt_client_disconnect_notify_set(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                          esp_azure_iot_hub_client_mqtt_disconnect_notify);

    /* Obtain the mutex.   */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Set connection status callback.  */
    hub_client_ptr -> esp_azure_iot_hub_client_connection_status_callback = connection_status_cb;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                            
uint32_t esp_azure_iot_hub_client_connect(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     uint32_t clean_session, uint32_t wait_option)
{
    uint32_t            status;
    size_t           server_address;
    ESP_AZURE_IOT_RESOURCE *resource_ptr;
    ESP_MQTT_CLIENT *mqtt_client_ptr;
    uint8_t           *buffer_ptr;
    uint32_t            buffer_size;
    void            *buffer_context;
    uint32_t            buffer_length;
    uint32_t            dns_timeout = wait_option;
    size_t           expiry_time_secs;
    az_result       core_result;
    
    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTHub client connect fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Check for status.  */
    if (hub_client_ptr -> esp_azure_iot_hub_client_state == ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED)
    {
        LogError("IoTHub client already connected");
        return(ESP_AZURE_IOT_ALREADY_CONNECTED);
    }
    else if (hub_client_ptr -> esp_azure_iot_hub_client_state == ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING)
    {
        LogError("IoTHub client is connecting");
        return(ESP_AZURE_IOT_CONNECTING);
    }

    /* Set the DNS timeout as ESP_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT for non-blocking mode.  */ /* TODO: DNS non-blocking.  */
    if (dns_timeout == 0)
    {
        dns_timeout = ESP_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT;
    }

    /* Resolve the host name.  */
    status = esp_azure_iot_get_host_by_name(az_span_ptr(hub_client_ptr -> iot_hub_client_core._internal.iot_hub_hostname), // TODO: ask core to expose api
                                      &server_address, dns_timeout, 0);
    if (status)
    {
        LogError("IoTHub client connect fail: DNS RESOLVE FAIL: 0x%02x", status);
        return(status);
    }

    /* Allocate buffer for client id, username and sas token.  */
    status = esp_azure_iot_buffer_allocate(hub_client_ptr -> esp_azure_iot_ptr,
                                          &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client failed initialization: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.   */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Set resource pointer and buffer context.  */
    resource_ptr = &(hub_client_ptr -> esp_azure_iot_hub_client_resource);

    /* Build client id.  */
    buffer_length = buffer_size;
    core_result = az_iot_hub_client_get_client_id(&hub_client_ptr -> iot_hub_client_core,
                                                  (char *)buffer_ptr, buffer_length, &buffer_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        esp_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client failed to get clientId with error : 0x%08x", core_result);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }
    resource_ptr -> esp_azure_iot_mqtt_client_id = buffer_ptr;
    resource_ptr -> esp_azure_iot_mqtt_client_id_length = buffer_length;

    /* Update buffer for user name.  */
    buffer_ptr += resource_ptr -> esp_azure_iot_mqtt_client_id_length;
    buffer_size -= resource_ptr -> esp_azure_iot_mqtt_client_id_length;

    /* Build user name.  */
    buffer_length = buffer_size;
    core_result = az_iot_hub_client_get_user_name(&hub_client_ptr -> iot_hub_client_core,
                                                  (char *)buffer_ptr, buffer_length, &buffer_length);
    if (az_failed(core_result))
    {

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        esp_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client connect fail, with error 0x%08x", core_result);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }
    resource_ptr -> esp_azure_iot_mqtt_user_name = buffer_ptr;
    resource_ptr -> esp_azure_iot_mqtt_user_name_length = buffer_length;

    /* Build sas token.  */
    resource_ptr -> esp_azure_iot_mqtt_sas_token = buffer_ptr + buffer_length;
    resource_ptr -> esp_azure_iot_mqtt_sas_token_length = buffer_size - buffer_length;

    /* Check if token refersh is setup */
    if (hub_client_ptr -> esp_azure_iot_hub_client_token_refresh)
    {
        status = esp_azure_iot_unix_time_get(hub_client_ptr -> esp_azure_iot_ptr, &expiry_time_secs);
        if (status)
        {

            /* Release the mutex.  */
            xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
            esp_azure_iot_buffer_free(buffer_context);
            LogError("IoTHub client connect fail: unixtime get failed: 0x%02x", status);
            return(status);
        }

        expiry_time_secs += ESP_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY;
        status = hub_client_ptr -> esp_azure_iot_hub_client_token_refresh(hub_client_ptr,
                                                                         expiry_time_secs, hub_client_ptr -> esp_azure_iot_hub_client_symmetric_key,
                                                                         hub_client_ptr -> esp_azure_iot_hub_client_symmetric_key_length,
                                                                         resource_ptr -> esp_azure_iot_mqtt_sas_token,
                                                                         resource_ptr -> esp_azure_iot_mqtt_sas_token_length,
                                                                         &(resource_ptr -> esp_azure_iot_mqtt_sas_token_length));
        if (status)
        {

            /* Release the mutex.  */
            xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
            esp_azure_iot_buffer_free(buffer_context);
            LogError("IoTHub client connect fail: Token generation failed: 0x%02x", status);
            return(status);
        }
    }
    else
    {
        resource_ptr ->  esp_azure_iot_mqtt_sas_token_length = 0;
    }

    /* Set azure IoT and MQTT client.  */
    mqtt_client_ptr = &(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt);

    /* Update client id.  */
    mqtt_client_ptr -> esp_mqtt_client_id = (char *)resource_ptr -> esp_azure_iot_mqtt_client_id;
    mqtt_client_ptr -> esp_mqtt_client_id_length = resource_ptr -> esp_azure_iot_mqtt_client_id_length;

    /* Set login info.  */
    status = esp_azure_iot_mqtt_client_login_set(&(resource_ptr -> esp_azure_iot_mqtt),
                                       (char *)resource_ptr -> esp_azure_iot_mqtt_user_name,
                                       resource_ptr -> esp_azure_iot_mqtt_user_name_length,
                                       (char *)resource_ptr -> esp_azure_iot_mqtt_sas_token,
                                       resource_ptr -> esp_azure_iot_mqtt_sas_token_length);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        esp_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client connect fail: MQTT CLIENT LOGIN SET FAIL: 0x%02x", status);
        return(status);
    }

    /* Set connect notify for non-blocking mode.  */
    if (wait_option == 0)
    {
        mqtt_client_ptr -> esp_mqtt_connect_notify = esp_azure_iot_hub_client_mqtt_connect_notify;
        mqtt_client_ptr -> esp_mqtt_connect_context = hub_client_ptr;
    }

    /* Save the resource buffer.  */
    resource_ptr -> esp_azure_iot_mqtt_buffer_context = buffer_context;
    resource_ptr -> esp_azure_iot_mqtt_buffer_size = buffer_size;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    /* Start MQTT connection.  */
    status = esp_azure_iot_mqtt_client_secure_connect(mqtt_client_ptr, &server_address, ESP_AZURE_IOT_MQTT_TLS_PORT,
                                                      ESP_AZURE_IOT_MQTT_KEEP_ALIVE, clean_session, wait_option);

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Check status for non-blocking mode.  */
    if ((wait_option == 0))
    {
        hub_client_ptr -> esp_azure_iot_hub_client_state = ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING;

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

        /* Return in-progress completion status.  */
        return(ESP_AZURE_IOT_CONNECTING);
    }

    /* Release the mqtt connection resource.  */
    if (resource_ptr -> esp_azure_iot_mqtt_buffer_context)
    {
        esp_azure_iot_buffer_free(resource_ptr -> esp_azure_iot_mqtt_buffer_context);
        resource_ptr -> esp_azure_iot_mqtt_buffer_context = NULL;
    }

    /* Check status.  */
    if (status != ESP_AZURE_IOT_SUCCESS)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_state = ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED;
        LogError("IoTHub client connect fail: MQTT CONNECT FAIL: 0x%02x", status);
    }
    else
    {

        /* Connected to IoT Hub.  */
        hub_client_ptr -> esp_azure_iot_hub_client_state = ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED;
    }

    /* Call connection notify if it is set.  */
    if (hub_client_ptr -> esp_azure_iot_hub_client_connection_status_callback)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_connection_status_callback(hub_client_ptr,
                                                                             hub_client_ptr -> esp_azure_iot_hub_client_state);
    }

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}
                                     
void esp_azure_iot_hub_client_mqtt_connect_notify(ESP_MQTT_CLIENT *client_ptr, uint32_t status, void *context)
{

    ESP_AZURE_IOT_HUB_CLIENT *iot_hub_client = (ESP_AZURE_IOT_HUB_CLIENT*)context;

    ESP_PARAMETER_NOT_USED(client_ptr);

    /* Obtain the mutex.  */
    xSemaphoreTake(iot_hub_client -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Release the mqtt connection resource.  */
    if (iot_hub_client -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context)
    {
        esp_azure_iot_buffer_free(iot_hub_client -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context);
        iot_hub_client -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context = NULL;
    }

    /* Update hub client status.  */
    if (status == MQTT_EVENT_CONNECTED)
    {
        iot_hub_client -> esp_azure_iot_hub_client_state = ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED;
    }
    else
    {
        iot_hub_client -> esp_azure_iot_hub_client_state = ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED;
    }

    /* Call connection notify if it is set.  */
    if (iot_hub_client -> esp_azure_iot_hub_client_connection_status_callback)
    {
        iot_hub_client -> esp_azure_iot_hub_client_connection_status_callback(iot_hub_client,
                                                                             iot_hub_client -> esp_azure_iot_hub_client_state);
    }

    /* Release the mutex.  */
    xSemaphoreGive(iot_hub_client -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
    
}

static void esp_azure_iot_hub_client_mqtt_disconnect_notify(ESP_MQTT_CLIENT *client_ptr)
{
ESP_AZURE_IOT_RESOURCE *resource = esp_azure_iot_resource_search(client_ptr);
ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr = NULL;

    /* This function is protected by MQTT mutex. */

    if (resource && (resource -> esp_azure_iot_resource_type == ESP_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_client_ptr = (ESP_AZURE_IOT_HUB_CLIENT *)resource -> esp_azure_iot_resource_data_ptr;
    }

    /* Call connection notify if it is set.  */
    if (hub_client_ptr && hub_client_ptr -> esp_azure_iot_hub_client_connection_status_callback)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_connection_status_callback(hub_client_ptr, ESP_AZURE_IOT_DISCONNECTED);
    }
}

void esp_azure_iot_hub_client_event_process(ESP_AZURE_IOT *esp_azure_iot_ptr,
                                           size_t common_events, size_t module_own_events) 
{

    ESP_PARAMETER_NOT_USED(esp_azure_iot_ptr);

    /* Process common events.  */
    ESP_PARAMETER_NOT_USED(common_events);

    /* Process module own events.  */
    ESP_PARAMETER_NOT_USED(module_own_events);
}
                                           
uint32_t esp_azure_iot_hub_client_disconnect(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
uint32_t status;
ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr;


    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTHub client disconnect fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Disconnect.  */
    status = esp_azure_iot_mqtt_client_disconnect(&hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt);
    if (status)
    {
        LogError("IoTHub client disconnect fail: 0x%02x", status);
        return(status);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Release the mqtt connection resource.  */
    if (hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context)
    {
        esp_azure_iot_buffer_free(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context);
        hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt_buffer_context = NULL;
    }

    /* Wakeup all suspend threads.  */
    for (thread_list_ptr = hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> esp_azure_iot_thread_next)
    {
        esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_thread_ptr);
    }

    /* Cleanup received messages. */
    esp_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata));
    esp_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata));
    esp_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata));
    esp_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata));

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}

static void esp_azure_iot_hub_client_received_message_cleanup(ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA *message)
{
ESP_PACKET *current_ptr = NULL;
ESP_PACKET *next_ptr = NULL;

    for (current_ptr = message -> esp_azure_iot_hub_client_message_head; current_ptr; current_ptr = next_ptr)
    {

        /* Get next packet in queue. */
        next_ptr = current_ptr -> esp_packet_next;

        /* Release current packet. */
        current_ptr -> esp_packet_next = NULL;
        esp_azure_iot_packet_release(current_ptr);
    }

    /* Reset received messages. */
    message -> esp_azure_iot_hub_client_message_head = NULL;
    message -> esp_azure_iot_hub_client_message_tail = NULL;
}

uint32_t esp_azure_iot_hub_client_deinitialize(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
uint32_t status;


    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTHub client deinitialize fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    esp_azure_iot_hub_client_disconnect(hub_client_ptr);

    status = esp_azure_iot_mqtt_client_delete(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt));
    if (status)
    {
        LogError("IoTHub client delete fail: 0x%02x", status);
        return(status);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Remove resource from list.  */
    status = esp_azure_iot_resource_remove(hub_client_ptr -> esp_azure_iot_ptr, &(hub_client_ptr -> esp_azure_iot_hub_client_resource));
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTHub client handle not found");
        return(status);
    }

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_device_cert_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             const char *device_certificate)
{
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL) || (device_certificate == NULL))
    {
        LogError("IoTHub device certificate set fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_device_certificate = device_certificate;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}
                                             
uint32_t esp_azure_iot_hub_client_symmetric_key_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               uint8_t *symmetric_key, uint32_t symmetric_key_length)
{
    if ((hub_client_ptr == NULL)  || (hub_client_ptr -> esp_azure_iot_ptr == NULL) ||
        (symmetric_key == NULL) || (symmetric_key_length == 0))
    {
        LogError("IoTHub client symmetric key fail: Invalid argument");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    hub_client_ptr -> esp_azure_iot_hub_client_symmetric_key = symmetric_key;
    hub_client_ptr -> esp_azure_iot_hub_client_symmetric_key_length = symmetric_key_length;

    hub_client_ptr -> esp_azure_iot_hub_client_token_refresh = esp_azure_iot_hub_client_sas_token_get;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_model_id_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                          uint8_t *model_id_ptr, uint32_t model_id_length)
{
    if ((hub_client_ptr == NULL)  || (hub_client_ptr -> esp_azure_iot_ptr == NULL) ||
        (model_id_ptr == NULL) || (model_id_length == 0))
    {
        LogError("IoTHub client model Id fail: Invalid argument");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Had no way to update option, so had to access the internal fields of iot_hub_client_core */
    hub_client_ptr -> iot_hub_client_core._internal.options.model_id = az_span_init(model_id_ptr, (int16_t)model_id_length);

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_telemetry_message_create(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      ESP_PACKET **packet_pptr, uint32_t wait_option)
{
ESP_PACKET *packet_ptr;
uint32_t topic_length;
uint32_t status;
az_result core_result;

    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL) || (packet_pptr == NULL))
    {
        LogError("IoTHub telemetry message create fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_publish_packet_get(hub_client_ptr -> esp_azure_iot_ptr,
                                             &(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                             &packet_ptr, wait_option);
    if (status)
    {
        LogError("Create telemetry data fail");
        return(status);
    }

    topic_length = (uint32_t)(packet_ptr -> esp_packet_data_end - packet_ptr -> esp_packet_prepend_ptr);
    core_result = az_iot_hub_client_telemetry_get_publish_topic(&hub_client_ptr -> iot_hub_client_core,
                                                                NULL, (char *)packet_ptr -> esp_packet_prepend_ptr,
                                                                topic_length, &topic_length);
    if (az_failed(core_result))
    {
        LogError("IoTHub client telemetry message create fail with error 0x%08x", core_result);
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_prepend_ptr + topic_length;
    packet_ptr -> esp_packet_length = topic_length;
    *packet_pptr = packet_ptr;

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                      
uint32_t esp_azure_iot_hub_client_telemetry_message_delete(ESP_PACKET *packet_ptr)
{

    esp_azure_iot_packet_release(packet_ptr);
    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_telemetry_property_add(ESP_PACKET *packet_ptr,
                                                    uint8_t *property_name, uint16_t property_name_length,
                                                    uint8_t *property_value, uint16_t property_value_length,
                                                    uint32_t wait_option)
{
    uint32_t status = 0;

    if ((packet_ptr == NULL) ||
        (property_name == NULL) ||
        (property_value == NULL))
    {
        LogError("IoTHub telemetry property add fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (*(packet_ptr -> esp_packet_append_ptr - 1) != '/')
    {
        status = esp_azure_iot_packet_append(packet_ptr, "&", 1, wait_option);
        if (status)
        {
            LogError("Telemetry data append fail");
            return(status);
        }
    }

    status = esp_azure_iot_packet_append(packet_ptr, property_name, (uint32_t)property_name_length, wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    status = esp_azure_iot_packet_append(packet_ptr, "=", 1, wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    status = esp_azure_iot_packet_append(packet_ptr, property_value, (uint32_t)property_value_length, wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                    
uint32_t esp_azure_iot_hub_client_telemetry_send(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                            ESP_PACKET *packet_ptr, uint8_t *telemetry_data,
                                            uint32_t data_size, uint32_t wait_option)
{
    uint32_t status;

    if ((hub_client_ptr == NULL) || (packet_ptr == NULL))
    {
        LogError("IoTHub telemetry send fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (telemetry_data && (data_size != 0))
    {

        /* Append payload. */
        status = esp_azure_iot_packet_append(packet_ptr, telemetry_data, data_size, 
                                       wait_option);
        if (status)
        {
            LogError("Telemetry data append fail");
            return(status);
        }
    }

    status = esp_azure_iot_publish_mqtt_packet(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                              packet_ptr, ESP_AZURE_IOT_MQTT_QOS_1, wait_option);
    if (status)
    {
        LogError("IoTHub client send fail: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }


    return(ESP_AZURE_IOT_SUCCESS );
}
                                            
uint32_t esp_azure_iot_hub_client_receive_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  uint32_t message_type,
                                                  void (*callback_ptr)(
                                                        ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        void *args),
                                                  void *callback_args)
{
    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTHub receive callback set fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    if (message_type == ESP_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_callback = callback_ptr;
        hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_callback_args = callback_args;
    }
    else if (message_type == ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_callback = callback_ptr;
        hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_callback_args = callback_args;
    }
    else if (message_type == ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata.esp_azure_iot_hub_client_message_callback = callback_ptr;
        hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata.esp_azure_iot_hub_client_message_callback_args = callback_args;
    }
    else if (message_type == ESP_AZURE_IOT_HUB_DIRECT_METHOD)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_callback = callback_ptr;
        hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_callback_args = callback_args;
    }
    else
    {

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        return(ESP_AZURE_IOT_NOT_SUPPORTED);
    }

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                  
uint32_t esp_azure_iot_hub_client_cloud_message_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    return(esp_azure_iot_hub_client_cloud_message_sub_unsub(hub_client_ptr, true));
}

uint32_t esp_azure_iot_hub_client_cloud_message_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    return(esp_azure_iot_hub_client_cloud_message_sub_unsub(hub_client_ptr, false));
}

static uint32_t esp_azure_iot_hub_client_message_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, uint32_t message_type,
                                                    ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA *metadata,
                                                    ESP_PACKET **packet_pptr, uint32_t wait_option)
{
    ESP_PACKET *packet_ptr = NULL;
    ESP_AZURE_IOT_THREAD_LIST thread_list;

    if ((hub_client_ptr == NULL) || (hub_client_ptr -> esp_azure_iot_ptr == NULL) || (packet_pptr == NULL))
    {
        LogError("IoTHub message receive fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (metadata -> esp_azure_iot_hub_client_message_process == NULL)
    {
        LogError("IoTHub message receive fail: NOT ENABLED");
        return(ESP_AZURE_IOT_NOT_ENABLED);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    if (metadata -> esp_azure_iot_hub_client_message_head)
    {
        packet_ptr = metadata -> esp_azure_iot_hub_client_message_head;
        if (metadata -> esp_azure_iot_hub_client_message_tail == packet_ptr)
        {
            metadata -> esp_azure_iot_hub_client_message_tail = NULL;
        }
        metadata -> esp_azure_iot_hub_client_message_head = packet_ptr -> esp_packet_next;
    } else if (wait_option) {
        thread_list.esp_azure_iot_thread_message_type = message_type;
        thread_list.esp_azure_iot_thread_ptr = esp_azure_iot_thread_identify();
        thread_list.esp_azure_iot_thread_received_message = NULL;
        thread_list.esp_azure_iot_thread_expected_id = 0;
        thread_list.esp_azure_iot_thread_next = hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended;
        hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended = &thread_list;

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

        esp_azure_iot_thread_sleep(thread_list.esp_azure_iot_thread_ptr, wait_option);

        /* Obtain the mutex.  */
        xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

        esp_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);

        /* Restore preemption. */
        esp_azure_iot_thread_preemption(thread_list.esp_azure_iot_thread_ptr);
        packet_ptr = thread_list.esp_azure_iot_thread_received_message;
    }

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    if (packet_ptr == NULL)
    {
        return(ESP_AZURE_IOT_NO_PACKET);
    }

    *packet_pptr = packet_ptr;

    return(ESP_AZURE_IOT_SUCCESS );
}

static uint32_t esp_azure_iot_hub_client_adjust_payload(ESP_PACKET *packet_ptr)
{
uint32_t status;
size_t topic_offset;
uint16_t topic_length;
size_t message_offset;
size_t message_length;

    status = esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset,
                                              &topic_length, &message_offset,
                                              &message_length);
    if (status)
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    packet_ptr -> esp_packet_length = message_length;

    /* Adjust packet to pointer to message payload. */
    while (packet_ptr)
    {
        if ((size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr) > message_offset)
        {

            /* This packet contains message payload. */
            packet_ptr -> esp_packet_prepend_ptr = packet_ptr -> esp_packet_prepend_ptr + message_offset;
            break;
        }

        message_offset -= (size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr);

        /* Set current packet to empty. */
        packet_ptr -> esp_packet_prepend_ptr = packet_ptr -> esp_packet_append_ptr;

        /* Move to next packet. */
        packet_ptr = packet_ptr -> esp_packet_next;
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_cloud_message_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   ESP_PACKET **packet_pptr, uint32_t wait_option)
{
    uint32_t status;
    
    status = esp_azure_iot_hub_client_message_receive(hub_client_ptr, ESP_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                     &(hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata),
                                                     packet_pptr, wait_option);
    if (status)
    {
        if (status != ESP_AZURE_IOT_NO_PACKET)
            LogError("IoTHub client device cloud message receive failed: 0x%02x", status);

        return(status);
    }

    return(esp_azure_iot_hub_client_adjust_payload(*packet_pptr));
}
                                                   
uint32_t esp_azure_iot_hub_client_cloud_message_property_get(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, ESP_PACKET *packet_ptr,
                                                        uint8_t *property_name, uint16_t property_name_length,
                                                        uint8_t **property_value, uint16_t *property_value_length)
{
    uint16_t topic_size;
    uint32_t status;
    size_t topic_offset;
    size_t message_offset = 0;
    size_t message_length = 0;
    uint8_t *topic_name;
    az_iot_hub_client_c2d_request request;
    az_span receive_topic;
    az_result core_result;
    az_span span;

    if (packet_ptr == NULL ||
        property_name == NULL ||
        property_value == NULL ||
        property_value_length == NULL)
    {
        LogError("IoTHub cloud message get property fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset, &topic_size, &message_offset, &message_length);
    if (status)
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    topic_name = packet_ptr -> esp_packet_data_start + topic_offset;

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((size_t)(packet_ptr -> esp_packet_append_ptr - topic_name) < (size_t)topic_size)
    {
        LogError("IoTHub cloud message get property fail: topic out of boundries of single packet");
        return(ESP_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, (int16_t)topic_size);
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_failed(core_result))
    {
        LogError("IoTHub cloud message get property fail: parsing error");
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    span = az_span_init(property_name, property_name_length);
    core_result = az_iot_hub_client_properties_find(&request.properties, span, &span);
    if (az_failed(core_result))
    {
        if (core_result == AZ_ERROR_ITEM_NOT_FOUND)
        {
            status = ESP_AZURE_IOT_NOT_FOUND;
        }
        else
        {
            LogError("IoTHub cloud message get property fail: property find");
            status = ESP_AZURE_IOT_SDK_CORE_ERROR;
        }

        return(status);
    }

    *property_value = (uint8_t *)az_span_ptr(span);
    *property_value_length = (uint16_t)az_span_size(span);

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_device_twin_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
uint32_t status;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client device twin subscribe fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_mqtt_client_subscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                       AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC) - 1,
                                       ESP_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client device twin subscribe fail: 0x%02x", status);
        return(status);
    }

    status = esp_azure_iot_mqtt_client_subscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                       AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC) - 1,
                                       ESP_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client device twin subscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_process =
                      esp_azure_iot_hub_client_device_twin_process;
    hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata.esp_azure_iot_hub_client_message_process =
                      esp_azure_iot_hub_client_device_twin_process;

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_device_twin_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
uint32_t status;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client device twin unsubscribe fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_mqtt_client_unsubscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                         AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client device twin unsubscribe fail: 0x%02x", status);
        return(status);
    }

    status = esp_azure_iot_mqtt_client_unsubscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                         AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client device twin unsubscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_process = NULL;
    hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata.esp_azure_iot_hub_client_message_process = NULL;

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_report_properties_response_callback_set(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     void (*callback_ptr)(
                                                                           ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           uint32_t request_id,
                                                                           uint32_t response_status,
                                                                           void *args),
                                                                     void *callback_args)
{
    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client device twin set callback fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    hub_client_ptr -> esp_azure_iot_hub_client_report_properties_response_callback = callback_ptr;
    hub_client_ptr -> esp_azure_iot_hub_client_report_properties_response_callback_args = callback_args;

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_device_twin_reported_properties_send(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  uint8_t *message_buffer, uint32_t message_length,
                                                                  uint32_t *request_id_ptr, uint32_t *response_status_ptr,
                                                                  uint32_t wait_option)
{
uint32_t status;
uint8_t *buffer_ptr;
uint32_t buffer_size;
void *buffer_context;
ESP_PACKET *packet_ptr;
az_span topic_span;
uint32_t topic_length;
uint32_t request_id;
az_span request_id_span;
ESP_AZURE_IOT_THREAD_LIST thread_list;
az_result core_result;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client device twin receive fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/PATCH/properties/reported/?$rid={request id}"
     * 2. Wait for the response if required.
     * 3. Return result if present.
     * */
    if (hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_process == NULL)
    {
        LogError("IoTHub client device twin receive fail: NOT ENABLED");
        return(ESP_AZURE_IOT_NOT_ENABLED);
    }

    status = esp_azure_iot_buffer_allocate(hub_client_ptr -> esp_azure_iot_ptr, &buffer_ptr,
                                          &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Generate odd request id for reported properties send */
    if ((hub_client_ptr -> esp_azure_iot_hub_client_request_id & 0x1))
    {
        hub_client_ptr -> esp_azure_iot_hub_client_request_id += 2;
    }
    else
    {
        hub_client_ptr -> esp_azure_iot_hub_client_request_id += 1;
    }

    request_id = hub_client_ptr -> esp_azure_iot_hub_client_request_id;
    topic_span = az_span_init(buffer_ptr, (int16_t)buffer_size);
    core_result = az_span_u32toa(topic_span, request_id, &topic_span);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTHub client device failed to u32toa");
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    request_id_span = az_span_init(buffer_ptr, (int16_t)(buffer_size - (uint32_t)az_span_size(topic_span)));
    core_result = az_iot_hub_client_twin_patch_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 request_id_span, (char *)az_span_ptr(topic_span),
                                                                 (uint32_t)az_span_size(topic_span), &topic_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTHub client device twin subscribe fail: ESP_AZURE_IOT_HUB_CLIENT_TOPIC_SIZE is too small.");
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    thread_list.esp_azure_iot_thread_message_type = ESP_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE;
    thread_list.esp_azure_iot_thread_ptr = esp_azure_iot_thread_identify();
    thread_list.esp_azure_iot_thread_expected_id = request_id;
    thread_list.esp_azure_iot_thread_received_message = NULL;
    thread_list.esp_azure_iot_thread_response_status = 0;
    thread_list.esp_azure_iot_thread_next = hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended;
    hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended = &thread_list;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    status = esp_azure_iot_mqtt_client_publish(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                     (char *)az_span_ptr(topic_span), topic_length,
                                     (char *)message_buffer, message_length, 0,
                                     ESP_AZURE_IOT_MQTT_QOS_0, wait_option);
    esp_azure_iot_buffer_free(buffer_context);

    if (status)
    {
        /* remove thread from waiting suspend queue.  */
        xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);
        esp_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);
        
        /* Restore preemption. */
        esp_azure_iot_thread_preemption(thread_list.esp_azure_iot_thread_ptr);
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

        LogError("IoTHub client reported state send: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }
    LogDebug("[%s]request_id: %u", __func__, request_id);

    if ((thread_list.esp_azure_iot_thread_received_message) == NULL && wait_option)
    {
        esp_azure_iot_thread_sleep(thread_list.esp_azure_iot_thread_ptr, wait_option);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    esp_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);

    /* Restore preemption. */
    esp_azure_iot_thread_preemption(thread_list.esp_azure_iot_thread_ptr);
    packet_ptr = thread_list.esp_azure_iot_thread_received_message;

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    if (packet_ptr == NULL)
    {
        LogError("IoTHub client reported state not responded");
        return(ESP_AZURE_IOT_NO_PACKET);
    }

    if (request_id_ptr)
    {
        *request_id_ptr = request_id;
    }

    if (response_status_ptr)
    {
        *response_status_ptr = thread_list.esp_azure_iot_thread_response_status;
    }

    /* Release message block. */
    esp_azure_iot_packet_release(packet_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_device_twin_properties_request(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            uint32_t wait_option)
{
uint32_t status;
uint32_t topic_length;
uint8_t *buffer_ptr;
uint32_t buffer_size;
void *buffer_context;
az_span request_id_span;
az_span topic_span;
az_result core_result;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client device twin publish fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/GET/?$rid={request id}"
     * */
    status = esp_azure_iot_buffer_allocate(hub_client_ptr -> esp_azure_iot_ptr, &buffer_ptr,
                                          &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin publish fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    /* Generate even request id for twin properties request */
    if ((hub_client_ptr -> esp_azure_iot_hub_client_request_id & 0x1) == 0)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_request_id += 2;
    }
    else
    {
        hub_client_ptr -> esp_azure_iot_hub_client_request_id += 1;
    }

    if (hub_client_ptr -> esp_azure_iot_hub_client_request_id == 0)
    {
        hub_client_ptr -> esp_azure_iot_hub_client_request_id = 2;
    }

    topic_span = az_span_init(buffer_ptr, (int16_t)buffer_size);
    core_result = az_span_u32toa(topic_span, hub_client_ptr -> esp_azure_iot_hub_client_request_id, &topic_span);
    if (az_failed(core_result))
    {

        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTHub client device failed to u32toa");
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    request_id_span = az_span_init(buffer_ptr, (int16_t)(buffer_size - (uint32_t)az_span_size(topic_span)));
    core_result = az_iot_hub_client_twin_document_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                    request_id_span, (char *)az_span_ptr(topic_span),
                                                                    (uint32_t)az_span_size(topic_span), &topic_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTHub client device twin get topic fail.");
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Release the mutex.  */
    xSemaphoreGive(hub_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    status = esp_azure_iot_mqtt_client_publish(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                     (char *)az_span_ptr(topic_span),
                                     topic_length, NULL, 0, 0,
                                     ESP_AZURE_IOT_MQTT_QOS_0, wait_option);
    esp_azure_iot_buffer_free(buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_hub_client_device_twin_properties_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            ESP_PACKET **packet_pptr, uint32_t wait_option)
{
uint32_t status;
size_t topic_offset;
uint16_t topic_length;
size_t message_offset = 0;
size_t message_length = 0;
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;
ESP_PACKET *packet_ptr;

    if (hub_client_ptr == NULL || packet_pptr == NULL)
    {
        LogError("IoTHub client device twin receive failed: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the twin document is available to receive from linklist.
     * 2. If present check the response.
     * 3. Return the payload of the response.
     * */
    status = esp_azure_iot_hub_client_message_receive(hub_client_ptr, ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES,
                                                     &(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata),
                                                     &packet_ptr, wait_option);
    if (status)
    {
        if (status != ESP_AZURE_IOT_NO_PACKET)
            LogError("IoTHub client device twin properties message receive failed: 0x%02x", status);

        return(status);
    }

    *packet_pptr = packet_ptr;
    status = esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length);
    if (status)
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    topic_span = az_span_init(&(packet_ptr -> esp_packet_prepend_ptr[topic_offset]), (int16_t)topic_length);
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                              topic_span, &out_twin_response);
    if (az_failed(core_result))
    {
        /* Topic name does not match device twin format. */
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    if ((out_twin_response.status < 200) || (out_twin_response.status >= 300))
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SERVER_RESPONSE_ERROR);
    }

    *packet_pptr = packet_ptr;

    return(esp_azure_iot_hub_client_adjust_payload(*packet_pptr));
}

uint32_t esp_azure_iot_hub_client_device_twin_desired_properties_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    ESP_PACKET **packet_pptr, uint32_t wait_option)
{
uint32_t status;

    if (hub_client_ptr == NULL || packet_pptr == NULL)
    {
        LogError("IoTHub client device twin receive properties failed: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the desired properties document is available to receive from linklist.
     * 2. Return result if present.
     * */
    status = esp_azure_iot_hub_client_message_receive(hub_client_ptr, ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES,
                                                     &(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata),
                                                     packet_pptr, wait_option);
    if (status)
    {
        if (status != ESP_AZURE_IOT_NO_PACKET)
            LogError("IoTHub client device twin desired message receive failed: 0x%02x", status);

        return(status);
    }

    return(esp_azure_iot_hub_client_adjust_payload(*packet_pptr));
}
                                                        
static uint32_t esp_azure_iot_hub_client_cloud_message_sub_unsub(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, uint32_t is_subscribe)
{
    uint32_t status;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub cloud message subscribe fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (is_subscribe)
    {
        status = esp_azure_iot_mqtt_client_subscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                           AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, sizeof(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC) - 1,
                                           ESP_AZURE_IOT_MQTT_QOS_1);
        if (status)
        {
            LogError("IoTHub cloud message subscribe fail: 0x%02x", status);
            return(status);
        }

        hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_process = esp_azure_iot_hub_client_c2d_process;
    }
    else
    {
        status = esp_azure_iot_mqtt_client_unsubscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                             AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, sizeof(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC) - 1);
        if (status)
        {
            LogError("IoTHub cloud message subscribe fail: 0x%02x", status);
            return(status);
        }

        hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_process = NULL;
    }

    return(ESP_AZURE_IOT_SUCCESS );
}

static void esp_azure_iot_hub_client_mqtt_receive_callback(ESP_MQTT_CLIENT* client_ptr,
                                                          uint32_t number_of_messages)
{

ESP_AZURE_IOT_RESOURCE *resource = esp_azure_iot_resource_search(client_ptr);
ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr = NULL;
ESP_PACKET *packet_ptr;
ESP_PACKET *packet_next_ptr = NULL;
size_t topic_offset;
uint16_t topic_length;
size_t message_offset;
size_t message_length;

    /* This function is protected by MQTT mutex. */

    ESP_PARAMETER_NOT_USED(number_of_messages);

    if (resource && (resource -> esp_azure_iot_resource_type == ESP_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_client_ptr = (ESP_AZURE_IOT_HUB_CLIENT *)resource -> esp_azure_iot_resource_data_ptr;
    }

    if (hub_client_ptr)
    {
        for (packet_ptr = client_ptr -> message_receive_queue_head;
             packet_ptr;
             packet_ptr = packet_next_ptr)
        {

            /* Store next packet in case current packet is consumed. */
            packet_next_ptr = packet_ptr -> esp_packet_next;

            /* Adjust packet to simply process logic. */
            esp_azure_iot_mqtt_packet_adjust(packet_ptr);

            if (esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length))
            {

                /* Message not supported. It will be released. */
                esp_azure_iot_packet_release(packet_ptr);
                continue;
            }

            if ((topic_offset + topic_length) >
                (size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr))
            {

                /* Only process topic in the first packet since the fixed topic is short enough to fit into one packet. */
                topic_length = (uint16_t)(((size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr) -
                                         topic_offset) & 0xFFFF);
            }

            if (hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_process &&
                (hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_process(hub_client_ptr, packet_ptr,
                                                                                                                          topic_offset,
                                                                                                                          topic_length) == ESP_AZURE_IOT_SUCCESS))
            {

                /* Direct method message is processed. */
                continue;
            }

            if (hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_process &&
                (hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata.esp_azure_iot_hub_client_message_process(hub_client_ptr, packet_ptr,
                                                                                                                        topic_offset,
                                                                                                                        topic_length) == ESP_AZURE_IOT_SUCCESS))
            {

                /* Could to Device message is processed. */
                continue;
            }

            if ((hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_process) &&
                (hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata.esp_azure_iot_hub_client_message_process(hub_client_ptr,
                                                                                               packet_ptr, topic_offset,
                                                                                               topic_length) == ESP_AZURE_IOT_SUCCESS))
            {

                /* Device Twin message is processed. */
                continue;
            }

            /* Message not supported. It will be released. */
            esp_azure_iot_packet_release(packet_ptr);
        }

        /* Clear all message from MQTT receive queue. */
        client_ptr -> message_receive_queue_head = NULL;
        client_ptr -> message_receive_queue_tail = NULL;
        client_ptr -> message_receive_queue_depth = 0;
    }
    
}
                                                          
static void esp_azure_iot_hub_client_message_notify(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   ESP_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_METADATA *metadata,
                                                   ESP_PACKET *packet_ptr)
{

    if (metadata -> esp_azure_iot_hub_client_message_tail)
    {
        metadata -> esp_azure_iot_hub_client_message_tail -> esp_packet_next = packet_ptr;
    }
    else
    {
        metadata -> esp_azure_iot_hub_client_message_head = packet_ptr;
    }
    metadata -> esp_azure_iot_hub_client_message_tail = packet_ptr;

    /* Check for user callback function. */
    if (metadata -> esp_azure_iot_hub_client_message_callback)
    {
        metadata -> esp_azure_iot_hub_client_message_callback(hub_client_ptr,
                                                             metadata -> esp_azure_iot_hub_client_message_callback_args);
    }
    
}

static uint32_t esp_azure_iot_hub_client_receive_thread_find(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        ESP_PACKET *packet_ptr, uint32_t message_type,
                                                        uint32_t request_id, ESP_AZURE_IOT_THREAD_LIST **thread_list_pptr)
{
ESP_AZURE_IOT_THREAD_LIST *thread_list_prev = NULL;
ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr;

    /* Search thread waiting for message type. */
    for (thread_list_ptr = hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> esp_azure_iot_thread_next)
    {
        if ((thread_list_ptr -> esp_azure_iot_thread_message_type == message_type) &&
            (request_id == thread_list_ptr -> esp_azure_iot_thread_expected_id))
        {

            /* Found a thread waiting for message type. */
            if (thread_list_prev == NULL)
            {
                hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended = thread_list_ptr -> esp_azure_iot_thread_next;
            }
            else
            {
                thread_list_prev -> esp_azure_iot_thread_next = thread_list_ptr -> esp_azure_iot_thread_next;
            }
            thread_list_ptr -> esp_azure_iot_thread_received_message = packet_ptr;
            *thread_list_pptr =  thread_list_ptr;
            return(ESP_AZURE_IOT_SUCCESS);
        }

        thread_list_prev = thread_list_ptr;
    }

    return(ESP_AZURE_IOT_NOT_FOUND);
}

static uint32_t esp_azure_iot_hub_client_c2d_process(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                ESP_PACKET *packet_ptr,
                                                size_t topic_offset,
                                                uint16_t topic_length)
{
    uint8_t *topic_name;
    az_iot_hub_client_c2d_request request;
    az_span receive_topic;
    az_result core_result;
    uint32_t status;
    ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_name = &(packet_ptr -> esp_packet_prepend_ptr[topic_offset]);

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((size_t)(packet_ptr -> esp_packet_append_ptr - topic_name) < topic_length)
    {
        LogError("topic out of boundries of single packet");
        return(ESP_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, topic_length);
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_failed(core_result))
    {

        /* Topic name does not match C2D format. */
        return(ESP_AZURE_IOT_NOT_FOUND);
    }

    status = esp_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         ESP_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                         0, &thread_list_ptr);
    if (status == ESP_AZURE_IOT_SUCCESS)
    {
        esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_thread_ptr);
        return(ESP_AZURE_IOT_SUCCESS);
    }

    /* No thread is waiting for C2D message yet. */
    esp_azure_iot_hub_client_message_notify(hub_client_ptr,
                                           &(hub_client_ptr -> esp_azure_iot_hub_client_c2d_message_metadata),
                                           packet_ptr);    

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                
static uint32_t esp_azure_iot_hub_client_direct_method_process(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                          ESP_PACKET *packet_ptr,
                                                          size_t topic_offset,
                                                          uint16_t topic_length)
{
    uint8_t *topic_name;
    az_iot_hub_client_method_request request;
    az_span receive_topic;
    az_result core_result;
    uint32_t status;
    ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_name = &(packet_ptr -> esp_packet_prepend_ptr[topic_offset]);

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((size_t)(packet_ptr -> esp_packet_append_ptr - topic_name) < topic_length)
    {
        LogError("topic out of boundries of single packet");
        return(ESP_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, topic_length);
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 receive_topic, &request);
    if (az_failed(core_result))
    {

        /* Topic name does not match direct method format. */
        return(ESP_AZURE_IOT_NOT_FOUND);
    }
    
    status = esp_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         ESP_AZURE_IOT_HUB_DIRECT_METHOD,
                                                         0, &thread_list_ptr);
    if (status == ESP_AZURE_IOT_SUCCESS)
    {
        esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_thread_ptr);
        return(ESP_AZURE_IOT_SUCCESS);
    }

    /* No thread is waiting for direct method message yet. */
    esp_azure_iot_hub_client_message_notify(hub_client_ptr,
                                           &(hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata),
                                           packet_ptr);

    return(ESP_AZURE_IOT_SUCCESS );
}

static uint32_t esp_azure_iot_hub_client_device_twin_message_type_get(az_iot_hub_client_twin_response *out_twin_response_ptr,
                                                                 uint32_t request_id)
{
uint32_t mesg_type;

    switch (out_twin_response_ptr -> response_type)
    {
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_GET :
        /* fall through */
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_REPORTED_PROPERTIES :
        {
            /* odd requests are of reported properties and even of twin properties*/
            mesg_type = request_id % 2 == 0 ? ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
                        ESP_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE;
        }
        break;

        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_DESIRED_PROPERTIES :
        {
            mesg_type = ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES;
        }
        break;

        default :
        {
            mesg_type = ESP_AZURE_IOT_HUB_NONE;
        }
    }

    return mesg_type;
}

static uint32_t esp_azure_iot_hub_client_device_twin_process(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        ESP_PACKET *packet_ptr,
                                                        size_t topic_offset,
                                                        uint16_t topic_length)
{
ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr = NULL;
uint32_t message_type;
uint32_t request_id;
uint32_t correlation_id;
uint32_t status;
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_span = az_span_init(&(packet_ptr -> esp_packet_prepend_ptr[topic_offset]), (int16_t)topic_length);
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                              topic_span, &out_twin_response);
    if (az_failed(core_result))
    {
        /* Topic name does not match device twin format. */
            return(ESP_AZURE_IOT_NOT_FOUND);
    }

    if (az_span_ptr(out_twin_response.request_id)) {
        core_result = az_span_atou32(out_twin_response.request_id, &request_id);
        if (az_failed(core_result))
        {
            /* Topic name does not match device twin format. */
            return(ESP_AZURE_IOT_NOT_FOUND);
        }
    }

    message_type = esp_azure_iot_hub_client_device_twin_message_type_get(&out_twin_response, request_id);
    if (message_type == ESP_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE)
    {
        /* only requested thread should be woken*/
        correlation_id = request_id;
    }
    else
    {
        /* any thread can be woken*/
        correlation_id = 0;
    }

    status = esp_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         message_type,
                                                         correlation_id, &thread_list_ptr);
    if (status == ESP_AZURE_IOT_SUCCESS)
    {
        thread_list_ptr -> esp_azure_iot_thread_response_status = (uint32_t)out_twin_response.status;
        esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_thread_ptr);
        return(ESP_AZURE_IOT_SUCCESS);
    }

    switch(message_type)
    {
        case ESP_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE :
        {
            if (hub_client_ptr -> esp_azure_iot_hub_client_report_properties_response_callback)
            {
                hub_client_ptr -> esp_azure_iot_hub_client_report_properties_response_callback(hub_client_ptr,
                                                                                              request_id,
                                                                                              out_twin_response.status,
                                                                                              hub_client_ptr -> esp_azure_iot_hub_client_report_properties_response_callback_args);
            }

            esp_azure_iot_packet_release(packet_ptr);
        }
        break;

        case ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
        {

            /* No thread is waiting for device twin message yet. */
            esp_azure_iot_hub_client_message_notify(hub_client_ptr,
                                                   &(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_metadata),
                                                   packet_ptr);
        }
        break;

        case ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES :
        {
            /* No thread is waiting for device twin message yet. */
            esp_azure_iot_hub_client_message_notify(hub_client_ptr,
                                                   &(hub_client_ptr -> esp_azure_iot_hub_client_device_twin_desired_properties_metadata),
                                                   packet_ptr);
        }
        break;

        default :
            esp_azure_iot_packet_release(packet_ptr);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

static void esp_azure_iot_hub_client_thread_dequeue(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   ESP_AZURE_IOT_THREAD_LIST *thread_list_ptr)
{
    ESP_AZURE_IOT_THREAD_LIST *thread_list_prev = NULL;
    ESP_AZURE_IOT_THREAD_LIST *thread_list_current;

    for (thread_list_current = hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended;
         thread_list_current;
         thread_list_current = thread_list_current -> esp_azure_iot_thread_next)
    {
        if (thread_list_current == thread_list_ptr)
        {

            /* Found the thread to dequeue. */
            if (thread_list_prev == NULL)
            {
                hub_client_ptr -> esp_azure_iot_hub_client_thread_suspended = thread_list_current -> esp_azure_iot_thread_next;
            }
            else
            {
                thread_list_prev -> esp_azure_iot_thread_next = thread_list_current -> esp_azure_iot_thread_next;
            }
            break;
        }

        thread_list_prev = thread_list_current;
    }
}   

static uint32_t esp_azure_iot_hub_client_sas_token_get(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  size_t expiry_time_secs, uint8_t *key, uint32_t key_len,
                                                  uint8_t *sas_buffer, uint32_t sas_buffer_len, uint32_t *sas_length)
{
    uint8_t *buffer_ptr;
    uint32_t buffer_size;
    void *buffer_context;
    az_span span = az_span_init(sas_buffer, (int16_t)sas_buffer_len);
    az_span buffer_span;
    uint32_t status;
    uint8_t *output_ptr;
    uint32_t output_len;
    az_result core_result;

    status = esp_azure_iot_buffer_allocate(hub_client_ptr -> esp_azure_iot_ptr, &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTProvisioning client connect fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    core_result = az_iot_hub_client_sas_get_signature(&(hub_client_ptr -> iot_hub_client_core),
                                                      expiry_time_secs, span, &span);
    if (az_failed(core_result))
    {
        LogError("IoTHub failed failed to get signature with error : 0x%08x", core_result);
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = esp_azure_iot_url_encoded_hmac_sha256_calculate(&(hub_client_ptr -> esp_azure_iot_hub_client_resource),
                                                            key, key_len, az_span_ptr(span), (uint32_t)az_span_size(span),
                                                            buffer_ptr, buffer_size, &output_ptr, &output_len);
    if (status)
    {
        LogError("IoTHub failed to encoded hash");
        esp_azure_iot_buffer_free(buffer_context);
        return(status);
    }

    buffer_span = az_span_init(output_ptr, (int16_t)output_len);
    core_result= az_iot_hub_client_sas_get_password(&(hub_client_ptr -> iot_hub_client_core),
                                                    buffer_span, expiry_time_secs, AZ_SPAN_NULL,
                                                    (char *)sas_buffer, sas_buffer_len, &sas_buffer_len);
    if (az_failed(core_result))
    {
        LogError("IoTHub failed to generate token with error : 0x%08x", core_result);
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    *sas_length = sas_buffer_len;
    esp_azure_iot_buffer_free(buffer_context);

    return(ESP_AZURE_IOT_SUCCESS );
}
                                                  
uint32_t esp_azure_iot_hub_client_direct_method_enable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    uint32_t status;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client direct method subscribe fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_mqtt_client_subscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                       AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC) - 1,
                                       ESP_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client direct method subscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_process = esp_azure_iot_hub_client_direct_method_process;
   
    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_direct_method_disable(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    uint32_t status;

    if (hub_client_ptr == NULL)
    {
        LogError("IoTHub client direct method unsubscribe fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_mqtt_client_unsubscribe(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                         AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client direct method unsubscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata.esp_azure_iot_hub_client_message_process = NULL;

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_direct_method_message_receive(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           uint8_t **method_name_pptr, uint16_t *method_name_length_ptr,
                                                           void **context_pptr, uint16_t *context_length_ptr,
                                                           ESP_PACKET **packet_pptr, uint32_t wait_option)
{
    uint32_t status;
    size_t topic_offset;
    uint16_t topic_length;
    az_span topic_span;
    size_t message_offset;
    size_t message_length;
    ESP_PACKET *packet_ptr;
    az_result core_result;
    az_iot_hub_client_method_request request;

    if ((hub_client_ptr == NULL) ||
        (method_name_pptr == NULL) ||
        (method_name_length_ptr == NULL) ||
        (context_pptr == NULL) ||
        (context_length_ptr == NULL) ||
        (packet_pptr == NULL))
    {
        LogError("IoTHub client direct method receive fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    status = esp_azure_iot_hub_client_message_receive(hub_client_ptr, ESP_AZURE_IOT_HUB_DIRECT_METHOD,
                                                     &(hub_client_ptr -> esp_azure_iot_hub_client_direct_method_metadata),
                                                     packet_pptr, wait_option);
    if (status)
    {
        if (status != ESP_AZURE_IOT_NO_PACKET)
            LogError("IoTHub client direct method message receive fail: status = 0x%08x\r\n", status);

        return(status);
    }

    packet_ptr = *packet_pptr;
    status = esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length);
    if (status)
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    topic_span = az_span_init(&(packet_ptr -> esp_packet_prepend_ptr[topic_offset]), topic_length);
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core), topic_span, &request);
    if (az_failed(core_result))
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    *packet_pptr = packet_ptr;

    /* Adjust packet to pointer to message payload. */
    while (packet_ptr)
    {
        if ((size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr) > message_offset)
        {

            /* This packet contains message payload. */
            packet_ptr -> esp_packet_prepend_ptr = packet_ptr -> esp_packet_prepend_ptr + message_offset;
            break;
        }

        message_offset -= (size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr);

        /* Set current packet to empty. */
        packet_ptr -> esp_packet_prepend_ptr = packet_ptr -> esp_packet_append_ptr;

        /* Move to next packet. */
        packet_ptr = packet_ptr -> esp_packet_next;
    }

    *method_name_pptr = az_span_ptr(request.name);
    *method_name_length_ptr = (uint16_t)az_span_size(request.name);
    *context_pptr = (void*)az_span_ptr(request.request_id);
    *context_length_ptr =  (uint16_t)az_span_size(request.request_id);

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_hub_client_direct_method_message_response(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            uint32_t status_code, void *context_ptr, uint16_t context_length,
                                                            uint8_t *payload, uint32_t payload_length, uint32_t wait_option)

{
    ESP_PACKET *packet_ptr;
    uint32_t topic_length;
    az_span request_id_span;
    uint32_t status;
    az_result core_result;

    if ((hub_client_ptr == NULL) ||
        (hub_client_ptr -> esp_azure_iot_ptr == NULL) ||
        (context_ptr == NULL) ||
        (context_length == 0))
    {
        LogError("IoTHub telemetry message create fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* prepare response packet */
    status = esp_azure_iot_publish_packet_get(hub_client_ptr -> esp_azure_iot_ptr,
                                             &(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt),
                                             &packet_ptr, wait_option);
    if (status)
    {
        LogError("Create response data fail");
        return(status);
    }

    topic_length = (uint32_t)(packet_ptr -> esp_packet_data_end - packet_ptr -> esp_packet_prepend_ptr);
    request_id_span = az_span_init((uint8_t*)context_ptr, (int16_t)context_length);
    core_result = az_iot_hub_client_methods_response_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                       request_id_span, (uint16_t)status_code,
                                                                       (char *)packet_ptr -> esp_packet_prepend_ptr,
                                                                       topic_length, &topic_length);
    if (az_failed(core_result))
    {
        LogError("Failed to create the method response topic");
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }


    packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_prepend_ptr + topic_length;
    packet_ptr -> esp_packet_length = topic_length;

    if (payload && (payload_length != 0))
    {

        /* Append payload. */
        status = esp_azure_iot_packet_append(packet_ptr, payload, payload_length, wait_option);
        if (status)
        {
            LogError("Method reponse data append fail");
            esp_azure_iot_packet_release(packet_ptr);
            return(status);
        }
    }
    else
    {
        /* Append payload. */
        status = esp_azure_iot_packet_append(packet_ptr, ESP_AZURE_IOT_HUB_CLIENT_EMPTY_JSON, sizeof(ESP_AZURE_IOT_HUB_CLIENT_EMPTY_JSON) - 1, wait_option);
        if (status)
        {
            LogError("Adding empty json failed.");
            esp_azure_iot_packet_release(packet_ptr);
            return(status);
        }
    }

    status = esp_azure_iot_publish_mqtt_packet(&(hub_client_ptr -> esp_azure_iot_hub_client_resource.esp_azure_iot_mqtt), packet_ptr, ESP_AZURE_IOT_MQTT_QOS_0, wait_option);
    if (status)
    {
        LogError("IoTHub client method response fail: PUBLISH FAIL: 0x%02x", status);
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}