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

#include "esp_azure_iot_provisioning_client.h"

/* Define AZ IoT Provisioning Client state.  */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_NONE                  0
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT                  1
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_CONNECT               2
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_SUBSCRIBE             3
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_REQUEST               4
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_WAITING_FOR_RESPONSE  5
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE                  6
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_ERROR                 7

/* Define AZ IoT Provisioning Client topic format. */
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_REG_SUB_TOPIC                "$dps/registrations/res/#"
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_START                "{\"registrationId\" : \""
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_END                  "\"}"
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_POLICY_NAME                  "registration"

/* Set the default timeout for connecting on event thread. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_TIMEOUT
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_TIMEOUT              (20 * ESP_IP_PERIODIC_RATE)
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_TIMEOUT */

/* Set the default retry to Provisioning service. */
#ifndef ESP_AZURE_IOT_PROVISIONING_CLIENT_DEFAULT_RETRY
#define ESP_AZURE_IOT_PROVISIONING_CLIENT_DEFAULT_RETRY                (3)
#endif /* ESP_AZURE_IOT_PROVISIONING_CLIENT_DEFAULT_RETRY */

static uint32_t esp_azure_iot_provisioning_client_connect_internal(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, uint32_t wait_option);
static void esp_azure_iot_provisioning_client_mqtt_receive_callback(ESP_MQTT_CLIENT *client_ptr, uint32_t number_of_messages);
static void esp_azure_iot_provisioning_client_mqtt_disconnect_notify(ESP_MQTT_CLIENT *client_ptr);
static uint32_t esp_azure_iot_provisioning_client_send_req(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, az_iot_provisioning_client_register_response const *register_response, uint32_t wait_option);
static void esp_azure_iot_provisioning_client_event_process(ESP_AZURE_IOT *esp_azure_iot_ptr, size_t common_events, size_t module_own_events);
static void esp_azure_iot_provisioning_client_update_state(ESP_AZURE_IOT_PROVISIONING_CLIENT *context, uint32_t action_result);

static uint32_t esp_azure_iot_provisioning_client_process_message(ESP_AZURE_IOT_PROVISIONING_CLIENT *context, ESP_PACKET *packet_ptr, ESP_AZURE_IOT_PROVISIONING_RESPONSE *response)
{
size_t topic_offset;
uint16_t topic_length;
size_t message_offset;
size_t message_length;
az_span received_topic;
az_span received_payload;
az_result core_result;
uint32_t status;

    status = esp_azure_iot_mqtt_client_packet_process(packet_ptr, &topic_offset, &topic_length,
                                              &message_offset, &message_length);
    if (status)
    {
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    if ((size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr) <
        (message_offset + message_length))
    {
        LogError("IoTProvisioning client failed to parse chained packet");
        return(ESP_AZURE_IOT_MESSAGE_TOO_LONG);
    }

    received_topic = az_span_init(packet_ptr -> esp_packet_prepend_ptr + topic_offset, (int16_t)topic_length);
    received_payload = az_span_init(packet_ptr -> esp_packet_prepend_ptr + message_offset, (int16_t)message_length);
    core_result = az_iot_provisioning_client_parse_received_topic_and_payload(&(context -> esp_azure_iot_provisioning_client_core),
                                                                  received_topic, received_payload,
                                                                  &response -> register_response);
    if (az_failed(core_result))
    {
        LogError("IoTProvisioning client failed to parse packet, error: 0x%08x", core_result);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    response -> packet_ptr = packet_ptr;

    return(ESP_AZURE_IOT_SUCCESS);
}

static void esp_azure_iot_provisioning_client_mqtt_disconnect_notify(ESP_MQTT_CLIENT *client_ptr)
{
uint32_t status;
ESP_AZURE_IOT_RESOURCE *resource = esp_azure_iot_resource_search(client_ptr);
ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr = NULL;

    /* This function is protected by MQTT mutex. */

    if (resource && (resource -> esp_azure_iot_resource_type == ESP_AZURE_IOT_RESOURCE_IOT_PROVISIONING))
    {
        prov_client_ptr = (ESP_AZURE_IOT_PROVISIONING_CLIENT *)resource -> esp_azure_iot_resource_data_ptr;
    }

    /* Set disconnect event.  */
    if (prov_client_ptr)
    {
        status = esp_azure_iot_event_group_set(&(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                           ESP_AZURE_IOT_PROVISIONING_CLIENT_DISCONNECT_EVENT);
        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(prov_client_ptr, status);
        }
    }
}

static uint32_t esp_azure_iot_provisioning_client_connect_internal(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                              uint32_t wait_option)
{

uint32_t status;
size_t server_address;
ESP_MQTT_CLIENT *mqtt_client_ptr;
uint32_t dns_timeout = wait_option;
ESP_AZURE_IOT_RESOURCE *resource_ptr;

    /* Set the DNS timeout as ESP_AZURE_IOT_PROVISIONING_CLIENT_DNS_TIMEOUT for non-blocking mode. */
    if (dns_timeout == 0)
    {
        dns_timeout = ESP_AZURE_IOT_PROVISIONING_CLIENT_DNS_TIMEOUT;
    }

    /* Resolve the host name.  */
    status = esp_azure_iot_get_host_by_name(prov_client_ptr -> esp_azure_iot_provisioning_client_endpoint,
                                      &server_address, dns_timeout, 0);
    if (status)
    {
        LogError("IoTProvisioning client connect fail: DNS RESOLVE FAIL: 0x%02x", status);
        return(status);
    }

    /* Set MQTT Client.  */
    resource_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource);
    mqtt_client_ptr = &(resource_ptr -> esp_azure_iot_mqtt);

    /* Set login info.  */
    status = esp_azure_iot_mqtt_client_login_set(mqtt_client_ptr, (char *)resource_ptr -> esp_azure_iot_mqtt_user_name,
                                       resource_ptr -> esp_azure_iot_mqtt_user_name_length,
                                       (char *)resource_ptr -> esp_azure_iot_mqtt_sas_token,
                                       resource_ptr -> esp_azure_iot_mqtt_sas_token_length);
    if (status)
    {
        LogError("IoTProvisioning client connect fail: MQTT CLIENT LOGIN SET FAIL: 0x%02x", status);
        return(status);
    }

    /* Start MQTT connection.  */
    status = esp_azure_iot_mqtt_client_secure_connect(mqtt_client_ptr, &server_address, ESP_AZURE_IOT_MQTT_TLS_PORT,
                                                      ESP_AZURE_IOT_MQTT_KEEP_ALIVE, false, wait_option);

    if ((wait_option == ESP_NO_WAIT) && (status == ESP_IN_PROGRESS))
    {
        LogInfo("IoTProvisioning client connect pending");
        return(ESP_AZURE_IOT_SUCCESS);
    }

    /* Check status.  */
    if (status != ESP_AZURE_IOT_SUCCESS)
    {
        LogError("IoTProvisioning client connect fail: MQTT CONNECT FAIL: 0x%02x", status);
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

static void esp_azure_iot_provisioning_client_mqtt_receive_callback(ESP_MQTT_CLIENT *client_ptr,
                                                                   uint32_t number_of_messages)
{
ESP_AZURE_IOT_RESOURCE *resource = esp_azure_iot_resource_search(client_ptr);
ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr = NULL;
ESP_PACKET *packet_ptr;
ESP_PACKET *packet_next_ptr;
uint32_t status;

    /* This function is protected by MQTT mutex. */

    ESP_PARAMETER_NOT_USED(number_of_messages);

    if (resource && (resource -> esp_azure_iot_resource_type == ESP_AZURE_IOT_RESOURCE_IOT_PROVISIONING))
    {
        prov_client_ptr = (ESP_AZURE_IOT_PROVISIONING_CLIENT *)resource -> esp_azure_iot_resource_data_ptr;
    }

    if (prov_client_ptr)
    {
        for (packet_ptr = client_ptr -> message_receive_queue_head;
            packet_ptr;
            packet_ptr = packet_next_ptr)
        {

            /* Store next packet in case current packet is consumed. */
            packet_next_ptr = packet_ptr -> esp_packet_next;

            /* Adjust packet to simply process logic. */
            esp_azure_iot_mqtt_packet_adjust(packet_ptr);

            /* Last response was not yet consumed, probably duplicate from service */
            if (prov_client_ptr -> esp_azure_iot_provisioning_client_last_response)
            {
                esp_azure_iot_packet_release(packet_ptr);
                continue;
            }

            prov_client_ptr -> esp_azure_iot_provisioning_client_last_response = packet_ptr;
            status = esp_azure_iot_event_group_set(&(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                              ESP_AZURE_IOT_PROVISIONING_CLIENT_RESPONSE_EVENT);
            if (status)
            {
                esp_azure_iot_provisioning_client_update_state(prov_client_ptr, status);
            }
        }

        /* Clear all message from MQTT receive queue. */
        client_ptr -> message_receive_queue_head = NULL;
        client_ptr -> message_receive_queue_tail = NULL;
        client_ptr -> message_receive_queue_depth = 0;
    }
}

/**
 *  State transitions :
 *      INIT -> {CONNECT|ERROR} -> {REQUEST|ERROR} -> {WAITING_FOR_REPONSE|ERROR} -> {DONE|REQUEST|ERROR}
 **/
static void esp_azure_iot_provisioning_client_update_state(ESP_AZURE_IOT_PROVISIONING_CLIENT *context,
                                                          uint32_t action_result)
{
uint32_t state = context -> esp_azure_iot_provisioning_client_state;
ESP_AZURE_IOT_PROVISIONING_THREAD_LIST *thread_list_ptr;

    LogDebug("Action result in state [%d]: %d \r\n", state, action_result);

    context -> esp_azure_iot_provisioning_client_result = action_result;

    if (action_result == ESP_AZURE_IOT_PENDING)
    {
        switch (state)
        {
            case ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT :
            {
                context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_CONNECT;
            }
            break;

            case ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_CONNECT :
            {
                context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_SUBSCRIBE;
            }
            break;

            case ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_SUBSCRIBE :
            {
                context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_REQUEST;
            }
            break;

            case ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_REQUEST :
            {
                context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_WAITING_FOR_RESPONSE;
            }
            break;

            case ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_WAITING_FOR_RESPONSE :
            {
                context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_REQUEST;
            }
            break;

            default :
            {
                LogError("Unknown state %d\r\n", state);
            }
            break;
        }
    }
    else
    {
        if (action_result == ESP_AZURE_IOT_SUCCESS)
        {
            context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE;
        }
        else
        {
            context -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_ERROR;
        }

        /* Wake up all threads */
        for (thread_list_ptr = context -> esp_azure_iot_provisioning_client_thread_suspended;
             thread_list_ptr;
             thread_list_ptr = thread_list_ptr -> esp_azure_iot_provisioning_thread_next)
        {
            esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_provisioning_thread_ptr);
        }

        /* Delete the list */
        context -> esp_azure_iot_provisioning_client_thread_suspended = NULL;

        /* notify completion if required */
        if (context -> esp_azure_iot_provisioning_client_on_complete_callback)
        {
            context -> esp_azure_iot_provisioning_client_on_complete_callback(context, context -> esp_azure_iot_provisioning_client_result);
        }
    }
}

static void esp_azure_iot_provisioning_client_mqtt_connect_notify(struct ESP_MQTT_CLIENT_STRUCT *client_ptr,
                                                                 uint32_t status, void *context)
{

ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr = (ESP_AZURE_IOT_PROVISIONING_CLIENT*)context;

    ESP_PARAMETER_NOT_USED(client_ptr);
    
    /* mutex might got deleted by deinitialization */
    if (!xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER))
    {
        return;
    }

    /* Update hub client status.  */
    if (status == ESP_AZURE_IOT_MQTT_SUCCESS)
    {
        if (prov_client_ptr -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_CONNECT)
        {
            esp_azure_iot_provisioning_client_update_state(prov_client_ptr, ESP_AZURE_IOT_PENDING);
            status = esp_azure_iot_event_group_set(&(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                                    ESP_AZURE_IOT_PROVISIONING_CLIENT_SUBSCRIBE_EVENT);
            if (status)
            {
                esp_azure_iot_provisioning_client_update_state(prov_client_ptr, status);
            }
        }
    }
    else
    {
        status = esp_azure_iot_event_group_set(&(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                                ESP_AZURE_IOT_PROVISIONING_CLIENT_DISCONNECT_EVENT);
        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(prov_client_ptr, status);
        }
    }
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
}

static void esp_azure_iot_provisioning_client_process_connect(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{
uint32_t status;

    if ((context == NULL) || (context -> esp_azure_iot_ptr == NULL))
    {
        return;
    }


    /* Check the state.  */
    if (context -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_CONNECT)
    {
        context -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt.esp_mqtt_connect_notify = esp_azure_iot_provisioning_client_mqtt_connect_notify;
        context -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt.esp_mqtt_connect_context = context;

        /* Start connect.  */
        status = esp_azure_iot_provisioning_client_connect_internal(context, ESP_NO_WAIT);

        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(context, status);
        }
    }
}

static void esp_azure_iot_provisioning_client_process_timer(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{
uint32_t status;

    if (context == NULL)
    {
        return;
    }

    if (context -> esp_azure_iot_provisioning_client_req_timeout == 0)
    {
        return;
    }

    /* Trigger Request  */
    if (context -> esp_azure_iot_provisioning_client_req_timeout == 1)
    {

        status = esp_azure_iot_event_group_set(&(context -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                                ESP_AZURE_IOT_PROVISIONING_CLIENT_REQUEST_EVENT);
        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(context, status);
        }
    }

    context -> esp_azure_iot_provisioning_client_req_timeout--;
}

static void esp_azure_iot_provisioning_client_subscribe(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{
uint32_t status;

    if (context == NULL)
    {
        return;
    }

    /* Check the state.  */
    if (context -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_SUBSCRIBE)
    {

        /* Subscribe topic. */
        status = esp_azure_iot_mqtt_client_subscribe(&(context -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt),
                                                    ESP_AZURE_IOT_PROVISIONING_CLIENT_REG_SUB_TOPIC,
                                                    sizeof(ESP_AZURE_IOT_PROVISIONING_CLIENT_REG_SUB_TOPIC) - 1, 0);

        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(context, status);
        }
        else
        {
            esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_PENDING);
            status = esp_azure_iot_event_group_set(&(context -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                                    ESP_AZURE_IOT_PROVISIONING_CLIENT_REQUEST_EVENT);
            if (status)
            {
                esp_azure_iot_provisioning_client_update_state(context, status);
            }
        }
    }
}

static void esp_azure_iot_provisioning_client_generate_service_request(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{
uint32_t status;

    if (context == NULL)
    {
        return;
    }

    /* Check the state.  */
    if (context -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_REQUEST)
    {
        if (context -> esp_azure_iot_provisioning_client_response.packet_ptr)
        {

            /* Request status of existing operationId */
            status = esp_azure_iot_provisioning_client_send_req(context, &(context -> esp_azure_iot_provisioning_client_response.register_response), ESP_NO_WAIT);
            esp_azure_iot_packet_release(context -> esp_azure_iot_provisioning_client_response.packet_ptr);

            context -> esp_azure_iot_provisioning_client_response.packet_ptr = NULL;
        }
        else
        {

            /* Start new operation */
            status = esp_azure_iot_provisioning_client_send_req(context, NULL, ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_TIMEOUT);
        }

        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(context, status);
        }
        else
        {
            esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_PENDING);
        }
    }
}

static void esp_azure_iot_provisioning_client_process_service_response(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{
ESP_PACKET *packet_ptr;
az_iot_provisioning_client_register_response *response;

    if (context == NULL)
    {
        return;
    }

    /* Check the state.  */
    if (context -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_WAITING_FOR_RESPONSE)
    {

        packet_ptr = context -> esp_azure_iot_provisioning_client_last_response;
        context -> esp_azure_iot_provisioning_client_last_response = NULL;

        context -> esp_azure_iot_provisioning_client_result = esp_azure_iot_provisioning_client_process_message(context, packet_ptr, &context -> esp_azure_iot_provisioning_client_response);
        if (context -> esp_azure_iot_provisioning_client_result)
        {
            esp_azure_iot_packet_release(packet_ptr);
            esp_azure_iot_provisioning_client_update_state(context, context -> esp_azure_iot_provisioning_client_result);
            return;
        }

        response = &(context -> esp_azure_iot_provisioning_client_response.register_response);
        if (az_span_is_content_equal(response -> operation_status, AZ_SPAN_FROM_STR("assigned")))
        {
            esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_SUCCESS);
        }
        else if (response -> retry_after_seconds == 0)
        {

            /* Server responded with error with no retry */
            esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_SERVER_RESPONSE_ERROR);
        }
        else
        {
            esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_PENDING);
            context -> esp_azure_iot_provisioning_client_req_timeout = response -> retry_after_seconds;
        }
    }
}

static void esp_azure_iot_provisioning_client_process_disconnect(ESP_AZURE_IOT_PROVISIONING_CLIENT *context)
{

    if (context == NULL)
    {
        return;
    }

    /* Check the state and only allow disconnect event to be processed in non-complete state  */
    if (context -> esp_azure_iot_provisioning_client_state > ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT &&
        context -> esp_azure_iot_provisioning_client_state < ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE)
    {
        esp_azure_iot_provisioning_client_update_state(context, ESP_AZURE_IOT_DISCONNECTED);
    }
}

static uint32_t esp_azure_iot_provisioning_client_send_req(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                      az_iot_provisioning_client_register_response const *register_response,
                                                      uint32_t wait_option)
{
ESP_PACKET *packet_ptr;
uint8_t *buffer_ptr;
uint32_t buffer_size;
uint32_t status;
uint32_t mqtt_topic_length;
az_result core_result;

    status = esp_azure_iot_publish_packet_get(prov_client_ptr -> esp_azure_iot_ptr,
                                             &prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt,
                                             &packet_ptr, wait_option);

    if (status)
    {
        LogError("IoTProvisioning request buffer creation failed");
        return(status);
    }

    buffer_ptr = packet_ptr -> esp_packet_prepend_ptr;
    buffer_size = (uint32_t)(packet_ptr -> esp_packet_data_end - packet_ptr -> esp_packet_prepend_ptr);

    if (register_response == NULL)
    {
        core_result = az_iot_provisioning_client_register_get_publish_topic(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                                            (char *)buffer_ptr, buffer_size, &mqtt_topic_length);
    }
    else
    {
        core_result = az_iot_provisioning_client_query_status_get_publish_topic(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                                                register_response, (char *)buffer_ptr,
                                                                                buffer_size, &mqtt_topic_length);
    }

    if (az_failed(core_result))
    {
        LogError("failed to get topic, error: 0x%08x", core_result);
        esp_azure_iot_packet_release(packet_ptr);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_prepend_ptr + mqtt_topic_length;
    packet_ptr -> esp_packet_length += mqtt_topic_length;

    status = esp_azure_iot_packet_append(packet_ptr, ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_START,
                                   sizeof(ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_START) - 1,
                                   wait_option);
    if (status)
    {
        LogError("failed to append data");
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    status = esp_azure_iot_packet_append(packet_ptr, prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id,
                                   prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id_length,
                                   wait_option);
    if (status)
    {
        LogError("failed to append data ");
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    status = esp_azure_iot_packet_append(packet_ptr, ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_END,
                                   sizeof(ESP_AZURE_IOT_PROVISIONING_CLIENT_PAYLOAD_END) - 1,
                                   wait_option);
    if (status)
    {
        LogError("failed to append data ");
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    status = esp_azure_iot_publish_mqtt_packet(&(prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt),
                                              packet_ptr, ESP_AZURE_IOT_MQTT_QOS_1, wait_option);

    if (status)
    {
        LogError("failed to publish packet");
        esp_azure_iot_packet_release(packet_ptr);
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

static void esp_azure_iot_provisioning_client_thread_dequeue(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                            ESP_AZURE_IOT_PROVISIONING_THREAD_LIST *node)
{
ESP_AZURE_IOT_PROVISIONING_THREAD_LIST *thread_list_ptr;
ESP_AZURE_IOT_PROVISIONING_THREAD_LIST *thread_list_prev = NULL;

    for (thread_list_ptr = prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended;
         thread_list_ptr;
         thread_list_prev = thread_list_ptr, thread_list_ptr = thread_list_ptr -> esp_azure_iot_provisioning_thread_next)
    {
        if (thread_list_ptr != node)
        {
            continue;
        }

        if (thread_list_prev == NULL)
        {
            prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended = thread_list_ptr -> esp_azure_iot_provisioning_thread_next;
        }
        else
        {
            thread_list_prev -> esp_azure_iot_provisioning_thread_next = thread_list_ptr -> esp_azure_iot_provisioning_thread_next;
        }

        break;
    }
}

static uint32_t esp_azure_iot_provisioning_client_sas_token_get(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                           size_t expiry_time_secs)
{
uint8_t *buffer_ptr;
uint32_t buffer_size;
void *buffer_context;
uint32_t status;
ESP_AZURE_IOT_RESOURCE *resource_ptr;
uint8_t *output_ptr;
uint32_t output_len;
az_span span;
az_result core_result;
az_span buffer_span;
az_span policy_name = AZ_SPAN_LITERAL_FROM_STR(ESP_AZURE_IOT_PROVISIONING_CLIENT_POLICY_NAME);

    resource_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource);
    span = az_span_init(resource_ptr -> esp_azure_iot_mqtt_sas_token, (int16_t)prov_client_ptr -> esp_azure_iot_provisioning_client_sas_token_buff_size);

    status = esp_azure_iot_buffer_allocate(prov_client_ptr -> esp_azure_iot_ptr,
                                          &buffer_ptr, &buffer_size,
                                          &buffer_context);
    if (status)
    {
        LogError("IoTProvisioning client connect fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    core_result = az_iot_provisioning_client_sas_get_signature(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                               expiry_time_secs, span, &span);

    if (az_failed(core_result))
    {
        LogError("IoTProvisioning failed failed to get signature with error : 0x%08x", core_result);
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = esp_azure_iot_url_encoded_hmac_sha256_calculate(resource_ptr,
                                                            prov_client_ptr -> esp_azure_iot_provisioning_client_symmetric_key,
                                                            prov_client_ptr -> esp_azure_iot_provisioning_client_symmetric_key_length,
                                                            az_span_ptr(span), (uint32_t)az_span_size(span), buffer_ptr, buffer_size,
                                                            &output_ptr, &output_len);
    if (status)
    {
        LogError("IoTProvisioning failed to encoded hash");
        esp_azure_iot_buffer_free(buffer_context);
        return(status);
    }

    buffer_span = az_span_init(output_ptr, (int16_t)output_len);
    core_result = az_iot_provisioning_client_sas_get_password(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                              buffer_span, expiry_time_secs, policy_name,
                                                              (char *)resource_ptr -> esp_azure_iot_mqtt_sas_token,
                                                              prov_client_ptr -> esp_azure_iot_provisioning_client_sas_token_buff_size,
                                                              &(resource_ptr -> esp_azure_iot_mqtt_sas_token_length));
    if (az_failed(core_result))
    {
        LogError("IoTProvisioning failed to generate token with error : 0x%08x", core_result);
        esp_azure_iot_buffer_free(buffer_context);
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    esp_azure_iot_buffer_free(buffer_context);

    return(ESP_AZURE_IOT_SUCCESS);
}

/* Define the prototypes for Azure RTOS IoT.  */
uint32_t esp_azure_iot_provisioning_client_initialize(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                 ESP_AZURE_IOT *esp_azure_iot_ptr,
                                                 uint8_t *endpoint, uint32_t endpoint_length,
                                                 uint8_t *id_scope, uint32_t id_scope_length,
                                                 uint8_t *registration_id, uint32_t registration_id_length,
                                                 const char *trusted_certificate)
{
uint32_t status;
uint32_t mqtt_user_name_length;
ESP_MQTT_CLIENT *mqtt_client_ptr;
ESP_AZURE_IOT_RESOURCE *resource_ptr;
uint8_t *buffer_ptr;
uint32_t buffer_size;
void *buffer_context;
az_span endpoint_span = az_span_init(endpoint, (int16_t)endpoint_length);
az_span id_scope_span = az_span_init(id_scope, (int16_t)id_scope_length);
az_span registration_id_span = az_span_init(registration_id, (int16_t)registration_id_length);

    if ((esp_azure_iot_ptr == NULL) || (prov_client_ptr == NULL) || (endpoint == NULL) ||
        (id_scope == NULL) || registration_id == NULL)
    {
        LogError("IoTProvisioning client create fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.   */
    xSemaphoreTake(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, portMAX_DELAY);

    memset(prov_client_ptr, 0, sizeof(ESP_AZURE_IOT_PROVISIONING_CLIENT));

    /* Set resource pointer.  */
    resource_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource);
    mqtt_client_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt);

    prov_client_ptr -> esp_azure_iot_ptr = esp_azure_iot_ptr;
    prov_client_ptr -> esp_azure_iot_provisioning_client_endpoint = endpoint;
    prov_client_ptr -> esp_azure_iot_provisioning_client_endpoint_length = endpoint_length;
    prov_client_ptr -> esp_azure_iot_provisioning_client_id_scope = id_scope;
    prov_client_ptr -> esp_azure_iot_provisioning_client_id_scope_length = id_scope_length;
    prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id = registration_id;
    prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id_length = registration_id_length;
    prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_trusted_certificate = trusted_certificate;
    resource_ptr -> esp_azure_iot_mqtt_client_id_length = prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id_length;
    resource_ptr -> esp_azure_iot_mqtt_client_id = prov_client_ptr -> esp_azure_iot_provisioning_client_registration_id;

    if (az_failed(az_iot_provisioning_client_init(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                  endpoint_span, id_scope_span, registration_id_span, NULL)))
    {
         LogError("IoTProvisioning client create fail: failed to initialize core client");
        return(ESP_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = esp_azure_iot_mqtt_client_create(mqtt_client_ptr, (char *)esp_azure_iot_ptr -> esp_azure_iot_name,
                                           (char *)resource_ptr -> esp_azure_iot_mqtt_client_id,
                                           resource_ptr -> esp_azure_iot_mqtt_client_id_length,
                                           &esp_azure_iot_ptr -> esp_azure_iot_event);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client create fail: MQTT CLIENT CREATE FAIL: 0x%02x", status);
        return(status);
    }

    status = esp_azure_iot_mqtt_client_receive_notify_set(mqtt_client_ptr, esp_azure_iot_provisioning_client_mqtt_receive_callback);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client set message callback: 0x%02x", status);
        esp_azure_iot_mqtt_client_delete(mqtt_client_ptr);
        return(status);
    }

    status = esp_azure_iot_buffer_allocate(prov_client_ptr -> esp_azure_iot_ptr, &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client failed initialization: BUFFER ALLOCATE FAIL");
        esp_azure_iot_mqtt_client_delete(mqtt_client_ptr);
        return(status);
    }

    /* Build user name.  */
    if (az_failed(az_iot_provisioning_client_get_user_name(&(prov_client_ptr -> esp_azure_iot_provisioning_client_core),
                                                           (char *)buffer_ptr, buffer_size, &mqtt_user_name_length)))
    {
        LogError("IoTProvisioning client connect fail: ESP_AZURE_IOT_Provisioning_CLIENT_USERNAME_SIZE is too small.");
        esp_azure_iot_buffer_free(buffer_context);
        esp_azure_iot_mqtt_client_delete(mqtt_client_ptr);
        return(ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Save the resource buffer.  */
    resource_ptr -> esp_azure_iot_mqtt_buffer_context = buffer_context;
    resource_ptr -> esp_azure_iot_mqtt_buffer_size = buffer_size;
    resource_ptr -> esp_azure_iot_mqtt_user_name_length = mqtt_user_name_length;
    resource_ptr -> esp_azure_iot_mqtt_user_name = buffer_ptr;
    resource_ptr -> esp_azure_iot_mqtt_sas_token = buffer_ptr + mqtt_user_name_length;
    prov_client_ptr -> esp_azure_iot_provisioning_client_sas_token_buff_size = buffer_size - mqtt_user_name_length;

    /* Link the resource. */
    prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_resource_data_ptr = (void *)prov_client_ptr;
    prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_resource_type = ESP_AZURE_IOT_RESOURCE_IOT_PROVISIONING;
    esp_azure_iot_resource_add(esp_azure_iot_ptr, &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource));

    /* Set event processing routine.   */
    esp_azure_iot_ptr -> esp_azure_iot_provisioning_client_event_process = esp_azure_iot_provisioning_client_event_process;

    /* Update state.  */
    prov_client_ptr -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT;

    /* Release the mutex.  */
    xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_provisioning_client_deinitialize(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr)
{
ESP_AZURE_IOT_PROVISIONING_THREAD_LIST *thread_list_ptr;
uint32_t status = ESP_AZURE_IOT_SUCCESS;

    /* Check for invalid input pointers.  */
    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTProvisioning client deinitialize fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    if ((prov_client_ptr -> esp_azure_iot_provisioning_client_state > ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT &&
         prov_client_ptr -> esp_azure_iot_provisioning_client_state < ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE))
    {

        /* wake up all the threads */
        for (thread_list_ptr = prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended;
             thread_list_ptr;
             thread_list_ptr = thread_list_ptr -> esp_azure_iot_provisioning_thread_next)
        {
            esp_azure_iot_thread_wait_abort(thread_list_ptr -> esp_azure_iot_provisioning_thread_ptr);
        }

        /* Delete the list */
        prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended = NULL;
    }

    /* force to error state */
    prov_client_ptr -> esp_azure_iot_provisioning_client_state = ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_ERROR;
    prov_client_ptr -> esp_azure_iot_provisioning_client_on_complete_callback = NULL;

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_last_response)
    {
        esp_azure_iot_packet_release(prov_client_ptr -> esp_azure_iot_provisioning_client_last_response);
        prov_client_ptr -> esp_azure_iot_provisioning_client_last_response = NULL;
    }

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_response.packet_ptr)
    {
        esp_azure_iot_packet_release(prov_client_ptr -> esp_azure_iot_provisioning_client_response.packet_ptr);
        prov_client_ptr -> esp_azure_iot_provisioning_client_response.packet_ptr = NULL;
    }

    /* Release the mqtt connection resource.  */
    if (prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt_buffer_context)
    {
        esp_azure_iot_buffer_free(prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt_buffer_context);
        prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt_buffer_context = NULL;
    }

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    /* Disconnect */
    esp_azure_iot_mqtt_client_disconnect(&prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt);

    /* Delete the client */
    esp_azure_iot_mqtt_client_delete(&prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt);

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    /* Remove resource from list.  */
    status = esp_azure_iot_resource_remove(prov_client_ptr -> esp_azure_iot_ptr, &(prov_client_ptr -> esp_azure_iot_provisioning_client_resource));

    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client handle not found");
        return(status);
    }

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_provisioning_client_device_cert_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                      const char *x509_cert)
{
    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTProvisioning device cert set fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_device_certificate = x509_cert;

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}


static void esp_azure_iot_provisioning_client_event_process(ESP_AZURE_IOT *esp_azure_iot_ptr,
                                                           size_t common_events, size_t module_own_events)
{
ESP_AZURE_IOT_RESOURCE *resource;
ESP_AZURE_IOT_PROVISIONING_CLIENT *provisioning_client;

    /* Process module own events.  */
    LogDebug("Event generated common event: 0x%lx, module event: 0x%lx \r\n", common_events, module_own_events);

    /* Obtain the mutex.  */
    xSemaphoreTake(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    /* Loop to check IoT Provisioning Client.  */
    for (resource = esp_azure_iot_ptr -> esp_azure_iot_resource_list_header; resource;
         resource = resource -> esp_azure_iot_resource_next)
    {
        if (resource -> esp_azure_iot_resource_type != ESP_AZURE_IOT_RESOURCE_IOT_PROVISIONING)
        {
            continue;
        }

        /* Set provisioning client pointer.  */
        provisioning_client = (ESP_AZURE_IOT_PROVISIONING_CLIENT *)resource -> esp_azure_iot_resource_data_ptr;

        if (common_events & ESP_AZURE_IOT_EVENT_COMMON_PERIODIC_EVENT)
        {
            esp_azure_iot_provisioning_client_process_timer(provisioning_client);
        }

        if (module_own_events & ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_EVENT)
        {
            esp_azure_iot_provisioning_client_process_connect(provisioning_client);
        }

        if (module_own_events & ESP_AZURE_IOT_PROVISIONING_CLIENT_SUBSCRIBE_EVENT)
        {
            esp_azure_iot_provisioning_client_subscribe(provisioning_client);
        }

        if (module_own_events & ESP_AZURE_IOT_PROVISIONING_CLIENT_RESPONSE_EVENT)
        {
            esp_azure_iot_provisioning_client_process_service_response(provisioning_client);
        }

        if (module_own_events & ESP_AZURE_IOT_PROVISIONING_CLIENT_REQUEST_EVENT)
        {
            esp_azure_iot_provisioning_client_generate_service_request(provisioning_client);
        }

        if (module_own_events & ESP_AZURE_IOT_PROVISIONING_CLIENT_DISCONNECT_EVENT)
        {
            esp_azure_iot_provisioning_client_process_disconnect(provisioning_client);
        }
    }

    /* Release the mutex.  */
    xSemaphoreGive(esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
}

uint32_t esp_azure_iot_provisioning_client_register(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, uint32_t wait_option)
{
ESP_AZURE_IOT_PROVISIONING_THREAD_LIST thread_list;
uint32_t status = ESP_AZURE_IOT_SUCCESS;

    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTProvisioning register fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_NONE)
    {
        LogError("IoTProvisioning register fail: not intialized");
        return(ESP_AZURE_IOT_NOT_INITIALIZED);
    }

    /* Set callback function for disconnection. */
    esp_azure_iot_mqtt_client_disconnect_notify_set(&(prov_client_ptr -> esp_azure_iot_provisioning_client_resource.esp_azure_iot_mqtt),
                                          esp_azure_iot_provisioning_client_mqtt_disconnect_notify);

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT)
    {

        /* Update state in user thread under mutex */
        esp_azure_iot_provisioning_client_update_state(prov_client_ptr, ESP_AZURE_IOT_PENDING);

        /* Trigger workflow */
        status = esp_azure_iot_event_group_set(&(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                                ESP_AZURE_IOT_PROVISIONING_CLIENT_CONNECT_EVENT);
        if (status)
        {
            esp_azure_iot_provisioning_client_update_state(prov_client_ptr, status);
        }
    }

    if (wait_option)
    {
        if (prov_client_ptr -> esp_azure_iot_provisioning_client_state > ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT &&
             prov_client_ptr -> esp_azure_iot_provisioning_client_state < ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE)
        {
            thread_list.esp_azure_iot_provisioning_thread_next = prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended;
            thread_list.esp_azure_iot_provisioning_thread_ptr = esp_azure_iot_thread_identify();
            prov_client_ptr -> esp_azure_iot_provisioning_client_thread_suspended = &thread_list;

            /* Release the mutex.  */
            xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

            esp_azure_iot_thread_sleep(thread_list.esp_azure_iot_provisioning_thread_ptr, wait_option);

            /* Obtain the mutex.  */
            xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

            /* Restore preemption. */
            esp_azure_iot_thread_preemption(thread_list.esp_azure_iot_provisioning_thread_ptr);

            esp_azure_iot_provisioning_client_thread_dequeue(prov_client_ptr, &thread_list);
        }
    }

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_state > ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_INIT &&
         prov_client_ptr -> esp_azure_iot_provisioning_client_state < ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE)
    {

        /* Release the mutex.  */
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        return(ESP_AZURE_IOT_PENDING);
    }
    else if (prov_client_ptr -> esp_azure_iot_provisioning_client_state == ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_ERROR)
    {

        /* Release the mutex.  */
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning register fail: Error out");
        return(prov_client_ptr -> esp_azure_iot_provisioning_client_result);
    }

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
    
    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_provisioning_client_completion_callback_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                              void (*on_complete_callback)(
                                                                    struct ESP_AZURE_IOT_PROVISIONING_CLIENT_STRUCT *client_ptr,
                                                                    uint32_t status))
{
    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL))
    {
        LogError("IoTProvisioning register fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    prov_client_ptr -> esp_azure_iot_provisioning_client_on_complete_callback = on_complete_callback;

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_provisioning_client_symmetric_key_set(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                        uint8_t *symmetric_key, uint32_t symmetric_key_length)
{
size_t expiry_time_secs;
uint32_t status = ESP_AZURE_IOT_SUCCESS;

    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL) ||
        (symmetric_key == NULL) || (symmetric_key_length == 0))
    {
        LogError("IoTProvisioning client symmetric key fail: Invalid argument");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);

    prov_client_ptr -> esp_azure_iot_provisioning_client_symmetric_key = symmetric_key;
    prov_client_ptr -> esp_azure_iot_provisioning_client_symmetric_key_length = symmetric_key_length;

    status = esp_azure_iot_unix_time_get(prov_client_ptr -> esp_azure_iot_ptr, &expiry_time_secs);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client symmetric key fail: 0x%02x", status);
        return(status);
    }

    expiry_time_secs += ESP_AZURE_IOT_PROVISIONING_CLIENT_TOKEN_EXPIRY;

    status = esp_azure_iot_provisioning_client_sas_token_get(prov_client_ptr, expiry_time_secs);
    if (status)
    {

        /* Release the mutex.  */
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        LogError("IoTProvisioning client symmetric key fail: sas token generation failed");
        return(status);
    }

    /* Release the mutex.  */
    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t esp_azure_iot_provisioning_client_iothub_device_info_get(ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                             uint8_t *iothub_hostname, uint32_t *iothub_hostname_len,
                                                             uint8_t *device_id, uint32_t *device_id_len)
{
uint32_t status = ESP_AZURE_IOT_SUCCESS;
az_span *device_id_span_ptr;
az_span *assigned_hub_span_ptr;

    if ((prov_client_ptr == NULL) || (prov_client_ptr -> esp_azure_iot_ptr == NULL) ||
        (iothub_hostname == NULL) || (iothub_hostname_len == NULL) ||
        (device_id == NULL) || (device_id_len == NULL))
    {
        LogError("IoTProvisioning client iothub device info get fail: Invalid argument");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    status = xSemaphoreTake(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr, ESP_WAIT_FOREVER);
    if (!status)
    {
        LogError("IoTProvisioning client iothub get fail: get mutex");
        return(status);
    }

    if (prov_client_ptr -> esp_azure_iot_provisioning_client_state != ESP_AZURE_IOT_PROVISIONING_CLIENT_STATUS_DONE)
    {
        LogError("IoTProvisioning client iothub device info get fail: wrong state");
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        return(ESP_AZURE_IOT_WRONG_STATE);
    }

    device_id_span_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_response.register_response.registration_result.device_id);
    assigned_hub_span_ptr = &(prov_client_ptr -> esp_azure_iot_provisioning_client_response.register_response.registration_result.assigned_hub_hostname);
    if ((uint32_t)az_span_size(*assigned_hub_span_ptr) >= *iothub_hostname_len || (uint32_t)az_span_size(*device_id_span_ptr) > *device_id_len)
    {
        LogError("IoTProvisioning client iothub device info get fail: insufficient memory");
        xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);
        return(ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* iothub hostname should be null terminated */
    memcpy((void *)iothub_hostname, (void *)az_span_ptr(*assigned_hub_span_ptr), (uint32_t)az_span_size(*assigned_hub_span_ptr));
    iothub_hostname[az_span_size(*assigned_hub_span_ptr)] = 0;
    *iothub_hostname_len = (uint32_t)az_span_size(*assigned_hub_span_ptr);

    memcpy((void *)device_id, (void *)az_span_ptr(*device_id_span_ptr), (uint32_t)az_span_size(*device_id_span_ptr));
    *device_id_len = (uint32_t)az_span_size(*device_id_span_ptr);

    xSemaphoreGive(prov_client_ptr -> esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr);

    return(ESP_AZURE_IOT_SUCCESS);
}
