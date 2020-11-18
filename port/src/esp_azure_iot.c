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

#include "esp_azure_iot.h"

#ifndef ESP_AZURE_IOT_WAIT_OPTION
#define ESP_AZURE_IOT_WAIT_OPTION ((size_t)0xFFFFFFFF)
#endif /* ESP_AZURE_IOT_WAIT_OPTION */

/* Convert number to upper hex */
#define ESP_AZURE_IOT_NUMBER_TO_UPPER_HEX(number)    (char)(number + (number < 10 ? '0' : 'A' - 10))
                                                    
/* Define the prototypes for Azure RTOS IoT.  */
ESP_AZURE_IOT *_esp_azure_iot_created_ptr;

extern void esp_azure_iot_hub_client_event_process(ESP_AZURE_IOT *esp_azure_iot_ptr,
                                                  size_t common_events, size_t module_own_events);

static uint32_t esp_azure_iot_url_encode(char *src_ptr, uint32_t src_len,
                                    char *dest_ptr, uint32_t dest_len, uint32_t *bytes_copied)
{
    uint32_t dest_index;
    uint32_t src_index;
    char ch;

    for (src_index = 0, dest_index = 0; src_index < src_len; src_index++)
    {
        ch = src_ptr[src_index];

        /* Check if encoding is required.
           copied from sdk-core */
        if ((('0' <= ch) && (ch <= '9')) ||
            (('a' <= (ch | 0x20)) && ((ch | 0x20) <= 'z')))
        {
            if (dest_index >= dest_len)
            {
                return ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE;
            }

            dest_ptr[dest_index++] = ch;
        }
        else
        {
            if ((dest_index + 2) >= dest_len)
            {
                return ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE;
            }

            dest_ptr[dest_index++] = '%';
            dest_ptr[dest_index++] = ESP_AZURE_IOT_NUMBER_TO_UPPER_HEX((ch >> 4));
            dest_ptr[dest_index++] = ESP_AZURE_IOT_NUMBER_TO_UPPER_HEX((ch & 0x0F));
        }
    }
    
    *bytes_copied = dest_index;

    return ESP_AZURE_IOT_SUCCESS ;
}

static void esp_azure_iot_event_process(void *esp_azure_iot, size_t common_events, size_t module_own_events)
{
    ESP_AZURE_IOT *esp_azure_iot_ptr = (ESP_AZURE_IOT *)esp_azure_iot;

    /* Process iot hub client */
    esp_azure_iot_hub_client_event_process(esp_azure_iot, common_events, module_own_events);

    /* Process DPS events.  */
    if (esp_azure_iot_ptr -> esp_azure_iot_provisioning_client_event_process)
    {
        esp_azure_iot_ptr -> esp_azure_iot_provisioning_client_event_process(esp_azure_iot_ptr, common_events, module_own_events);
    }
}

ESP_AZURE_IOT_RESOURCE *esp_azure_iot_resource_search(ESP_MQTT_CLIENT *client_ptr)
{
    ESP_AZURE_IOT_RESOURCE *resource_ptr;

    /* Check if created Azure RTOS IoT.  */
    if ((_esp_azure_iot_created_ptr == NULL) || (client_ptr == NULL))
    {
        return(NULL);
    }

    /* Loop to find the resource associated with current MQTT client. */
    for (resource_ptr = _esp_azure_iot_created_ptr -> esp_azure_iot_resource_list_header;
         resource_ptr; resource_ptr = resource_ptr -> esp_azure_iot_resource_next)
    {

        if (&(resource_ptr -> esp_azure_iot_mqtt) == client_ptr)
        {
            return(resource_ptr);
        }
    }

    return(NULL);
}

uint32_t esp_azure_iot_resource_add(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_AZURE_IOT_RESOURCE *resource_ptr)
{

    resource_ptr -> esp_azure_iot_resource_next = esp_azure_iot_ptr -> esp_azure_iot_resource_list_header;
    esp_azure_iot_ptr -> esp_azure_iot_resource_list_header = resource_ptr;

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_resource_remove(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_AZURE_IOT_RESOURCE *resource_ptr)
{

    ESP_AZURE_IOT_RESOURCE   *resource_previous;

    if (esp_azure_iot_ptr -> esp_azure_iot_resource_list_header == NULL)
    {
        return(ESP_AZURE_IOT_NOT_FOUND);
    }

    if (esp_azure_iot_ptr -> esp_azure_iot_resource_list_header == resource_ptr)
    {
        esp_azure_iot_ptr -> esp_azure_iot_resource_list_header = esp_azure_iot_ptr -> esp_azure_iot_resource_list_header -> esp_azure_iot_resource_next;
        return(ESP_AZURE_IOT_SUCCESS);
    }

    for (resource_previous = esp_azure_iot_ptr -> esp_azure_iot_resource_list_header;
         resource_previous -> esp_azure_iot_resource_next;
         resource_previous = resource_previous -> esp_azure_iot_resource_next)
    {
        if (resource_previous -> esp_azure_iot_resource_next == resource_ptr)
        {
            resource_previous -> esp_azure_iot_resource_next = resource_previous -> esp_azure_iot_resource_next -> esp_azure_iot_resource_next;
            return(ESP_AZURE_IOT_SUCCESS);
        }
    }

    return(ESP_AZURE_IOT_NOT_FOUND);
}

uint32_t esp_azure_iot_create(ESP_AZURE_IOT *esp_azure_iot_ptr, uint8_t *name_ptr, uint32_t stack_memory_size,
                         uint32_t priority, uint32_t (*unix_time_callback)(size_t *unix_time))
{
    uint32_t status = 0;

    if ((esp_azure_iot_ptr == NULL))
    {
        LogError("IoT create fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    esp_azure_iot_ptr -> esp_azure_iot_name = name_ptr;
    esp_azure_iot_ptr -> esp_azure_iot_unix_time_get = unix_time_callback;

    status = esp_azure_iot_event_create(&esp_azure_iot_ptr -> esp_azure_iot_event, (char *)name_ptr, NULL,
                             stack_memory_size, priority);
    if (status)
    {
        LogError("IoT create fail: 0x%02x", status);
        return(status);
    }

    /* Register SDK module on event helper.  */
    status = esp_azure_iot_event_group_register(&(esp_azure_iot_ptr -> esp_azure_iot_event), &(esp_azure_iot_ptr -> esp_azure_iot_event_group),
                                      "Azure SDK Module", ESP_AZURE_IOT_EVENT_GROUP_AZURE_SDK_EVENT | ESP_AZURE_IOT_EVENT_COMMON_PERIODIC_EVENT,
                                      esp_azure_iot_event_process, esp_azure_iot_ptr);
    if (status)
    {
        LogError("IoT module register fail: 0x%02x", status);
        return(status);
    }

    /* Set the mutex.  */
    esp_azure_iot_ptr -> esp_azure_iot_mutex_ptr = esp_azure_iot_ptr->esp_azure_iot_event.esp_event_mutex;

    /* Set created IoT pointer.  */
    _esp_azure_iot_created_ptr = esp_azure_iot_ptr;
    

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_delete(ESP_AZURE_IOT *esp_azure_iot_ptr)
{
    uint32_t status = 0;

    if (esp_azure_iot_ptr == NULL)
    {
        LogError("IoT delete fail: INVALID POINTER");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    if (esp_azure_iot_ptr -> esp_azure_iot_resource_list_header)
    {
        LogError("IoT delete fail: IOTHUB CLIENT NOT DELETED");
        return(ESP_AZURE_IOT_NOT_FOUND);
    }

    /* Deregister SDK module on event helper.  */
    esp_azure_iot_event_group_deregister(&(esp_azure_iot_ptr -> esp_azure_iot_event), &(esp_azure_iot_ptr -> esp_azure_iot_event_group));

    /* Delete event.  */
    status = esp_azure_iot_event_delete(&esp_azure_iot_ptr -> esp_azure_iot_event);
    if (status)
    {
        LogError("IoT delete fail: 0x%02x", status);
        return(status);
    }

    _esp_azure_iot_created_ptr = NULL;

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_buffer_allocate(ESP_AZURE_IOT *esp_azure_iot_ptr, uint8_t **buffer_pptr,
                                  uint32_t *buffer_size, void **buffer_context)
{
    ESP_PACKET *packet_ptr = NULL;
    uint32_t status = 0;

    status = esp_azure_iot_packet_allocate(&packet_ptr, 0, ESP_AZURE_IOT_WAIT_OPTION);
    if (status)
    {
        return(status);
    }

    *buffer_pptr = packet_ptr -> esp_packet_data_start;
    *buffer_size = (uint32_t)(packet_ptr -> esp_packet_data_end - packet_ptr -> esp_packet_data_start);
    *buffer_context = (void *)packet_ptr;

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_buffer_free(void *buffer_context)
{
    ESP_PACKET *packet_ptr = (ESP_PACKET *)buffer_context;

    return(esp_azure_iot_packet_release(packet_ptr));
}

uint32_t esp_azure_iot_publish_packet_get(ESP_AZURE_IOT *esp_azure_iot_ptr, ESP_MQTT_CLIENT *client_ptr,
                                     ESP_PACKET  **packet_pptr, uint32_t wait_option)
{
    uint32_t status = 0;

    status = esp_azure_iot_packet_allocate(packet_pptr, 0, wait_option);
    if (status)
    {
        LogError("Create publish packet failed");
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_publish_mqtt_packet(ESP_MQTT_CLIENT *client_ptr, ESP_PACKET  *packet_ptr, uint32_t qos, uint32_t wait_option)
{
    uint32_t status = 0;

    /* Note, mutex will be released by this function. */
    status = esp_azure_iot_mqtt_client_publish_packet(client_ptr, packet_ptr, qos, wait_option);
    if (status)
    {
        LogError("Mqtt client send fail: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS );
}

void esp_azure_iot_mqtt_packet_adjust(ESP_PACKET  *packet_ptr)
{
uint32_t size;
uint32_t copy_size;
ESP_PACKET *current_packet_ptr;

    /* Adjust the packet to make sure,
     * 1. esp_packet_prepend_ptr does not pointer to esp_packet_data_start.
     * 2. The first packet is full if it is chained with multiple packets. */

    if (packet_ptr -> esp_packet_prepend_ptr != packet_ptr -> esp_packet_data_start)
    {

        /* Move data to the esp_packet_data_start. */
        size = (uint32_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr);
        memmove(packet_ptr -> esp_packet_data_start, packet_ptr -> esp_packet_prepend_ptr, size);
        packet_ptr -> esp_packet_prepend_ptr = packet_ptr -> esp_packet_data_start;
        packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_data_start + size;
    }

    if (packet_ptr -> esp_packet_next == NULL)
    {

        /* All data are in the first packet. */
        return;
    }

    /* Move data in the chained packet into first one until it is full. */
    for (current_packet_ptr = packet_ptr -> esp_packet_next;
         current_packet_ptr;
         current_packet_ptr = packet_ptr -> esp_packet_next)
    {

        /* Calculate remaining buffer size in the first packet. */
        size = (uint32_t)(packet_ptr -> esp_packet_data_end - packet_ptr -> esp_packet_append_ptr);

        /* Calculate copy size from current packet. */
        copy_size = (uint32_t)(current_packet_ptr -> esp_packet_append_ptr - current_packet_ptr -> esp_packet_prepend_ptr);

        if (size >= copy_size)
        {

            /* Copy all data from current packet. */
            memcpy((void *)packet_ptr -> esp_packet_append_ptr, (void *)current_packet_ptr -> esp_packet_prepend_ptr, copy_size);
            packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_append_ptr + copy_size;
        }
        else
        {

            /* Copy partial data from current packet. */
            memcpy(packet_ptr -> esp_packet_append_ptr, current_packet_ptr -> esp_packet_prepend_ptr, size);
            packet_ptr -> esp_packet_append_ptr = packet_ptr -> esp_packet_data_end;

            /* Move data in current packet to esp_packet_data_start. */
            memmove((void *)current_packet_ptr -> esp_packet_data_start, (void *)(current_packet_ptr -> esp_packet_prepend_ptr + size),
                    (copy_size - size));
            current_packet_ptr -> esp_packet_prepend_ptr = current_packet_ptr -> esp_packet_data_start;
            current_packet_ptr -> esp_packet_append_ptr = current_packet_ptr -> esp_packet_data_start + (copy_size - size);

            /* First packet is full. */
            break;
        }

        /* Remove current packet from packet chain. */
        packet_ptr -> esp_packet_next = current_packet_ptr -> esp_packet_next;

        /* Release current packet. */
        current_packet_ptr -> esp_packet_next = NULL;
        esp_azure_iot_packet_release(current_packet_ptr);
    }
}

uint32_t esp_azure_iot_unix_time_get(ESP_AZURE_IOT *esp_azure_iot_ptr, size_t *unix_time)
{
    if ((esp_azure_iot_ptr == NULL) ||
        (esp_azure_iot_ptr -> esp_azure_iot_unix_time_get == NULL) ||
        (unix_time == NULL))
    {
        LogError("Unix time callback not set");
        return(ESP_AZURE_IOT_INVALID_PARAMETER);
    }

    return(esp_azure_iot_ptr -> esp_azure_iot_unix_time_get(unix_time));
}

static uint32_t esp_azure_iot_base64_decode(char *base64name, uint32_t length, uint8_t *name, uint32_t name_size, uint32_t *bytes_copied)
{
    int ret = mbedtls_base64_decode((unsigned char *)name, name_size, (size_t *)bytes_copied, (unsigned char *)base64name, length);
    return (ret == ESP_AZURE_IOT_SUCCESS) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

static uint32_t esp_azure_iot_base64_encode(uint8_t *name, uint32_t length, char *base64name, uint32_t base64name_size)
{
    size_t out_len = base64name_size;
    int ret = mbedtls_base64_encode((unsigned char *)base64name, base64name_size, &out_len, (unsigned char *)name, length);
    return (ret == ESP_AZURE_IOT_SUCCESS) ? (ESP_AZURE_IOT_SUCCESS) : (ESP_AZURE_IOT_INVALID_PARAMETER);
}

/* HMAC-SHA256(master key, message ) */
static uint32_t esp_azure_iot_hmac_sha256_calculate(ESP_AZURE_IOT_RESOURCE *resource_ptr, uint8_t *key, uint32_t key_size,
                                               uint8_t *message, uint32_t message_size, uint8_t *output)
{
    hmac_sha256(key, key_size, message, message_size, output);
    
    return(ESP_AZURE_IOT_SUCCESS );
}

uint32_t esp_azure_iot_url_encoded_hmac_sha256_calculate(ESP_AZURE_IOT_RESOURCE *resource_ptr,
                                                    uint8_t *key_ptr, uint32_t key_size,
                                                    uint8_t *message_ptr, uint32_t message_size,
                                                    uint8_t *buffer_ptr, uint32_t buffer_len,
                                                    uint8_t **output_pptr, uint32_t *output_len)
{
    uint32_t status;
    uint8_t *hash_buf;
    uint32_t hash_buf_size = 33;
    char *encoded_hash_buf;
    uint32_t encoded_hash_buf_size = 48;
    uint32_t binary_key_buf_size;

    binary_key_buf_size = buffer_len;
    status = esp_azure_iot_base64_decode((char *)key_ptr, key_size,
                                        buffer_ptr, binary_key_buf_size, &binary_key_buf_size);
    if (status)
    {
        LogError("Failed to base64 decode");
        return(status);
    }

    buffer_len -= binary_key_buf_size;
    if ((hash_buf_size + encoded_hash_buf_size) > buffer_len)
    {
        LogError("Failed to not enough memory");
        return(ESP_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    hash_buf = buffer_ptr + binary_key_buf_size;
    status = esp_azure_iot_hmac_sha256_calculate(resource_ptr, buffer_ptr, binary_key_buf_size,
                                                message_ptr, (uint32_t)message_size, hash_buf);
    if (status)
    {
        LogError("Failed to get hash256");
        return(status);
    }

    buffer_len -= hash_buf_size;
    encoded_hash_buf = (char *)(hash_buf + hash_buf_size);
    /* Additional space is required by encoder */
    hash_buf[hash_buf_size - 1] = 0;
    status = esp_azure_iot_base64_encode(hash_buf, hash_buf_size - 1,
                                        encoded_hash_buf, encoded_hash_buf_size);
    if (status)
    {
        LogError("Failed to base64 encode");
        return(status);
    }

    buffer_len -= encoded_hash_buf_size;
    *output_pptr = (uint8_t *)(encoded_hash_buf + encoded_hash_buf_size);
    status = esp_azure_iot_url_encode(encoded_hash_buf, strlen((char *)encoded_hash_buf),
                                     (char *)*output_pptr, buffer_len, output_len);
    if (status)
    {
        LogError("Failed to get hash256");
        return(status);
    }

    return(ESP_AZURE_IOT_SUCCESS );
}
