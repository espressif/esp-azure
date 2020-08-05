// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "esp_azure_iot.h"
#include "esp_azure_iot_hub_client.h"

/* Define the Azure IOT task stack and priority.  */
#ifndef ESP_AZURE_IOT_STACK_SIZE
#define ESP_AZURE_IOT_STACK_SIZE                     (2048)
#endif /* ESP_AZURE_IOT_STACK_SIZE */

#ifndef ESP_AZURE_IOT_THREAD_PRIORITY
#define ESP_AZURE_IOT_THREAD_PRIORITY                (3)
#endif /* ESP_AZURE_IOT_THREAD_PRIORITY */

#ifndef SAMPLE_HOST_NAME
#define SAMPLE_HOST_NAME                        CONFIG_IOTHUB_HOST_NAME
#endif /* SAMPLE_HOST_NAME */

#ifndef SAMPLE_DEVICE_ID
#define SAMPLE_DEVICE_ID                        CONFIG_IOTHUB_DEVICE_ID
#endif /* SAMPLE_DEVICE_ID */

/* Optional DEVICE KEY.  */
#ifndef SAMPLE_DEVICE_KEY
#define SAMPLE_DEVICE_KEY                       CONFIG_IOTHUB_DEVICE_KEY
#endif /* SAMPLE_DEVICE_KEY */

/* Optional module ID.  */
#ifndef SAMPLE_MODULE_ID
#define SAMPLE_MODULE_ID                        CONFIG_IOTHUB_MODULE_ID
#endif /* SAMPLE_MODULE_ID */

#ifndef SAMPLE_IOTHUB_WAIT_OPTION
#define SAMPLE_IOTHUB_WAIT_OPTION               CONFIG_IOTHUB_WAIT_OPTION
#endif /* SAMPLE_IOTHUB_WAIT_OPTION */

#if CONFIG_IOTHUB_PROPERTY

/* Define sample properties count. */
#define MAX_PROPERTY_COUNT                          2

/* Define sample properties.  */
static const char *sample_properties[MAX_PROPERTY_COUNT][2] = {{"propertyA", "valueA"},
                                                               {"propertyB", "valueB"}};

#endif

static uint32_t unix_time_get(size_t *unix_time)
{

    /* Using time() to get unix time.
       Note: User needs to implement own time function to get the real time on device, such as: SNTP.  */
    *unix_time = (size_t)time(NULL);

    return(ESP_OK);
}

static void printf_packet(ESP_PACKET *packet_ptr)
{
    while (packet_ptr != NULL)
    {
        printf("%.*s", (int16_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr),
               (char *)packet_ptr -> esp_packet_prepend_ptr);
        packet_ptr = packet_ptr -> esp_packet_next;
    }
}

static void connection_status_callback(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, uint32_t status)
{
    ESP_PARAMETER_NOT_USED(hub_client_ptr);
    switch (status) {
        case ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED:
            printf("Connected to IoTHub.\r\n");
            break;
        case ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED:
            printf("Disconnected from IoTHub!: error code = 0x%08x\r\n", status);
            break;
        default:
            break;
    }
}

static void iot_hub_client_sample_mqtt(ESP_AZURE_IOT_HUB_CLIENT *iothub_client)
{
    uint32_t i = 0, index_count = 0;
    uint32_t status = 0;
    char buffer[30];
    uint32_t buffer_length;
    ESP_PACKET *packet_ptr;

#if CONFIG_IOTHUB_PROPERTY
    uint16_t property_buf_size;
    uint8_t *property_buf;
#endif

    bool sammple_session = false;

    if ((status = esp_azure_iot_hub_client_cloud_message_enable(iothub_client)))
    {
        printf("C2D receive enable failed!: error code = 0x%08x\r\n", status);
        return;
    }

    /* Loop to send telemetry message and receive c2d message.  */
    while (index_count ++ < 100) {
        
        /* Create a telemetry message packet. */
        sammple_session = false;
        if ((status = esp_azure_iot_hub_client_telemetry_message_create(iothub_client, &packet_ptr, portMAX_DELAY)))
        {
            printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
            break;
        }
#if CONFIG_IOTHUB_PROPERTY
        /* Add properties to telemetry message. */
        for (int index = 0; index < MAX_PROPERTY_COUNT; index++)
        {
            if ((status = esp_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                   (uint8_t *)sample_properties[index][0],
                                                                   (uint16_t)strlen(sample_properties[index][0]),
                                                                   (uint8_t *)sample_properties[index][1],
                                                                   (uint16_t)strlen(sample_properties[index][1]),
                                                                   portMAX_DELAY)))
            {
                printf("Telemetry property add failed!: error code = 0x%08x\r\n", status);
                break;
            }
        }
        
        if (status)
        {
            esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
            break;
        }
#endif

        buffer_length = (uint32_t)snprintf(buffer, sizeof(buffer), "{\"Message ID\":%u}", i++);
        if (esp_azure_iot_hub_client_telemetry_send(iothub_client, packet_ptr, (uint8_t *)buffer, buffer_length, portMAX_DELAY))
        {
            printf("Telemetry message send failed!: error code = 0x%08x\r\n", status);
            break;
        }
        printf("Telemetry message send: %s.\r\n", buffer);
        esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        packet_ptr = NULL;

        /* Wait for receive message from cloud.  */
        sammple_session = true;
        if ((status = esp_azure_iot_hub_client_cloud_message_receive(iothub_client, &packet_ptr, SAMPLE_IOTHUB_WAIT_OPTION)))
        {
            if (status != ESP_AZURE_IOT_NO_PACKET) {
                printf("C2D receive failed!: error code = 0x%08x\r\n", status);
                break;
            }
        } else {
#if CONFIG_IOTHUB_PROPERTY
            for (int index = 0; index < MAX_PROPERTY_COUNT; index ++) {
                if ((status = esp_azure_iot_hub_client_cloud_message_property_get(iothub_client, packet_ptr,
                                                                                (uint8_t *)sample_properties[index][0],
                                                                                (uint16_t)strlen(sample_properties[index][0]),
                                                                                &property_buf, &property_buf_size)))
                {
                    printf("Property [%s] not found: 0x%08x\r\n", sample_properties[index][0], status);
                }
                else
                {
                    printf("Receive property: %s = %.*s\r\n", sample_properties[index][0],
                        (int16_t)property_buf_size, property_buf);
                }
            }
#endif
            printf("Receive message:");
            printf_packet(packet_ptr);
            printf("\r\n");

            esp_azure_iot_packet_release(packet_ptr);
        }
    }

    if (sammple_session) {
        esp_azure_iot_packet_release(packet_ptr);
    } else {
        esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
    }

}

void iothub_client_sample_mqtt_run(void) 
{
    uint32_t                    status = 0;
    ESP_AZURE_IOT               *esp_azure_iot;
    ESP_AZURE_IOT_HUB_CLIENT    *iothub_client;
    uint8_t *iothub_hostname = (uint8_t *)SAMPLE_HOST_NAME;
    uint8_t *iothub_device_id = (uint8_t *)SAMPLE_DEVICE_ID;
    uint32_t iothub_hostname_length = sizeof(SAMPLE_HOST_NAME) - 1;
    uint32_t iothub_device_id_length = sizeof(SAMPLE_DEVICE_ID) - 1;

    /* Init Azure IoT Time Handle */
    if (esp_azure_iot_time_init()) {
        (void)printf("Failed to initialize the platform.\r\n");
        return;
    } 
    
    while (1) {
        esp_azure_iot = calloc(1, sizeof(ESP_AZURE_IOT));
        iothub_client = calloc(1, sizeof(ESP_AZURE_IOT_HUB_CLIENT));
        if (!esp_azure_iot || !iothub_client) {
            printf("Failed to initialize the azure.\r\n");
            break;
        }
        
        do {
            /* Create Azure IoT handler.  */
            if ((status = esp_azure_iot_create(esp_azure_iot, (uint8_t *)"Azure IoT", ESP_AZURE_IOT_STACK_SIZE,
                                            ESP_AZURE_IOT_THREAD_PRIORITY, unix_time_get)))
            {
                printf("Failed on esp_azure_iot_create!: error code = 0x%08x\r\n", status);
                break;
            }
            
            /* Initialize IoTHub client. */
            if ((status = esp_azure_iot_hub_client_initialize(iothub_client, esp_azure_iot,
                                                            iothub_hostname, iothub_hostname_length,
                                                            iothub_device_id, iothub_device_id_length,
                                                            (uint8_t *)SAMPLE_MODULE_ID, sizeof(SAMPLE_MODULE_ID) - 1,
                                                            NULL)))
            {
                printf("Failed on esp_azure_iot_hub_client_initialize!: error code = 0x%08x\r\n", status);
                break;
            }

#if CONFIG_IOTHUB_USING_CERTIFICATE

            /* Initialize the device certificate.  */
            if ((status = esp_secure_x509_certificate_initialize(&device_certificate, device_cert, sizeof(device_cert),
                                                                    NULL, 0, device_private_key, sizeof(device_private_key),
                                                                    DEVICE_KEY_TYPE)))
            {
                printf("Failed on esp_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
                break;
            }

            /* Set device certificate.  */
            if ((status = esp_azure_iot_hub_client_device_cert_set(iothub_client, &device_certificate)))
            {
                printf("Failed on esp_azure_iot_hub_client_device_cert_set!: error code = 0x%08x\r\n", status);
                break;
            }
#else

            /* Set symmetric key.  */
            if ((status = esp_azure_iot_hub_client_symmetric_key_set(iothub_client, (uint8_t *)SAMPLE_DEVICE_KEY, sizeof(SAMPLE_DEVICE_KEY) - 1)))
            {
                printf("Failed on esp_azure_iot_hub_client_symmetric_key_set!\r\n");
                break;
            }
#endif /* USE_DEVICE_CERTIFICATE */

            /* Set connection status callback. */
            if (esp_azure_iot_hub_client_connection_status_callback_set(iothub_client, connection_status_callback))
            {
                printf("Failed on connection_status_callback!\r\n");
            }

            /* Connect to IoTHub client. */
            if (esp_azure_iot_hub_client_connect(iothub_client, true, portMAX_DELAY))
            {
                printf("Failed on esp_azure_iot_hub_client_connect!\r\n");
            }

            /* Run MQTT sample. */
            iot_hub_client_sample_mqtt(iothub_client);

        } while (0);

        /* Destroy IoTHub Client.  */
        esp_azure_iot_hub_client_disconnect(iothub_client);
        esp_azure_iot_hub_client_deinitialize(iothub_client);
        esp_azure_iot_delete(esp_azure_iot);

        /* Destory azure iot.  */
        if (iothub_client) {
            free(iothub_client);
            iothub_client = NULL;
        }

        if (esp_azure_iot) {
            free(esp_azure_iot);
            esp_azure_iot = NULL;
        }
    }
    
}
