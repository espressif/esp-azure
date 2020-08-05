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

/* Define sample properties.  */
static char fixed_reported_properties[] = "{\"sample_report\": \"OK\"}";
static char method_response_payload[] = "{\"status\": \"OK\"}";

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

static void iothub_client_sample_device_twin_and_methods(ESP_AZURE_IOT_HUB_CLIENT *iothub_client)
{
    ESP_PACKET *packet_ptr;
    uint32_t status = 0;
    uint32_t response_status;
    uint32_t request_id;
    uint16_t method_name_length;
    uint8_t *method_name_ptr;
    uint16_t context_length;
    void *context_ptr;

    if ((status = esp_azure_iot_hub_client_direct_method_enable(iothub_client)))
    {
        printf("Direct method receive enable failed!: error code = 0x%08x\r\n", status);
        return;
    }

    if ((status = esp_azure_iot_hub_client_device_twin_enable(iothub_client)))
    {
        printf("device twin enabled failed!: error code = 0x%08x\r\n", status);
        return;
    }

    if ((status = esp_azure_iot_hub_client_device_twin_properties_request(iothub_client, portMAX_DELAY)))
    {
        printf("device twin document request failed!: error code = 0x%08x\r\n", status);
        return;
    }

    if ((status = esp_azure_iot_hub_client_device_twin_properties_receive(iothub_client, &packet_ptr, portMAX_DELAY)))
    {
        printf("device twin document receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Receive twin properties :");
    printf_packet(packet_ptr);
    printf("\r\n");
    esp_azure_iot_packet_release(packet_ptr);
    packet_ptr = NULL;

    /* Loop to receive device twin and direct method message.  */
    while (1)
    {

        if ((status = esp_azure_iot_hub_client_direct_method_message_receive(iothub_client,
                                                                            &method_name_ptr, &method_name_length,
                                                                            &context_ptr, &context_length,
                                                                            &packet_ptr, SAMPLE_IOTHUB_WAIT_OPTION)))
        {
            if (status != ESP_AZURE_IOT_NO_PACKET) {
                printf("Direct method receive failed!: error code = 0x%08x\r\n", status);
                break;
            }
        } else {

            printf("Receive method call: %.*s, with payload:", (int16_t)method_name_length, (char *)method_name_ptr);
            printf_packet(packet_ptr);
            printf("\r\n");

            if ((status = esp_azure_iot_hub_client_direct_method_message_response(iothub_client, 200 /* method status */,
                                                                                context_ptr, context_length,
                                                                                (uint8_t *)method_response_payload, sizeof(method_response_payload) - 1,
                                                                                portMAX_DELAY)))
            {
                printf("Direct method response failed!: error code = 0x%08x\r\n", status);
                break;
            }

            esp_azure_iot_packet_release(packet_ptr);
            packet_ptr = NULL;
        }

        if ((status = esp_azure_iot_hub_client_device_twin_desired_properties_receive(iothub_client, &packet_ptr,
                                                                                     SAMPLE_IOTHUB_WAIT_OPTION)))
        {
            if (status != ESP_AZURE_IOT_NO_PACKET) {
                printf("Receive desired property receive failed!: error code = 0x%08x\r\n", status);
                break;
            }
        } else {

            printf("Receive desired property call: ");
            printf_packet(packet_ptr);
            printf("\r\n");
            esp_azure_iot_packet_release(packet_ptr);
            packet_ptr = NULL;

            if ((status = esp_azure_iot_hub_client_device_twin_reported_properties_send(iothub_client,
                                                                                    (uint8_t *)fixed_reported_properties, sizeof(fixed_reported_properties) - 1,
                                                                                    &request_id, &response_status,
                                                                                    portMAX_DELAY)))
            {
                printf("Device twin reported properties failed!: error code = 0x%08x\r\n", status);
            }

            if ((response_status < 200) || (response_status >= 300))
            {
                printf("device twin report properties failed with code : %d\r\n", response_status);
                break;
            }
        }
    }

    esp_azure_iot_packet_release(packet_ptr);
    packet_ptr = NULL;
}

static void iothub_client_device_twin_and_methods_sample_run(void) 
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

            /* Run Device Twin and sample. */
            iothub_client_sample_device_twin_and_methods(iothub_client);

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

int iothub_client_device_twin_init(void)
{
    iothub_client_device_twin_and_methods_sample_run();
    return 0;
}