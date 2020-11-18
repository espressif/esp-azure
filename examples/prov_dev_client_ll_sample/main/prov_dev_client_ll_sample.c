// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "esp_azure_iot.h"
#include "esp_azure_iot_hub_client.h"
#include "esp_azure_iot_provisioning_client.h"

/* Define the Azure IOT task stack and priority.  */
#ifndef ESP_AZURE_IOT_STACK_SIZE
#define ESP_AZURE_IOT_STACK_SIZE                     (3072)
#endif /* ESP_AZURE_IOT_STACK_SIZE */

#ifndef ESP_AZURE_IOT_THREAD_PRIORITY
#define ESP_AZURE_IOT_THREAD_PRIORITY                (3)
#endif /* ESP_AZURE_IOT_THREAD_PRIORITY */

#ifndef SAMPLE_IOTHUB_ENDPOINT
#define SAMPLE_IOTHUB_ENDPOINT                  CONFIG_IOTHUB_ENDPOINT
#endif /* SAMPLE_IOTHUB_ENDPOINT */

#ifndef SAMPLE_IOTHUB_REGISTRATION_ID
#define SAMPLE_IOTHUB_REGISTRATION_ID           CONFIG_IOTHUB_REGISTRATION_ID
#endif /* SAMPLE_IOTHUB_REGISTRATION_ID */

#ifndef SAMPLE_IOTHUB_ID_SCOPE
#define SAMPLE_IOTHUB_ID_SCOPE                  CONFIG_IOTHUB_ID_SCOPE
#endif /* SAMPLE_IOTHUB_ID_SCOPE */

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

static uint8_t sample_iothub_hostname[256];
static uint8_t sample_iothub_device_id[256];

static uint32_t unix_time_get(size_t *unix_time)
{

    /* Using time() to get unix time.
       Note: User needs to implement own time function to get the real time on device, such as: SNTP.  */
    *unix_time = (size_t)time(NULL);

    return(ESP_OK);
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

static void iot_hub_client_sample_telemetry(ESP_AZURE_IOT_HUB_CLIENT *iothub_client)
{
    uint32_t i = 0, index_count = 0;;
    uint32_t status = 0;
    char buffer[30];
    uint32_t buffer_length;
    ESP_PACKET *packet_ptr;

    /* Loop to send telemetry message.  */
    while (index_count ++ < 100) {
        
        /* Create a telemetry message packet. */
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
            esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
            break;
        }
        printf("Telemetry message send: %s.\r\n", buffer);

        vTaskDelay(SAMPLE_IOTHUB_WAIT_OPTION);
    }
}

static uint32_t iot_hub_sample_provisioning(ESP_AZURE_IOT *esp_azure_iot, uint8_t **iothub_hostname, uint32_t *iothub_hostname_length,
                                 uint8_t **iothub_device_id, uint32_t *iothub_device_id_length)
{
    uint32_t status;

    ESP_AZURE_IOT_PROVISIONING_CLIENT *prov_client = calloc(1, sizeof(ESP_AZURE_IOT_PROVISIONING_CLIENT));

    /* Initialize IoT provisioning client.  */
    if ((status = esp_azure_iot_provisioning_client_initialize(prov_client, esp_azure_iot,
                                                              (uint8_t *)SAMPLE_IOTHUB_ENDPOINT, sizeof(SAMPLE_IOTHUB_ENDPOINT) - 1,
                                                              (uint8_t *)SAMPLE_IOTHUB_ID_SCOPE, sizeof(SAMPLE_IOTHUB_ID_SCOPE) - 1,
                                                              (uint8_t *)SAMPLE_IOTHUB_REGISTRATION_ID, sizeof(SAMPLE_IOTHUB_REGISTRATION_ID) - 1,
                                                              NULL)))
    {
        printf("Failed on esp_azure_iot_provisioning_client_initialize!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Initialize length of hostname and device ID. */
    *iothub_hostname_length = sizeof(sample_iothub_hostname);
    *iothub_device_id_length = sizeof(sample_iothub_device_id);

#if CONFIG_IOTHUB_USING_CERTIFICATE

    /* Initialize the device certificate.  */
    if ((status = esp_secure_x509_certificate_initialize(&device_certificate, device_cert, sizeof(device_cert), NULL, 0,
                                                        device_private_key, sizeof(device_private_key), DEVICE_KEY_TYPE)))
    {
        printf("Failed on esp_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = esp_azure_iot_provisioning_client_device_cert_set(prov_client, &device_certificate)))
    {
        printf("Failed on esp_azure_iot_provisioning_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#else

    /* Set symmetric key.  */
    if ((status = esp_azure_iot_provisioning_client_symmetric_key_set(prov_client, (uint8_t *)SAMPLE_DEVICE_KEY,
                                                                     sizeof(SAMPLE_DEVICE_KEY) - 1)))
    {
        printf("Failed on esp_azure_iot_hub_client_symmetric_key_set!: error code = 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */

    /* Register device */
    else if ((status = esp_azure_iot_provisioning_client_register(prov_client, portMAX_DELAY)))
    {
        printf("Failed on esp_azure_iot_provisioning_client_register!: error code = 0x%08x\r\n", status);
    }

    /* Get Device info */
    else if ((status = esp_azure_iot_provisioning_client_iothub_device_info_get(prov_client,
                                                                               sample_iothub_hostname, iothub_hostname_length,
                                                                               sample_iothub_device_id, iothub_device_id_length)))
    {
        printf("Failed on esp_azure_iot_provisioning_client_iothub_device_info_get!: error code = 0x%08x\r\n", status);
    }
    else
    {
        *iothub_hostname = sample_iothub_hostname;
        *iothub_device_id = sample_iothub_device_id;
    }

    /* Destroy Provisioning Client.  */
    esp_azure_iot_provisioning_client_deinitialize(prov_client);
    free(prov_client);
    prov_client = NULL;
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    
    return(status);
}

int prov_dev_client_ll_sample_run(void) 
{
    uint32_t                    status = 0;
    ESP_AZURE_IOT               *esp_azure_iot = NULL;
    ESP_AZURE_IOT_HUB_CLIENT    *iothub_client = NULL;
    uint8_t                     *iothub_hostname = NULL;
    uint8_t                     *iothub_device_id = NULL;
    uint32_t                    iothub_hostname_length = 0;
    uint32_t                    iothub_device_id_length = 0;

    /* Init Azure IoT Time Handle */
    if (esp_azure_iot_time_init()) {
        (void)printf("Failed to initialize the platform.\r\n");
        return ESP_FAIL;
    }

    while (1) {
        esp_azure_iot = calloc(1, sizeof(ESP_AZURE_IOT));
        if (!esp_azure_iot) {
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

            if ((status = iot_hub_sample_provisioning(esp_azure_iot, &iothub_hostname, &iothub_hostname_length,
                                        &iothub_device_id, &iothub_device_id_length)))
            {
                printf("Failed on iot_hub_sample_provisioning!: error code = 0x%08x\r\n", status);
                break;
            }

            iothub_client = calloc(1, sizeof(ESP_AZURE_IOT_HUB_CLIENT));
            if (!iothub_client) {
                printf("Failed to initialize the azure iot.\r\n");
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

            /* Run telemetry sample. */
            iot_hub_client_sample_telemetry(iothub_client);

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

    return ESP_OK;
}
