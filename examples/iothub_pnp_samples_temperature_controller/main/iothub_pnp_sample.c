// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "azure/core/az_json.h"
#include "esp_azure_iot.h"
#include "esp_azure_iot_hub_client.h"
#include "esp_azure_iot_provisioning_client.h"

#include "sample_pnp_deviceinfo.h"
#include "esp_azure_iot_pnp.h"
#include "sample_pnp_thermostat.h"

#include "iothub_pnp_sample.h"

/* Define the Azure IOT task stack and priority.  */
#ifndef ESP_AZURE_IOT_STACK_SIZE
#define ESP_AZURE_IOT_STACK_SIZE                     (2048)
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

#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC                           (10 * 60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC                       (3)
#endif /* SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT                   (60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT */

#ifndef SAMPLE_WAIT_OPTION
#define SAMPLE_WAIT_OPTION                                              (ESP_WAIT_FOREVER)
#endif /* SAMPLE_WAIT_OPTION */

/* Sample events */
#define SAMPLE_CONNECT_EVENT                                            ((size_t)0x00000001)
#define SAMPLE_INITIALIZATION_EVENT                                     ((size_t)0x00000002)
#define SAMPLE_METHOD_MESSAGE_EVENT                                     ((size_t)0x00000004)
#define SAMPLE_DEVICE_TWIN_GET_EVENT                                    ((size_t)0x00000008)
#define SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT                       ((size_t)0x00000010)
#define SAMPLE_TELEMETRY_SEND_EVENT                                     ((size_t)0x00000020)
#define SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT                      ((size_t)0x00000040)
#define SAMPLE_DISCONNECT_EVENT                                         ((size_t)0x00000080)
#define SAMPLE_RECONNECT_EVENT                                          ((size_t)0x00000100)
#define SAMPLE_CONNECTED_EVENT                                          ((size_t)0x00000200)
#define SAMPLE_ALL_EVENTS                                               (SAMPLE_CONNECT_EVENT | \
                                                                        SAMPLE_INITIALIZATION_EVENT |   \
                                                                        SAMPLE_METHOD_MESSAGE_EVENT |   \
                                                                        SAMPLE_DEVICE_TWIN_GET_EVENT |  \
                                                                        SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT | \
                                                                        SAMPLE_TELEMETRY_SEND_EVENT |   \
                                                                        SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT |    \
                                                                        SAMPLE_DISCONNECT_EVENT |   \
                                                                        SAMPLE_RECONNECT_EVENT |    \
                                                                        SAMPLE_CONNECTED_EVENT)

/* Sample states */
#define SAMPLE_STATE_NONE                                               (0)
#define SAMPLE_STATE_INIT                                               (1)
#define SAMPLE_STATE_CONNECTING                                         (2)
#define SAMPLE_STATE_CONNECT                                            (3)
#define SAMPLE_STATE_CONNECTED                                          (4)
#define SAMPLE_STATE_DISCONNECTED                                       (5)

#define SAMPLE_DEFAULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)
#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)
#define SAMPLE_COMMAND_NOT_FOUND_STATUS                                 (404)

/* Define Sample context.  */
typedef struct SAMPLE_CONTEXT_STRUCT
{
    uint32_t                             state;
    uint32_t                             action_result;
    size_t                               last_periodic_action_tick;

    EventGroupHandle_t                   sample_events;
    ESP_AZURE_IOT_HUB_CLIENT             iothub_client;
    ESP_AZURE_IOT                        esp_azure_iot;
} SAMPLE_CONTEXT;

/* Define the prototypes for AZ IoT.  */
static SAMPLE_CONTEXT sample_context;
static volatile uint32_t sample_connection_status = -1;
static uint32_t exponential_retry_count;

/* PNP model id */
static const char sample_model_id[] = "dtmi:com:example:TemperatureController;1";
static SAMPLE_PNP_THERMOSTAT_COMPONENT sample_thermostat_1;
static const char sample_thermostat_1_component[] = "thermostat1";
static double sample_thermostat_1_last_device_max_temp_reported;
static SAMPLE_PNP_THERMOSTAT_COMPONENT sample_thermostat_2;
static const char sample_thermostat_2_component[] = "thermostat2";
static double sample_thermostat_2_last_device_max_tem_reported;
static const char sample_device_info_component[] = "deviceInformation";
static uint32_t sample_device_info_sent;
static uint32_t sample_device_serial_info_sent;
static const char *sample_components[] = { sample_thermostat_1_component,
                                           sample_thermostat_2_component,
                                           sample_device_info_component };
static uint32_t sample_components_num = sizeof(sample_components) / sizeof(sample_components[0]);

/* Name of the serial number property as defined in this component's DTML */
static const az_span sample_serial_number_property_name = AZ_SPAN_LITERAL_FROM_STR("serialNumber");

/* Value of the serial number.  NOTE: This must be a legal JSON string which requires value to be in "..." */
static const az_span sample_serial_number_property_value = AZ_SPAN_LITERAL_FROM_STR("serial-no-123-abc");

static const az_span working_set_span = AZ_SPAN_LITERAL_FROM_STR("workingSet");

/* PnP command supported */
static const char rebootCommand[] = "reboot";

static const int32_t working_set_minimum = 1000;
static const int32_t working_set_random_modulo = 500;

static uint8_t scratch_buffer[512];

#if CONFIG_IOTHUB_DPS_ENABLE
static uint8_t sample_iothub_hostname[256];
static uint8_t sample_iothub_device_id[256];

static uint32_t sample_iot_hub_device_provisioning_entry(ESP_AZURE_IOT *esp_azure_iot, uint8_t **iothub_hostname, uint32_t *iothub_hostname_length,
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

#endif /* CONFIG_IOTHUB_DPS_ENABLE */

static uint32_t sample_pnp_temp_controller_reboot_command(ESP_PACKET *packet_ptr, uint8_t *buffer,
                                                     uint32_t buffer_size, uint32_t *bytes_copied)
{
int32_t delay;
az_json_reader jp;
az_span payload_span = az_span_init(packet_ptr -> esp_packet_prepend_ptr,
                                    (int32_t)(packet_ptr -> esp_packet_append_ptr -
                                          packet_ptr -> esp_packet_prepend_ptr));

    ESP_PARAMETER_NOT_USED(buffer);
    ESP_PARAMETER_NOT_USED(buffer_size);

    if (az_span_size(payload_span) == 0)
    {
        printf("Payload found to be null for reboot command\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }
    else
    {
        if (!(az_succeeded(az_json_reader_init(&jp, payload_span, NULL)) &&
              az_succeeded(az_json_reader_next_token(&jp)) &&
              az_succeeded(az_json_token_get_int32(&jp.token, (int32_t *)&delay))))
        {
             return(ESP_AZURE_IOT_PNP_FAIL);
        }

        *bytes_copied = 0;
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

static uint32_t sample_pnp_temp_controller_telemetry_send(ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
uint32_t status;
ESP_PACKET *packet_ptr;
az_json_writer json_writer;
uint32_t buffer_length;
int32_t working_set;

    working_set = working_set_minimum + (rand() % working_set_random_modulo);

    /* Create a telemetry message packet. */
    if ((status = esp_azure_iot_pnp_telemetry_message_create(iothub_client_ptr, NULL, 0,
                                                                   &packet_ptr, ESP_WAIT_FOREVER)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Build telemetry JSON payload */
    if(!(az_succeeded(az_json_writer_init(&json_writer, AZ_SPAN_FROM_BUFFER(scratch_buffer), NULL)) &&
         az_succeeded(az_json_writer_append_begin_object(&json_writer)) &&
         az_succeeded(az_json_writer_append_property_name(&json_writer, working_set_span)) &&
         az_succeeded(az_json_writer_append_int32(&json_writer, working_set)) &&
         az_succeeded(az_json_writer_append_end_object(&json_writer))))
    {
        printf("Telemetry message failed to build message\r\n");
        esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    buffer_length = (uint32_t)az_span_size(az_json_writer_get_json(&json_writer));
    if ((status = esp_azure_iot_hub_client_telemetry_send(iothub_client_ptr, packet_ptr,
                                                         (uint8_t *)scratch_buffer, buffer_length, ESP_WAIT_FOREVER)))
    {
        printf("Telemetry message send failed!: error code = 0x%08x\r\n", status);
        esp_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(status);
    }

    printf("Temp Controller Telemetry message send: %.*s.\r\n", buffer_length, scratch_buffer);

    return(status);
}

static uint32_t sample_pnp_temp_controller_process_command(uint8_t *component_name_ptr, uint32_t component_name_length,
                                                       uint8_t *pnp_command_name_ptr, uint32_t pnp_command_name_length,
                                                       ESP_PACKET *packet_ptr, ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                       void *context_ptr, uint16_t context_length)
{
uint32_t status;
uint32_t response_payload_len = 0;
uint32_t dm_status;

    if (component_name_ptr != NULL || component_name_length != 0)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (pnp_command_name_length != (sizeof(rebootCommand) - 1) ||
        strncmp((char *)pnp_command_name_ptr, (char *)rebootCommand, pnp_command_name_length) != 0)
    {
        printf("PnP command=%.*s is not supported on thermostat component", pnp_command_name_length, pnp_command_name_ptr);
        dm_status = SAMPLE_COMMAND_NOT_FOUND_STATUS;
    }
    else
    {
        dm_status = (sample_pnp_temp_controller_reboot_command(packet_ptr, scratch_buffer, sizeof(scratch_buffer),
                                                               &response_payload_len) != ESP_AZURE_IOT_SUCCESS) ? SAMPLE_COMMAND_ERROR_STATUS :
                                                                                                                 SAMPLE_COMMAND_SUCCESS_STATUS;
    }

    if ((status = esp_azure_iot_hub_client_direct_method_message_response(iothub_client_ptr, dm_status,
                                                                         context_ptr, context_length, scratch_buffer,
                                                                         response_payload_len, ESP_WAIT_FOREVER)))
    {
        printf("Direct method response failed!: error code = 0x%08x\r\n", status);
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

static uint32_t append_serial_number(az_json_writer *json_writer, void *context)
{
uint32_t status;

    ESP_PARAMETER_NOT_USED(context);

    if (az_succeeded(az_json_writer_append_property_name(json_writer, sample_serial_number_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_serial_number_property_value)))
    {
        status = ESP_AZURE_IOT_SUCCESS;
    }
    else
    {
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

static uint32_t sample_pnp_temp_controller_report_serial_number_property(ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
uint32_t reported_properties_length;
uint32_t status;
uint32_t response_status;
uint32_t request_id;

    if ((status = esp_azure_iot_pnp_build_reported_property(NULL, 0, append_serial_number, NULL,
                                                                  (uint8_t *)scratch_buffer, sizeof(scratch_buffer),
                                                                  &reported_properties_length)))
    {
        printf("Failed to build reported property!: error code = 0x%08x\r\n", status);
        return(status);
    }

    if ((status = esp_azure_iot_hub_client_device_twin_reported_properties_send(iothub_client_ptr,
                                                                               scratch_buffer,
                                                                               reported_properties_length,
                                                                               &request_id, &response_status,
                                                                               (5 * ESP_IP_PERIODIC_RATE))))
    {
        printf("Device twin reported properties failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    if ((response_status < 200) || (response_status >= 300))
    {
        printf("device twin report properties failed with code : %d\r\n", response_status);
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    return(status);
}

static void printf_packet(ESP_PACKET *packet_ptr)
{
    while (packet_ptr != NULL)
    {
        printf("%.*s", (int32_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr),
               (char *)packet_ptr -> esp_packet_prepend_ptr);
        packet_ptr = packet_ptr -> esp_packet_next;
    }
}

static uint32_t exponential_backoff_with_jitter()
{
double jitter_percent = (SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT / 100.0) * (rand() / ((double)RAND_MAX));
uint32_t base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;

    if (exponential_retry_count < (sizeof(uint32_t) * 8))
    {
        base_delay = (uint32_t)((2 << exponential_retry_count) * SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC);
    }

    if (base_delay > SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC)
    {
        base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;
    }
    else
    {
        exponential_retry_count++;
    }

    return((uint32_t)(base_delay * (1 + jitter_percent)) * ESP_IP_PERIODIC_RATE) ;
}

static void exponential_backoff_reset()
{
    exponential_retry_count = 0;
}

static void connection_status_callback(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, uint32_t status)
{
    ESP_PARAMETER_NOT_USED(hub_client_ptr);

    sample_connection_status = status;

    switch (status) {
        case ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED:
            printf("Connected to IoTHub and update states.\r\n");
            xEventGroupSetBits(sample_context.sample_events, SAMPLE_CONNECTED_EVENT);
            exponential_backoff_reset();
            break;
        case ESP_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED:
            printf("Disconnected from IoTHub!: error code = 0x%08x\r\n", status);
            xEventGroupSetBits(sample_context.sample_events, SAMPLE_DISCONNECT_EVENT);
            break;
        default:
            break;
    }
}

static void message_receive_callback_twin(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, void *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    ESP_PARAMETER_NOT_USED(hub_client_ptr);
    xEventGroupSetBits(sample_ctx->sample_events, SAMPLE_DEVICE_TWIN_GET_EVENT);
}

static void message_receive_callback_method(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, void *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    ESP_PARAMETER_NOT_USED(hub_client_ptr);
    xEventGroupSetBits(sample_ctx->sample_events, SAMPLE_METHOD_MESSAGE_EVENT);
}

static void message_receive_callback_desired_property(ESP_AZURE_IOT_HUB_CLIENT *hub_client_ptr, void *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    ESP_PARAMETER_NOT_USED(hub_client_ptr);
    xEventGroupSetBits(sample_ctx->sample_events, SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT);
}

static void sample_connect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECT)
    {
        return;
    }

    context -> action_result = esp_azure_iot_hub_client_connect(&(context -> iothub_client), false, SAMPLE_WAIT_OPTION);

    if (context -> action_result == ESP_AZURE_IOT_CONNECTING)
    {
        context -> state = SAMPLE_STATE_CONNECTING;
    }
    else if (context -> action_result != ESP_AZURE_IOT_SUCCESS)
    {
        sample_connection_status = context -> action_result;
        context -> state = SAMPLE_STATE_DISCONNECTED;
    }
    else
    {
        context -> state = SAMPLE_STATE_CONNECTED;
        uint32_t status = ESP_AZURE_IOT_SUCCESS;
        if ((status = esp_azure_iot_hub_client_direct_method_enable(&(context -> iothub_client))))
        {
            printf("Direct method receive enable failed!: error code = 0x%08x\r\n", status);
        }
        else if ((status = esp_azure_iot_hub_client_device_twin_enable(&(context -> iothub_client))))
        {
            printf("device twin enabled failed!: error code = 0x%08x\r\n", status);
        }

        context -> action_result = esp_azure_iot_hub_client_device_twin_properties_request(&(context -> iothub_client), ESP_WAIT_FOREVER);
    }
}

static void sample_disconnect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTED &&
        context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> action_result = esp_azure_iot_hub_client_disconnect(&(context -> iothub_client));
    context -> state = SAMPLE_STATE_DISCONNECTED;
}

static void sample_connected_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> state = SAMPLE_STATE_CONNECTED;

    context -> action_result =
        esp_azure_iot_hub_client_device_twin_properties_request(&(context -> iothub_client), ESP_WAIT_FOREVER);
}

static void sample_initialize_iothub(SAMPLE_CONTEXT *context)
{
uint32_t status;
#if CONFIG_IOTHUB_DPS_ENABLE
uint8_t *iothub_hostname = NULL;
uint8_t *iothub_device_id = NULL;
uint32_t iothub_hostname_length = 0;
uint32_t iothub_device_id_length = 0;
#else
uint8_t *iothub_hostname = (uint8_t *)SAMPLE_HOST_NAME;
uint8_t *iothub_device_id = (uint8_t *)SAMPLE_DEVICE_ID;
uint32_t iothub_hostname_length = sizeof(SAMPLE_HOST_NAME) - 1;
uint32_t iothub_device_id_length = sizeof(SAMPLE_DEVICE_ID) - 1;
#endif /* CONFIG_IOTHUB_DPS_ENABLE */
ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr = &(context -> iothub_client);

    if (context -> state != SAMPLE_STATE_INIT)
    {
        return;
    }

#if CONFIG_IOTHUB_DPS_ENABLE
    /* Run DPS. */
    if ((status = sample_iot_hub_device_provisioning_entry(&(context -> esp_azure_iot), &iothub_hostname, &iothub_hostname_length,
                                   &iothub_device_id, &iothub_device_id_length)))
    {
        printf("Failed on sample_iot_hub_device_provisioning_entry!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }
#endif /* CONFIG_IOTHUB_DPS_ENABLE */

    /* Initialize IoTHub client. */
    if ((status = esp_azure_iot_hub_client_initialize(iothub_client_ptr, &context->esp_azure_iot,
                                                     iothub_hostname, iothub_hostname_length,
                                                     iothub_device_id, iothub_device_id_length,
                                                     (uint8_t *)SAMPLE_MODULE_ID, sizeof(SAMPLE_MODULE_ID) - 1,
                                                     NULL)))
    {
        printf("Failed on esp_azure_iot_hub_client_initialize!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }

#if CONFIG_IOTHUB_USING_CERTIFICATE

    /* Initialize the device certificate.  */
    if ((status = esp_secure_x509_certificate_initialize(&device_certificate,
                                                        (uint8_t *)sample_device_cert_ptr, (uint16_t)sample_device_cert_len,
                                                        NULL, 0,
                                                        (uint8_t *)sample_device_private_key_ptr, (uint16_t)sample_device_private_key_len,
                                                        DEVICE_KEY_TYPE)))
    {
        printf("Failed on esp_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }
    /* Set device certificate.  */
    else if ((status = esp_azure_iot_hub_client_device_cert_set(iothub_client_ptr, &device_certificate)))
    {
        printf("Failed on esp_azure_iot_hub_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#else

    /* Set symmetric key.  */
    if ((status = esp_azure_iot_hub_client_symmetric_key_set(iothub_client_ptr,
                                                            (uint8_t *)SAMPLE_DEVICE_KEY,
                                                            sizeof(SAMPLE_DEVICE_KEY) - 1)))
    {
        printf("Failed on esp_azure_iot_hub_client_symmetric_key_set! error: 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */

    /* Set connection status callback. */
    else if ((status = esp_azure_iot_hub_client_connection_status_callback_set(iothub_client_ptr,
                                                                              connection_status_callback)))
    {
        printf("Failed on connection_status_callback!\r\n");
    }
    else if ((status = esp_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    ESP_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES,
                                                                    message_receive_callback_twin,
                                                                    (void *)context)))
    {
        printf("device twin callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = esp_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    ESP_AZURE_IOT_HUB_DIRECT_METHOD,
                                                                    message_receive_callback_method,
                                                                    (void *)context)))
    {
        printf("device method callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = esp_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    ESP_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES,
                                                                    message_receive_callback_desired_property,
                                                                    (void *)context)))
    {
        printf("device twin desired property callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = esp_azure_iot_hub_client_model_id_set(iothub_client_ptr, (uint8_t *)sample_model_id, sizeof(sample_model_id) - 1)))
    {
        printf("digital twin modelId set!: error code = 0x%08x\r\n", status);
    }
    
    if (status)
    {
        esp_azure_iot_hub_client_deinitialize(iothub_client_ptr);
    }

    context -> action_result = status;

    if (status == ESP_AZURE_IOT_SUCCESS)
    {
        context -> state = SAMPLE_STATE_CONNECT;
    }
}

static void sample_connection_error_recover(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_DISCONNECTED)
    {
        return;
    }

    switch (sample_connection_status)
    {
        case ESP_AZURE_IOT_SUCCESS:
        {
            printf("already connected\r\n");
        }
        break;

        case ESP_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED:
            printf("Connected to IoTHub.\r\n");
        break;

        default:
        {
            printf("reconnecting iothub, after backoff\r\n");

            vTaskDelay(exponential_backoff_with_jitter() / portTICK_PERIOD_MS);
            context -> state = SAMPLE_STATE_CONNECT;
        }
        break;
    }
}

static void sample_trigger_action(SAMPLE_CONTEXT *context)
{
    switch (context -> state)
    {
        case SAMPLE_STATE_INIT:
        {
            xEventGroupSetBits(context->sample_events, SAMPLE_INITIALIZATION_EVENT);
        }
        break;

        case SAMPLE_STATE_CONNECT:
        {
            xEventGroupSetBits(context->sample_events, SAMPLE_CONNECT_EVENT);
        }
        break;

        case SAMPLE_STATE_CONNECTED:
        {
            if ((time(NULL) - context -> last_periodic_action_tick) >= (5 * ESP_IP_PERIODIC_RATE))
            {
                context -> last_periodic_action_tick = time(NULL);
                xEventGroupSetBits(context->sample_events, SAMPLE_TELEMETRY_SEND_EVENT);
                xEventGroupSetBits(context->sample_events, SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT);
            }
        }
        break;

        case SAMPLE_STATE_DISCONNECTED:
        {
            xEventGroupSetBits(context->sample_events, SAMPLE_RECONNECT_EVENT);
        }
        break;
    }
}

static void sample_direct_method_action(SAMPLE_CONTEXT *sample_context_ptr)
{
ESP_PACKET *packet_ptr;
uint32_t status;
uint16_t method_name_length;
uint8_t *method_name_ptr;
uint16_t context_length;
void *context_ptr;
uint32_t component_name_length;
uint8_t *component_name_ptr;
uint32_t pnp_command_name_length;
uint8_t *pnp_command_name_ptr;


    if (sample_context_ptr -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = esp_azure_iot_hub_client_direct_method_message_receive(&(sample_context_ptr -> iothub_client),
                                                                        &method_name_ptr, &method_name_length,
                                                                        &context_ptr, &context_length,
                                                                        &packet_ptr, ESP_WAIT_FOREVER)))
    {
        printf("Direct method receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Receive method call: %.*s, with payload:", (int32_t)method_name_length, (char *)method_name_ptr);
    printf_packet(packet_ptr);
    printf("\r\n");

    if ((status = esp_azure_iot_pnp_command_name_parse(method_name_ptr, method_name_length,
                                                             &component_name_ptr, &component_name_length,
                                                             &pnp_command_name_ptr,
                                                             &pnp_command_name_length)) != ESP_AZURE_IOT_SUCCESS)
    {
        printf("Failed to parse command name: error code = 0x%08x\r\n", status);
    }
    else if ((status = sample_pnp_thermostat_process_command(&sample_thermostat_1, component_name_ptr, component_name_length,
                                                             pnp_command_name_ptr, pnp_command_name_length,
                                                             packet_ptr, &(sample_context_ptr -> iothub_client),
                                                             context_ptr, context_length)) == ESP_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s on thermostat 1\r\n", method_name_length, method_name_ptr);
    }
    else if ((status = sample_pnp_thermostat_process_command(&sample_thermostat_2, component_name_ptr, component_name_length,
                                                             pnp_command_name_ptr, pnp_command_name_length,
                                                             packet_ptr, &(sample_context_ptr -> iothub_client),
                                                             context_ptr, context_length)) == ESP_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s on thermostat 2\r\n", method_name_length, method_name_ptr);
    }
    else if((status = sample_pnp_temp_controller_process_command(component_name_ptr, component_name_length,
                                                                 pnp_command_name_ptr, pnp_command_name_length,
                                                                 packet_ptr, &(sample_context_ptr -> iothub_client),
                                                                 context_ptr, context_length)) == ESP_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s  controller \r\n", method_name_length, method_name_ptr);
    }
    else
    {
        printf("Failed to find any handler for method %.*s\r\n", method_name_length, method_name_ptr);

        if ((status = esp_azure_iot_hub_client_direct_method_message_response(&(sample_context_ptr -> iothub_client),
                                                                             SAMPLE_COMMAND_NOT_FOUND_STATUS,
                                                                             context_ptr, context_length, NULL, 0,
                                                                             ESP_WAIT_FOREVER)))
        {
            printf("Direct method response failed!: error code = 0x%08x\r\n", status);
        }

    }

    esp_azure_iot_packet_release(packet_ptr);

}

static void sample_desired_property_callback(uint8_t *component_name_ptr, uint32_t component_name_len,
                                             uint8_t *property_name_ptr, uint32_t property_name_len,
                                             az_json_token *propertyValue, uint32_t version,
                                             void *userContextCallback)
{
    if (component_name_ptr == NULL || component_name_len == 0)
    {
        // The PnP protocol does not define a mechanism to report errors such as this to IoTHub, so
        // the best we can do here is to log for diagnostics purposes.
        printf("Property=%.*s arrived for Control component itself. This does not support writeable properties on it (all properties are on subcomponents)\r\n", property_name_len, property_name_ptr);
    }
    else if (sample_pnp_thermostat_process_property_update(&sample_thermostat_1,
                                                           (ESP_AZURE_IOT_HUB_CLIENT *)userContextCallback,
                                                           component_name_ptr, component_name_len,
                                                           property_name_ptr, property_name_len,
                                                           propertyValue, version) == ESP_AZURE_IOT_SUCCESS)
    {
        printf("property updated of thermostat 1\r\n");
    }
    else if (sample_pnp_thermostat_process_property_update(&sample_thermostat_2,
                                                           (ESP_AZURE_IOT_HUB_CLIENT *)userContextCallback,
                                                           component_name_ptr, component_name_len,
                                                           property_name_ptr, property_name_len,
                                                           propertyValue, version) == ESP_AZURE_IOT_SUCCESS)
    {
        printf("property updated of thermostat 2\r\n");
    }
    else
    {
        printf("Component=%.*s is not implemented by the Controller\r\n", component_name_len, component_name_ptr);
    }
}

static void sample_device_twin_desired_property_action(SAMPLE_CONTEXT *context)
{
ESP_PACKET *packet_ptr;
uint32_t status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = esp_azure_iot_hub_client_device_twin_desired_properties_receive(&(context -> iothub_client), &packet_ptr,
                                                                                 ESP_WAIT_FOREVER)))
    {
        printf("Receive desired property receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Receive desired property: ");
    printf_packet(packet_ptr);
    printf("\r\n");

    if ((status = esp_azure_iot_pnp_twin_data_parse(packet_ptr, true,
                                                          (char **)sample_components, sample_components_num,
                                                          scratch_buffer, sizeof(scratch_buffer),
                                                          sample_desired_property_callback,
                                                          (void *)&(context -> iothub_client))))
    {
        printf("Failed to parse twin data!: error code = 0x%08x\r\n", status);
    }

    esp_azure_iot_packet_release(packet_ptr);
}

static void sample_device_twin_reported_property_action(SAMPLE_CONTEXT *context)
{
uint32_t status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    /* Only report once */
    if (sample_device_serial_info_sent == 0)
    {
        if ((status = sample_pnp_temp_controller_report_serial_number_property(&(context -> iothub_client))))
        {
            printf("Failed sample_pnp_temp_controller_report_serial_number_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_device_serial_info_sent = 1;
        }
    }


    /* Only report once */
    if (sample_device_info_sent == 0)
    {
        if ((status = sample_pnp_deviceinfo_report_all_properties((uint8_t *)sample_device_info_component,
                                                                  sizeof(sample_device_info_component) - 1,
                                                                  &(context -> iothub_client))))
        {
            printf("Failed sample_pnp_deviceinfo_report_all_properties: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_device_info_sent = 1;
        }
    }

    /* Only report when changed */
    if (!(((sample_thermostat_1_last_device_max_temp_reported - 0.01) < sample_thermostat_1.maxTemperature) &&
          ((sample_thermostat_1_last_device_max_temp_reported + 0.01) > sample_thermostat_1.maxTemperature)))
    {
        if ((status = sample_pnp_thermostat_report_max_temp_since_last_reboot_property(&sample_thermostat_1,
                                                                                       &(context -> iothub_client))))
        {
            printf("Failed sample_pnp_thermostat_report_max_temp_since_last_reboot_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_thermostat_1_last_device_max_temp_reported = sample_thermostat_1.maxTemperature;
        }
    }

    /* Only report when changed */
    if (!(((sample_thermostat_2_last_device_max_tem_reported - 0.01) < sample_thermostat_2.maxTemperature) &&
          ((sample_thermostat_2_last_device_max_tem_reported + 0.01) > sample_thermostat_2.maxTemperature)))
    {
        if ((status = sample_pnp_thermostat_report_max_temp_since_last_reboot_property(&sample_thermostat_2,
                                                                                       &(context -> iothub_client))))
        {
            printf("Failed sample_pnp_thermostat_report_max_temp_since_last_reboot_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_thermostat_2_last_device_max_tem_reported = sample_thermostat_2.maxTemperature;
        }
    }
}

static void sample_device_twin_get_action(SAMPLE_CONTEXT *context)
{
ESP_PACKET *packet_ptr;
uint32_t status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = esp_azure_iot_hub_client_device_twin_properties_receive(&(context -> iothub_client), &packet_ptr,
                                                                     ESP_WAIT_FOREVER)))
    {
        printf("Twin receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Received twin properties: ");
    printf_packet(packet_ptr);
    printf("\r\n");

    if ((status = esp_azure_iot_pnp_twin_data_parse(packet_ptr, false,
                                                          (char **)sample_components, sample_components_num,
                                                          scratch_buffer, sizeof(scratch_buffer),
                                                          sample_desired_property_callback,
                                                          (void *)&(context -> iothub_client))))
    {
        printf("Failed to parse twin data!: error code = 0x%08x\r\n", status);
    }

    esp_azure_iot_packet_release(packet_ptr);
}

static void sample_telemetry_action(SAMPLE_CONTEXT *context)
{
uint32_t status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = sample_pnp_temp_controller_telemetry_send(&(context -> iothub_client))) != ESP_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp__telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_1,
                                                       &(context -> iothub_client))) != ESP_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp_thermostat_telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_2,
                                                       &(context -> iothub_client))) != ESP_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp_thermostat_telemetry_send, error: %d", status);
    }
}

/**
 *
 * Sample Event loop
 *
 *
 *       +--------------+           +--------------+      +--------------+       +--------------+
 *       |              |  INIT     |              |      |              |       |              |
 *       |              | SUCCESS   |              |      |              |       |              +--------+
 *       |    INIT      |           |    CONNECT   |      |  CONNECTING  |       |   CONNECTED  |        | (TELEMETRY |
 *       |              +----------->              +----->+              +------->              |        |  METHOD |
 *       |              |           |              |      |              |       |              <--------+  DEVICETWIN)
 *       |              |           |              |      |              |       |              |
 *       +-----+--------+           +----+---+-----+      +------+-------+       +--------+-----+
 *             ^                         ^   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   | CONNECT           | CONNECTING             |
 *             |                         |   |  FAIL             |   FAIL                 |
 * REINITIALIZE|                RECONNECT|   |                   |                        |
 *             |                         |   |                   v                        |  DISCONNECT
 *             |                         |   |        +----------+-+                      |
 *             |                         |   |        |            |                      |
 *             |                         |   +------->+            |                      |
 *             |                         |            | DISCONNECT |                      |
 *             |                         |            |            +<---------------------+
 *             |                         +------------+            |
 *             +--------------------------------------+            |
 *                                                    +------------+
 *
 *
 *
 */
static void sample_event_loop(SAMPLE_CONTEXT *context)
{
    while (1)
    {
        /* Pickup IP event flags.  */
        EventBits_t app_events = xEventGroupWaitBits(context -> sample_events, SAMPLE_ALL_EVENTS, true, false, 5 * ESP_IP_PERIODIC_RATE / portTICK_PERIOD_MS );
        if (!app_events)
        {
            if (context -> state == SAMPLE_STATE_CONNECTED)
            {
                sample_trigger_action(context);
            }

            continue;
        }
        
        if (app_events & SAMPLE_CONNECT_EVENT)
        {
            sample_connect_action(context);
        }

        if (app_events & SAMPLE_INITIALIZATION_EVENT)
        {
            sample_initialize_iothub(context);
        }

        if (app_events & SAMPLE_DEVICE_TWIN_GET_EVENT)
        {
            sample_device_twin_get_action(context);
        }

        if (app_events & SAMPLE_METHOD_MESSAGE_EVENT)
        {
            sample_direct_method_action(context);
        }

        if (app_events & SAMPLE_DEVICE_TWIN_DESIRED_PROPERTY_EVENT)
        {
            sample_device_twin_desired_property_action(context);
        }

        if (app_events & SAMPLE_TELEMETRY_SEND_EVENT)
        {
            sample_telemetry_action(context);
        }

        if (app_events & SAMPLE_DEVICE_TWIN_REPORTED_PROPERTY_EVENT)
        {
            sample_device_twin_reported_property_action(context);
        }

        if (app_events & SAMPLE_DISCONNECT_EVENT)
        {
            sample_disconnect_action(context);
        }

        if (app_events & SAMPLE_CONNECTED_EVENT)
        {
            sample_connected_action(context);
        }

        if (app_events & SAMPLE_RECONNECT_EVENT)
        {
            sample_connection_error_recover(context);
        }
        
        xEventGroupClearBits(context -> sample_events, app_events);

        sample_trigger_action(context);
    }
}

static void sample_context_init(SAMPLE_CONTEXT *context)
{
    memset(context, 0, sizeof(SAMPLE_CONTEXT));

    context->state = SAMPLE_STATE_INIT;
    context->sample_events = xEventGroupCreate();
    xEventGroupSetBits(context->sample_events, SAMPLE_INITIALIZATION_EVENT);
}

static uint32_t unix_time_get(size_t *unix_time)
{

    /* Using time() to get unix time.
       Note: User needs to implement own time function to get the real time on device, such as: SNTP.  */
    *unix_time = (size_t)time(NULL);

    return(ESP_OK);
}

static uint32_t sample_components_init()
{
    uint32_t status;

    if ((status = sample_pnp_thermostat_init(&sample_thermostat_1,
                                             (uint8_t *)sample_thermostat_1_component,
                                             sizeof(sample_thermostat_1_component) - 1,
                                             SAMPLE_DEFAULT_START_TEMP_CELSIUS)))
    {
        printf("Faild to initialize %s: error code = 0x%08x\r\n",
               sample_thermostat_1_component, status);
    }
    else if ((status = sample_pnp_thermostat_init(&sample_thermostat_2,
                                                  (uint8_t *)sample_thermostat_2_component,
                                                  sizeof(sample_thermostat_2_component) - 1,
                                                  SAMPLE_DEFAULT_START_TEMP_CELSIUS)))
    {
        printf("Faild to initialize %s: error code = 0x%08x\r\n",
               sample_thermostat_2_component, status);
    }

    sample_thermostat_1_last_device_max_temp_reported = 0;
    sample_thermostat_2_last_device_max_tem_reported = 0;
    sample_device_info_sent = 0;
    sample_device_serial_info_sent = 0;

    return(0);
}

void iothub_pnp_sample_run(void) 
{
    uint32_t                    status = 0;

    /* Init Azure IoT Time Handle */
    if (esp_azure_iot_time_init()) {
        (void)printf("Failed to initialize the platform.\r\n");
        return;
    }

    if ((sample_components_init()))
    {
        printf("Failed on initialize sample components!: error code = 0x%08x\r\n", status);
        return;
    }
    
    while (1) {
        sample_context_init(&sample_context);
        
        /* Create Azure IoT handler.  */
        if ((status = esp_azure_iot_create(&sample_context.esp_azure_iot, (uint8_t *)"Azure IoT", ESP_AZURE_IOT_STACK_SIZE,
                                            ESP_AZURE_IOT_THREAD_PRIORITY, unix_time_get)))
        {
            printf("Failed on esp_azure_iot_create!: error code = 0x%08x\r\n", status);
        } else {
            /* Handle event loop */
            sample_event_loop(&sample_context);
        }

        /* Destroy IoTHub Client.  */
        esp_azure_iot_delete(&sample_context.esp_azure_iot);
    }
}
