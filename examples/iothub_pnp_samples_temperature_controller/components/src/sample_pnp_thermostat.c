/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include "sample_pnp_thermostat.h"

#include "esp_azure_iot_pnp.h"

#define SAMPLE_DEAFULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)
#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)

/* Telemetry key */
static const az_span telemetry_name = AZ_SPAN_LITERAL_FROM_STR("temperature");

/* Pnp command supported */
static const char get_max_min_report[] = "getMaxMinReport";

/* Names of properties for desired/reporting */
static const az_span reported_max_temp_since_last_reboot = AZ_SPAN_LITERAL_FROM_STR("maxTempSinceLastReboot");
static const az_span report_max_temp_name_span = AZ_SPAN_LITERAL_FROM_STR("maxTemp");
static const az_span report_min_temp_name_span = AZ_SPAN_LITERAL_FROM_STR("minTemp");
static const az_span report_avg_temp_name_span = AZ_SPAN_LITERAL_FROM_STR("avgTemp");
static const az_span report_start_time_name_span = AZ_SPAN_LITERAL_FROM_STR("startTime");
static const az_span report_end_time_name_span = AZ_SPAN_LITERAL_FROM_STR("endTime");
static const char target_temp_property_name[] = "targetTemperature";
static const char temp_response_description_success[] = "success";
static const char temp_response_description_failed[] = "failed";

/* Fake device data */
static const az_span fake_start_report_time = AZ_SPAN_LITERAL_FROM_STR("2020-01-10T10:00:00:000Z");
static const az_span fake_end_report_time = AZ_SPAN_LITERAL_FROM_STR("2023-01-10T10:00:00:000Z");

static uint8_t scratch_buffer[256];

/* sample direct method implementation */
static uint32_t sample_get_maxmin_report(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                     ESP_PACKET *packet_ptr, uint8_t *buffer,
                                     uint32_t buffer_size, uint32_t *bytes_copied)
{
uint32_t status;
az_json_writer json_writer;
az_json_reader jp;
az_span response = az_span_init(buffer, (int32_t)buffer_size);
az_span start_time_span = fake_start_report_time;
az_span payload_span = az_span_init(packet_ptr -> esp_packet_prepend_ptr,
                                    (int32_t)(packet_ptr -> esp_packet_append_ptr -
                                          packet_ptr -> esp_packet_prepend_ptr));
int32_t time_len;
uint8_t time_buf[32];

    if (az_span_size(payload_span) != 0)
    {
        if (!(az_succeeded(az_json_reader_init(&jp, payload_span, NULL)) &&
              az_succeeded(az_json_reader_next_token(&jp)) &&
              az_succeeded(az_json_token_get_string(&jp.token, (char *)time_buf, sizeof(time_buf), (int32_t *)&time_len))))
        {
             return(ESP_AZURE_IOT_PNP_FAIL);
        }

        start_time_span = az_span_init(time_buf, time_len);
    }

    /* Build the method response payload */
    if (az_succeeded(az_json_writer_init(&json_writer, response, NULL)) &&
        az_succeeded(az_json_writer_append_begin_object(&json_writer)) &&
        az_succeeded(az_json_writer_append_property_name(&json_writer, report_max_temp_name_span)) &&
        az_succeeded(az_json_writer_append_double(&json_writer, handle -> maxTemperature, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
        az_succeeded(az_json_writer_append_property_name(&json_writer, report_min_temp_name_span)) &&
        az_succeeded(az_json_writer_append_double(&json_writer, handle -> minTemperature, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
        az_succeeded(az_json_writer_append_property_name(&json_writer, report_avg_temp_name_span)) &&
        az_succeeded(az_json_writer_append_double(&json_writer, handle -> avgTemperature, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
        az_succeeded(az_json_writer_append_property_name(&json_writer, report_start_time_name_span)) &&
        az_succeeded(az_json_writer_append_string(&json_writer, start_time_span)) &&
        az_succeeded(az_json_writer_append_property_name(&json_writer, report_end_time_name_span)) &&
        az_succeeded(az_json_writer_append_string(&json_writer, fake_end_report_time)) &&
        az_succeeded(az_json_writer_append_end_object(&json_writer)))
    {
        status = ESP_AZURE_IOT_SUCCESS;
        *bytes_copied = (uint32_t)az_span_size(az_json_writer_get_json(&json_writer));
    }
    else
    {
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

static uint32_t append_temp(az_json_writer *json_writer, void *context)
{
double temp = *(double *)context;
uint32_t status;

    if (az_succeeded(az_json_writer_append_double(json_writer, temp, DOUBLE_DECIMAL_PLACE_DIGITS)))
    {
        status = ESP_AZURE_IOT_SUCCESS;
    }
    else
    {
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

static uint32_t append_max_temp(az_json_writer *json_writer, void *context)
{
SAMPLE_PNP_THERMOSTAT_COMPONENT *handle = (SAMPLE_PNP_THERMOSTAT_COMPONENT *)context;
uint32_t status;

    if (az_succeeded(az_json_writer_append_property_name(json_writer, reported_max_temp_since_last_reboot)) &&
        az_succeeded(az_json_writer_append_double(json_writer, (int32_t)handle -> maxTemperature, DOUBLE_DECIMAL_PLACE_DIGITS)))
    {
        status = ESP_AZURE_IOT_SUCCESS;
    }
    else
    {
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

static void sample_send_target_temperature_report(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                  ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, double temp,
                                                  int32_t status_code, uint32_t version, const char *description)
{
uint32_t bytes_copied;
uint32_t response_status;
uint32_t request_id;

    if (esp_azure_iot_pnp_build_reported_property_with_status(handle -> component_name_ptr, handle -> component_name_length,
                                                                    (uint8_t *)target_temp_property_name,
                                                                    sizeof(target_temp_property_name) - 1,
                                                                    append_temp, (void *)&temp, status_code,
                                                                    (uint8_t *)description,
                                                                    strlen(description), version, scratch_buffer,
                                                                    sizeof(scratch_buffer),
                                                                    &bytes_copied))
    {
        printf("Failed to create reported response\r\n");
    }
    else
    {
        if (esp_azure_iot_hub_client_device_twin_reported_properties_send(iothub_client_ptr,
                                                                         scratch_buffer, bytes_copied,
                                                                         &request_id, &response_status,
                                                                         (5 * ESP_IP_PERIODIC_RATE)))
        {
            printf("Failed to send reported response\r\n");
        }
    }
}

uint32_t sample_pnp_thermostat_init(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                uint8_t *component_name_ptr, uint32_t component_name_length,
                                double default_temp)
{
    if (handle == NULL)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    handle -> component_name_ptr = component_name_ptr;
    handle -> component_name_length = component_name_length;
    handle -> currentTemperature = default_temp;
    handle -> minTemperature = default_temp;
    handle -> maxTemperature = default_temp;
    handle -> allTemperatures = default_temp;
    handle -> numTemperatureUpdates = 1;
    handle -> avgTemperature = default_temp;

    return(ESP_AZURE_IOT_SUCCESS);
}

uint32_t sample_pnp_thermostat_process_command(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                           uint8_t *component_name_ptr, uint32_t component_name_length,
                                           uint8_t *pnp_command_name_ptr, uint32_t pnp_command_name_length,
                                           ESP_PACKET *packet_ptr, ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                           void *context_ptr, uint16_t context_length)
{
uint32_t status;
uint32_t response_payload_len = 0;
uint32_t dm_status;

    if (handle == NULL)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (handle -> component_name_length != component_name_length ||
        strncmp((char *)handle -> component_name_ptr, (char *)component_name_ptr, component_name_length) != 0)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (pnp_command_name_length != (sizeof(get_max_min_report) - 1) ||
        strncmp((char *)pnp_command_name_ptr, (char *)get_max_min_report, pnp_command_name_length) != 0)
    {
        printf("PnP command=%.*s is not supported on thermostat component\r\n", pnp_command_name_length, pnp_command_name_ptr);
        dm_status = 404;
    }
    else
    {
        dm_status = (sample_get_maxmin_report(handle, packet_ptr, scratch_buffer, sizeof(scratch_buffer),
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

uint32_t sample_pnp_thermostat_telemetry_send(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle, ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
uint32_t status;
ESP_PACKET *packet_ptr;
az_json_writer json_writer;
uint32_t buffer_length;

    if (handle == NULL)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    /* Create a telemetry message packet. */
    if ((status = esp_azure_iot_pnp_telemetry_message_create(iothub_client_ptr, handle -> component_name_ptr,
                                                                   handle -> component_name_length,
                                                                   &packet_ptr, ESP_WAIT_FOREVER)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Build telemetry JSON payload */
    if(!(az_succeeded(az_json_writer_init(&json_writer, AZ_SPAN_FROM_BUFFER(scratch_buffer), NULL)) &&
         az_succeeded(az_json_writer_append_begin_object(&json_writer)) &&
         az_succeeded(az_json_writer_append_property_name(&json_writer, telemetry_name)) &&
         az_succeeded(az_json_writer_append_double(&json_writer, handle -> currentTemperature, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
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

    printf("Thermostat %.*s Telemetry message send: %.*s.\r\n", handle -> component_name_length,
           handle -> component_name_ptr, buffer_length, scratch_buffer);

    return(status);
}

uint32_t sample_pnp_thermostat_report_max_temp_since_last_reboot_property(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                                      ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
uint32_t reported_properties_length;
uint32_t status;
uint32_t response_status;
uint32_t request_id;

    if ((status = esp_azure_iot_pnp_build_reported_property(handle -> component_name_ptr,
                                                                  handle -> component_name_length,
                                                                  append_max_temp, (void *)handle,
                                                                  (uint8_t *)scratch_buffer,
                                                                  sizeof(scratch_buffer),
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

uint32_t sample_pnp_thermostat_process_property_update(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                   ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                   uint8_t *component_name_ptr, uint32_t component_name_length,
                                                   uint8_t *property_name_ptr, uint32_t property_name_length,
                                                   az_json_token *property_token, uint32_t version)
{
double parsed_value = 0;
int32_t status_code;
const char *description;

    if (handle == NULL)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (handle -> component_name_length != component_name_length ||
        strncmp((char *)handle -> component_name_ptr, (char *)component_name_ptr, component_name_length) != 0)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (property_name_length != (sizeof(target_temp_property_name) - 1) ||
        strncmp((char *)property_name_ptr, (char *)target_temp_property_name, property_name_length) != 0)
    {
        printf("PnP property=%.*s is not supported on thermostat component\r\n", property_name_length, property_name_ptr);
        status_code = 404;
        description = temp_response_description_failed;
    }
    else if (az_failed(az_json_token_get_double(property_token, &parsed_value)))
    {
        status_code = 401;
        description = temp_response_description_failed;
    }
    else
    {
        status_code = 200;
        description = temp_response_description_success;

        handle -> currentTemperature = parsed_value;
        if (handle -> currentTemperature > handle -> maxTemperature)
        {
            handle -> maxTemperature = handle -> currentTemperature;
        }

        if (handle -> currentTemperature < handle -> minTemperature)
        {
            handle -> minTemperature = handle -> currentTemperature;
        }

        /* Increment the avg count, add the new temp to the total, and calculate the new avg */
        handle -> numTemperatureUpdates++;
        handle -> allTemperatures += handle -> currentTemperature;
        handle -> avgTemperature = handle -> allTemperatures / handle -> numTemperatureUpdates;
    }

    sample_send_target_temperature_report(handle, iothub_client_ptr, parsed_value,
                                          status_code, version, description);

    return(ESP_AZURE_IOT_SUCCESS);
}
