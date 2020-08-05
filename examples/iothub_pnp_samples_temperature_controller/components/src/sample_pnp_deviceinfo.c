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

#include "sample_pnp_deviceinfo.h"

#include "esp_azure_iot_pnp.h"

#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)

/* Reported property keys and values */
static const az_span sample_pnp_device_info_software_version_property_name = AZ_SPAN_LITERAL_FROM_STR("swVersion");
static const az_span sample_pnp_device_info_software_version_property_value = AZ_SPAN_LITERAL_FROM_STR("1.0.0.0");
static const az_span sample_pnp_device_info_manufacturer_property_name = AZ_SPAN_LITERAL_FROM_STR("manufacturer");
static const az_span sample_pnp_device_info_manufacturer_property_value = AZ_SPAN_LITERAL_FROM_STR("Sample-Manufacturer");
static const az_span sample_pnp_device_info_model_property_name = AZ_SPAN_LITERAL_FROM_STR("model");
static const az_span sample_pnp_device_info_model_property_value = AZ_SPAN_LITERAL_FROM_STR("pnp-sample-Model-123");
static const az_span sample_pnp_device_info_os_name_property_name = AZ_SPAN_LITERAL_FROM_STR("osName");
static const az_span sample_pnp_device_info_os_name_property_value = AZ_SPAN_LITERAL_FROM_STR("AzureRTOS");
static const az_span sample_pnp_device_info_processor_architecture_property_name = AZ_SPAN_LITERAL_FROM_STR("processorArchitecture");
static const az_span sample_pnp_device_info_processor_architecture_property_value = AZ_SPAN_LITERAL_FROM_STR("Contoso-Arch-64bit");
static const az_span sample_pnp_device_info_processor_manufacturer_property_name = AZ_SPAN_LITERAL_FROM_STR("processorManufacturer");
static const az_span sample_pnp_device_info_processor_manufacturer_property_value = AZ_SPAN_LITERAL_FROM_STR("Processor Manufacturer(TM)");
static const az_span sample_pnp_device_info_total_storage_property_name = AZ_SPAN_LITERAL_FROM_STR("totalStorage");
static const double sample_pnp_device_info_total_storage_property_value = 1024.0;
static const az_span sample_pnp_device_info_total_memory_property_name = AZ_SPAN_LITERAL_FROM_STR("totalMemory");
static const double sample_pnp_device_info_total_memory_property_value = 128;

static uint8_t scratch_buffer[512];

static uint32_t append_properties(az_json_writer *json_writer, void *context)
{
uint32_t status;

    ESP_PARAMETER_NOT_USED(context);

    if (az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_manufacturer_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_manufacturer_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_model_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_model_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_software_version_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_software_version_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_os_name_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_os_name_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_processor_architecture_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_processor_architecture_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_processor_manufacturer_property_name)) &&
        az_succeeded(az_json_writer_append_string(json_writer, sample_pnp_device_info_processor_manufacturer_property_value)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_total_storage_property_name)) &&
        az_succeeded(az_json_writer_append_double(json_writer, sample_pnp_device_info_total_storage_property_value, DOUBLE_DECIMAL_PLACE_DIGITS)) &&
        az_succeeded(az_json_writer_append_property_name(json_writer, sample_pnp_device_info_total_memory_property_name)) &&
        az_succeeded(az_json_writer_append_double(json_writer, sample_pnp_device_info_total_memory_property_value, DOUBLE_DECIMAL_PLACE_DIGITS)))
    {
        status = ESP_AZURE_IOT_SUCCESS;
    }
    else
    {
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

uint32_t sample_pnp_deviceinfo_report_all_properties(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                 ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
uint32_t reported_properties_length;
uint32_t status;
uint32_t response_status;
uint32_t request_id;

    if ((status = esp_azure_iot_pnp_build_reported_property(component_name_ptr, component_name_len,
                                                                  append_properties, NULL,
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
