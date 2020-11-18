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

#ifndef SAMPLE_PNP_THERMOSTAT_H
#define SAMPLE_PNP_THERMOSTAT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/core/az_json.h"
#include "esp_azure_iot_hub_client.h"

typedef struct SAMPLE_PNP_THERMOSTAT_COMPONENT_TAG
{
    /* Name of this component */
    uint8_t *component_name_ptr;

    uint32_t component_name_length;

    /* Current temperature of this thermostat component */
    double currentTemperature;

    /* Minimum temperature this thermostat has been at during current execution run of this thermostat component */
    double minTemperature;

    /* Maximum temperature thermostat has been at during current execution run of this thermostat component */
    double maxTemperature;

    /* Number of times temperature has been updated, counting the initial setting as 1.  Used to determine average temperature of this thermostat component */
    uint32_t numTemperatureUpdates;

    /* Total of all temperature updates during current exceution run.  Used to determine average temperature of this thermostat component */
    double allTemperatures;

    double avgTemperature;
} SAMPLE_PNP_THERMOSTAT_COMPONENT;

uint32_t sample_pnp_thermostat_init(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                uint8_t *component_name_ptr, uint32_t component_name_length,
                                double default_temp);

uint32_t sample_pnp_thermostat_process_command(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                           uint8_t *component_name_ptr, uint32_t component_name_length,
                                           uint8_t *pnp_command_name_ptr, uint32_t pnp_command_name_length,
                                           ESP_PACKET *packet_ptr, ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                           void *context_ptr, uint16_t context_length);

uint32_t sample_pnp_thermostat_telemetry_send(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle, ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr);

uint32_t sample_pnp_thermostat_report_max_temp_since_last_reboot_property(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                                      ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr);


uint32_t sample_pnp_thermostat_process_property_update(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                   ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                   uint8_t *component_name_ptr, uint32_t component_name_length,
                                                   uint8_t *property_name_ptr, uint32_t property_name_length,
                                                   az_json_token *property_token, uint32_t version);

#ifdef __cplusplus
}
#endif
#endif /* SAMPLE_PNP_THERMOSTAT_H */
