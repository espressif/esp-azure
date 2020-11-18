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

#ifndef SAMPLE_PNP_DEVICEINFO_H
#define SAMPLE_PNP_DEVICEINFO_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "esp_azure_iot_hub_client.h"

uint32_t sample_pnp_deviceinfo_report_all_properties(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                 ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr);

#ifdef __cplusplus
}
#endif
#endif /* SAMPLE_PNP_DEVICEINFO_H */
