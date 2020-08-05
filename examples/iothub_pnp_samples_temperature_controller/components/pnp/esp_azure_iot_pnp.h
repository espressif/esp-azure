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

#ifndef ESP_AZURE_IOT_PNP_H
#define ESP_AZURE_IOT_PNP_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/core/az_json.h"
#include "esp_azure_iot_hub_client.h"

#define ESP_AZURE_IOT_PNP_FAIL 0x43

/**
 * @brief Parse PnP command name
 *
 * @param[in] method_name_ptr Pointer to method name
 * @param[in] method_name_length Length of method name
 * @param[out] component_name_pptr Pointer to component pointer
 * @param[out] component_name_length_ptr Pointer to length of component name length
 * @param[out] pnp_command_name_pptr Pointer to command name pointer
 * @param[out] pnp_command_name_length_ptr Pointer to length of command name
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if successful parsed command name.
 */
uint32_t esp_azure_iot_pnp_command_name_parse(uint8_t *method_name_ptr, uint32_t method_name_length,
                                                uint8_t **component_name_pptr, uint32_t *component_name_length_ptr,
                                                uint8_t **pnp_command_name_pptr, uint32_t *pnp_command_name_length_ptr);

/**
 * @brief Parse twin data and call callback on each desired property
 *
 * @param[in] packet_ptr `ESP_PACKET` pointer containing the twin data
 * @param[in] is_partial 1 if twin data is patch else 0 if full twin document
 * @param[in] sample_components_ptr Pointer to list of all components name pointers
 * @param[in] sample_components_num Size of component list
 * @param[in] scratch_buf Temporary buffer used for staging property names out of the JSON document
 * @param[in] scratch_buf_len Temporary buffer length size
 * @param[in] sample_desired_property_callback Callback called with each desired property
 * @param[in] context_ptr Context passed to the callback
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if successful parsed twin data.
 */
uint32_t esp_azure_iot_pnp_twin_data_parse(ESP_PACKET *packet_ptr, uint32_t is_partial,
                                             char **sample_components_ptr, uint32_t sample_components_num,
                                             uint8_t *scratch_buf, uint32_t scratch_buf_len,
                                             void (*sample_desired_property_callback)(uint8_t *component_name_ptr,
                                                   uint32_t component_name_len, uint8_t *property_name_ptr,
                                                   uint32_t property_name_len,
                                                   az_json_token *propertyValue, uint32_t version,
                                                   void *userContextCallback),
                                             void *context_ptr);

/**
 * @brief Create PnP telemetry message
 *
 * @param[in] iothub_client_ptr Pointer to `ESP_AZURE_IOT_HUB_CLIENT`
 * @param[in] component_name Pointer to component name
 * @param[in] component_name_len Length of component name
 * @param[out] packet_pptr `ESP_PACKET` return via the API.
 * @param[in] wait_option Ticks to wait if no packet is available.
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if successful created ESP_PACKET.
 */
uint32_t esp_azure_iot_pnp_telemetry_message_create(ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                      uint8_t *component_name, uint32_t component_name_len,
                                                      ESP_PACKET **packet_pptr, uint32_t wait_option);

/**
 * @brief Build PnP reported property into user provided buffer
 *
 * @param[in] component_name_ptr Pointer to component name
 * @param[in] component_name_len Length of component name
 * @param[in] buffer_ptr Pointer to buffer used for storing message
 * @param[in] buffer_len Size of buffer
 * @param[out] data_copied_ptr Number of bytes copied into buffer
 * @param[in] append_reported_property Callback to add reported property
 * @param[in] context Context pass to callback
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if successful created reported property message.
 */
uint32_t esp_azure_iot_pnp_build_reported_property(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                     uint32_t (*append_reported_property)(az_json_writer *json_builder,
                                                                                      void *context),
                                                     void *context, uint8_t *buffer_ptr, uint32_t buffer_len,
                                                     uint32_t *data_copied_ptr);

/**
 * @brief Build reported property with status
 *
 * @param[in] component_name_ptr Pointer to component name
 * @param[in] component_name_len Length of component name
 * @param[in] property_name_ptr Pointer to property name
 * @param[in] property_name_len Length of property name
 * @param[in] append_value Callback to add property value
 * @param[in] context Context pass to callback
 * @param[in] result Status for reported property
 * @param[in] description Pointer to description
 * @param[in] description_len Length of description
 * @param[in] ack_version ack version
 * @param[in] buffer_ptr Pointer to buffer to where message is stored.
 * @param[in] buffer_len Length of buffer
 * @param[out] byte_copied Number of bytes copied to buffer
 * @return A `uint32_t` with the result of the API.
 *   @retval #ESP_AZURE_IOT_SUCCESS Successful if successful created reported property message.
 */
uint32_t esp_azure_iot_pnp_build_reported_property_with_status(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                                 uint8_t *property_name_ptr, uint32_t property_name_len,
                                                                 uint32_t (*append_value)(az_json_writer *builder,
                                                                                      void *context),
                                                                 void *context,
                                                                 int32_t result, uint8_t *description_ptr,
                                                                 uint32_t description_len,
                                                                 uint32_t ack_version, uint8_t *buffer_ptr,
                                                                 uint32_t buffer_len,
                                                                 uint32_t *byte_copied);

#ifdef __cplusplus
}
#endif
#endif /* ESP_AZURE_IOT_PNP_H */