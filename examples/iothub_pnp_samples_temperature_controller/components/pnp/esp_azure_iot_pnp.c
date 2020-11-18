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

#include "esp_azure_iot_pnp.h"

#include <stdio.h>

#include "azure/core/az_json.h"

/* Telemetry message property used to indicate the message's component. */
static const char sample_pnp_telemetry_component_property[] = "$.sub";

/* Reported property response proptery keys */
static const az_span sample_pnp_component_type_property_name = AZ_SPAN_LITERAL_FROM_STR("__t");
static const az_span reported_component_type_value = AZ_SPAN_LITERAL_FROM_STR("c");
static const az_span reported_value_property_name = AZ_SPAN_LITERAL_FROM_STR("value");
static const az_span reported_status_property_name = AZ_SPAN_LITERAL_FROM_STR("ac");
static const az_span reported_version_property_name = AZ_SPAN_LITERAL_FROM_STR("av");
static const az_span reported_description_property_name = AZ_SPAN_LITERAL_FROM_STR("ad");

/* PnP command seperator */
static const az_span command_separator = AZ_SPAN_LITERAL_FROM_STR("*");

/* Device twin keys */
static const az_span sample_iot_hub_twin_desired_version = AZ_SPAN_LITERAL_FROM_STR("$version");
static const az_span sample_iot_hub_twin_desired = AZ_SPAN_LITERAL_FROM_STR("desired");

/* Move reader to the value of property name */
static uint32_t sample_json_child_token_move(az_json_reader *json_reader, az_span property_name)
{
    while (az_succeeded(az_json_reader_next_token(json_reader)))
    {
        if ((json_reader -> token.kind == AZ_JSON_TOKEN_PROPERTY_NAME) &&
            az_json_token_is_text_equal(&(json_reader -> token), property_name))
        {
           if (az_failed(az_json_reader_next_token(json_reader)))
           {
               printf("Failed to read next token\r\n");
               return(ESP_AZURE_IOT_PNP_FAIL);
           }

           return(ESP_AZURE_IOT_SUCCESS);
        }
        else if (json_reader -> token.kind == AZ_JSON_TOKEN_BEGIN_OBJECT)
        {
            if (az_failed(az_json_reader_skip_children(json_reader)))
            {
                printf("Failed to skip child of complex object\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }
        }
        else if (json_reader -> token.kind == AZ_JSON_TOKEN_END_OBJECT)
        {
            return(ESP_AZURE_IOT_NOT_FOUND);
        }
    }

    return(ESP_AZURE_IOT_NOT_FOUND);
}

/* Visit component property Object and call callback on each property of that component */
static uint32_t visit_component_properties(uint8_t *component_name_ptr, uint32_t component_name_len,
                                       az_json_reader *json_reader, uint32_t version, uint8_t *scratch_buf, uint32_t scratch_buf_len,
                                       void (*sample_desired_property_callback)(uint8_t *component_name_ptr,
                                             uint32_t component_name_len,
                                             uint8_t *property_name_ptr, uint32_t property_name_len,
                                             az_json_token *propertyValue, uint32_t version,
                                             void *userContextCallback), void *context_ptr)
{
uint32_t len;

    while (az_succeeded(az_json_reader_next_token(json_reader)))
    {
        if (json_reader -> token.kind == AZ_JSON_TOKEN_PROPERTY_NAME)
        {
            if (az_failed(az_json_token_get_string(&(json_reader -> token), (char *)scratch_buf, (int32_t)scratch_buf_len, (int32_t *)&len)))
            {
                printf("Failed to get string property value\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }

            if (az_failed(az_json_reader_next_token(json_reader)))
            {
                printf("Failed to get next token\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }

            if ((len == (uint32_t)az_span_size(sample_pnp_component_type_property_name))  &&
                (memcmp((void *)scratch_buf, (void *)az_span_ptr(sample_pnp_component_type_property_name), len) == 0))
            {
                continue;
            }

            if ((len == (uint32_t)az_span_size(sample_iot_hub_twin_desired_version)) &&
                (memcmp((void *)scratch_buf, (void *)az_span_ptr(sample_iot_hub_twin_desired_version), len) == 0))
            {
                continue;
            }

            sample_desired_property_callback(component_name_ptr, component_name_len,
                                             scratch_buf, len, &(json_reader -> token), version, context_ptr);

        }

        if (json_reader -> token.kind == AZ_JSON_TOKEN_BEGIN_OBJECT)
        {
            if (az_failed(az_json_reader_skip_children(json_reader)))
            {
                printf("Failed to skip children of object\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }
        }
        else if (json_reader -> token.kind == AZ_JSON_TOKEN_END_OBJECT)
        {
            break;
        }
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

/* Check if component is part of component list */
static uint32_t is_component_in_model(uint8_t *component_name_ptr, uint32_t component_name_len,
                                  char **sample_components_ptr, uint32_t sample_components_num,
                                  uint32_t *out_index)
{
uint32_t index = 0;

    if (component_name_ptr == NULL || component_name_len == 0)
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    while (index < sample_components_num)
    {
        if ((component_name_len == strlen(sample_components_ptr[index])) &&
            (memcmp((void *)component_name_ptr, (void *)sample_components_ptr[index], component_name_len) == 0))
        {
            *out_index = index;
            return(ESP_AZURE_IOT_SUCCESS);
        }

        index++;
    }

    return(ESP_AZURE_IOT_NOT_FOUND);
}

/* Parse PnP command names*/
uint32_t esp_azure_iot_pnp_command_name_parse(uint8_t *method_name_ptr, uint32_t method_name_length,
                                                uint8_t **component_name_pptr, uint32_t *component_name_length_ptr,
                                                uint8_t **pnp_command_name_pptr, uint32_t *pnp_command_name_length_ptr)
{
int32_t index;
az_span method_name = az_span_init(method_name_ptr, (int32_t)method_name_length);

    if ((index = az_span_find(method_name, command_separator)) != -1)
    {
        /* If a separator character is present in the device method name, then a command on a subcomponent of
           the model is being targeted (e.g. thermostat1*getMaxMinReport). */
        *component_name_pptr = method_name_ptr;
        *component_name_length_ptr = (uint32_t)index;
        *pnp_command_name_pptr = method_name_ptr + index + 1;
        *pnp_command_name_length_ptr = method_name_length - (uint32_t)index - 1;
    }
    else
    {
        /* The separator character is optional.  If it is not present, it indicates a command of the root
           component and not a subcomponent (e.g. "reboot"). */
        *component_name_pptr = NULL;
        *component_name_length_ptr = 0;
        *pnp_command_name_pptr = method_name_ptr;
        *pnp_command_name_length_ptr = method_name_length;
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

/* Parse twin data and call callback on each desired property */
uint32_t esp_azure_iot_pnp_twin_data_parse(ESP_PACKET *packet_ptr, uint32_t is_partial,
                                             char **sample_components_ptr, uint32_t sample_components_num,
                                             uint8_t *scratch_buf, uint32_t scratch_buf_len,
                                             void (*sample_desired_property_callback)(uint8_t *component_name_ptr,
                                                   uint32_t component_name_len, uint8_t *property_name_ptr,
                                                   uint32_t property_name_len,
                                                   az_json_token *propertyValue, uint32_t version,
                                                   void *userContextCallback),
                                             void *context_ptr)
{
az_json_reader json_reader;
az_json_reader copy_json_reader;
az_span payload;
uint32_t version;
uint32_t len;
uint32_t index;

    if (packet_ptr -> esp_packet_length >
        (size_t)(packet_ptr -> esp_packet_append_ptr - packet_ptr -> esp_packet_prepend_ptr))
    {
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    payload = az_span_init(packet_ptr -> esp_packet_prepend_ptr, (int32_t)(packet_ptr -> esp_packet_length));
    if (az_failed(az_json_reader_init(&json_reader, payload, NULL)) ||
        az_failed(az_json_reader_next_token(&json_reader)))
    {
        printf("Failed to intialize json reader\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (!is_partial && sample_json_child_token_move(&json_reader, sample_iot_hub_twin_desired))
    {
        printf("Failed to get desired property\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    copy_json_reader = json_reader;
    if (sample_json_child_token_move(&copy_json_reader, sample_iot_hub_twin_desired_version) ||
        az_failed(az_json_token_get_int32(&(copy_json_reader.token), (int32_t *)&version)))
    {
        printf("Failed to get version\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    while (az_succeeded(az_json_reader_next_token(&json_reader)))
    {
        if (json_reader.token.kind == AZ_JSON_TOKEN_PROPERTY_NAME)
        {
            if (az_failed(az_json_token_get_string(&(json_reader.token), (char *)scratch_buf,
                                                   (int32_t)scratch_buf_len, (int32_t *)&len)))
            {
                printf("Failed to string value for property name\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }

            if (az_failed(az_json_reader_next_token(&json_reader)))
            {
                printf("Failed to next token\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }

            if ((len == (uint32_t)az_span_size(sample_iot_hub_twin_desired_version)) &&
                (memcmp((void *)az_span_ptr(sample_iot_hub_twin_desired_version), (void *)scratch_buf,
                        (uint32_t)az_span_size(sample_iot_hub_twin_desired_version)) == 0))
            {
                continue;
            }

            if (json_reader.token.kind == AZ_JSON_TOKEN_BEGIN_OBJECT &&
                sample_components_ptr != NULL &&
                (is_component_in_model(scratch_buf, len,
                                       sample_components_ptr, sample_components_num,
                                       &index) == ESP_AZURE_IOT_SUCCESS))
            {
                if (visit_component_properties((uint8_t *)sample_components_ptr[index],
                                               strlen(sample_components_ptr[index]),
                                               &json_reader, version, scratch_buf, scratch_buf_len,
                                               sample_desired_property_callback, context_ptr))
                {
                    printf("Failed to visit component properties\r\n");
                    return(ESP_AZURE_IOT_PNP_FAIL);
                }
            }
            else
            {
                sample_desired_property_callback(NULL, 0, scratch_buf, len, &(json_reader.token), version, context_ptr);
            }
        }
        else if (json_reader.token.kind == AZ_JSON_TOKEN_BEGIN_OBJECT)
        {
            if (az_failed(az_json_reader_skip_children(&json_reader)))
            {
                printf("Failed to skip children of object\r\n");
                return(ESP_AZURE_IOT_PNP_FAIL);
            }
        }
        else if (json_reader.token.kind == AZ_JSON_TOKEN_END_OBJECT)
        {
            break;
        }
    }

    return(ESP_AZURE_IOT_SUCCESS);
}

/* Create PnP telemetry message */
uint32_t esp_azure_iot_pnp_telemetry_message_create(ESP_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                      uint8_t *component_name, uint32_t component_name_len,
                                                      ESP_PACKET **packet_pptr, uint32_t wait_option)
{
uint32_t status;

    /* Create a telemetry message packet. */
    if ((status = esp_azure_iot_hub_client_telemetry_message_create(iothub_client_ptr, packet_pptr, wait_option)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
    }
    /* If the component will be used, then specify this as a property of the message. */
    else if ((component_name != NULL) &&
             (status = esp_azure_iot_hub_client_telemetry_property_add(*packet_pptr,
                                                                      (uint8_t *)sample_pnp_telemetry_component_property,
                                                                      (uint16_t)sizeof(sample_pnp_telemetry_component_property) - 1,
                                                                      component_name, (uint16_t)component_name_len,
                                                                      ESP_WAIT_FOREVER)) != ESP_AZURE_IOT_SUCCESS)
    {
        printf("esp_azure_iot_hub_client_telemetry_property_add=%s failed, error=%d",
                sample_pnp_telemetry_component_property, status);
        esp_azure_iot_hub_client_telemetry_message_delete(*packet_pptr);
    }
    else
    {
        status = ESP_AZURE_IOT_SUCCESS;
    }

    return(status);
}

/* Build PnP reported property into user provided buffer */
uint32_t esp_azure_iot_pnp_build_reported_property(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                     uint32_t (*append_reported_property)(az_json_writer *json_builder,
                                                                                      void *context),
                                                     void *context, uint8_t *buffer_ptr, uint32_t buffer_len,
                                                     uint32_t *data_copied_length_ptr )
{
uint32_t status;
az_span buff_span = az_span_init(buffer_ptr, (int32_t)buffer_len);
az_json_writer json_builder;
az_span component_name = az_span_init(component_name_ptr, (int32_t)component_name_len);

    if (az_succeeded(az_json_writer_init(&json_builder, buff_span, NULL)) &&
        az_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
        (component_name_ptr == NULL ||
         (az_succeeded(az_json_writer_append_property_name(&json_builder, component_name)) &&
          az_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, sample_pnp_component_type_property_name)) &&
          az_succeeded(az_json_writer_append_string(&json_builder, reported_component_type_value)))) &&
        (append_reported_property(&json_builder, context) == ESP_AZURE_IOT_SUCCESS) &&
        (component_name_ptr == NULL || az_succeeded(az_json_writer_append_end_object(&json_builder))) &&
        az_succeeded(az_json_writer_append_end_object(&json_builder)))
    {
        *data_copied_length_ptr  = (uint32_t)az_span_size(az_json_writer_get_json(&json_builder));
        status = ESP_AZURE_IOT_SUCCESS;
    }
    else
    {
        printf("Failed to build reported property\r\n");
        status = ESP_AZURE_IOT_PNP_FAIL;
    }

    return(status);
}

/* Build reported property with status */
uint32_t esp_azure_iot_pnp_build_reported_property_with_status(uint8_t *component_name_ptr, uint32_t component_name_len,
                                                                 uint8_t *property_name_ptr, uint32_t property_name_len,
                                                                 uint32_t (*append_value)(az_json_writer *builder,
                                                                                      void *context),
                                                                 void *context,
                                                                 int32_t result, uint8_t *description_ptr,
                                                                 uint32_t description_len,
                                                                 uint32_t ack_version, uint8_t *buffer_ptr,
                                                                 uint32_t buffer_len,
                                                                 uint32_t *byte_copied)
{
az_span buff_span = az_span_init(buffer_ptr, (int32_t)buffer_len);
az_json_writer json_builder;
az_span component_name = az_span_init(component_name_ptr, (int32_t)component_name_len);
az_span reported_property_name = az_span_init(property_name_ptr, (int32_t)property_name_len);
az_span description = az_span_init(description_ptr, (int32_t)description_len);

    if (az_failed(az_json_writer_init(&json_builder, buff_span, NULL)) ||
        az_failed(az_json_writer_append_begin_object(&json_builder)))
    {
        printf("Failed intialize json writer \r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (component_name_ptr != NULL &&
        !(az_succeeded(az_json_writer_append_property_name(&json_builder, component_name)) &&
          az_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, sample_pnp_component_type_property_name)) &&
          az_succeeded(az_json_writer_append_string(&json_builder, reported_component_type_value))))
    {
        printf("Failed build reported property with status message \r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (!(az_succeeded(az_json_writer_append_property_name(&json_builder, reported_property_name)) &&
          az_succeeded(az_json_writer_append_begin_object(&json_builder)) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, reported_value_property_name)) &&
          (append_value(&json_builder, context) == ESP_AZURE_IOT_SUCCESS) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, reported_status_property_name)) &&
          az_succeeded(az_json_writer_append_int32(&json_builder, result)) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, reported_description_property_name)) &&
          az_succeeded(az_json_writer_append_string(&json_builder, description)) &&
          az_succeeded(az_json_writer_append_property_name(&json_builder, reported_version_property_name)) &&
          az_succeeded(az_json_writer_append_int32(&json_builder, (int32_t)ack_version)) &&
          az_succeeded(az_json_writer_append_end_object(&json_builder)) &&
          az_succeeded(az_json_writer_append_end_object(&json_builder))))
    {
        printf("Failed build reported property with status message\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    if (component_name_ptr  != NULL &&
        az_failed(az_json_writer_append_end_object(&json_builder)))
    {
        printf("Failed build reported property with status message\r\n");
        return(ESP_AZURE_IOT_PNP_FAIL);
    }

    *byte_copied = (uint32_t)az_span_size(az_json_writer_get_json(&json_builder));

    return(ESP_AZURE_IOT_SUCCESS);
}
