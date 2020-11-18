#
# Component Makefile
#

set (AZURE_IOT_SDK "${CMAKE_CURRENT_LIST_DIR}/../azure-sdk-for-c")

set (includes
    "inc"
    "${AZURE_IOT_SDK}/sdk/inc"
	"${AZURE_IOT_SDK}/sdk/src/azure/core"
	)

set (srcs
	"src/esp_azure_iot.c"
	"src/esp_azure_iot_hub_client.c"
	"src/esp_azure_iot_mqtt_client.c"
	"src/esp_azure_iot_provisioning_client.c"
	"src/esp_azure_iot_time.c"
    "azure-sdk-for-c/sdk/src/azure/core/az_span.c"
    "azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_sas.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_aad.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_context.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_credential_client_secret.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_credential_token.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_pipeline.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_policy.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_policy_logging.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_policy_retry.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_request.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_http_response.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_json_reader.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_json_writer.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_json_token.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_log.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_precondition.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/core/az_spinlock.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_common.c"
    "${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_hub_client.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_hub_client_c2d.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_hub_client_methods.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_hub_client_telemetry.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_hub_client_twin.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_provisioning_client.c"
	"${AZURE_IOT_SDK}/sdk/src/azure/iot/az_iot_provisioning_client_sas.c"
	)

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS ${includes}
                    REQUIRES esp_ringbuf mqtt)


