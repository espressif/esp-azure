#
# Component Makefile
#

set (AZURE_IOT_SDK "${CMAKE_CURRENT_LIST_DIR}/../azure-iot-sdk-c")

set (COMPONENT_ADD_INCLUDEDIRS
    "inc"
    "${AZURE_IOT_SDK}/certs"
	"${AZURE_IOT_SDK}/c-utility/inc"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos"
	"${AZURE_IOT_SDK}/c-utility/pal/generic"
    "${AZURE_IOT_SDK}/c-utility/deps/azure-macro-utils-c/inc"
    "${AZURE_IOT_SDK}/c-utility/deps/azure-macro-utils-c/inc/azure_macro_utils"
    "${AZURE_IOT_SDK}/c-utility/deps/umock-c/inc"
	"${AZURE_IOT_SDK}/iothub_client/inc"
	"${AZURE_IOT_SDK}/serializer/inc"
	"${AZURE_IOT_SDK}/umqtt/inc"
	"${AZURE_IOT_SDK}/umqtt/inc/azure_umqtt_c"
	"${AZURE_IOT_SDK}/deps/parson"
	"${AZURE_IOT_SDK}/provisioning_client/inc"
	"${AZURE_IOT_SDK}/provisioning_client/adapters"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/inc"
	)

set (COMPONENT_SRCS
	"src/agenttime_esp.c"
	"src/platform_esp.c"
	"src/tlsio_esp_tls.c"
    "src/threadapi.c"
	"${AZURE_IOT_SDK}/certs/certs.c"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos/lock.c"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos/tickcounter.c"
	"${AZURE_IOT_SDK}/c-utility/pal/tlsio_options.c"
	"${AZURE_IOT_SDK}/c-utility/src/xlogging.c"
	"${AZURE_IOT_SDK}/c-utility/src/singlylinkedlist.c"
	"${AZURE_IOT_SDK}/c-utility/src/buffer.c"
	"${AZURE_IOT_SDK}/c-utility/src/consolelogger.c"
	"${AZURE_IOT_SDK}/c-utility/src/constbuffer.c"
	"${AZURE_IOT_SDK}/c-utility/src/constmap.c"
	"${AZURE_IOT_SDK}/c-utility/src/crt_abstractions.c"
	"${AZURE_IOT_SDK}/c-utility/src/doublylinkedlist.c"
	"${AZURE_IOT_SDK}/c-utility/src/gballoc.c"
	"${AZURE_IOT_SDK}/c-utility/src/gb_stdio.c"
	"${AZURE_IOT_SDK}/c-utility/src/gb_time.c"
	"${AZURE_IOT_SDK}/c-utility/src/hmac.c"
	"${AZURE_IOT_SDK}/c-utility/src/hmacsha256.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpapiex.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpapiexsas.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpheaders.c"
	"${AZURE_IOT_SDK}/c-utility/src/map.c"
	"${AZURE_IOT_SDK}/c-utility/src/optionhandler.c"
	"${AZURE_IOT_SDK}/c-utility/src/sastoken.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha1.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha224.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha384-512.c"
	"${AZURE_IOT_SDK}/c-utility/src/strings.c"
	"${AZURE_IOT_SDK}/c-utility/src/string_tokenizer.c"
	"${AZURE_IOT_SDK}/c-utility/src/urlencode.c"
	"${AZURE_IOT_SDK}/c-utility/src/usha.c"
	"${AZURE_IOT_SDK}/c-utility/src/vector.c"
	"${AZURE_IOT_SDK}/c-utility/src/xio.c"
	"${AZURE_IOT_SDK}/c-utility/src/azure_base64.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_device_client_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_core_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_ll_uploadtoblob.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_authorization.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_retry_control.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_diagnostic.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_message.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportmqtt.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_mqtt_common.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_transport_ll_private.c"
	"${AZURE_IOT_SDK}/iothub_client/src/version.c"
    "${AZURE_IOT_SDK}/iothub_client/src/iothub_client_core.c"
    "${AZURE_IOT_SDK}/iothub_client/src/iothub_device_client.c"
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_client.c"
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_codec.c"
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_message.c"
	"${AZURE_IOT_SDK}/deps/parson/parson.c"
	"${AZURE_IOT_SDK}/serializer/src/codefirst.c"
	"${AZURE_IOT_SDK}/serializer/src/agenttypesystem.c"
	"${AZURE_IOT_SDK}/serializer/src/commanddecoder.c"
	"${AZURE_IOT_SDK}/serializer/src/datamarshaller.c"
	"${AZURE_IOT_SDK}/serializer/src/datapublisher.c"
	"${AZURE_IOT_SDK}/serializer/src/dataserializer.c"
	"${AZURE_IOT_SDK}/serializer/src/iotdevice.c"
	"${AZURE_IOT_SDK}/serializer/src/jsondecoder.c"
	"${AZURE_IOT_SDK}/serializer/src/jsonencoder.c"
	"${AZURE_IOT_SDK}/serializer/src/methodreturn.c"
	"${AZURE_IOT_SDK}/serializer/src/multitree.c"
	"${AZURE_IOT_SDK}/serializer/src/schema.c"
	"${AZURE_IOT_SDK}/serializer/src/schemalib.c"
	"${AZURE_IOT_SDK}/serializer/src/schemaserializer.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_device_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_transport_mqtt_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_transport_mqtt_common.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_security_factory.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_device_ll_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/iothub_security_factory.c"
    "${AZURE_IOT_SDK}/provisioning_client/src/iothub_auth_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/adapters/hsm_client_data.c"
	"${AZURE_IOT_SDK}/provisioning_client/adapters/hsm_client_tpm.c"
    "${AZURE_IOT_SDK}/provisioning_client/adapters/hsm_client_key.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_auth_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_codec.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/Marshal.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_comm_emulator.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/Memory.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_socket_comm.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub.c"
	"${AZURE_IOT_SDK}/c-utility/src/http_proxy_io.c"
	"${AZURE_IOT_SDK}/c-utility/src/azure_base32.c"
	)

if (CONFIG_DEVICE_COMMON_NAME)
	list (APPEND COMPONENT_SRCS "${AZURE_IOT_SDK}/provisioning_client/src/iothub_auth_client.c")
endif()

set (COMPONENT_SUBMODULES "${AZURE_IOT_SDK}")

set(COMPONENT_PRIV_REQUIRES "mbedtls esp-tls main")

register_component()

component_compile_options (
	-Wno-unused-function
	-Wno-missing-braces
	-Wno-missing-field-initializers
	)

component_compile_definitions (
    USE_LWIP_SOCKET_FOR_AZURE_IOT
	HSM_TYPE_SYMM_KEY
	HSM_TYPE_SAS_TOKEN
    USE_PROV_MODULE
)

if (CONFIG_DEVICE_COMMON_NAME)
	add_definitions(-DUSE_PROV_MODULE)
endif()
