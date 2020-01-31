#
# Component Makefile
#

set (AZURE_IOT_SDK "${CMAKE_CURRENT_LIST_DIR}/azure-iot-sdk-c")

set (COMPONENT_ADD_INCLUDEDIRS
    "port/inc"
    "${AZURE_IOT_SDK}/certs"
	"${AZURE_IOT_SDK}/c-utility/inc"
	"${AZURE_IOT_SDK}/c-utility/pal/inc"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos"
	"${AZURE_IOT_SDK}/c-utility/pal/generic"
	"${AZURE_IOT_SDK}/iothub_client/inc"
	"${AZURE_IOT_SDK}/serializer/inc"
	"${AZURE_IOT_SDK}/umqtt/inc"
	"${AZURE_IOT_SDK}/umqtt/inc/azure_umqtt_c"
	"${AZURE_IOT_SDK}/uamqp/inc"
	"${AZURE_IOT_SDK}/uamqp/inc/azure_uamqp_c"
	"${AZURE_IOT_SDK}/deps/parson"
	"${AZURE_IOT_SDK}/deps/azure-macro-utils-c/inc"
	"${AZURE_IOT_SDK}/deps/umock-c/inc"
	"${AZURE_IOT_SDK}/provisioning_client/inc"
	"${AZURE_IOT_SDK}/provisioning_client/adapters"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/inc"
	)

set (COMPONENT_SRCS
	"port/src/agenttime_esp.c"
	"port/src/platform_esp.c"
	"port/src/tlsio_esp_tls.c"
	"port/src/uniqueid_esp32.c"
	"port/src/threadapi_esp32_pthreads.c"
	"${AZURE_IOT_SDK}/certs/certs.c"
	"${AZURE_IOT_SDK}/c-utility/adapters/httpapi_compact.c"
	"${AZURE_IOT_SDK}/c-utility/pal/agenttime.c"
	"${AZURE_IOT_SDK}/c-utility/pal/socket_async.c"
	"${AZURE_IOT_SDK}/c-utility/pal/tlsio_options.c"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos/lock.c"
	"${AZURE_IOT_SDK}/c-utility/pal/freertos/tickcounter.c"
	#begin include c-utility
	"${AZURE_IOT_SDK}/c-utility/src/azure_base32.c"
	"${AZURE_IOT_SDK}/c-utility/src/azure_base64.c"
	"${AZURE_IOT_SDK}/c-utility/src/buffer.c"
	"${AZURE_IOT_SDK}/c-utility/src/connection_string_parser.c"
	"${AZURE_IOT_SDK}/c-utility/src/consolelogger.c"
	"${AZURE_IOT_SDK}/c-utility/src/constbuffer_array_batcher.c"
	"${AZURE_IOT_SDK}/c-utility/src/constbuffer_array.c"
	"${AZURE_IOT_SDK}/c-utility/src/constbuffer.c"
	"${AZURE_IOT_SDK}/c-utility/src/constmap.c"
	"${AZURE_IOT_SDK}/c-utility/src/crt_abstractions.c"
	"${AZURE_IOT_SDK}/c-utility/src/dns_resolver_sync.c"
	"${AZURE_IOT_SDK}/c-utility/src/doublylinkedlist.c"
	"${AZURE_IOT_SDK}/c-utility/src/gballoc.c"
	"${AZURE_IOT_SDK}/c-utility/src/gbnetwork.c"
	"${AZURE_IOT_SDK}/c-utility/src/gb_rand.c"
	"${AZURE_IOT_SDK}/c-utility/src/gb_stdio.c"
	"${AZURE_IOT_SDK}/c-utility/src/gb_time.c"
	"${AZURE_IOT_SDK}/c-utility/src/hmac.c"
	"${AZURE_IOT_SDK}/c-utility/src/hmacsha256.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpapiex.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpapiexsas.c"
	"${AZURE_IOT_SDK}/c-utility/src/httpheaders.c"
	"${AZURE_IOT_SDK}/c-utility/src/http_proxy_io.c"
	"${AZURE_IOT_SDK}/c-utility/src/http_proxy_stub.c"
	"${AZURE_IOT_SDK}/c-utility/src/map.c"
	"${AZURE_IOT_SDK}/c-utility/src/memory_data.c"
	"${AZURE_IOT_SDK}/c-utility/src/optionhandler.c"
	"${AZURE_IOT_SDK}/c-utility/src/sastoken.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha1.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha224.c"
	"${AZURE_IOT_SDK}/c-utility/src/sha384-512.c"
	"${AZURE_IOT_SDK}/c-utility/src/singlylinkedlist.c"
	"${AZURE_IOT_SDK}/c-utility/src/strings.c"
	"${AZURE_IOT_SDK}/c-utility/src/string_token.c"
	"${AZURE_IOT_SDK}/c-utility/src/string_tokenizer.c"
	"${AZURE_IOT_SDK}/c-utility/src/urlencode.c"
	"${AZURE_IOT_SDK}/c-utility/src/usha.c"
	"${AZURE_IOT_SDK}/c-utility/src/utf8_checker.c"
	"${AZURE_IOT_SDK}/c-utility/src/uuid.c"
	"${AZURE_IOT_SDK}/c-utility/src/uws_client.c"
	"${AZURE_IOT_SDK}/c-utility/src/uws_frame_encoder.c"
	"${AZURE_IOT_SDK}/c-utility/src/vector.c"
	"${AZURE_IOT_SDK}/c-utility/src/wsio.c"
	"${AZURE_IOT_SDK}/c-utility/src/ws_url.c"
	"${AZURE_IOT_SDK}/c-utility/src/xio.c"
	"${AZURE_IOT_SDK}/c-utility/src/xlogging.c"
	#end include c-utility
	#begin include iothub client
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_device_client.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_edge.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_message.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_mqtt_common.c"
	"${AZURE_IOT_SDK}/iothub_client/src/uamqp_messaging.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_messenger.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_module_client_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_device.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportamqp_websockets.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_authorization.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_core_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/blob.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_cbs_auth.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransporthttp.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_device_client_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportamqp_methods.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_twin_messenger.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_ll_uploadtoblob.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_core.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_module_client.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_connection.c"
	"${AZURE_IOT_SDK}/iothub_client/src/version.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportmqtt_websockets.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportmqtt.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_telemetry_messenger.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_transport_ll_private.c"
	"${AZURE_IOT_SDK}/iothub_client/src/message_queue.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_ll.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_diagnostic.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport_amqp_common.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub_client_retry_control.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransportamqp.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothubtransport.c"
	#end include iothub client
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_client.c"
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_codec.c"
	"${AZURE_IOT_SDK}/umqtt/src/mqtt_message.c"
	#begin include amqp
	#"${AZURE_IOT_SDK}/uamqp/src/amqp_definitions.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_server_mechanism.c"
	#"${AZURE_IOT_SDK}/uamqp/src/amqpvalue_to_string.c"
	#"${AZURE_IOT_SDK}/uamqp/src/cbs.c"
	#"${AZURE_IOT_SDK}/uamqp/src/message_sender.c"
	#"${AZURE_IOT_SDK}/uamqp/src/header_detect_io.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_anonymous.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_plain.c"
	#"${AZURE_IOT_SDK}/uamqp/src/message.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_frame_codec.c"
	#"${AZURE_IOT_SDK}/uamqp/src/message_receiver.c"
	#"${AZURE_IOT_SDK}/uamqp/src/frame_codec.c"
	#"${AZURE_IOT_SDK}/uamqp/src/async_operation.c"
	#"${AZURE_IOT_SDK}/uamqp/src/saslclientio.c"
	#"${AZURE_IOT_SDK}/uamqp/src/session.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_mechanism.c"
	#"${AZURE_IOT_SDK}/uamqp/src/amqp_management.c"
	#"${AZURE_IOT_SDK}/uamqp/src/messaging.c"
	#"${AZURE_IOT_SDK}/uamqp/src/connection.c"
	#"${AZURE_IOT_SDK}/uamqp/src/sasl_mssbcbs.c"
	#"${AZURE_IOT_SDK}/uamqp/src/amqp_frame_codec.c"
	#"${AZURE_IOT_SDK}/uamqp/src/link.c"
	#"${AZURE_IOT_SDK}/uamqp/src/amqpvalue.c"
	#"${AZURE_IOT_SDK}/uamqp/src/socket_listener_berkeley.c"
	#end include amqp
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
	"${AZURE_IOT_SDK}/provisioning_client/adapters/hsm_client_data.c"
	"${AZURE_IOT_SDK}/provisioning_client/adapters/hsm_client_tpm.c"
	"${AZURE_IOT_SDK}/provisioning_client/src/prov_auth_client.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_codec.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/Marshal.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_comm_emulator.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/Memory.c"
	"${AZURE_IOT_SDK}/provisioning_client/deps/utpm/src/tpm_socket_comm.c"
	"${AZURE_IOT_SDK}/iothub_client/src/iothub.c"
	)

if (CONFIG_DEVICE_COMMON_NAME)
	list (APPEND COMPONENT_SRCS "${AZURE_IOT_SDK}/provisioning_client/src/iothub_auth_client.c")
endif()

set (COMPONENT_SUBMODULES "${AZURE_IOT_SDK}")

set(COMPONENT_PRIV_REQUIRES "mbedtls esp-tls lwip")

register_component()

component_compile_options (
	-Wno-unused-function
	-Wno-missing-braces
	-Wno-missing-field-initializers
	-Wno-unknown-pragmas
	-Wno-unused-variable
	-Wno-error=enum-compare
	)

component_compile_definitions (
    USE_LWIP_SOCKET_FOR_AZURE_IOT
	HSM_TYPE_X509
	HSM_TYPE_SAS_TOKEN
	USE_HTTP
	USE_MQTT
#	USE_AMQP
)

if(NOT CONFIG_AZURE_SDK_ENABLE_LOGGING)
	add_definitions(-DNO_LOGGING)
endif()

if (CONFIG_DEVICE_COMMON_NAME)
	add_definitions(-DUSE_PROV_MODULE)
endif()
