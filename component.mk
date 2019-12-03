#
# Component Makefile
#
 
# Component configuration in preprocessor defines
CFLAGS += -DUSE_LWIP_SOCKET_FOR_AZURE_IOT

COMPONENT_ADD_INCLUDEDIRS := \
port \
port/inc \
azure-iot-sdk-c/c-utility/inc \
azure-iot-sdk-c/c-utility/inc/azure_c_shared_utility \
azure-iot-sdk-c/c-utility/pal/inc \
azure-iot-sdk-c/c-utility/pal/freertos \
azure-iot-sdk-c/c-utility/pal/generic \
azure-iot-sdk-c/iothub_client/inc \
azure-iot-sdk-c/serializer/inc \
azure-iot-sdk-c/umqtt/inc \
azure-iot-sdk-c/umqtt/inc/azure_umqtt_c \
azure-iot-sdk-c/deps/parson \
azure-iot-sdk-c/provisioning_client/inc \
azure-iot-sdk-c/provisioning_client/adapters \
azure-iot-sdk-c/provisioning_client/deps/utpm/inc \
 
ifndef CONFIG_TARGET_PLATFORM_ESP8266
COMPONENT_ADD_INCLUDEDIRS += azure-iot-sdk-c/certs
endif
 
COMPONENT_OBJS = \
azure-iot-sdk-c/c-utility/pal/freertos/lock.o \
azure-iot-sdk-c/c-utility/pal/dns_async.o \
azure-iot-sdk-c/c-utility/pal/socket_async.o \
azure-iot-sdk-c/c-utility/pal/freertos/threadapi.o \
azure-iot-sdk-c/c-utility/pal/freertos/tickcounter.o \
azure-iot-sdk-c/c-utility/pal/tlsio_options.o \
\
port/src/agenttime_esp.o \
port/src/platform_esp.o \
port/src/tlsio_esp_tls.o \
\
azure-iot-sdk-c/c-utility/src/xlogging.o \
azure-iot-sdk-c/c-utility/src/singlylinkedlist.o \
azure-iot-sdk-c/c-utility/src/buffer.o \
azure-iot-sdk-c/c-utility/src/consolelogger.o \
azure-iot-sdk-c/c-utility/src/constbuffer.o \
azure-iot-sdk-c/c-utility/src/constmap.o \
azure-iot-sdk-c/c-utility/src/crt_abstractions.o \
azure-iot-sdk-c/c-utility/src/doublylinkedlist.o \
azure-iot-sdk-c/c-utility/src/gballoc.o \
azure-iot-sdk-c/c-utility/src/gb_stdio.o \
azure-iot-sdk-c/c-utility/src/gb_time.o \
azure-iot-sdk-c/c-utility/src/hmac.o \
azure-iot-sdk-c/c-utility/src/hmacsha256.o \
azure-iot-sdk-c/c-utility/src/httpapiex.o \
azure-iot-sdk-c/c-utility/src/httpapiexsas.o \
azure-iot-sdk-c/c-utility/src/httpheaders.o \
azure-iot-sdk-c/c-utility/src/map.o \
azure-iot-sdk-c/c-utility/src/optionhandler.o \
azure-iot-sdk-c/c-utility/src/sastoken.o \
azure-iot-sdk-c/c-utility/src/sha1.o \
azure-iot-sdk-c/c-utility/src/sha224.o \
azure-iot-sdk-c/c-utility/src/sha384-512.o \
azure-iot-sdk-c/c-utility/src/strings.o \
azure-iot-sdk-c/c-utility/src/string_tokenizer.o \
azure-iot-sdk-c/c-utility/src/urlencode.o \
azure-iot-sdk-c/c-utility/src/usha.o \
azure-iot-sdk-c/c-utility/src/vector.o \
azure-iot-sdk-c/c-utility/src/xio.o \
azure-iot-sdk-c/c-utility/src/azure_base64.o \
azure-iot-sdk-c/c-utility/adapters/httpapi_compact.o \
\
\
azure-iot-sdk-c/iothub_client/src/iothub_device_client_ll.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_ll.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_core_ll.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_ll_uploadtoblob.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_authorization.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_retry_control.o \
azure-iot-sdk-c/iothub_client/src/iothub_client_diagnostic.o \
azure-iot-sdk-c/iothub_client/src/iothub_message.o \
azure-iot-sdk-c/iothub_client/src/iothubtransport.o \
azure-iot-sdk-c/iothub_client/src/iothubtransportmqtt.o \
azure-iot-sdk-c/iothub_client/src/iothubtransport_mqtt_common.o \
azure-iot-sdk-c/iothub_client/src/iothub_transport_ll_private.o \
azure-iot-sdk-c/iothub_client/src/version.o \
azure-iot-sdk-c/iothub_client/src/blob.o \
\
\
azure-iot-sdk-c/umqtt/src/mqtt_client.o \
azure-iot-sdk-c/umqtt/src/mqtt_codec.o \
azure-iot-sdk-c/umqtt/src/mqtt_message.o \
\
\
azure-iot-sdk-c/deps/parson/parson.o \
\
azure-iot-sdk-c/serializer/src/codefirst.o \
azure-iot-sdk-c/serializer/src/agenttypesystem.o \
azure-iot-sdk-c/serializer/src/commanddecoder.o \
azure-iot-sdk-c/serializer/src/datamarshaller.o \
azure-iot-sdk-c/serializer/src/datapublisher.o \
azure-iot-sdk-c/serializer/src/dataserializer.o \
azure-iot-sdk-c/serializer/src/iotdevice.o \
azure-iot-sdk-c/serializer/src/jsondecoder.o \
azure-iot-sdk-c/serializer/src/jsonencoder.o \
azure-iot-sdk-c/serializer/src/methodreturn.o \
azure-iot-sdk-c/serializer/src/multitree.o \
azure-iot-sdk-c/serializer/src/schema.o \
azure-iot-sdk-c/serializer/src/schemalib.o \
azure-iot-sdk-c/serializer/src/schemaserializer.o \
\
\
azure-iot-sdk-c/provisioning_client/src/prov_device_client.o \
azure-iot-sdk-c/provisioning_client/src/prov_transport_mqtt_client.o \
azure-iot-sdk-c/provisioning_client/src/prov_transport_mqtt_common.o \
azure-iot-sdk-c/provisioning_client/src/prov_security_factory.o \
azure-iot-sdk-c/provisioning_client/src/prov_device_ll_client.o \
azure-iot-sdk-c/provisioning_client/src/iothub_security_factory.o \
azure-iot-sdk-c/provisioning_client/adapters/hsm_client_data.o \
azure-iot-sdk-c/provisioning_client/adapters/hsm_client_tpm.o \
azure-iot-sdk-c/provisioning_client/src/prov_auth_client.o \
azure-iot-sdk-c/provisioning_client/deps/utpm/src/tpm_codec.o \
azure-iot-sdk-c/provisioning_client/deps/utpm/src/Marshal.o \
azure-iot-sdk-c/provisioning_client/deps/utpm/src/tpm_comm_emulator.o \
azure-iot-sdk-c/provisioning_client/deps/utpm/src/Memory.o \
azure-iot-sdk-c/provisioning_client/deps/utpm/src/tpm_socket_comm.o \
azure-iot-sdk-c/iothub_client/src/iothub.o \
azure-iot-sdk-c/c-utility/src/http_proxy_io.o \
azure-iot-sdk-c/c-utility/src/base32.o \

ifdef CONFIG_DEVICE_COMMON_NAME
COMPONENT_OBJS += azure-iot-sdk-c/provisioning_client/src/iothub_auth_client.o
endif

ifdef CONFIG_TARGET_PLATFORM_ESP8266
COMPONENT_OBJS += port/src/certs.o
endif

ifndef CONFIG_TARGET_PLATFORM_ESP8266
COMPONENT_OBJS += azure-iot-sdk-c/certs/certs.o
endif

COMPONENT_SRCDIRS := \
port/src \
azure-iot-sdk-c/c-utility/pal \
azure-iot-sdk-c/c-utility/pal/freertos \
azure-iot-sdk-c/c-utility/pal/lwip \
azure-iot-sdk-c/c-utility/src \
azure-iot-sdk-c/c-utility/adapters \
azure-iot-sdk-c/umqtt/src \
azure-iot-sdk-c/iothub_client/src \
azure-iot-sdk-c/serializer/src \
azure-iot-sdk-c/deps/parson \
azure-iot-sdk-c/prov_device_client/src \
azure-iot-sdk-c/iothub_client_mqtt_transport \
azure-iot-sdk-c/iothub_client_amqp_transport \
azure-iot-sdk-c/provisioning_client/src \
azure-iot-sdk-c/provisioning_client/adapters \
azure-iot-sdk-c/provisioning_client/deps/utpm/src \

ifndef CONFIG_TARGET_PLATFORM_ESP8266
COMPONENT_SRCDIRS += azure-iot-sdk-c/certs
endif

CFLAGS += -Wno-unused-function -Wno-missing-braces -Wno-missing-field-initializers -DHSM_TYPE_X509 -DHSM_TYPE_SAS_TOKEN -DHSM_TYPE_SYMM_KEY
CFLAGS += -Wno-error=maybe-uninitialized -Wno-error=char-subscripts

ifdef CONFIG_DEVICE_COMMON_NAME
CFLAGS += -DUSE_PROV_MODULE
endif
