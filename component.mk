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
azure-iot-sdk-c/deps/parson
 
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
port/src/tlsio_openssl_compact.o \
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
azure-iot-sdk-c/c-utility/src/base64.o \
\
\
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
azure-iot-sdk-c/deps/parson
