#
# Component Makefile
#
 
# Component configuration in preprocessor defines
CFLAGS += -DUSE_LWIP_SOCKET_FOR_AZURE_IOT

COMPONENT_ADD_INCLUDEDIRS := \
pal \
pal/inc \
azure/c-utility/inc \
azure/c-utility/inc/azure_c_shared_utility \
azure/c-utility/pal/inc \
azure/c-utility/pal/freertos \
azure/c-utility/pal/generic \
azure/iothub_client/inc \
azure/serializer/inc \
azure/umqtt/inc \
azure/umqtt/inc/azure_umqtt_c \
azure/deps/parson
 
COMPONENT_OBJS = \
azure/c-utility/pal/freertos/lock.o \
azure/c-utility/pal/dns_async.o \
azure/c-utility/pal/socket_async.o \
azure/c-utility/pal/freertos/threadapi.o \
azure/c-utility/pal/freertos/tickcounter.o \
azure/c-utility/pal/tlsio_options.o \
\
pal/src/agenttime_esp.o \
pal/src/platform_esp.o \
pal/src/tlsio_openssl_compact.o \
\
azure/c-utility/src/xlogging.o \
azure/c-utility/src/singlylinkedlist.o \
azure/c-utility/src/buffer.o \
azure/c-utility/src/consolelogger.o \
azure/c-utility/src/constbuffer.o \
azure/c-utility/src/constmap.o \
azure/c-utility/src/crt_abstractions.o \
azure/c-utility/src/doublylinkedlist.o \
azure/c-utility/src/gballoc.o \
azure/c-utility/src/gb_stdio.o \
azure/c-utility/src/gb_time.o \
azure/c-utility/src/hmac.o \
azure/c-utility/src/hmacsha256.o \
azure/c-utility/src/httpapiex.o \
azure/c-utility/src/httpapiexsas.o \
azure/c-utility/src/httpheaders.o \
azure/c-utility/src/map.o \
azure/c-utility/src/optionhandler.o \
azure/c-utility/src/sastoken.o \
azure/c-utility/src/sha1.o \
azure/c-utility/src/sha224.o \
azure/c-utility/src/sha384-512.o \
azure/c-utility/src/strings.o \
azure/c-utility/src/string_tokenizer.o \
azure/c-utility/src/urlencode.o \
azure/c-utility/src/usha.o \
azure/c-utility/src/vector.o \
azure/c-utility/src/xio.o \
azure/c-utility/src/base64.o \
\
\
azure/iothub_client/src/iothub_client_ll.o \
azure/iothub_client/src/iothub_client_core_ll.o \
azure/iothub_client/src/iothub_client_ll_uploadtoblob.o \
azure/iothub_client/src/iothub_client_authorization.o \
azure/iothub_client/src/iothub_client_retry_control.o \
azure/iothub_client/src/iothub_client_diagnostic.o \
azure/iothub_client/src/iothub_message.o \
azure/iothub_client/src/iothubtransport.o \
azure/iothub_client/src/iothubtransportmqtt.o \
azure/iothub_client/src/iothubtransport_mqtt_common.o \
azure/iothub_client/src/version.o \
\
\
azure/umqtt/src/mqtt_client.o \
azure/umqtt/src/mqtt_codec.o \
azure/umqtt/src/mqtt_message.o \
\
\
azure/deps/parson/parson.o \
\
azure/serializer/src/codefirst.o \
azure/serializer/src/agenttypesystem.o \
azure/serializer/src/commanddecoder.o \
azure/serializer/src/datamarshaller.o \
azure/serializer/src/datapublisher.o \
azure/serializer/src/dataserializer.o \
azure/serializer/src/iotdevice.o \
azure/serializer/src/jsondecoder.o \
azure/serializer/src/jsonencoder.o \
azure/serializer/src/methodreturn.o \
azure/serializer/src/multitree.o \
azure/serializer/src/schema.o \
azure/serializer/src/schemalib.o \
azure/serializer/src/schemaserializer.o \
\
\
 
COMPONENT_SRCDIRS := \
pal/src \
azure/c-utility/pal \
azure/c-utility/pal/freertos \
azure/c-utility/pal/lwip \
azure/c-utility/src \
azure/c-utility/adapters \
azure/umqtt/src \
azure/iothub_client/src \
azure/serializer/src \
azure/deps/parson
