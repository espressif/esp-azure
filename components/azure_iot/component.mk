#
# Component Makefile
#
#COMPONENT_ADD_INCLUDEDIRS := azure/iothub_client/inc azure/c-utility/inc azure/uamqp/inc 

#COMPONENT_SRCDIRS := azure/iothub_client/src azure/c-utility/src azure/uamqp/src

COMPONENT_ADD_INCLUDEDIRS :=  \
azure/c-utility/inc azure/c-utility/inc/azure_c_shared_utility \
azure/iothub_client/inc \
azure/umqtt/inc azure/umqtt/inc/azure_umqtt_c 	\
azure/parson	\
adapter/azure/c-utility	

COMPONENT_OBJS =  \
azure/c-utility/src/xlogging.o	\
azure/c-utility/src/buffer.o	\
azure/c-utility/src/consolelogger.o	\
azure/c-utility/src/constbuffer.o	\
azure/c-utility/src/constmap.o	\
azure/c-utility/src/crt_abstractions.o	\
azure/c-utility/src/doublylinkedlist.o	\
azure/c-utility/src/gballoc.o	\
azure/c-utility/src/gb_stdio.o	\
azure/c-utility/src/gb_time.o	\
azure/c-utility/src/hmac.o	\
azure/c-utility/src/hmacsha256.o	\
azure/c-utility/src/httpapiex.o	\
azure/c-utility/src/httpapiexsas.o	\
azure/c-utility/src/httpheaders.o	\
azure/c-utility/src/map.o	\
azure/c-utility/src/optionhandler.o	\
azure/c-utility/src/sastoken.o	\
azure/c-utility/src/sha1.o	\
azure/c-utility/src/sha224.o	\
azure/c-utility/src/sha384-512.o	\
azure/c-utility/src/strings.o	\
azure/c-utility/src/string_tokenizer.o	\
azure/c-utility/src/urlencode.o	\
azure/c-utility/src/usha.o	\
azure/c-utility/src/vector.o	\
azure/c-utility/src/xio.o	\
azure/c-utility/src/base64.o \
\
\
azure/iothub_client/src/iothub_client.o	\
azure/iothub_client/src/iothub_client_ll.o	\
azure/iothub_client/src/iothub_client_ll_uploadtoblob.o	\
azure/iothub_client/src/iothub_message.o	\
azure/iothub_client/src/iothubtransport.o	\
azure/iothub_client/src/iothubtransportmqtt.o	\
azure/iothub_client/src/iothubtransport_mqtt_common.o	\
azure/iothub_client/src/version.o	\
\
\
azure/umqtt/src/mqtt_client.o	\
azure/umqtt/src/mqtt_codec.o	\
azure/umqtt/src/mqtt_message.o	\
\
\
\
adapter/azure/c-utility/agenttime_esp32.o	\
adapter/azure/c-utility/platform_esp32.o	\
adapter/azure/c-utility/threadapi_esp32.o	\
adapter/azure/c-utility/tickcounter_esp32.o	\
adapter/azure/c-utility/tlsio_ssl_esp32.o	

COMPONENT_SRCDIRS :=  \
azure/c-utility/src \
azure/umqtt/src	\
azure/iothub_client/src  \
azure/parson	\
adapter/azure/c-utility	















