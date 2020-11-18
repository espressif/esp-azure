#
# Component Makefile
#

COMPONENT_ADD_INCLUDEDIRS := \
    azure-sdk-for-c/sdk/inc \
	port/inc 

COMPONENT_PRIV_INCLUDEDIRS := \
azure-sdk-for-c/sdk/src/azure/core 

COMPONENT_OBJEXCLUDE += azure-sdk-for-c/sdk/src/azure/core/az_span.o \
                        azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_sas.o 

COMPONENT_SRCDIRS := \
azure-sdk-for-c/sdk/src/azure/core \
azure-sdk-for-c/sdk/src/azure/iot \
port/src \
port/azure-sdk-for-c/sdk/src/azure/core \
port/azure-sdk-for-c/sdk/src/azure/iot 
