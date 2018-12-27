set(COMPONENT_SRCS "iothub_client_sample_mqtt.c"
			"azure_main.c"
			)
set(COMPONENT_ADD_INCLUDEDIRS ".")

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
