set(COMPONENT_SRCS "azure_main.c"
                "iothub_client_device_twin_and_methods_sample.c"
                )
set(COMPONENT_ADD_INCLUDEDIRS ".")

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
