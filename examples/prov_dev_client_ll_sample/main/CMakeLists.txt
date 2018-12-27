set(COMPONENT_SRCS "azure_main.c"
				"custom_hsm_x509.c"
				"prov_dev_client_ll_sample.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS ".")

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
