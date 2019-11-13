set(COMPONENT_SRCS "azure_main.c"
				"custom_hsm_x509.c"
				"prov_dev_client_ll_sample.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS ".")

set(COMPONENT_EMBED_TXTFILES "certs/leaf_certificate.pem"
                             "certs/leaf_private_key.pem"
                             )

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
