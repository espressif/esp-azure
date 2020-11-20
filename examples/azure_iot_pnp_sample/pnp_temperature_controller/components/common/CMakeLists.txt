set(COMPONENT_SRCS "pnp_device_client_ll.c"
                "pnp_dps_ll.c"
                "pnp_protocol.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS ".")

set(COMPONENT_PRIV_REQUIRES port)

register_component()

component_compile_definitions(USE_PROV_MODULE_FULL)