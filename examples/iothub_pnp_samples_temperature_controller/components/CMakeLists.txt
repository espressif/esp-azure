idf_component_register(SRCS "src/sample_pnp_deviceinfo.c"
                            "src/sample_pnp_thermostat.c"
                            "pnp/esp_azure_iot_pnp.c"
                        INCLUDE_DIRS include pnp
                        REQUIRES port)
