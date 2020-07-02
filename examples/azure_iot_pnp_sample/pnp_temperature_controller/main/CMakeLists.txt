set(COMPONENT_SRCS "azure_main.c"
				"esp32AzureKit_impl.c"
				"motor.c"
				"oled.c"
                "pnp_temperature_controller.c" 
                "sensor_manager.c"
                "utilities/digitaltwin_serializer.c"
                "utilities/pnp_deviceinfo_component.c"
                "utilities/pnp_telemetries_component.c"
                "utilities/pnp_thermostat_component.c"
                "utilities/sensor_interface.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS "." "utilities")

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES USE_PROV_MODULE_FULL)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-const-variable)
