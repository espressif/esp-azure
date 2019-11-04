set(COMPONENT_SRCS "azure_main.c"
				"iot_pnp_client.c"
				"pnp_azure_board_sensor.c"
				"pnp_azure_board_device_info.c"
				"sensor_manager.c"
				"motor.c"
				"oled.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS ".")

register_component()

component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
