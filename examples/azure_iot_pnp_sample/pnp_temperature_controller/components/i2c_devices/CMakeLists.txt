set(COMPONENT_SRCS "i2c_bus/i2c_bus.c"
                "sensor/bh1750/bh1750.c"
                "sensor/hts221/hts221.c"
                "sensor/mpu6050/mpu6050.c"
                "sensor/mag3110/mag3110.c"
                "sensor/fbm320/fbm320.c"
                "ssd1306/ssd1306.c"
                "ssd1306/ssd1306_fonts.c"
                "wm8960/wm8960.c"
				)
set(COMPONENT_ADD_INCLUDEDIRS "i2c_bus/include"
                        "sensor/bh1750/include"
                        "sensor/hts221/include"
                        "sensor/mpu6050/include"
                        "sensor/mag3110/include"
                        "sensor/fbm320/include"
                        "ssd1306/include"
                        "wm8960/include"
)

register_component()
