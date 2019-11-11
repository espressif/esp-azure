#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

COMPONENT_ADD_INCLUDEDIRS := \
i2c_bus/include \
sensor/bh1750/include \
sensor/hts221/include \
sensor/mpu6050/include \
sensor/mag3110/include \
sensor/fbm320/include \
ssd1306/include \
wm8960/include

COMPONENT_SRCDIRS := \
i2c_bus \
sensor/bh1750 \
sensor/hts221 \
sensor/mpu6050 \
sensor/mag3110 \
sensor/fbm320 \
ssd1306 \
wm8960