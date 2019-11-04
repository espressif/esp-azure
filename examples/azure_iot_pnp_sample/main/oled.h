/* OLED screen Example

   For other examples please check:
   https://github.com/espressif/esp-iot-solution/tree/master/examples

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
 */
#ifndef _APP_OLED_H_
#define _APP_OLED_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "driver/gpio.h"
#include "iot_ssd1306.h"
#include "ssd1306_fonts.h"

esp_err_t oled_show_time(ssd1306_handle_t dev);
esp_err_t oled_show_string(ssd1306_handle_t dev, const char* string);
esp_err_t oled_show_temp_humidity(ssd1306_handle_t dev, float temprature, float humidity);
void oled_clean(ssd1306_handle_t dev);
void oled_init(ssd1306_handle_t dev);

#ifdef __cplusplus
}
#endif

#endif
