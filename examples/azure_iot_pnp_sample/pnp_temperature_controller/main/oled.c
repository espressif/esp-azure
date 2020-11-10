/* OLED screen Example

   For other examples please check:
   https://github.com/espressif/esp-iot-solution/tree/master/examples

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
 */

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "oled.h"

void oled_show_signs(ssd1306_handle_t dev);

void oled_init(ssd1306_handle_t dev)
{
    oled_show_signs(dev);
}

void oled_clean(ssd1306_handle_t dev)
{
    iot_ssd1306_clear_screen(dev, 0);
    oled_show_signs(dev);
}

void oled_show_signs(ssd1306_handle_t dev)
{
    iot_ssd1306_draw_bitmap(dev, 0, 2, &c_chSingal816[0], 16, 8);
    iot_ssd1306_draw_bitmap(dev, 24, 2, &c_chBluetooth88[0], 8, 8);
    iot_ssd1306_draw_bitmap(dev, 40, 2, &c_chMsg816[0], 16, 8);
    iot_ssd1306_draw_bitmap(dev, 64, 2, &c_chGPRS88[0], 8, 8);
    iot_ssd1306_draw_bitmap(dev, 90, 2, &c_chAlarm88[0], 8, 8);
    iot_ssd1306_draw_bitmap(dev, 112, 2, &c_chBat816[0], 16, 8);
}

esp_err_t oled_show_time(ssd1306_handle_t dev)
{
    struct tm timeinfo;
    char strftime_buf[64];
    time_t t_now;
    time(&t_now);
    setenv("TZ", "GMT-8", 1);
    tzset();
    localtime_r(&t_now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);

    iot_ssd1306_draw_3216char(dev, 0, 16, strftime_buf[11]);
    iot_ssd1306_draw_3216char(dev, 16, 16, strftime_buf[12]);
    iot_ssd1306_draw_3216char(dev, 32, 16, strftime_buf[13]);
    iot_ssd1306_draw_3216char(dev, 48, 16, strftime_buf[14]);
    iot_ssd1306_draw_3216char(dev, 64, 16, strftime_buf[15]);
    iot_ssd1306_draw_1616char(dev, 80, 32, strftime_buf[16]);
    iot_ssd1306_draw_1616char(dev, 96, 32, strftime_buf[17]);
    iot_ssd1306_draw_1616char(dev, 112, 32, strftime_buf[18]);
    char *day = strftime_buf;
    day[3] = '\0';
    iot_ssd1306_draw_string(dev, 87, 16, (const uint8_t *) day, 14, 1);    

    return iot_ssd1306_refresh_gram(dev);
}

esp_err_t oled_show_temp_humidity(ssd1306_handle_t dev, float temprature, float humidity)
{
    char tempraturestr[6];
    sprintf(tempraturestr, "%4.1f", temprature);
    tempraturestr[4] = '\0';

    iot_ssd1306_draw_string(dev, 0, 16, (const uint8_t *) "TEM:", 16, 1);
    iot_ssd1306_draw_1616char(dev, 36, 16, tempraturestr[0]);
    iot_ssd1306_draw_1616char(dev, 52, 16, tempraturestr[1]);
    iot_ssd1306_draw_char(dev, 70, 16, tempraturestr[2], 16, 1);
    iot_ssd1306_draw_1616char(dev, 75, 16, tempraturestr[3]);

    char humiditystr[6];
    sprintf(humiditystr, "%4.1f", humidity);
    humiditystr[4] = '\0';
    iot_ssd1306_draw_string(dev, 0, 36, (const uint8_t *) "HUM:", 16, 1);
    iot_ssd1306_draw_1616char(dev, 36, 36, humiditystr[0]);
    iot_ssd1306_draw_1616char(dev, 52, 36, humiditystr[1]);
    iot_ssd1306_draw_char(dev, 70, 36, humiditystr[2], 16, 1);
    iot_ssd1306_draw_1616char(dev, 75, 36, humiditystr[3]);

    return iot_ssd1306_refresh_gram(dev);
}

esp_err_t oled_show_string(ssd1306_handle_t dev, const char* string)
{ 
    iot_ssd1306_draw_string(dev, 0, 16, (const uint8_t *) string, 12, 1);

    return iot_ssd1306_refresh_gram(dev);
}