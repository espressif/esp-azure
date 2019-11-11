#include <stdio.h>
#include <math.h>
#include "driver/i2c.h"

#include "hts221.h"
#include "bh1750.h"
#include "mpu6050.h"
#include "fbm320.h"
#include "mag3110.h"
#include "oled.h"
#include "iot_ssd1306.h"
#include "motor.h"

#define I2C_MASTER_SCL_IO 26        /*!< gpio number for I2C master clock */
#define I2C_MASTER_SDA_IO 25        /*!< gpio number for I2C master data  */
#define I2C_MASTER_FREQ_HZ 100000   /*!< I2C master clock frequency */

#define SHAKE_THRESHOLD 4

static i2c_bus_handle_t i2c_bus = NULL;
static hts221_handle_t hts221 = NULL;
static bh1750_handle_t bh1750 = NULL;
static fbm320_handle_t fbm320 = NULL;
static mag3110_handle_t mag3110 = NULL;
static mpu6050_handle_t mpu6050 = NULL;
static ssd1306_handle_t oled = NULL;
static float range_per_digit = 0;

static int last_x;
static int last_y;
static int last_z;
/**
 * @brief i2c master initialization
 */
static void i2c_master_init()
{
    int i2c_master_port = I2C_NUM_0;
    i2c_config_t conf;
    conf.mode = I2C_MODE_MASTER;
    conf.sda_io_num = I2C_MASTER_SDA_IO;
    conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
    conf.scl_io_num = I2C_MASTER_SCL_IO;
    conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
    conf.master.clk_speed = I2C_MASTER_FREQ_HZ;

    i2c_bus = iot_i2c_bus_create(i2c_master_port, &conf);
}

void init_humiture_sensor()
{
    hts221 = iot_hts221_create(i2c_bus, HTS221_I2C_ADDRESS);

    hts221_config_t hts221_config;
    hts221_config.avg_h = HTS221_AVGH_32;
    hts221_config.avg_t = HTS221_AVGT_16;
    hts221_config.odr = HTS221_ODR_1HZ;
    hts221_config.bdu_status = HTS221_DISABLE;
    hts221_config.heater_status = HTS221_DISABLE;
    iot_hts221_set_config(hts221, &hts221_config);
    
    iot_hts221_set_activate(hts221);
}

void init_ambient_light_sensor()
{
    bh1750 = iot_bh1750_create(i2c_bus, BH1750_I2C_ADDRESS);
    bh1750_cmd_measure_t cmd_measure = BH1750_CONTINUE_4LX_RES;
    iot_bh1750_power_on(bh1750);
    iot_bh1750_set_measure_mode(bh1750, cmd_measure);
}

void init_motion_sensor()
{
    uint8_t range;
    mpu6050 = iot_mpu6050_create(i2c_bus, MPU6050_I2C_ADDRESS);

    mpu6050_init(mpu6050);
    mpu6050_get_full_scale_accel_range(mpu6050, &range);

    switch (range)
    {
    case 0:
        range_per_digit = .000061f;
        break;
    case 1:
        range_per_digit = .000122f;
        break;
    case 2:
        range_per_digit = .000244f;
        break;
    case 3:
        range_per_digit = .0004882f;
        break;
    default:
        range_per_digit = .000061f;
        break;
    }
}

void init_barometer_sensor()
{
    fbm320 = iot_fbm320_create(i2c_bus, FBM320_I2C_ADDRESS);
    fbm320_init(fbm320);
}

void init_magnetometer_sensor()
{
    mag3110 = iot_mag3110_create(i2c_bus, MAG3110_I2C_ADDRESS);
    mag3110_start(mag3110);
}

void init_oled()
{
    oled = iot_ssd1306_create(i2c_bus, SSD1306_I2C_ADDRESS);
    oled_init(oled);
}

void init_motor()
{
    //1. mcpwm gpio initialization
    mcpwm_example_gpio_initialize();
    //2. initial mcpwm configuration
    printf("Configuring Initial Parameters of mcpwm...\n");
    mcpwm_config_t pwm_config;
    pwm_config.frequency = 1000; //frequency = 500Hz,
    pwm_config.cmpr_a = 0;       //duty cycle of PWMxA = 0
    pwm_config.cmpr_b = 0;       //duty cycle of PWMxb = 0
    pwm_config.counter_mode = MCPWM_UP_COUNTER;
    pwm_config.duty_mode = MCPWM_DUTY_MODE_0;
    mcpwm_init(MCPWM_UNIT_0, MCPWM_TIMER_0, &pwm_config); //Configure PWM0A & PWM0B with above settings
    // Initial humiture
    iot_hts221_set_activate(hts221);
}

void initialize_sensors()
{
    i2c_master_init();
    init_humiture_sensor();
    init_ambient_light_sensor();
    init_motion_sensor();
    init_barometer_sensor();
    init_magnetometer_sensor();
    init_motor();
    init_oled();
}

void oled_show_message(const char *message)
{
    oled_clean(oled);
    oled_show_string(oled, message);
}

void oled_update_humiture(float temprature, float humidity)
{
    oled_show_temp_humidity(oled, temprature, humidity);
}

float get_temperature()
{
    int16_t temperature;
    if (hts221 == NULL)
    {
        return 0;
    }
    iot_hts221_get_temperature(hts221, &temperature);

    return (float)temperature / 10;
}

float get_humidity()
{
    int16_t humidity;
    if (hts221 == NULL)
    {
        return 0;
    }
    iot_hts221_get_humidity(hts221, &humidity);

    return (float)humidity / 10;
}

float get_ambientLight()
{

    int ret;
    float bh1750_data;
    if (bh1750 == NULL)
    {
        return 0;
    }

    ret = iot_bh1750_get_data(bh1750, &bh1750_data);
    if (ret != ESP_OK)
    {
        printf("No ack, sensor not connected...\n");
        return 0;
    }
    return bh1750_data;
}

void get_pitch_roll(int *pitch, int *roll)
{
    mpu6050_acceleration_t result;
    int16_t norm_accel_x;
    int16_t norm_accel_y;
    int16_t norm_accel_z;

    mpu6050_get_acceleration(mpu6050, &result);

    norm_accel_x = result.accel_x * range_per_digit * 9.80665f;
    norm_accel_y = result.accel_y * range_per_digit * 9.80665f;
    norm_accel_z = result.accel_z * range_per_digit * 9.80665f;

    *pitch = -(atan2(norm_accel_x, 
            sqrt(norm_accel_y * norm_accel_y + norm_accel_z * norm_accel_z)) * 180.0) / 3.1415;
    *roll = (atan2(norm_accel_y, norm_accel_z) * 180.0) / 3.1415;
}

void get_pressure_altitude(float *pressure, float *altitude)
{
    int32_t real_p, real_t, abs_alt;

    fbm320_update_data(fbm320);
    fbm320_read_data(fbm320, &real_p, &real_t);

    *pressure = real_p / 1000.0; // convert pa to Kpa
    abs_altitude(fbm320, real_p, &abs_alt);
    *altitude = abs_alt / 1000.0;
}

void get_magnetometer(int *magnetometerX, int *magnetometerY, int *magnetometerZ)
{
    uint16_t x = 0, y = 0, z = 0;
    bool ready;
    mag3110_data_ready(mag3110, &ready);
    if (ready)
    {
        mag3110_read_mag(mag3110, &x, &y, &z);
    }

    *magnetometerX = x;
    *magnetometerY = y;
    *magnetometerZ = z;
}

bool check_for_shake()
{
    bool shake = false;
    mpu6050_acceleration_t result;
    int16_t norm_accel_x;
    int16_t norm_accel_y;
    int16_t norm_accel_z;

    mpu6050_get_acceleration(mpu6050, &result);

    norm_accel_x = result.accel_x * range_per_digit * 9.80665f;
    norm_accel_y = result.accel_y * range_per_digit * 9.80665f;
    norm_accel_z = result.accel_z * range_per_digit * 9.80665f;

    int speed = abs(norm_accel_x + norm_accel_y + norm_accel_z - last_x - last_y - last_z);
    if (speed > SHAKE_THRESHOLD)
    {
        shake = true;
    }

    last_x = norm_accel_x;
    last_y = norm_accel_y;
    last_z = norm_accel_z;

    return shake;
}

void stop_motor()
{
    brushed_motor_stop(MCPWM_UNIT_0, MCPWM_TIMER_0);
}

void start_motor_with_speed(float speed)
{
    brushed_motor_forward(MCPWM_UNIT_0, MCPWM_TIMER_0, speed);
}