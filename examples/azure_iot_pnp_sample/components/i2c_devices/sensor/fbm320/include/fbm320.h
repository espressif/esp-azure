#ifndef _IOT_FBM320_H_
#define _IOT_FBM320_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "driver/i2c.h"
#include "iot_i2c_bus.h"

typedef void* fbm320_handle_t;

/**
 * { I2C 7bit address setting for fbm320 }
 */
#define FBM320_I2C_ADDRESS 0x6D

/* Define the oversampling rate setting of fbm320.
 * Range of setting:
 * {osr_1024, osr_2048, osr_4096, osr_8192, osr_16384}
 */
#define OVERSAMPLING_RATE_DEFAULT  osr_8192

/* Control registers address*/
#define FBM320_TAKE_MEAS_REG	0xf4
#define FBM320_READ_MEAS_REG_U	0xf6
#define FBM320_READ_MEAS_REG_L	0xf7
#define FBM320_READ_MEAS_REG_XL	0xf8
#define FBM320_SOFTRESET_REG    0xe0

/* CMD list */
#define FBM320_MEAS_TEMP		        0x2e /* 2.5ms wait for measurement */
#define FBM320_MEAS_PRESS_OVERSAMP_0	0x34 /* 2.5ms wait for measurement */
#define FBM320_MEAS_PRESS_OVERSAMP_1	0x74 /* 3.7ms wait for measurement */
#define FBM320_MEAS_PRESS_OVERSAMP_2	0xb4 /* 6ms wait for measurement */
#define FBM320_MEAS_PRESS_OVERSAMP_3	0xf4 /* 10.7ms wait for measurement */

#define FBM320_CONVERSION_usTIME_OSR1024   2500  /*us*/
#define FBM320_CONVERSION_usTIME_OSR2048   3700  /*us*/
#define FBM320_CONVERSION_usTIME_OSR4096   6000  /*us*/
#define FBM320_CONVERSION_usTIME_OSR8192   10700 /*us*/
#define FBM320_CONVERSION_usTIME_OSR16384   20500 /*us*/

/* Calibration registers */
#define FBM320_CALIBRATION_DATA_START0	 0xaa /* Calibraton data address
                                      	       * {0xf1, 0xd0, 0xbb:0xaa} */
#define FBM320_CALIBRATION_DATA_START1	 0xab												
#define FBM320_CALIBRATION_DATA_START2   0xa4
#define FBM320_CALIBRATION_DATA_START3   0xf1

struct fbm320_calibration_data {
	int32_t C0, C1, C2, C3, C4, C5, C6, C7, \
	C8, C9, C10, C11, C12, C13;
};

enum fbm320_osr {
	osr_1024 = 0x0,
	osr_2048 = 0x1,
	osr_4096 = 0x2,
	osr_8192 = 0x3,
	osr_16384 = 0x4
};

enum fbm320_hw_version {
	hw_ver_b1 = 0x0,
	hw_ver_b2 = 0x1,
	hw_ver_b3 = 0x3,
	hw_ver_b4 = 0x5,
	hw_ver_unknown = 0xFF
};

struct fbm320_data {
	enum fbm320_osr oversampling_rate;
	struct fbm320_calibration_data calibration;
	uint8_t cmd_start_p;
	uint8_t cmd_start_t;
	uint32_t cnvTime_temp; //unit:us
	uint32_t cnvTime_press; //unit:us
	uint32_t raw_temperature;
	uint32_t raw_pressure;
	int32_t real_temperature; //unit:0.01 degree Celsisu
	int32_t real_pressure; //unit: Pa
};

/**
 * @brief Create and init sensor object and return a sensor handle
 *
 * @param bus I2C bus object handle
 * @param dev_addr I2C device address of sensor
 *
 * @return
 *     - NULL Fail
 *     - Others Success
 */
fbm320_handle_t iot_fbm320_create(i2c_bus_handle_t bus, uint16_t dev_addr);

/**
 * @brief Delete and release a sensor object
 *
 * @param sensor object handle of fbm320
 * @param del_bus Whether to delete the I2C bus
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t iot_fbm320_delete(fbm320_handle_t sensor, bool del_bus);

/**
 * @brief Init the sensor fbm320
 *
 * @param sensor object handle of fbm320
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_init(fbm320_handle_t sensor);

/**
 * @brief Get real pressure and temperature from fbm320
 *
 * @param sensor object handle of fbm320
 * @param real_pressure raw pressure value got from fbm320
 * @param real_temperature raw temperature value got from fbm320
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_read_data(fbm320_handle_t sensor, int32_t* real_pressure, int32_t* real_temperature);

/**
 * @brief Get real temperature from fbm320
 *
 * @param sensor object handle of fbm320
 * @param real_temperature real temperature value got from fbm320
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_read_temperature(fbm320_handle_t sensor, float* real_temperature);

/**
 * @brief Get raw pressure from fbm320
 *
 * @param sensor object handle of fbm320
 * @param raw_pressure raw pressure value got from fbm320
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_read_pressure(fbm320_handle_t sensor, float* real_pressure);

/**
 * @brief Update fbm320 sensor data
 *
 * @param sensor object handle of fbm320
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_update_data(fbm320_handle_t sensor);

/**
 * @brief Converting pressure value to altitude
 *
 * @param sensor object handle of fbm320
 * @param raw_pressure The real pressure in unit of 1 Pa
 * @param altitude Absolute altitude value in unit millimeter(mm)
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t abs_altitude(fbm320_handle_t sensor, int32_t real_pressure, int32_t* altitude);

#ifdef __cplusplus
}
#endif

#endif