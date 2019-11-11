#ifndef _IOT_MAG3110_H_
#define _IOT_MAG3110_H_
#ifdef __cplusplus
extern "C" {
#endif

#include "driver/i2c.h"
#include "iot_i2c_bus.h"

typedef void* mag3110_handle_t;

/////////////////////////////////////////
// MAG3110 I2C Address    			   //
/////////////////////////////////////////

#define MAG3110_I2C_ADDRESS 0x0E

/////////////////////////////////////////
// MAG3110 Magnetometer Registers      //
/////////////////////////////////////////
#define MAG3110_DR_STATUS			0x00
#define MAG3110_OUT_X_MSB			0x01
#define MAG3110_OUT_X_LSB			0x02
#define MAG3110_OUT_Y_MSB			0x03
#define MAG3110_OUT_Y_LSB			0x04
#define MAG3110_OUT_Z_MSB			0x05
#define MAG3110_OUT_Z_LSB			0x06
#define MAG3110_WHO_AM_I			0x07
#define MAG3110_SYSMOD				0x08
#define MAG3110_OFF_X_MSB			0x09
#define MAG3110_OFF_X_LSB			0x0A
#define MAG3110_OFF_Y_MSB			0x0B
#define MAG3110_OFF_Y_LSB			0x0C
#define MAG3110_OFF_Z_MSB			0x0D
#define MAG3110_OFF_Z_LSB			0x0E
#define MAG3110_DIE_TEMP			0x0F
#define MAG3110_CTRL_REG1			0x10
#define MAG3110_CTRL_REG2			0x11

////////////////////////////////
// MAG3110 WHO_AM_I Response  //
////////////////////////////////
#define MAG3110_WHO_AM_I_RSP		0xC4

/////////////////////////////////////////
// MAG3110 Commands and Settings       //
/////////////////////////////////////////

//CTRL_REG1 Settings
//Output Data Rate/Oversample Settings
//DR_OS_80_16 -> Output Data Rate = 80Hz, Oversampling Ratio = 16

#define MAG3110_DR_OS_80_16 		0x00
#define MAG3110_DR_OS_40_32 		0x08
#define MAG3110_DR_OS_20_64 		0x10
#define MAG3110_DR_OS_10_128		0x18
#define MAG3110_DR_OS_40_16			0x20
#define MAG3110_DR_OS_20_32			0x28
#define MAG3110_DR_OS_10_64			0x30
#define MAG3110_DR_OS_5_128			0x38
#define MAG3110_DR_OS_20_16			0x40
#define MAG3110_DR_OS_10_32			0x48
#define MAG3110_DR_OS_5_64			0x50
#define MAG3110_DR_OS_2_5_128		0x58
#define MAG3110_DR_OS_10_16			0x60
#define MAG3110_DR_OS_5_32			0x68
#define MAG3110_DR_OS_2_5_64		0x70
#define MAG3110_DR_OS_1_25_128		0x78
#define MAG3110_DR_OS_5_16			0x80
#define MAG3110_DR_OS_2_5_32		0x88
#define	MAG3110_DR_OS_1_25_64		0x90
#define MAG3110_DR_OS_0_63_128		0x98
#define MAG3110_DR_OS_2_5_16		0xA0
#define MAG3110_DR_OS_1_25_32		0xA8
#define MAG3110_DR_OS_0_63_64		0xB0
#define MAG3110_DR_OS_0_31_128		0xB8
#define MAG3110_DR_OS_1_25_16		0xC0
#define MAG3110_DR_OS_0_63_32		0xC8
#define MAG3110_DR_OS_0_31_64		0xD0
#define MAG3110_DR_OS_0_16_128		0xD8
#define MAG3110_DR_OS_0_63_16		0xE0
#define MAG3110_DR_OS_0_31_32		0xE8
#define MAG3110_DR_OS_0_16_64		0xF0
#define MAG3110_DR_OS_0_08_128		0xF8

//Other CTRL_REG1 Settings
#define MAG3110_FAST_READ 			0x04
#define MAG3110_TRIGGER_MEASUREMENT	0x02
#define MAG3110_ACTIVE_MODE			0x01
#define MAG3110_STANDBY_MODE		0x00

//CTRL_REG2 Settings
#define MAG3110_AUTO_MRST_EN		0x80
#define MAG3110_RAW_MODE			0x20
#define MAG3110_NORMAL_MODE			0x00
#define MAG3110_MAG_RST				0x10

//SYSMOD Readings
#define MAG3110_SYSMOD_STANDBY		0x00
#define MAG3110_SYSMOD_ACTIVE_RAW	0x01
#define	MAG3110_SYSMOD_ACTIVE		0x02

#define MAG3110_X_AXIS 1
#define MAG3110_Y_AXIS 3
#define MAG3110_Z_AXIS 5

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
mag3110_handle_t iot_mag3110_create(i2c_bus_handle_t bus, uint16_t dev_addr);

/**
 * @brief Delete and release a sensor object
 *
 * @param sensor object handle of mag3110
 * @param del_bus Whether to delete the I2C bus
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t iot_mag3110_delete(mag3110_handle_t sensor, bool del_bus);

/**
 * @brief Start mag3110 sensor to measure
 *
 * @param sensor object handle of mag3110
 * @param del_bus Whether to delete the I2C bus
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mag3110_start(mag3110_handle_t sensor);

/**
 * @brief Whether the sensor data is ready for reading
 *
 * @param sensor object handle of mag3110
 * @param[out] ready Whether data is ready
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mag3110_data_ready(mag3110_handle_t sensor, bool* ready);

/**
 * @brief Get x, y anda z value from mag3110
 *
 * @param sensor object handle of mag3110
 * @param x x value got from mag3110
 * @param y y value got from mag3110
 * @param z z value got from mag3110
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mag3110_read_mag(mag3110_handle_t sensor, uint16_t *x, uint16_t *y, uint16_t *z);

#ifdef __cplusplus
}
#endif

#endif
