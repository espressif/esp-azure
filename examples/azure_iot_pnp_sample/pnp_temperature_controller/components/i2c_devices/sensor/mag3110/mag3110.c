#include <stdio.h>
#include <math.h>
#include "driver/i2c.h"
#include "mag3110.h"

#define DEG_PER_RAD (180.0 / 3.14159265358979)
#define CALIBRATION_TIMEOUT 5000 //timeout in milliseconds

static uint16_t x_offset = 0;
static uint16_t y_offset = 0;

static uint16_t x_scale = 0.0f;
static uint16_t y_scale = 0.0f;

static uint16_t x_min;
static uint16_t x_max;

static uint16_t y_min;
static uint16_t y_max;

static bool calibrated = false;
static bool calibration_mode = false;
static bool active_mode = false;
static bool raw_mode = false;

typedef struct
{
	i2c_bus_handle_t bus;
	uint16_t dev_addr;
} mag3110_dev_t;

mag3110_handle_t iot_mag3110_create(i2c_bus_handle_t bus, uint16_t dev_addr)
{
	mag3110_dev_t *sensor = (mag3110_dev_t *)calloc(1, sizeof(mag3110_dev_t));
	sensor->bus = bus;
	sensor->dev_addr = dev_addr;
	return (mag3110_handle_t)sensor;
}

esp_err_t iot_mag3110_delete(mag3110_handle_t sensor, bool del_bus)
{
	mag3110_dev_t *sens = (mag3110_dev_t *)sensor;
	if (del_bus)
	{
		iot_i2c_bus_delete(sens->bus);
		sens->bus = NULL;
	}
	free(sens);
	return ESP_OK;
}

/*
 * @brief Select the register in the device where data will be read from.
 *
 * @param sensor object handle of mag3110.
 * @param register_address: Address of the first register to read from.
 * 
 * @return
 *   - ESP_OK Success
 *   - ESP_FAIL Fail
 */
esp_err_t mag3110_select_register(mag3110_handle_t sensor, uint8_t register_address)
{
	mag3110_dev_t *sens = (mag3110_dev_t *)sensor;
	i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
	i2c_master_write_byte(cmd, register_address, 1);
	i2c_master_stop(cmd);
	int ret = iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
	i2c_cmd_link_delete(cmd);
	return ret;
}

/*
 * @brief Read multiple bytes from 8-bit registers.
 *
 * @param sensor object handle of mag3110.
 * @param register_address: Address of the first register to read from.
 * @param size: Number of registers to read.
 * @param data: Buffer to store the read data in.
 * 
 * @return
 *   - ESP_OK Success
 *   - ESP_FAIL Fail
 */
esp_err_t mag3110_esp32_i2c_read_bytes(mag3110_handle_t sensor, uint8_t register_address, uint8_t size, uint8_t *data)
{
	mag3110_dev_t *sens = (mag3110_dev_t *)sensor;
	mag3110_select_register(sensor, register_address);
	i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_READ, 1);
	if (size > 1)
	{
		i2c_master_read(cmd, data, size - 1, 0);
	}

	i2c_master_read_byte(cmd, data + size - 1, 1);
	i2c_master_stop(cmd);
	int ret = iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
	i2c_cmd_link_delete(cmd);

	return ret;
}

/*
 * @brief Read single byte from an 8-bit register.
 *
 * @param sensor object handle of mag3110.
 * @param register_address: Address of the register to read from.
 * @param data: Container to store the byte read from register.
 * 
 * @return
 *   - ESP_OK Success
 *   - ESP_FAIL Fail
 */
esp_err_t mag3110_esp32_i2c_read_byte(mag3110_handle_t sensor, uint8_t register_address, uint8_t *data)
{
	return (mag3110_esp32_i2c_read_bytes(sensor, register_address, 1, data));
}

/*
 * @brief Write single byte to an 8-bit register.
 *
 * @param sensor object handle of mag3110.
 * @param device_address: I2C slave device address.
 * @param register_address: Address of the register to write to.
 * @param data: Array of bytes to write.
 * 
 * @return
 *   - ESP_OK Success
 *   - ESP_FAIL Fail
 */
esp_err_t mag3110_esp32_i2c_write_byte(mag3110_handle_t sensor, uint8_t register_address, uint8_t data)
{
	mag3110_dev_t *sens = (mag3110_dev_t *)sensor;
	i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
	i2c_master_write_byte(cmd, register_address, 1);
	i2c_master_write_byte(cmd, data, 1);
	i2c_master_stop(cmd);
	int ret = iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
	i2c_cmd_link_delete(cmd);

	return ret;
}

// This is private because you must read each axis for the data ready bit to be cleared
// It may be confusing for casual users
esp_err_t mag3110_read_axis(mag3110_handle_t sensor, uint8_t axis, uint16_t *value)
{
	esp_err_t ret;
	uint8_t lsbAddress, msbAddress;
	uint8_t lsb, msb;

	msbAddress = axis;
	lsbAddress = axis + 1;

	ret = mag3110_esp32_i2c_read_byte(sensor, msbAddress, &msb);
	if (ret == ESP_FAIL)
		return ret;

	vTaskDelay(10 / portTICK_RATE_MS); //needs at least 1.3us free time between start and stop

	ret = mag3110_esp32_i2c_read_byte(sensor, lsbAddress, &lsb);
	if (ret == ESP_FAIL)
		return ret;

	*value = (lsb | (msb << 8)); //concatenate the MSB and LSB
	return ret;
}

esp_err_t mag3110_read_mag(mag3110_handle_t sensor, uint16_t *x, uint16_t *y, uint16_t *z)
{
	//Read each axis
	esp_err_t ret;
	ret = mag3110_read_axis(sensor, MAG3110_OUT_X_MSB, x);
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_read_axis(sensor, MAG3110_OUT_Y_MSB, y);
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_read_axis(sensor, MAG3110_OUT_Z_MSB, z);
	if (ret == ESP_FAIL)
		goto exit;
exit:
	return ret;
}

esp_err_t mag3110_data_ready(mag3110_handle_t sensor, bool *ready)
{
	uint8_t temp;
	esp_err_t ret = mag3110_esp32_i2c_read_byte(sensor, MAG3110_DR_STATUS, &temp);
	if (ret == ESP_FAIL)
		return ret;

	*ready = ((temp & 0x8) >> 3);
	return ret;
}

esp_err_t mag3110_enter_standby(mag3110_handle_t sensor)
{
	esp_err_t ret;
	active_mode = false;
	uint8_t current;
	ret = mag3110_esp32_i2c_read_byte(sensor, MAG3110_CTRL_REG1, &current);
	if (ret == ESP_FAIL)
		goto exit;

	//Clear bits 0 and 1 to enter low power standby mode
	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG1, (current & ~(0x3)));
	if (ret == ESP_FAIL)
		goto exit;

exit:
	return ret;
}

esp_err_t mag3110_exit_standby(mag3110_handle_t sensor)
{
	esp_err_t ret;
	uint8_t current;
	ret = mag3110_esp32_i2c_read_byte(sensor, MAG3110_CTRL_REG1, &current);
	if (ret == ESP_FAIL)
		goto exit;

	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG1, (current | MAG3110_ACTIVE_MODE));
	if (ret == ESP_FAIL)
		goto exit;

exit:
	return ret;
}

esp_err_t mag3110_start(mag3110_handle_t sensor)
{
	return mag3110_exit_standby(sensor);
}

esp_err_t mag3110_read_micro_teslas(mag3110_handle_t sensor, float *x, float *y, float *z)
{
	esp_err_t ret;
	uint16_t int_x, int_y, int_z;
	//Read each axis and scale to Teslas
	ret = mag3110_read_axis(sensor, MAG3110_OUT_X_MSB, &int_x);
	if (ret == ESP_FAIL)
		goto exit;
	*x = (float)int_x * 0.1f;

	ret = mag3110_read_axis(sensor, MAG3110_OUT_Y_MSB, &int_y);
	if (ret == ESP_FAIL)
		goto exit;
	*y = (float)int_y * 0.1f;

	ret = mag3110_read_axis(sensor, MAG3110_OUT_Z_MSB, &int_z);
	if (ret == ESP_FAIL)
		goto exit;
	*z = (float)int_z * 0.1f;

exit:
	return ret;
}

//Note: Must be calibrated to use readHeading!!!
esp_err_t mag3110_read_heading(mag3110_handle_t sensor, float *value)
{
	esp_err_t ret;
	uint16_t x, y, z;
	ret = mag3110_read_mag(sensor, &x, &y, &z);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	//Calculate the heading
	*value = atan2(-y * y_scale, x * x_scale) * DEG_PER_RAD;
	return ret;
}

esp_err_t mag3110_set_DR_OS(mag3110_handle_t sensor, uint8_t DROS)
{
	esp_err_t ret;
	bool was_active = active_mode;

	if (active_mode)
	{
		ret = mag3110_enter_standby(sensor); //Must be in standby to modify CTRL_REG1
		if (ret == ESP_FAIL)
			goto exit;
	}

	//If we attempt to write to CTRL_REG1 right after going into standby
	//It might fail to modify the other bits
	vTaskDelay(100 / portTICK_RATE_MS);

	//Get the current control register
	uint8_t current, new;
	ret = mag3110_esp32_i2c_read_byte(sensor, MAG3110_CTRL_REG1, &current);
	if (ret == ESP_FAIL)
		goto exit;
	new = current & 0x07;														 //And chop off the 5 MSB
	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG1, (new | DROS)); //Write back the register with new DR_OS set
	if (ret == ESP_FAIL)
		goto exit;

	vTaskDelay(100 / portTICK_RATE_MS);

	//Start sampling again if we were before
	if (was_active)
	{
		ret = mag3110_exit_standby(sensor);
		if (ret == ESP_FAIL)
			goto exit;
	}

exit:
	return ret;
}

esp_err_t mag3110_trigger_measurement(mag3110_handle_t sensor)
{
	esp_err_t ret;
	uint8_t current;
	ret = mag3110_esp32_i2c_read_byte(sensor, MAG3110_CTRL_REG1, &current);
	if (ret == ESP_FAIL)
		return ret;
	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG1, (current | 0x02));
	if (ret == ESP_FAIL)
		return ret;

	return ret;
}

//Note that AUTO_MRST_EN will always read back as 0
//Therefore we must explicitly set this bit every time we modify CTRL_REG2
esp_err_t mag3110_raw_data(mag3110_handle_t sensor, bool raw)
{
	esp_err_t ret;
	if (raw) //Turn on raw (non-user corrected) mode
	{
		raw_mode = true;
		ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG2, MAG3110_AUTO_MRST_EN | (0x01 << 5));
		if (ret == ESP_FAIL)
			return ret;
	}
	else //Turn off raw mode
	{
		raw_mode = false;
		ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG2, MAG3110_AUTO_MRST_EN & ~(0x01 << 5));
		if (ret == ESP_FAIL)
			return ret;
	}
	return ret;
}

//If you look at the datasheet, the offset registers are kind of strange
//The offset is stored in the most significant 15 bits.
//Bit 0 of the LSB register is always 0 for some reason...
//So we have to left shift the values by 1
//Ask me how confused I was...
esp_err_t mag3110_set_offset(mag3110_handle_t sensor, uint8_t axis, uint16_t offset)
{
	esp_err_t ret;
	offset = offset << 1;
	uint8_t msbAddress = axis + 8;
	uint8_t lsbAddress = msbAddress + 1;

	ret = mag3110_esp32_i2c_write_byte(sensor,msbAddress, (uint8_t)((offset >> 8) & 0xFF));
	if (ret == ESP_FAIL)
		return ret;

	vTaskDelay(15 / portTICK_RATE_MS);

	ret = mag3110_esp32_i2c_write_byte(sensor,lsbAddress, (uint8_t)offset & 0xFF);
	if (ret == ESP_FAIL)
		return ret;

	return ret;
}

//See above
esp_err_t mag3110_read_offset(mag3110_handle_t sensor, uint8_t axis, uint16_t *value)
{
	uint16_t temp;
	esp_err_t ret = mag3110_read_axis(sensor, axis + 8, &temp);
	if (ret == ESP_FAIL)
		return ret;

	*value = temp >> 1;
	return ret;
}

esp_err_t mag3110_is_active(mag3110_handle_t sensor, bool *is_active)
{
	*is_active = active_mode;
	return ESP_OK;
}

esp_err_t mag3110_is_raw(mag3110_handle_t sensor, bool *is_raw)
{
	*is_raw = raw_mode;
	return ESP_OK;
}

esp_err_t mag3110_is_calibrated(mag3110_handle_t sensor, bool *is_calibrated)
{
	*is_calibrated = calibrated;
	return ESP_OK;
}

esp_err_t mag3110_is_calibrating(mag3110_handle_t sensor, bool *is_calibrating)
{
	*is_calibrating = calibration_mode;
	return ESP_OK;
}

esp_err_t mag3110_get_sys_mode(mag3110_handle_t sensor, uint8_t *mode)
{
	return mag3110_esp32_i2c_read_byte(sensor, MAG3110_SYSMOD, mode);
}

esp_err_t mag3110_exit_cal_mode(mag3110_handle_t sensor)
{
	esp_err_t ret;
	//Calculate offsets
	x_offset = (x_min + x_max) / 2;

	y_offset = (y_min + y_max) / 2;

	x_scale = 1.0 / (x_max - x_min);
	y_scale = 1.0 / (y_max - y_min);

	ret = mag3110_set_offset(sensor, MAG3110_X_AXIS, x_offset);
	if (ret == ESP_FAIL)
		goto exit;

	//Set the offsets
	ret = mag3110_set_offset(sensor, MAG3110_Y_AXIS, y_offset);
	if (ret == ESP_FAIL)
		goto exit;

	//Use the offsets (set to normal mode)
	ret = mag3110_raw_data(sensor, false);
	if (ret == ESP_FAIL)
		goto exit;

	calibration_mode = false;
	calibrated = true;

	//Enter standby and wait
	//enterStandby();

exit:
	return ret;
}

esp_err_t mag3110_calibrate(mag3110_handle_t sensor)
{
	// uint16_t x, y, z;
	// mag3110_read_mag(&x, &y, &z);

	// bool changed = false; //Keep track of if a min/max is updated
	// if(x < x_min)
	// {
	//   x_min = x;
	//   changed = true;
	// }
	// if(x > x_max)
	// {
	//   x_max = x;
	//   changed = true;
	// }
	// if(y < y_min)
	// {
	//   y_min = y;
	//   changed = true;
	// }
	// if(y > y_max)
	// {
	//   y_max = y;
	//   changed = true;
	// }

	// if(changed)
	//  time_last_change = millis(); //Reset timeout counter

	// if(millis() > 5000 && millis() - time_last_change > CALIBRATION_TIMEOUT) //If the timeout has been reached, exit calibration
	//  mag3110_exit_cal_mode();
	return ESP_OK;
}

esp_err_t mag3110_enter_cal_mode(mag3110_handle_t sensor)
{
	esp_err_t ret;
	calibration_mode = true;
	//Starting values for calibration
	x_min = 32767;
	x_max = 0x8000;

	y_min = 32767;
	y_max = 0x8000;

	//Read raw readings for calibration
	ret = mag3110_raw_data(sensor, true);
	if (ret == ESP_FAIL)
		goto exit;

	calibrated = false;

	//Set to active mode, highest DROS for continous readings
	ret = mag3110_set_DR_OS(sensor, MAG3110_DR_OS_80_16);
	if (ret == ESP_FAIL)
		goto exit;

	if (!active_mode)
	{
		ret = mag3110_start(sensor);
		if (ret == ESP_FAIL)
			goto exit;
	}

exit:
	return ret;
}

esp_err_t mag3110_reset(mag3110_handle_t sensor)
{
	esp_err_t ret;
	ret = mag3110_enter_standby(sensor);
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG1, 0x00); //Set everything to 0
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_esp32_i2c_write_byte(sensor, MAG3110_CTRL_REG2, 0x80); //Enable Auto Mag Reset, non-raw mode
	if (ret == ESP_FAIL)
		goto exit;

	calibration_mode = false;
	active_mode = false;
	raw_mode = false;
	calibrated = false;

	ret = mag3110_set_offset(sensor, MAG3110_X_AXIS, 0);
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_set_offset(sensor, MAG3110_Y_AXIS, 0);
	if (ret == ESP_FAIL)
		goto exit;
	ret = mag3110_set_offset(sensor, MAG3110_Z_AXIS, 0);
	if (ret == ESP_FAIL)
		goto exit;

exit:
	return ret;
}