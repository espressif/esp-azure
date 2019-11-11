#include <stdio.h>
#include <string.h>
#include "driver/i2c.h"
#include "iot_i2c_bus.h"
#include "mpu6050.h"

void select_register (mpu6050_handle_t sensor, uint8_t register_address);
int8_t mpu6050_i2c_read_bytes (mpu6050_handle_t sensor, uint8_t register_address, uint8_t size, uint8_t* data);
int8_t mpu6050_i2c_read_byte (mpu6050_handle_t sensor, uint8_t register_address, uint8_t* data);
int8_t mpu6050_i2c_read_bits (mpu6050_handle_t sensor, uint8_t register_address, uint8_t bit_start, uint8_t size, uint8_t* data);
int8_t mpu6050_i2c_read_bit (mpu6050_handle_t sensor, uint8_t register_address, uint8_t bit_number, uint8_t* data);
bool mpu6050_i2c_write_bytes (mpu6050_handle_t sensor, uint8_t register_address, uint8_t size, uint8_t* data);
bool mpu6050_i2c_write_byte (mpu6050_handle_t sensor, uint8_t register_address, uint8_t data);
bool mpu6050_i2c_write_bits (mpu6050_handle_t sensor, uint8_t register_address, uint8_t bit_start, uint8_t size, uint8_t data);
bool mpu6050_i2c_write_bit (mpu6050_handle_t sensor, uint8_t register_address, uint8_t bit_number, uint8_t data);

typedef struct
{
	i2c_bus_handle_t bus;
	uint16_t dev_addr;
} mpu6050_dev_t;

esp_err_t mpu6050_init(mpu6050_handle_t sensor)
{
    esp_err_t ret;
    ret = mpu6050_set_clock_source(sensor, MPU6050_CLOCK_PLL_XGYRO);
    if (ret == ESP_FAIL)
        goto exit;
    ret = mpu6050_set_full_scale_gyro_range(sensor, MPU6050_GYRO_FULL_SCALE_RANGE_250);
    if (ret == ESP_FAIL)
        goto exit;
    ret = mpu6050_set_full_scale_accel_range(sensor, MPU6050_ACCEL_FULL_SCALE_RANGE_2);
    if (ret == ESP_FAIL)
        goto exit;
    ret = mpu6050_set_sleep_enabled(sensor, false);
    if (ret == ESP_FAIL)
        goto exit;

exit:
    return ret;
}

esp_err_t mpu6050_get_full_scale_gyro_range(mpu6050_handle_t sensor, uint8_t *scale)
{
    uint8_t data;
    esp_err_t ret = mpu6050_i2c_read_bits(sensor, MPU6050_REGISTER_GYRO_CONFIG,
                                          MPU6050_GCONFIG_FS_SEL_BIT, MPU6050_GCONFIG_FS_SEL_LENGTH, &data);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *scale = data;
    return ESP_OK;
}

esp_err_t mpu6050_set_full_scale_gyro_range(mpu6050_handle_t sensor, uint8_t range)
{
    return mpu6050_i2c_write_bits(sensor, MPU6050_REGISTER_GYRO_CONFIG,
                         MPU6050_GCONFIG_FS_SEL_BIT, MPU6050_GCONFIG_FS_SEL_LENGTH, range);
}

esp_err_t mpu6050_get_full_scale_accel_range(mpu6050_handle_t sensor, uint8_t *range)
{
    uint8_t data;
    esp_err_t ret = mpu6050_i2c_read_bits(sensor, MPU6050_REGISTER_ACCEL_CONFIG,
                                          MPU6050_ACONFIG_AFS_SEL_BIT, MPU6050_ACONFIG_AFS_SEL_LENGTH, &data);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *range = data;
    return ESP_OK;
}

esp_err_t mpu6050_set_full_scale_accel_range(mpu6050_handle_t sensor, uint8_t range)
{
    return mpu6050_i2c_write_bits(sensor, MPU6050_REGISTER_ACCEL_CONFIG,
                         MPU6050_ACONFIG_AFS_SEL_BIT, MPU6050_ACONFIG_AFS_SEL_LENGTH, range);
}

esp_err_t mpu6050_get_acceleration(mpu6050_handle_t sensor, mpu6050_acceleration_t* data)
{
    uint8_t temp[6];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_ACCEL_XOUT_H, 6, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    data->accel_x = (((int16_t)temp[0]) << 8) | temp[1];
    data->accel_y = (((int16_t)temp[2]) << 8) | temp[3];
    data->accel_z = (((int16_t)temp[4]) << 8) | temp[5];
    return ESP_OK;
}

esp_err_t mpu6050_get_acceleration_x(mpu6050_handle_t sensor, int16_t* x)
{
    uint8_t temp[2];
    esp_err_t ret =  mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_ACCEL_XOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *x = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_acceleration_y(mpu6050_handle_t sensor, int16_t *y)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_ACCEL_YOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *y = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_acceleration_z(mpu6050_handle_t sensor, int16_t *z)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_ACCEL_ZOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *z = ((((int16_t)temp[0]) << 8) | temp[1]);
    return ESP_OK;
}

esp_err_t mpu6050_get_temperature(mpu6050_handle_t sensor, int16_t *temperature)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_TEMP_OUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *temperature = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_rotation(mpu6050_handle_t sensor, mpu6050_rotation_t *data)
{
    uint8_t temp[6];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_GYRO_XOUT_H, 6,
                                           temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    data->gyro_x = (((int16_t)temp[0]) << 8) | temp[1];
    data->gyro_y = (((int16_t)temp[2]) << 8) | temp[3];
    data->gyro_z = (((int16_t)temp[4]) << 8) | temp[5];
    return ESP_OK;
}

esp_err_t mpu6050_get_rotation_x(mpu6050_handle_t sensor, int16_t *x)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_GYRO_XOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    *x = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_rotation_y(mpu6050_handle_t sensor, int16_t *y)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_GYRO_YOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    *y = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_rotation_z(mpu6050_handle_t sensor, int16_t* z)
{
    uint8_t temp[2];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_GYRO_ZOUT_H, 2, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    *z = (((int16_t)temp[0]) << 8) | temp[1];
    return ESP_OK;
}

esp_err_t mpu6050_get_motion(mpu6050_handle_t sensor, mpu6050_acceleration_t *data_accel, mpu6050_rotation_t *data_gyro)
{
    uint8_t temp[14];
    esp_err_t ret = mpu6050_i2c_read_bytes(sensor, MPU6050_REGISTER_ACCEL_XOUT_H, 14, temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }

    data_accel->accel_x = (((int16_t)temp[0]) << 8) | temp[1];
    data_accel->accel_y = (((int16_t)temp[2]) << 8) | temp[3];
    data_accel->accel_z = (((int16_t)temp[4]) << 8) | temp[5];
    data_gyro->gyro_x = (((int16_t)temp[8]) << 8) | temp[9];
    data_gyro->gyro_y = (((int16_t)temp[10]) << 8) | temp[11];
    data_gyro->gyro_z = (((int16_t)temp[12]) << 8) | temp[13];
    return ESP_OK;
}


esp_err_t mpu6050_set_sleep_enabled(mpu6050_handle_t sensor, bool enabled)
{
    return mpu6050_i2c_write_bit(sensor, MPU6050_REGISTER_PWR_MGMT_1,
                        MPU6050_PWR1_SLEEP_BIT, enabled);
}

esp_err_t mpu6050_get_device_id(mpu6050_handle_t sensor, uint8_t *id)
{
    uint8_t temp;
    esp_err_t ret = mpu6050_i2c_read_bits(sensor, MPU6050_REGISTER_WHO_AM_I,
                                          MPU6050_WHO_AM_I_BIT, MPU6050_WHO_AM_I_LENGTH, &temp);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    *id = temp;
    return ESP_OK;
}

/*
 * @brief Set clock source setting.
 * An internal 8MHz oscillator, gyroscope based clock, or external sources can
 * be selected as the MPU-60X0 clock source. When the internal 8 MHz oscillator
 * or an external source is chosen as the clock source, the MPU-60X0 can operate
 * in low power modes with the gyroscopes disabled.
 *
 * Upon power up, the MPU-60X0 clock source defaults to the internal oscillator.
 * However, it is highly recommended that the device be configured to use one of
 * the gyroscopes (or an external clock source) as the clock reference for
 * improved stability. The clock source can be selected according to the
 * following table:
 *
 * CLK_SEL | Clock Source
 * --------+--------------------------------------
 * 0       | Internal oscillator
 * 1       | PLL with X Gyro reference
 * 2       | PLL with Y Gyro reference
 * 3       | PLL with Z Gyro reference
 * 4       | PLL with external 32.768kHz reference
 * 5       | PLL with external 19.2MHz reference
 * 6       | Reserved
 * 7       | Stops the clock and keeps the timing generator in reset
 *
 * @param source: New clock source setting.
 */
esp_err_t mpu6050_set_clock_source (mpu6050_handle_t sensor, uint8_t source)
{
    return mpu6050_i2c_write_bits(sensor, MPU6050_REGISTER_PWR_MGMT_1,
    MPU6050_PWR1_CLKSEL_BIT, MPU6050_PWR1_CLKSEL_LENGTH, source);
}

mpu6050_handle_t iot_mpu6050_create(i2c_bus_handle_t bus, uint16_t dev_addr)
{
	mpu6050_dev_t *sensor = (mpu6050_dev_t *)calloc(1, sizeof(mpu6050_dev_t));
	sensor->bus = bus;
	sensor->dev_addr = dev_addr;
	return (mpu6050_handle_t)sensor;
}

esp_err_t iot_mpu6050_delete(mpu6050_handle_t sensor, bool del_bus)
{
	mpu6050_dev_t *sens = (mpu6050_dev_t *)sensor;
	if (del_bus)
	{
		iot_i2c_bus_delete(sens->bus);
		sens->bus = NULL;
	}
	free(sens);
	return ESP_OK;
}

void select_register(mpu6050_handle_t sensor, uint8_t register_address)
{
    mpu6050_dev_t *sens = (mpu6050_dev_t *)sensor;
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
    i2c_master_write_byte(cmd, register_address, 1);
    i2c_master_stop(cmd);
    iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);
}

int8_t mpu6050_i2c_read_bytes(mpu6050_handle_t sensor, uint8_t register_address,
                            uint8_t size, uint8_t *data)
{
    mpu6050_dev_t *sens = (mpu6050_dev_t *)sensor;
    select_register(sensor, register_address);
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_READ, 1);

    if (size > 1)
    {
        i2c_master_read(cmd, data, size - 1, 0);
    }
    i2c_master_read_byte(cmd, data + size - 1, 1);
    i2c_master_stop(cmd);
    iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);

    return size;
}

int8_t mpu6050_i2c_read_byte(mpu6050_handle_t sensor, uint8_t register_address, uint8_t *data)
{
    return (mpu6050_i2c_read_bytes(sensor, register_address, 1, data));
}


int8_t mpu6050_i2c_read_bits(mpu6050_handle_t sensor, uint8_t register_address,
                           uint8_t bit_start, uint8_t size, uint8_t *data)
{
    uint8_t bit;
    uint8_t count;

    if ((count = mpu6050_i2c_read_byte(sensor, register_address, &bit)) != 0)
    {
        uint8_t mask = ((1 << size) - 1) << (bit_start - size + 1);

        bit &= mask;
        bit >>= (bit_start - size + 1);
        *data = bit;
    }

    return (count);
}

int8_t mpu6050_i2c_read_bit(mpu6050_handle_t sensor, uint8_t register_address,
                          uint8_t bit_number, uint8_t *data)
{
    uint8_t bit;
    uint8_t count = mpu6050_i2c_read_byte(sensor, register_address,
                                        &bit);

    *data = bit & (1 << bit_number);

    return (count);
}

bool mpu6050_i2c_write_bytes(mpu6050_handle_t sensor, uint8_t register_address,
                           uint8_t size, uint8_t *data)
{
    mpu6050_dev_t *sens = (mpu6050_dev_t *)sensor;
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
    i2c_master_write_byte(cmd, register_address, 1);
    i2c_master_write(cmd, data, size - 1, 0);
    i2c_master_write_byte(cmd, data[size - 1], 1);
    i2c_master_stop(cmd);
    iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);

    return (true);
}

bool mpu6050_i2c_write_byte(mpu6050_handle_t sensor, uint8_t register_address,
                          uint8_t data)
{
    mpu6050_dev_t *sens = (mpu6050_dev_t *)sensor;
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
    i2c_master_write_byte(cmd, register_address, 1);
    i2c_master_write_byte(cmd, data, 1);
    i2c_master_stop(cmd);
    iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
    i2c_cmd_link_delete(cmd);

    return (true);
}

bool mpu6050_i2c_write_bits(mpu6050_handle_t sensor, uint8_t register_address,
                          uint8_t bit_start, uint8_t size, uint8_t data)
{
    uint8_t bit = 0;
    if (mpu6050_i2c_read_byte(sensor, register_address, &bit) != 0)
    {
        uint8_t mask = ((1 << size) - 1) << (bit_start - size + 1);
        data <<= (bit_start - size + 1); // Shift data into correct position.
        data &= mask;                    // Zero all non-important bits in data.
        bit &= ~(mask);                  // Zero all important bits in existing byte.
        bit |= data;                     // Combine data with existing byte.

        return (mpu6050_i2c_write_byte(sensor, register_address, bit));
    }
    else
    {
        return (false);
    }
}

bool mpu6050_i2c_write_bit(mpu6050_handle_t sensor, uint8_t register_address,
                         uint8_t bit_number, uint8_t data)
{
    uint8_t bit;

    mpu6050_i2c_read_byte(sensor, register_address, &bit);

    if (data != 0)
    {
        bit = (bit | (1 << bit_number));
    }
    else
    {
        bit = (bit & ~(1 << bit_number));
    }

    return (mpu6050_i2c_write_byte(sensor, register_address, bit));
}
