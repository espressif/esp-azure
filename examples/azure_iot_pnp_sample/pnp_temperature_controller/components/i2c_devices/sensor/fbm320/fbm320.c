#include <stdio.h>
#include <string.h>
#include "driver/i2c.h"
#include "iot_i2c_bus.h"
#include "fbm320.h"

esp_err_t fbm320_i2c_writeblock(fbm320_handle_t sensor, uint8_t reg_addr, uint8_t cnt, uint8_t *reg_data);
esp_err_t fbm320_i2c_readblock(fbm320_handle_t sensor, uint8_t reg_addr, uint8_t cnt, uint8_t *reg_data);
esp_err_t fbm320_set_oversampling_rate(fbm320_handle_t sensor, enum fbm320_osr osr_setting);
esp_err_t fbm320_version_identification(fbm320_handle_t sensor);
esp_err_t fbm320_read_store_otp_data(fbm320_handle_t sensor);
esp_err_t fbm320_startMeasure_temp(fbm320_handle_t sensor);
esp_err_t fbm320_get_raw_temperature(fbm320_handle_t sensor);
esp_err_t fbm320_startMeasure_press(fbm320_handle_t sensor);
esp_err_t fbm320_get_raw_pressure(fbm320_handle_t sensor);
esp_err_t fbm320_calculation(fbm320_handle_t sensor);

static struct fbm320_data fbm320_barom;
struct fbm320_data *barom = &fbm320_barom;

typedef struct
{
	i2c_bus_handle_t bus;
	uint16_t dev_addr;
} fbm320_dev_t;

fbm320_handle_t iot_fbm320_create(i2c_bus_handle_t bus, uint16_t dev_addr)
{
	fbm320_dev_t *sensor = (fbm320_dev_t *)calloc(1, sizeof(fbm320_dev_t));
	sensor->bus = bus;
	sensor->dev_addr = dev_addr;
	return (fbm320_handle_t)sensor;
}

esp_err_t iot_fbm320_delete(fbm320_handle_t sensor, bool del_bus)
{
	fbm320_dev_t *sens = (fbm320_dev_t *)sensor;
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
 * @param sensor object handle of fbm320.
 * @param register_address: Address of the first register to read from.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_select_register(fbm320_handle_t sensor, uint8_t register_address)
{
	fbm320_dev_t *sens = (fbm320_dev_t *)sensor;
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
 * @param sensor object handle of fbm320.
 * @param register_address: Address of the first register to read from.
 * @param size: Number of registers to read.
 * @param data: Buffer to store the read data in.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_esp32_i2c_read_bytes(fbm320_handle_t sensor, uint8_t register_address, uint8_t size, uint8_t *data)
{
	fbm320_dev_t *sens = (fbm320_dev_t *)sensor;
	fbm320_select_register(sensor, register_address);
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
 * @brief Write multiple bytes to 8-bit registers.
 *
 * @param sensor object handle of fbm320.
 * @param register_address: Address of the first register to write to.
 * @param size: Number of bytes to write.
 * @param data: Array of bytes to write.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_esp32_i2c_write_bytes(fbm320_handle_t sensor, uint8_t register_address, uint8_t size, uint8_t *data)
{
	fbm320_dev_t *sens = (fbm320_dev_t *)sensor;
	i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, (sens->dev_addr << 1) | I2C_MASTER_WRITE, 1);
	i2c_master_write_byte(cmd, register_address, 1);
	i2c_master_write(cmd, data, size - 1, 0);
	i2c_master_write_byte(cmd, data[size - 1], 1);
	i2c_master_stop(cmd);
	int ret = iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_PERIOD_MS);
	i2c_cmd_link_delete(cmd);

	return ret;
}

esp_err_t fbm320_i2c_writeblock(fbm320_handle_t sensor, uint8_t reg_addr, uint8_t cnt, uint8_t *reg_data)
{
	return fbm320_esp32_i2c_write_bytes(sensor, reg_addr, cnt, reg_data);
}

esp_err_t fbm320_i2c_readblock(fbm320_handle_t sensor, uint8_t reg_addr, uint8_t cnt, uint8_t *reg_data)
{
	return fbm320_esp32_i2c_read_bytes(sensor, reg_addr, cnt, reg_data);
}

/**
 * @brief      { API for assigning function pointers, as bus read/write
 *               and delay. }
 *
 * @param sensor object handle of fbm320
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t fbm320_init(fbm320_handle_t sensor)
{
	esp_err_t ret;
	ret = fbm320_read_store_otp_data(sensor);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	ret = fbm320_set_oversampling_rate(sensor, OVERSAMPLING_RATE_DEFAULT);
	if (ret == ESP_FAIL)
	{
		return ret;
	}

	return ESP_OK;
}

esp_err_t fbm320_set_oversampling_rate(fbm320_handle_t sensor, enum fbm320_osr osr_setting)
{
	esp_err_t ret;
	uint8_t reg_addr;
	uint8_t data_buf;

	barom->oversampling_rate = osr_setting;

	/* Setting conversion time for pressure measurement */
	switch (osr_setting)
	{
	case osr_1024:
		barom->cnvTime_press = FBM320_CONVERSION_usTIME_OSR1024;
		barom->cmd_start_p = FBM320_MEAS_PRESS_OVERSAMP_0;
		break;
	case osr_2048:
		barom->cnvTime_press = FBM320_CONVERSION_usTIME_OSR2048;
		barom->cmd_start_p = FBM320_MEAS_PRESS_OVERSAMP_1;
		break;
	case osr_4096:
		barom->cnvTime_press = FBM320_CONVERSION_usTIME_OSR4096;
		barom->cmd_start_p = FBM320_MEAS_PRESS_OVERSAMP_2;
		break;
	case osr_8192:
		barom->cnvTime_press = FBM320_CONVERSION_usTIME_OSR8192;
		barom->cmd_start_p = FBM320_MEAS_PRESS_OVERSAMP_3;
		break;
	case osr_16384:
		barom->cnvTime_press = FBM320_CONVERSION_usTIME_OSR16384;
		reg_addr = 0xa6;
		ret = fbm320_i2c_readblock(sensor, reg_addr, sizeof(uint8_t), &data_buf);
		if (ret == ESP_FAIL)
		{
			return ret;
		}
		data_buf &= 0xf8;
		data_buf |= 0x6;
		ret = fbm320_i2c_writeblock(sensor, reg_addr, sizeof(uint8_t), &data_buf);
		if (ret == ESP_FAIL)
		{
			return ret;
		}
		barom->cmd_start_p = FBM320_MEAS_PRESS_OVERSAMP_2;
		ret = fbm320_i2c_readblock(sensor, 0xA6, sizeof(uint8_t), &data_buf);
		if (ret == ESP_FAIL)
		{
			return ret;
		}
		break;
	}
	/* Setting covversion time for temperature measurement */
	barom->cnvTime_temp = FBM320_CONVERSION_usTIME_OSR1024;

	return ESP_OK;
}

/**
 * @brief      { API for reading calibration data saved in OTP memory }
 */
esp_err_t fbm320_read_store_otp_data(fbm320_handle_t sensor)
{
	esp_err_t ret;
	uint8_t tmp[2];
	uint16_t R[10];

	struct fbm320_calibration_data *cali = &(barom->calibration);

	for (uint8_t i = 0; i < 9; i++)
	{
		ret = fbm320_i2c_readblock(sensor, FBM320_CALIBRATION_DATA_START0 + (i * 2), 1, &tmp[0]);
		if (ret < 0)
			goto exit;
		ret = fbm320_i2c_readblock(sensor, FBM320_CALIBRATION_DATA_START1 + (i * 2), 1, &tmp[1]);
		if (ret < 0)
			goto exit;

		R[i] = ((uint8_t)tmp[0] << 8 | tmp[1]);
	}
	ret = fbm320_i2c_readblock(sensor, FBM320_CALIBRATION_DATA_START2, 1, &tmp[0]);
	if (ret < 0)
		goto exit;
	ret = fbm320_i2c_readblock(sensor, FBM320_CALIBRATION_DATA_START3, 1, &tmp[1]);

	R[9] = ((uint8_t)tmp[0] << 8) | tmp[1];

	/* Coefficient reconstruction */
	cali->C0 = R[0] >> 4;
	cali->C1 = ((R[1] & 0xFF00) >> 5) | (R[2] & 7);
	cali->C2 = ((R[1] & 0xFF) << 1) | (R[4] & 1);
	cali->C3 = R[2] >> 3;
	cali->C4 = ((uint32_t)R[3] << 2) | (R[0] & 3);
	cali->C5 = R[4] >> 1;
	cali->C6 = R[5] >> 3;
	cali->C7 = ((uint32_t)R[6] << 3) | (R[5] & 7);
	cali->C8 = R[7] >> 3;
	cali->C9 = R[8] >> 2;
	cali->C10 = ((R[9] & 0xFF00) >> 6) | (R[8] & 3);
	cali->C11 = R[9] & 0xFF;
	cali->C12 = ((R[0] & 0x0C) << 1) | (R[7] & 7);
exit:
	return ret;
}

/**
 * @brief      { API for triggering measurement procedure and updating
 *               the temperature and pressure data in fbm320_data structure. }
 */
esp_err_t fbm320_update_data(fbm320_handle_t sensor)
{
	esp_err_t ret;
	ret = fbm320_startMeasure_temp(sensor);
	if (ret < 0)
		goto exit;
	vTaskDelay(10 / portTICK_RATE_MS);
	ret = fbm320_get_raw_temperature(sensor);
	if (ret < 0)
		goto exit;
	ret = fbm320_startMeasure_press(sensor);
	if (ret < 0)
		goto exit;
	vTaskDelay(30 / portTICK_RATE_MS);
	ret = fbm320_get_raw_pressure(sensor);
	if (ret < 0)
		goto exit;
exit:
	return ret;
}

/**
 * @brief      { This api ignite a measurement procedure. It writes data into
 *               the register of FBM320_TAKE_MEAS_REG. }
 */
esp_err_t fbm320_startMeasure_temp(fbm320_handle_t sensor)
{
	uint8_t bus_wr_data = FBM320_MEAS_TEMP;
	return fbm320_i2c_writeblock(sensor, FBM320_TAKE_MEAS_REG, sizeof(uint8_t), &bus_wr_data);
}

/**
 * @brief      { This api gets the data from the registers of FBM320_READ_MEAS_REG_U
 *               , FBM320_READ_MEAS_REG_L and FBM320_READ_MEAS_REG_XL. And the data are
 *               stored in "barom->raw_temperature". }
 */
esp_err_t fbm320_get_raw_temperature(fbm320_handle_t sensor)
{
	esp_err_t ret;
	uint8_t buf[3] = {0};

	ret = fbm320_i2c_readblock(sensor, FBM320_READ_MEAS_REG_U, 3 * sizeof(uint8_t), buf);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	barom->raw_temperature = (buf[0] << 16) + (buf[1] << 8) + buf[2];

	return ESP_OK;
}

/**
 * @brief      { This api ignite a measurement procedure. It writes data into
 *               the register of FBM320_TAKE_MEAS_REG. }
 */
esp_err_t fbm320_startMeasure_press(fbm320_handle_t sensor)
{
	uint8_t bus_wr_data;
	bus_wr_data = barom->cmd_start_p;
	return fbm320_i2c_writeblock(sensor, FBM320_TAKE_MEAS_REG, sizeof(uint8_t), &bus_wr_data);
}

/**
 * @brief      { This api gets the data from the registers of FBM320_READ_MEAS_REG_U
 *               , FBM320_READ_MEAS_REG_L and FBM320_READ_MEAS_REG_XL. And the data are
 *               stored in "barom->raw_temperature". }
 */
esp_err_t fbm320_get_raw_pressure(fbm320_handle_t sensor)
{
	esp_err_t ret;
	uint8_t buf[3] = {0};

	ret = fbm320_i2c_readblock(sensor, FBM320_READ_MEAS_REG_U, 3 * sizeof(uint8_t), buf);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	barom->raw_pressure = (buf[0] << 16) + (buf[1] << 8) + buf[2];

	return ESP_OK;
}

/**
 * @brief      API for read real temperature and pressure values
 *             stored in fbm320_data structure
 *
 * @param sensor object handle of fbm320
 * @param      real_pressure     The pointer for saving real pressure value
 *                               Pressure unit: Pa
 * @param      real_temperature  The pointer for saving real temperature value
 *                               Temperature unit: 0.01 degree Celsius
 */
esp_err_t fbm320_read_data(fbm320_handle_t sensor, int32_t *real_pressure, int32_t *real_temperature)
{
	esp_err_t ret;
	ret = fbm320_calculation(sensor);
	if (ret == ESP_FAIL)
	{
		return ret;
	}

	*real_pressure = barom->real_pressure;
	*real_temperature = barom->real_temperature;

	return ESP_OK;
}

/**
 * @brief      { API for calculating real temperature and pressure values.
 *               The results are stored in fbm320_data structure.
 *               "barom->real_temperature" is represented real temperature value.
 *               "barom->real_temperature" is in uint of drgree Celsius.
 *               "barom->real_pressure" is represented real pressure value.
 *               "barom->real_pressure" is in unit of Pa. }
 */
esp_err_t fbm320_calculation(fbm320_handle_t sensor)
{
	struct fbm320_calibration_data *cali = &barom->calibration;
	int32_t X01, X02, X03, X11, X12, X13, X21, X22, X23, X24, X25, X26, X31, X32;
	int32_t PP1, PP2, PP3, PP4, CF;
	int32_t RT, RP, UT, UP, DT, DT2;

	/* calculation for real temperature value*/
	UT = barom->raw_temperature;
	DT = ((UT - 8388608) >> 4) + (cali->C0 << 4);
	X01 = (cali->C1 + 4459) * DT >> 1;
	X02 = ((((cali->C2 - 256) * DT) >> 14) * DT) >> 4;
	X03 = (((((cali->C3 * DT) >> 18) * DT) >> 18) * DT);
	RT = ((2500 << 15) - X01 - X02 - X03) >> 15;

	DT2 = (X01 + X02 + X03) >> 12;
	X11 = ((cali->C5 - 4443) * DT2);
	X12 = (((cali->C6 * DT2) >> 16) * DT2) >> 2;
	X13 = ((X11 + X12) >> 10) + ((cali->C4 + 120586) << 4);

	X21 = ((cali->C8 + 7180) * DT2) >> 10;
	X22 = (((cali->C9 * DT2) >> 17) * DT2) >> 12;
	X23 = abs(X22 - X21);
	X24 = (X23 >> 11) * (cali->C7 + 166426);
	X25 = ((X23 & 0x7FF) * (cali->C7 + 166426)) >> 11;
	X26 = (X21 >= X22) ? (((0 - X24 - X25) >> 11) + cali->C7 + 166426) : (((X24 + X25) >> 11) + cali->C7 + 166426);

	UP = barom->raw_pressure;
	PP1 = ((UP - 8388608) - X13) >> 3;
	PP2 = (X26 >> 11) * PP1;
	PP3 = ((X26 & 0x7FF) * PP1) >> 11;
	PP4 = (PP2 + PP3) >> 10;

	CF = (2097152 + cali->C12 * DT2) >> 3;
	X31 = (((CF * cali->C10) >> 17) * PP4) >> 2;
	X32 = (((((CF * cali->C11) >> 15) * PP4) >> 18) * PP4);
	RP = ((X31 + X32) >> 15) + PP4 + 99880;

	barom->real_temperature = RT; //uint:0.01 degree Celsius
	barom->real_pressure = RP;	//uint: Pa

	return ESP_OK;
}

/**
 * @brief      { API for converting pressure value to altitude }
 *
 * @param sensor object handle of fbm320
 * @param[in]  real_pressure  The real pressure in unit of 1 Pa
 * @param[out]  altitude Absolute altitude value in unit millimeter(mm) }
 */
esp_err_t abs_altitude(fbm320_handle_t sensor, int32_t real_pressure, int32_t *altitude)
{
	int8_t P0;
	int16_t hs1, dP0;
	int32_t RP, h0, hs0, HP1, HP2, RH;

	RP = real_pressure;

	if (RP >= 103000)
	{
		P0 = 103;
		h0 = -138507;
		hs0 = -21007;
		hs1 = 311;
	}
	else if (RP >= 98000)
	{
		P0 = 98;
		h0 = 280531;
		hs0 = -21869;
		hs1 = 338;
	}
	else if (RP >= 93000)
	{
		P0 = 93;
		h0 = 717253;
		hs0 = -22813;
		hs1 = 370;
	}
	else if (RP >= 88000)
	{
		P0 = 88;
		h0 = 1173421;
		hs0 = -23854;
		hs1 = 407;
	}
	else if (RP >= 83000)
	{
		P0 = 83;
		h0 = 1651084;
		hs0 = -25007;
		hs1 = 450;
	}
	else if (RP >= 78000)
	{
		P0 = 78;
		h0 = 2152645;
		hs0 = -26292;
		hs1 = 501;
	}
	else if (RP >= 73000)
	{
		P0 = 73;
		h0 = 2680954;
		hs0 = -27735;
		hs1 = 560;
	}
	else if (RP >= 68000)
	{
		P0 = 68;
		h0 = 3239426;
		hs0 = -29366;
		hs1 = 632;
	}
	else if (RP >= 63000)
	{
		P0 = 63;
		h0 = 3832204;
		hs0 = -31229;
		hs1 = 719;
	}
	else if (RP >= 58000)
	{
		P0 = 58;
		h0 = 4464387;
		hs0 = -33377;
		hs1 = 826;
	}
	else if (RP >= 53000)
	{
		P0 = 53;
		h0 = 5142359;
		hs0 = -35885;
		hs1 = 960;
	}
	else if (RP >= 48000)
	{
		P0 = 48;
		h0 = 5874268;
		hs0 = -38855;
		hs1 = 1131;
	}
	else if (RP >= 43000)
	{
		P0 = 43;
		h0 = 6670762;
		hs0 = -42434;
		hs1 = 1354;
	}
	else if (RP >= 38000)
	{
		P0 = 38;
		h0 = 7546157;
		hs0 = -46841;
		hs1 = 1654;
	}
	else if (RP >= 33000)
	{
		P0 = 33;
		h0 = 8520395;
		hs0 = -52412;
		hs1 = 2072;
	}
	else
	{
		P0 = 28;
		h0 = 9622536;
		hs0 = -59704;
		hs1 = 2682;
	}
	dP0 = RP - P0 * 1000;
	HP1 = (hs0 * dP0) >> 2;
	HP2 = (((hs1 * dP0) >> 10) * dP0) >> 4;
	RH = ((h0 << 6) + HP1 + HP2) >> 6;

	*altitude = RH;
	return ESP_OK;
}

/**
 * @brief      API for read real temperature value in unit of degree Celsius
 *
 * @param sensor object handle of fbm320
 * @param[out]  real_temperature temperature value in unit of degree Celsius }
 */
esp_err_t fbm320_read_temperature(fbm320_handle_t sensor, float *real_temperature)
{
	esp_err_t ret;
	ret = fbm320_calculation(sensor);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	*real_temperature = barom->real_temperature * 0.01;
	return ESP_OK;
}

/**
 * @brief      API for read real pressure value in unit of Pa
 *
 * @param sensor object handle of fbm320
 * @param[out] real_pressure pressure value in unit of Pa }
 */
esp_err_t fbm320_read_pressure(fbm320_handle_t sensor, float *real_pressure)
{
	esp_err_t ret;
	ret = fbm320_calculation(sensor);
	if (ret == ESP_FAIL)
	{
		return ret;
	}
	*real_pressure = barom->real_pressure;
	return ESP_OK;
}