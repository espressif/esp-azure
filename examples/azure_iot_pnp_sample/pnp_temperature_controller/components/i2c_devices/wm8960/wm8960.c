#include <stdio.h>
#include "driver/i2c.h"
#include "wm8960.h"

#define WRITE_BIT      I2C_MASTER_WRITE  /*!< I2C master write */
#define READ_BIT       I2C_MASTER_READ   /*!< I2C master read */
#define ACK_CHECK_EN   0x1               /*!< I2C master will check ack from slave*/
#define ACK_CHECK_DIS  0x0               /*!< I2C master will not check ack from slave */
#define ACK_VAL        0x0               /*!< I2C ack value */
#define NACK_VAL       0x1               /*!< I2C nack value */

typedef struct {
    i2c_bus_handle_t bus;
    uint16_t dev_addr;
} wm8960_dev_t;

wm8960_handle_t iot_wm8960_create(i2c_bus_handle_t bus, uint16_t dev_addr)
{
    wm8960_dev_t* sensor = (wm8960_dev_t*) calloc(1, sizeof(wm8960_dev_t));
    sensor->bus = bus;
    sensor->dev_addr = dev_addr;
    return (wm8960_handle_t) sensor;
}

esp_err_t iot_wm8960_delete(wm8960_handle_t sensor, bool del_bus)
{
    wm8960_dev_t* sens = (wm8960_dev_t*) sensor;
    if(del_bus) {
        iot_i2c_bus_delete(sens->bus);
        sens->bus = NULL;
    }
    free(sens);
    return ESP_OK;
}

esp_err_t iot_wm8960_write_byte(wm8960_handle_t sensor, uint8_t reg_addr, uint16_t data)
{
    wm8960_dev_t* sens = (wm8960_dev_t*) sensor;
	esp_err_t  ret;

    uint8_t byte1 = (reg_addr << 1) | ((uint8_t)((data >> 8) & 0x0001));
    uint8_t byte2 = data & 0xff;

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (sens->dev_addr << 1) | WRITE_BIT, ACK_CHECK_EN);
    i2c_master_write_byte(cmd, byte1, ACK_CHECK_EN);
    i2c_master_write_byte(cmd, byte2, ACK_CHECK_EN);
    ret = iot_i2c_bus_cmd_begin(sens->bus, cmd, 1000 / portTICK_RATE_MS);
    i2c_cmd_link_delete(cmd);
    if (ret == ESP_FAIL) {
        return ret;
    }
	return ESP_OK;
}

esp_err_t wm8960_init(wm8960_handle_t sensor)
{
    esp_err_t ret;

    //Reset Device
    ret = iot_wm8960_write_byte(sensor, 0x0f, 0x0000);
    if (ret == ESP_FAIL)
    {
        return ret;
    }
    else
        printf("WM8960 reset completed !!\r\n");

    //Set Power Source
    ret = iot_wm8960_write_byte(sensor, 0x19, 1<<8 | 1<<7 | 1<<6); 
    ret = iot_wm8960_write_byte(sensor, 0x1A, 1<<8 | 1<<7 | 1<<6 | 1<<5 | 1<<4 | 1<<3); 

    ret = iot_wm8960_write_byte(sensor, 0x2F, 1<<3 | 1<<2); 
    if (ret != ESP_OK)
    {
        printf("Source set fail !!\r\n");
        printf("Error code: %d\r\n", ret);
        return ret;
    }

    //Configure clock
    //MCLK->div1->SYSCLK->DAC/ADC sample Freq = 25MHz(MCLK)/2*256 = 48.8kHz
    iot_wm8960_write_byte(sensor, 0x04, 0x0000);

    //Configure ADC/DAC
    iot_wm8960_write_byte(sensor, 0x05, 0x0000);

    //Configure audio interface
    //I2S format 16 bits word length
    iot_wm8960_write_byte(sensor, 0x07, 0x0002);

    //Configure HP_L and HP_R OUTPUTS
    iot_wm8960_write_byte(sensor, 0x02, 0x006F | 0x0100); //LOUT1 Volume Set
    iot_wm8960_write_byte(sensor, 0x03, 0x006F | 0x0100); //ROUT1 Volume Set

    //Configure SPK_RP and SPK_RN
    iot_wm8960_write_byte(sensor, 0x28, 0x004F | 0x0100); //Left Speaker Volume
    iot_wm8960_write_byte(sensor, 0x29, 0x004F | 0x0100); //Right Speaker Volume

    //Enable the OUTPUTS
    iot_wm8960_write_byte(sensor, 0x31, 0x00F7); //Enable Class D Speaker Outputs

    //Configure DAC volume
    iot_wm8960_write_byte(sensor, 0x0a, 0x00FF | 0x0100);
    iot_wm8960_write_byte(sensor, 0x0b, 0x00FF | 0x0100);

    //3D
    //  iot_wm8960_write_byte(sensor, 0x10, 0x001F);

    //Configure MIXER
    iot_wm8960_write_byte(sensor, 0x22, 1<<8 | 1<<7); 
    iot_wm8960_write_byte(sensor, 0x25, 1<<8 | 1<<7);

    //Jack Detect
    iot_wm8960_write_byte(sensor, 0x18, 1<<6 | 0<<5);
    iot_wm8960_write_byte(sensor, 0x17, 0x01C3);
    iot_wm8960_write_byte(sensor, 0x30, 0x0009); //0x000D,0x0005

    return 0;
}