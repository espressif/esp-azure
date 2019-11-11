#ifndef _IOT_MPU6050_H_
#define _IOT_MPU6050_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "driver/i2c.h"
#include "iot_i2c_bus.h"

typedef void* mpu6050_handle_t;

// Address of MPU6050
#define MPU6050_I2C_ADDRESS                 0x68

// Registers:
#define MPU6050_REGISTER_XG_OFFS_TC         0x00
#define MPU6050_REGISTER_YG_OFFS_TC         0x01
#define MPU6050_REGISTER_ZG_OFFS_TC         0x02
#define MPU6050_REGISTER_X_FINE_GAIN        0x03
#define MPU6050_REGISTER_Y_FINE_GAIN        0x04
#define MPU6050_REGISTER_Z_FINE_GAIN        0x05
#define MPU6050_REGISTER_XA_OFFS_H          0x06
#define MPU6050_REGISTER_XA_OFFS_L_TC       0x07
#define MPU6050_REGISTER_YA_OFFS_H          0x08
#define MPU6050_REGISTER_YA_OFFS_L_TC       0x09
#define MPU6050_REGISTER_ZA_OFFS_H          0x0A
#define MPU6050_REGISTER_ZA_OFFS_L_TC       0x0B
#define MPU6050_REGISTER_SELF_TEST_X        0x0D
#define MPU6050_REGISTER_SELF_TEST_Y        0x0E
#define MPU6050_REGISTER_SELF_TEST_Z        0x0F
#define MPU6050_REGISTER_SELF_TEST_A        0x10
#define MPU6050_REGISTER_XG_OFFS_USRH       0x13
#define MPU6050_REGISTER_XG_OFFS_USRL       0x14
#define MPU6050_REGISTER_YG_OFFS_USRH       0x15
#define MPU6050_REGISTER_YG_OFFS_USRL       0x16
#define MPU6050_REGISTER_ZG_OFFS_USRH       0x17
#define MPU6050_REGISTER_ZG_OFFS_USRL       0x18
#define MPU6050_REGISTER_SMPLRT_DIV         0x19
#define MPU6050_REGISTER_CONFIG             0x1A
#define MPU6050_REGISTER_GYRO_CONFIG        0x1B
#define MPU6050_REGISTER_ACCEL_CONFIG       0x1C
#define MPU6050_REGISTER_FF_THR             0x1D
#define MPU6050_REGISTER_FF_DUR             0x1E
#define MPU6050_REGISTER_MOT_THR            0x1F
#define MPU6050_REGISTER_MOT_DUR            0x20
#define MPU6050_REGISTER_ZRMOT_THR          0x21
#define MPU6050_REGISTER_ZRMOT_DUR          0x22
#define MPU6050_REGISTER_FIFO_EN            0x23
#define MPU6050_REGISTER_I2C_MST_CTRL       0x24
#define MPU6050_REGISTER_I2C_SLV0_ADDR      0x25
#define MPU6050_REGISTER_I2C_SLV0_REG       0x26
#define MPU6050_REGISTER_I2C_SLV0_CTRL      0x27
#define MPU6050_REGISTER_I2C_SLV1_ADDR      0x28
#define MPU6050_REGISTER_I2C_SLV1_REG       0x29
#define MPU6050_REGISTER_I2C_SLV1_CTRL      0x2A
#define MPU6050_REGISTER_I2C_SLV2_ADDR      0x2B
#define MPU6050_REGISTER_I2C_SLV2_REG       0x2C
#define MPU6050_REGISTER_I2C_SLV2_CTRL      0x2D
#define MPU6050_REGISTER_I2C_SLV3_ADDR      0x2E
#define MPU6050_REGISTER_I2C_SLV3_REG       0x2F
#define MPU6050_REGISTER_I2C_SLV3_CTRL      0x30
#define MPU6050_REGISTER_I2C_SLV4_ADDR      0x31
#define MPU6050_REGISTER_I2C_SLV4_REG       0x32
#define MPU6050_REGISTER_I2C_SLV4_DO        0x33
#define MPU6050_REGISTER_I2C_SLV4_CTRL      0x34
#define MPU6050_REGISTER_I2C_SLV4_DI        0x35
#define MPU6050_REGISTER_I2C_MST_STATUS     0x36
#define MPU6050_REGISTER_INT_PIN_CFG        0x37
#define MPU6050_REGISTER_INT_ENABLE         0x38
#define MPU6050_REGISTER_DMP_INT_STATUS     0x39
#define MPU6050_REGISTER_INT_STATUS         0x3A
#define MPU6050_REGISTER_ACCEL_XOUT_H       0x3B
#define MPU6050_REGISTER_ACCEL_XOUT_L       0x3C
#define MPU6050_REGISTER_ACCEL_YOUT_H       0x3D
#define MPU6050_REGISTER_ACCEL_YOUT_L       0x3E
#define MPU6050_REGISTER_ACCEL_ZOUT_H       0x3F
#define MPU6050_REGISTER_ACCEL_ZOUT_L       0x40
#define MPU6050_REGISTER_TEMP_OUT_H         0x41
#define MPU6050_REGISTER_TEMP_OUT_L         0x42
#define MPU6050_REGISTER_GYRO_XOUT_H        0x43
#define MPU6050_REGISTER_GYRO_XOUT_L        0x44
#define MPU6050_REGISTER_GYRO_YOUT_H        0x45
#define MPU6050_REGISTER_GYRO_YOUT_L        0x46
#define MPU6050_REGISTER_GYRO_ZOUT_H        0x47
#define MPU6050_REGISTER_GYRO_ZOUT_L        0x48
#define MPU6050_REGISTER_EXT_SENS_DATA_00   0x49
#define MPU6050_REGISTER_EXT_SENS_DATA_01   0x4A
#define MPU6050_REGISTER_EXT_SENS_DATA_02   0x4B
#define MPU6050_REGISTER_EXT_SENS_DATA_03   0x4C
#define MPU6050_REGISTER_EXT_SENS_DATA_04   0x4D
#define MPU6050_REGISTER_EXT_SENS_DATA_05   0x4E
#define MPU6050_REGISTER_EXT_SENS_DATA_06   0x4F
#define MPU6050_REGISTER_EXT_SENS_DATA_07   0x50
#define MPU6050_REGISTER_EXT_SENS_DATA_08   0x51
#define MPU6050_REGISTER_EXT_SENS_DATA_09   0x52
#define MPU6050_REGISTER_EXT_SENS_DATA_10   0x53
#define MPU6050_REGISTER_EXT_SENS_DATA_11   0x54
#define MPU6050_REGISTER_EXT_SENS_DATA_12   0x55
#define MPU6050_REGISTER_EXT_SENS_DATA_13   0x56
#define MPU6050_REGISTER_EXT_SENS_DATA_14   0x57
#define MPU6050_REGISTER_EXT_SENS_DATA_15   0x58
#define MPU6050_REGISTER_EXT_SENS_DATA_16   0x59
#define MPU6050_REGISTER_EXT_SENS_DATA_17   0x5A
#define MPU6050_REGISTER_EXT_SENS_DATA_18   0x5B
#define MPU6050_REGISTER_EXT_SENS_DATA_19   0x5C
#define MPU6050_REGISTER_EXT_SENS_DATA_20   0x5D
#define MPU6050_REGISTER_EXT_SENS_DATA_21   0x5E
#define MPU6050_REGISTER_EXT_SENS_DATA_22   0x5F
#define MPU6050_REGISTER_EXT_SENS_DATA_23   0x60
#define MPU6050_REGISTER_MOT_DETECT_STATUS  0x61
#define MPU6050_REGISTER_I2C_SLV0_DO        0x63
#define MPU6050_REGISTER_I2C_SLV1_DO        0x64
#define MPU6050_REGISTER_I2C_SLV2_DO        0x65
#define MPU6050_REGISTER_I2C_SLV3_DO        0x66
#define MPU6050_REGISTER_I2C_MST_DELAY_CTRL 0x67
#define MPU6050_REGISTER_SIGNAL_PATH_RESET  0x68
#define MPU6050_REGISTER_MOT_DETECT_CTRL    0x69
#define MPU6050_REGISTER_USER_CTRL          0x6A
#define MPU6050_REGISTER_PWR_MGMT_1         0x6B
#define MPU6050_REGISTER_PWR_MGMT_2         0x6C
#define MPU6050_REGISTER_BANK_SEL           0x6D
#define MPU6050_REGISTER_MEM_START_ADDR     0x6E
#define MPU6050_REGISTER_MEM_R_W            0x6F
#define MPU6050_REGISTER_DMP_CFG_1          0x70
#define MPU6050_REGISTER_DMP_CFG_2          0x71
#define MPU6050_REGISTER_FIFO_COUNTH        0x72
#define MPU6050_REGISTER_FIFO_COUNTL        0x73
#define MPU6050_REGISTER_FIFO_R_W           0x74
#define MPU6050_REGISTER_WHO_AM_I           0x75

// Self test values:
#define MPU6050_SELF_TEST_XA_1_BIT          0x07
#define MPU6050_SELF_TEST_XA_1_LENGTH       0x03
#define MPU6050_SELF_TEST_XA_2_BIT          0x05
#define MPU6050_SELF_TEST_XA_2_LENGTH       0x02
#define MPU6050_SELF_TEST_YA_1_BIT          0x07
#define MPU6050_SELF_TEST_YA_1_LENGTH       0x03
#define MPU6050_SELF_TEST_YA_2_BIT          0x03
#define MPU6050_SELF_TEST_YA_2_LENGTH       0x02
#define MPU6050_SELF_TEST_ZA_1_BIT          0x07
#define MPU6050_SELF_TEST_ZA_1_LENGTH       0x03
#define MPU6050_SELF_TEST_ZA_2_BIT          0x01
#define MPU6050_SELF_TEST_ZA_2_LENGTH       0x02
#define MPU6050_SELF_TEST_XG_1_BIT          0x04
#define MPU6050_SELF_TEST_XG_1_LENGTH       0x05
#define MPU6050_SELF_TEST_YG_1_BIT          0x04
#define MPU6050_SELF_TEST_YG_1_LENGTH       0x05
#define MPU6050_SELF_TEST_ZG_1_BIT          0x04
#define MPU6050_SELF_TEST_ZG_1_LENGTH       0x05

// DLPF values:
#define MPU6050_DLPF_BW_256                 0x00
#define MPU6050_DLPF_BW_188                 0x01
#define MPU6050_DLPF_BW_98                  0x02
#define MPU6050_DLPF_BW_42                  0x03
#define MPU6050_DLPF_BW_20                  0x04
#define MPU6050_DLPF_BW_10                  0x05
#define MPU6050_DLPF_BW_5                   0x06

// DHPF values:
#define MPU6050_DHPF_RESET                  0x00
#define MPU6050_DHPF_5                      0x01
#define MPU6050_DHPF_2P5                    0x02
#define MPU6050_DHPF_1P25                   0x03
#define MPU6050_DHPF_0P63                   0x04
#define MPU6050_DHPF_HOLD                   0x07

// Full scale gyroscope range:
#define MPU6050_GYRO_FULL_SCALE_RANGE_250   0x00
#define MPU6050_GYRO_FULL_SCALE_RANGE_500   0x01
#define MPU6050_GYRO_FULL_SCALE_RANGE_1000  0x02
#define MPU6050_GYRO_FULL_SCALE_RANGE_2000  0x03

// Full scale accelerometer range:
#define MPU6050_ACCEL_FULL_SCALE_RANGE_2    0x00
#define MPU6050_ACCEL_FULL_SCALE_RANGE_4    0x01
#define MPU6050_ACCEL_FULL_SCALE_RANGE_8    0x02
#define MPU6050_ACCEL_FULL_SCALE_RANGE_16   0x03

// Interrupt values:
#define MPU6050_INTMODE_ACTIVEHIGH          0x00
#define MPU6050_INTMODE_ACTIVELOW           0x01
#define MPU6050_INTDRV_PUSHPULL             0x00
#define MPU6050_INTDRV_OPENDRAIN            0x01
#define MPU6050_INTLATCH_50USPULSE          0x00
#define MPU6050_INTLATCH_WAITCLEAR          0x01
#define MPU6050_INTCLEAR_STATUSREAD         0x00
#define MPU6050_INTCLEAR_ANYREAD            0x01

// Clock sources:
#define MPU6050_CLOCK_INTERNAL              0x00
#define MPU6050_CLOCK_PLL_XGYRO             0x01
#define MPU6050_CLOCK_PLL_YGYRO             0x02
#define MPU6050_CLOCK_PLL_ZGYRO             0x03
#define MPU6050_CLOCK_PLL_EXTERNAL_32K      0x04
#define MPU6050_CLOCK_PLL_EXTERNAL_19M      0x05
#define MPU6050_CLOCK_KEEP_RESET            0x07

// Wake frequencies:
#define MPU6050_WAKE_FREQ_1P25              0x0
#define MPU6050_WAKE_FREQ_2P5               0x1
#define MPU6050_WAKE_FREQ_5                 0x2
#define MPU6050_WAKE_FREQ_10                0x3

// Decrement values:
#define MPU6050_DETECT_DECREMENT_RESET      0x0
#define MPU6050_DETECT_DECREMENT_1          0x1
#define MPU6050_DETECT_DECREMENT_2          0x2
#define MPU6050_DETECT_DECREMENT_4          0x3

// External sync values:
#define MPU6050_EXT_SYNC_DISABLED           0x0
#define MPU6050_EXT_SYNC_TEMP_OUT_L         0x1
#define MPU6050_EXT_SYNC_GYRO_XOUT_L        0x2
#define MPU6050_EXT_SYNC_GYRO_YOUT_L        0x3
#define MPU6050_EXT_SYNC_GYRO_ZOUT_L        0x4
#define MPU6050_EXT_SYNC_ACCEL_XOUT_L       0x5
#define MPU6050_EXT_SYNC_ACCEL_YOUT_L       0x6
#define MPU6050_EXT_SYNC_ACCEL_ZOUT_L       0x7

// Clock division values:
#define MPU6050_CLOCK_DIV_348               0x0
#define MPU6050_CLOCK_DIV_333               0x1
#define MPU6050_CLOCK_DIV_320               0x2
#define MPU6050_CLOCK_DIV_308               0x3
#define MPU6050_CLOCK_DIV_296               0x4
#define MPU6050_CLOCK_DIV_286               0x5
#define MPU6050_CLOCK_DIV_276               0x6
#define MPU6050_CLOCK_DIV_267               0x7
#define MPU6050_CLOCK_DIV_258               0x8
#define MPU6050_CLOCK_DIV_500               0x9
#define MPU6050_CLOCK_DIV_471               0xA
#define MPU6050_CLOCK_DIV_444               0xB
#define MPU6050_CLOCK_DIV_421               0xC
#define MPU6050_CLOCK_DIV_400               0xD
#define MPU6050_CLOCK_DIV_381               0xE
#define MPU6050_CLOCK_DIV_364               0xF

// CONFIG bits and lengths:
#define MPU6050_CFG_EXT_SYNC_SET_BIT        5
#define MPU6050_CFG_EXT_SYNC_SET_LENGTH     3
#define MPU6050_CFG_DLPF_CFG_BIT            2
#define MPU6050_CFG_DLPF_CFG_LENGTH         3

// GYRO_CONFIG bits and lengths:
#define MPU6050_GCONFIG_FS_SEL_BIT          4
#define MPU6050_GCONFIG_FS_SEL_LENGTH       2

// ACCEL_CONFIG bits and lengths:
#define MPU6050_ACONFIG_XA_ST_BIT           7
#define MPU6050_ACONFIG_YA_ST_BIT           6
#define MPU6050_ACONFIG_ZA_ST_BIT           5
#define MPU6050_ACONFIG_AFS_SEL_BIT         4
#define MPU6050_ACONFIG_AFS_SEL_LENGTH      2
#define MPU6050_ACONFIG_ACCEL_HPF_BIT       2
#define MPU6050_ACONFIG_ACCEL_HPF_LENGTH    3

// FIFO_EN bits:
#define MPU6050_TEMP_FIFO_EN_BIT            7
#define MPU6050_XG_FIFO_EN_BIT              6
#define MPU6050_YG_FIFO_EN_BIT              5
#define MPU6050_ZG_FIFO_EN_BIT              4
#define MPU6050_ACCEL_FIFO_EN_BIT           3
#define MPU6050_SLV2_FIFO_EN_BIT            2
#define MPU6050_SLV1_FIFO_EN_BIT            1
#define MPU6050_SLV0_FIFO_EN_BIT            0

// I2C_MST_CTRL bits and lengths:
#define MPU6050_MULT_MST_EN_BIT             7
#define MPU6050_WAIT_FOR_ES_BIT             6
#define MPU6050_SLV_3_FIFO_EN_BIT           5
#define MPU6050_I2C_MST_P_NSR_BIT           4
#define MPU6050_I2C_MST_CLK_BIT             3
#define MPU6050_I2C_MST_CLK_LENGTH          4

// I2C_SLV* bits and lengths:
#define MPU6050_I2C_SLV_RW_BIT              7
#define MPU6050_I2C_SLV_ADDR_BIT            6
#define MPU6050_I2C_SLV_ADDR_LENGTH         7
#define MPU6050_I2C_SLV_EN_BIT              7
#define MPU6050_I2C_SLV_BYTE_SW_BIT         6
#define MPU6050_I2C_SLV_REG_DIS_BIT         5
#define MPU6050_I2C_SLV_GRP_BIT             4
#define MPU6050_I2C_SLV_LEN_BIT             3
#define MPU6050_I2C_SLV_LEN_LENGTH          4

// I2C_SLV4 bits and lenghts:
#define MPU6050_I2C_SLV4_RW_BIT             7
#define MPU6050_I2C_SLV4_ADDR_BIT           6
#define MPU6050_I2C_SLV4_ADDR_LENGTH        7
#define MPU6050_I2C_SLV4_EN_BIT             7
#define MPU6050_I2C_SLV4_INT_EN_BIT         6
#define MPU6050_I2C_SLV4_REG_DIS_BIT        5
#define MPU6050_I2C_SLV4_MST_DLY_BIT        4
#define MPU6050_I2C_SLV4_MST_DLY_LENGTH     5

// I2C_MST_STATUS bits:
#define MPU6050_MST_PASS_THROUGH_BIT        7
#define MPU6050_MST_I2C_SLV4_DONE_BIT       6
#define MPU6050_MST_I2C_LOST_ARB_BIT        5
#define MPU6050_MST_I2C_SLV4_NACK_BIT       4
#define MPU6050_MST_I2C_SLV3_NACK_BIT       3
#define MPU6050_MST_I2C_SLV2_NACK_BIT       2
#define MPU6050_MST_I2C_SLV1_NACK_BIT       1
#define MPU6050_MST_I2C_SLV0_NACK_BIT       0

// INT_PIN_CFG bits:
#define MPU6050_INTCFG_INT_LEVEL_BIT        7
#define MPU6050_INTCFG_INT_OPEN_BIT         6
#define MPU6050_INTCFG_LATCH_INT_EN_BIT     5
#define MPU6050_INTCFG_INT_RD_CLEAR_BIT     4
#define MPU6050_INTCFG_FSYNC_INT_LEVEL_BIT  3
#define MPU6050_INTCFG_FSYNC_INT_EN_BIT     2
#define MPU6050_INTCFG_I2C_BYPASS_EN_BIT    1
#define MPU6050_INTCFG_CLKOUT_EN_BIT        0

// INT_ENABLE and INT_STATUS bits:
#define MPU6050_INTERRUPT_FF_BIT            7
#define MPU6050_INTERRUPT_MOT_BIT           6
#define MPU6050_INTERRUPT_ZMOT_BIT          5
#define MPU6050_INTERRUPT_FIFO_OFLOW_BIT    4
#define MPU6050_INTERRUPT_I2C_MST_INT_BIT   3
#define MPU6050_INTERRUPT_PLL_RDY_INT_BIT   2
#define MPU6050_INTERRUPT_DMP_INT_BIT       1
#define MPU6050_INTERRUPT_DATA_RDY_BIT      0

// MOT_DETECT_STATUS bits:
#define MPU6050_MOTION_MOT_XNEG_BIT         7
#define MPU6050_MOTION_MOT_XPOS_BIT         6
#define MPU6050_MOTION_MOT_YNEG_BIT         5
#define MPU6050_MOTION_MOT_YPOS_BIT         4
#define MPU6050_MOTION_MOT_ZNEG_BIT         3
#define MPU6050_MOTION_MOT_ZPOS_BIT         2
#define MPU6050_MOTION_MOT_ZRMOT_BIT        0

// I2C_MST_DELAY_CTRL bits:
#define MPU6050_DLYCTRL_DELAY_ES_SHADOW_BIT 7
#define MPU6050_DLYCTRL_I2C_SLV4_DLY_EN_BIT 4
#define MPU6050_DLYCTRL_I2C_SLV3_DLY_EN_BIT 3
#define MPU6050_DLYCTRL_I2C_SLV2_DLY_EN_BIT 2
#define MPU6050_DLYCTRL_I2C_SLV1_DLY_EN_BIT 1
#define MPU6050_DLYCTRL_I2C_SLV0_DLY_EN_BIT 0

// SIGNAL_PATH_RESET bits:
#define MPU6050_PATHRESET_GYRO_RESET_BIT    2
#define MPU6050_PATHRESET_ACCEL_RESET_BIT   1
#define MPU6050_PATHRESET_TEMP_RESET_BIT    0

// MOT_DETECT_CTRL bits and lengths:
#define MPU6050_DETECT_ACCEL_DELAY_BIT      5
#define MPU6050_DETECT_ACCEL_DELAY_LENGTH   2
#define MPU6050_DETECT_FF_COUNT_BIT         3
#define MPU6050_DETECT_FF_COUNT_LENGTH      2
#define MPU6050_DETECT_MOT_COUNT_BIT        1
#define MPU6050_DETECT_MOT_COUNT_LENGTH     2

// USER_CTRL bits:
#define MPU6050_USERCTRL_DMP_EN_BIT         7
#define MPU6050_USERCTRL_FIFO_EN_BIT        6
#define MPU6050_USERCTRL_I2C_MST_EN_BIT     5
#define MPU6050_USERCTRL_I2C_IF_DIS_BIT     4
#define MPU6050_USERCTRL_DMP_RESET_BIT      3
#define MPU6050_USERCTRL_FIFO_RESET_BIT     2
#define MPU6050_USERCTRL_I2C_MST_RESET_BIT  1
#define MPU6050_USERCTRL_SIG_COND_RESET_BIT 0

// PWR_MGMT_1 bits and lengths:
#define MPU6050_PWR1_DEVICE_RESET_BIT       7
#define MPU6050_PWR1_SLEEP_BIT              6
#define MPU6050_PWR1_CYCLE_BIT              5
#define MPU6050_PWR1_TEMP_DIS_BIT           3
#define MPU6050_PWR1_CLKSEL_BIT             2
#define MPU6050_PWR1_CLKSEL_LENGTH          3

// PWR_MGMT_2 bits and lengths:
#define MPU6050_PWR2_LP_WAKE_CTRL_BIT       7
#define MPU6050_PWR2_LP_WAKE_CTRL_LENGTH    2
#define MPU6050_PWR2_STBY_XA_BIT            5
#define MPU6050_PWR2_STBY_YA_BIT            4
#define MPU6050_PWR2_STBY_ZA_BIT            3
#define MPU6050_PWR2_STBY_XG_BIT            2
#define MPU6050_PWR2_STBY_YG_BIT            1
#define MPU6050_PWR2_STBY_ZG_BIT            0

// WHO_AM_I bit and length:
#define MPU6050_WHO_AM_I_BIT                6
#define MPU6050_WHO_AM_I_LENGTH             6

// Undocumented bits and lengths:
#define MPU6050_TC_PWR_MODE_BIT             7
#define MPU6050_TC_OFFSET_BIT               6
#define MPU6050_TC_OFFSET_LENGTH            6
#define MPU6050_TC_OTP_BNK_VLD_BIT          0
#define MPU6050_DMPINT_5_BIT                5
#define MPU6050_DMPINT_4_BIT                4
#define MPU6050_DMPINT_3_BIT                3
#define MPU6050_DMPINT_2_BIT                2
#define MPU6050_DMPINT_1_BIT                1
#define MPU6050_DMPINT_0_BIT                0

typedef struct _mpu6050_acceleration_t
{
    int16_t accel_x;
    int16_t accel_y;
    int16_t accel_z;
} mpu6050_acceleration_t;

typedef struct _mpu6050_rotation_t
{
    int16_t gyro_x;
    int16_t gyro_y;
    int16_t gyro_z;
} mpu6050_rotation_t;

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
mpu6050_handle_t iot_mpu6050_create(i2c_bus_handle_t bus, uint16_t dev_addr);

/**
 * @brief Delete and release a sensor object
 *
 * @param sensor object handle of mpu6050
 * @param del_bus Whether to delete the I2C bus
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t iot_mpu6050_delete(mpu6050_handle_t sensor, bool del_bus);

/**
 * @brief Init the sensor mpu6050
 *
 * @param sensor object handle of mpu6050
 * @param del_bus Whether to delete the I2C bus
 *
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_init(mpu6050_handle_t sensor);

/*
 * @brief Get full-scale gyroscope range. The FS_SEL parameter allows setting
 * the full-scale range of the gyro sensors, as described below:
 *
 * 0 = +/- 250 degrees/sec
 * 1 = +/- 500 degrees/sec
 * 2 = +/- 1000 degrees/sec
 * 3 = +/- 2000 degrees/sec
 *
 * @param sensor object handle of mpu6050
 * @param[out] scale: Current full-scale gyroscope range setting.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_full_scale_gyro_range(mpu6050_handle_t sensor, uint8_t* scale);

/*
 * @brief Set full-scale gyroscope range.
 *
 * @param sensor object handle of mpu6050
 * @param range: New full-scale gyroscope range value.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_set_full_scale_gyro_range(mpu6050_handle_t sensor, uint8_t range);

/*
 * @brief Get full-scale accelerometer range.
 * The FS_SEL parameter allows setting the full-scale range of the accelerometer
 * sensors, as described below:
 *
 * 0 = +/- 2g
 * 1 = +/- 4g
 * 2 = +/- 8g
 * 3 = +/- 16g
 *
 * @param sensor object handle of mpu6050
 * @param[out] range: Current full-scale accelerometer range setting.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_full_scale_accel_range(mpu6050_handle_t sensor, uint8_t* range);

/*
 * @brief Set full-scale accelerometer range.
 *
 * @param sensor object handle of mpu6050
 * @param range: New full-scale accelerometer range setting.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_set_full_scale_accel_range(mpu6050_handle_t sensor, uint8_t range);

/*
 * @brief Get 3-axis accelerometer readings.
 * These registers store the most recent accelerometer measurements.
 * Accelerometer measurements are written to these registers at the Sample Rate
 * as defined in Register 25.
 * The accelerometer measurement registers, along with the temperature
 * measurement registers, gyroscope measurement registers, and external sensor
 * data registers, are composed of two sets of registers: an internal register
 * set and a user-facing read register set.
 * The data within the accelerometer sensors' internal register set is always
 * updated at the Sample Rate. Meanwhile, the user-facing read register set
 * duplicates the internal register set's data values whenever the serial
 * interface is idle. This guarantees that a burst read of sensor registers will
 * read measurements from the same sampling instant. Note that if burst reads
 * are not used, the user is responsible for ensuring a set of single byte reads
 * correspond to a single sampling instant by checking the Data Ready interrupt.
 * Each 16-bit accelerometer measurement has a full scale defined in ACCEL_FS
 * (Register 28). For each full scale setting, the accelerometers' sensitivity
 * per LSB in ACCEL_XOUT is shown in the table below:
 *
 * AFS_SEL | Full Scale Range | LSB Sensitivity
 * --------+------------------+----------------
 * 0       | +/- 2g           | 8192 LSB/mg
 * 1       | +/- 4g           | 4096 LSB/mg
 * 2       | +/- 8g           | 2048 LSB/mg
 * 3       | +/- 16g          | 1024 LSB/mg
 *
 * @param sensor object handle of mpu6050
 * @param data: pointer to acceleration struct.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_acceleration(mpu6050_handle_t sensor, mpu6050_acceleration_t* data);

/*
 * @brief Get X-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] x: X-axis acceleration measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_acceleration_x(mpu6050_handle_t sensor, int16_t* x);

/*
 * @brief Get Y-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] y: Y-axis acceleration measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_acceleration_y(mpu6050_handle_t sensor, int16_t* y);

/*
 * @brief Get Z-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] z: Z-axis acceleration measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_acceleration_z(mpu6050_handle_t sensor, int16_t* z);

/*
 * @brief Get current internal temperature.
 *
 * @param sensor object handle of mpu6050
 * @param[out] temperature: Temperature reading in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_temperature(mpu6050_handle_t sensor, int16_t* temperature);

/*
 * @brief Get 3-axis gyroscope readings.
 * These gyroscope measurement registers, along with the accelerometer
 * measurement registers, temperature measurement registers, and external sensor
 * data registers, are composed of two sets of registers: an internal register
 * set and a user-facing read register set.
 * The data within the gyroscope sensors' internal register set is always
 * updated at the Sample Rate. Meanwhile, the user-facing read register set
 * duplicates the internal register set's data values whenever the serial
 * interface is idle. This guarantees that a burst read of sensor registers will
 * read measurements from the same sampling instant. Note that if burst reads
 * are not used, the user is responsible for ensuring a set of single byte reads
 * correspond to a single sampling instant by checking the Data Ready interrupt.
 * Each 16-bit gyroscope measurement has a full scale defined in FS_SEL
 * (Register 27). For each full scale setting, the gyroscopes' sensitivity per
 * LSB in GYRO_xOUT is shown in the table below:
 *
 * FS_SEL | Full Scale Range   | LSB Sensitivity
 * -------+--------------------+----------------
 * 0      | +/- 250 degrees/s  | 131 LSB/deg/s
 * 1      | +/- 500 degrees/s  | 65.5 LSB/deg/s
 * 2      | +/- 1000 degrees/s | 32.8 LSB/deg/s
 * 3      | +/- 2000 degrees/s | 16.4 LSB/deg/s
 *
 * @param sensor object handle of mpu6050
 * @param data: pointer to rotation struct.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_rotation(mpu6050_handle_t sensor, mpu6050_rotation_t* data);

/*
 * @brief Get X-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] x: X-axis rotation measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_rotation_x(mpu6050_handle_t sensor, int16_t* x);

/*
 * @brief Get Y-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] y: Y-axis rotation measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_rotation_y(mpu6050_handle_t sensor, int16_t* y);

/*
 * @brief Get Z-axis accelerometer reading.
 *
 * @param sensor object handle of mpu6050
 * @param[out] z: Z-axis rotation measurement in 16-bit 2's complement format.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_rotation_z(mpu6050_handle_t sensor, int16_t* z);

/*
 * @brief Get raw 6-axis motion sensor readings (accel/gyro).
 * Retrieves all currently available motion sensor values.
 *
 * @param sensor object handle of mpu6050
 * @param data_accel: pointer to acceleration struct.
 * @param data_gyro: pointer to rotation struct.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_motion(mpu6050_handle_t sensor, mpu6050_acceleration_t* data_accel, mpu6050_rotation_t* data_gyro);

/*
 * @brief Get the identity of the device that is stored in the WHO_AM_I
 * register. The device ID is 6 bits (Should be 0x34).
 * 
 * @param sensor object handle of mpu6050
 * @param id: device id.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_get_device_id(mpu6050_handle_t sensor, uint8_t* id);

/*
 * @brief Set sleep mode status.
 *
 * @param sensor object handle of mpu6050
 * @param enabled: New sleep mode enabled status.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_set_sleep_enabled(mpu6050_handle_t sensor, bool enabled);

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
 * @param sensor object handle of mpu6050
 * @param source: New clock source setting.
 * 
 * @return
 *     - ESP_OK Success
 *     - ESP_FAIL Fail
 */
esp_err_t mpu6050_set_clock_source (mpu6050_handle_t sensor, uint8_t source);

#ifdef __cplusplus
}
#endif

#endif