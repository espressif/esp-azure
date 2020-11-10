// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef SENSOR_MANAGER_H
#define SENSOR_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif
    void initialize_sensors();
    float get_temperature();
    float get_humidity();
    float get_ambientLight();
    void oled_show_message(const char *message);
    void oled_update_humiture(float temprature, float humidity);
    void get_pitch_roll(int *pitch,int *roll);
    void get_pressure_altitude(float *pressure,float *altitude);
    void get_magnetometer(int *magnetometerX,int *magnetometerY,int *magnetometerZ);
    bool check_for_shake();
    void stop_motor();
    void start_motor_with_speed(float speed);

#ifdef __cplusplus
}
#endif

#endif /* SENSOR_MANAGER_H */