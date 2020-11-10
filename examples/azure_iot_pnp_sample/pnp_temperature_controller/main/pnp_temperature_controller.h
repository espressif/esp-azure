// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PNP_TEMPERATURE_CONTROLLER_H
#define PNP_TEMPERATURE_CONTROLLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

/* FreeRTOS event group to signal when we are connected & ready to make a request */
extern EventGroupHandle_t wifi_event_group;
extern const int CONNECTED_BIT;

int pnp_temperature_controller(void);

#ifdef __cplusplus
}
#endif

#endif /* PNP_TEMPERATURE_CONTROLLER_H */
