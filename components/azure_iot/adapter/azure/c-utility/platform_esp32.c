// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/tlsio_openssl.h"
#include "azure_c_shared_utility/xlogging.h"
#include "apps/sntp/sntp.h"
//#include "lwip/apps/sntp_time.h"
#define TICK_RATE CONFIG_FREERTOS_HZ

time_t sntp_get_current_timestamp();

int platform_init(void)
{
    printf("Initializing SNTP\n");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
    printf("ESP32 sntp init!\n");
    u32_t ts = 1;
    while(ts == 0){
        vTaskDelay(1 * TICK_RATE);
        time_t sntp_time = sntp_get_current_timestamp();;
        ts = (u32_t)sntp_time;

    }
    return 0;
}

const IO_INTERFACE_DESCRIPTION* platform_get_default_tlsio(void)
{
    return tlsio_openssl_get_interface_description();
	return NULL;
}

void platform_deinit(void)
{
      sntp_stop();
}
