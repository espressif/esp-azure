// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_attr.h"

#include "lwip/err.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/xlogging.h"

#include "lwip/apps/sntp.h"

#include "agenttime_esp.h"

static unsigned sntp_initialized = 0;

void initialize_sntp(void)
{
	if(!sntp_initialized) {
		printf("Initializing SNTP\n");
		sntp_setoperatingmode(SNTP_OPMODE_POLL);
		sntp_setservername(0, "pool.ntp.org");
		sntp_init();

		sntp_initialized = 1;
	}
}

void finalize_sntp(void)
{
	if(sntp_initialized) {
		printf("Finalizing SNTP\n");
		sntp_stop();

		sntp_initialized = 0;
	}
}

static void obtain_time(void)
{
    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;

    while(timeinfo.tm_year < (2016 - 1900) ) {
        printf("Waiting for system time to be set... tm_year:%d[times:%d]\n", timeinfo.tm_year, ++retry);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        time(&now);
        localtime_r(&now, &timeinfo);
    }
}

time_t sntp_get_current_timestamp()
{
    time_t now;
	struct tm timeinfo;
	time(&now);
	localtime_r(&now, &timeinfo);
	// Is time set? If not, tm_year will be (1970 - 1900).
	if (timeinfo.tm_year < (2016 - 1900)) {
		printf("Time is not set yet. Connecting to WiFi and getting time over NTP. timeinfo.tm_year:%d\n",timeinfo.tm_year);
		obtain_time();
		// update 'now' variable with current time
		time(&now);
	}
	localtime_r(&now, &timeinfo);
	return now;
}
