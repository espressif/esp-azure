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
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/xlogging.h"

#ifdef CONFIG_TARGET_PLATFORM_ESP8266
#include "lwip/apps/sntp.h"
#else
#include "apps/sntp/sntp.h"
#endif



void initialize_sntp(void)
{
    printf("Initializing SNTP\n");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
 //    sntp_setservername(1, "202.112.29.82");        // set sntp server after got ip address, you had better to adjust the sntp server to your area
    sntp_init();
}

static void obtain_time(void)
{
    //initialize_sntp();

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
	char strftime_buf[64];

	// Set timezone to China Standard Time
	setenv("TZ", "CST-8CDT-9,M4.2.0/2,M9.2.0/3", 1);
	tzset();
	localtime_r(&now, &timeinfo);
	return now;

}

time_t get_time(time_t* currentTime)
{
    return sntp_get_current_timestamp();

}

double get_difftime(time_t stopTime, time_t startTime)
{	
    return (double)stopTime - (double)startTime;
}

struct tm* get_gmtime(time_t* currentTime)
{
    return NULL;
}

char* get_ctime(time_t* timeToGet)
{
    return NULL;
}
