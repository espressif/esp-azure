// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/xlogging.h"
#include "lwip/apps/sntp.h"
#include "lwip/apps/sntp_time.h"

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
