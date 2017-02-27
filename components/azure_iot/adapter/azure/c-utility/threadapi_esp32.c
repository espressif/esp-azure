// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdint.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/xlogging.h"


DEFINE_ENUM_STRINGS(THREADAPI_RESULT, THREADAPI_RESULT_VALUES);

THREADAPI_RESULT ThreadAPI_Create(THREAD_HANDLE* threadHandle, THREAD_START_FUNC func, void* arg)
{
	LogError("ESP8266 RTOS does not support multi-thread function.");
    return THREADAPI_ERROR;
}

THREADAPI_RESULT ThreadAPI_Join(THREAD_HANDLE threadHandle, int* res)
{
    LogError("ESP8266 RTOS does not support multi-thread function.");
    return THREADAPI_ERROR;
}

void ThreadAPI_Exit(int res)
{
	vTaskDelete(NULL);
}

void ThreadAPI_Sleep(unsigned int milliseconds)
{
	vTaskDelay(milliseconds);
}
