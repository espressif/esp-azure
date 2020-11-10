// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "azure_c_shared_utility/xlogging.h"

/*Codes_SRS_THREADAPI_FREERTOS_30_001: [ The threadapi_freertos shall implement the method ThreadAPI_Sleep defined in threadapi.h ]*/
#include "azure_c_shared_utility/threadapi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pthread.h"

MU_DEFINE_ENUM_STRINGS(THREADAPI_RESULT, THREADAPI_RESULT_VALUES);

typedef struct THREAD_INSTANCE_TAG
{
    pthread_t Pthread_handle;
    THREAD_START_FUNC ThreadStartFunc;
    void* Arg;
} THREAD_INSTANCE;

static void* ThreadWrapper(void* threadInstanceArg)
{
    THREAD_INSTANCE* threadInstance = (THREAD_INSTANCE*)threadInstanceArg;
    int result = threadInstance->ThreadStartFunc(threadInstance->Arg);
    return (void*)(intptr_t)result;
}

/*Codes_SRS_THREADAPI_FREERTOS_30_002: [ The ThreadAPI_Sleep shall receive a time in milliseconds. ]*/
/*Codes_SRS_THREADAPI_FREERTOS_30_003: [ The ThreadAPI_Sleep shall stop the thread for the specified time. ]*/
void ThreadAPI_Sleep(unsigned int milliseconds)
{
    vTaskDelay((milliseconds * CONFIG_FREERTOS_HZ) / 1000);
}

/*Codes_SRS_THREADAPI_FREERTOS_30_004: [ FreeRTOS is not guaranteed to support threading, so ThreadAPI_Create shall return THREADAPI_ERROR. ]*/
THREADAPI_RESULT ThreadAPI_Create(THREAD_HANDLE* threadHandle, THREAD_START_FUNC func, void* arg)
{
    (void)threadHandle;
    (void)func;
    (void)arg;
    THREADAPI_RESULT result;

    if ((threadHandle == NULL) ||
        (func == NULL))
    {
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
    }
    else
    {
        THREAD_INSTANCE* threadInstance = malloc(sizeof(THREAD_INSTANCE));
        if (threadInstance == NULL)
        {
            result = THREADAPI_NO_MEMORY;
            LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
        }
        else
        {
            threadInstance->ThreadStartFunc = func;
            threadInstance->Arg = arg;
            int createResult = pthread_create(&threadInstance->Pthread_handle, NULL, ThreadWrapper, threadInstance);
            switch (createResult)
            {
            case 0:
                *threadHandle = threadInstance;
                result = THREADAPI_OK;
                break;
            default:
                free(threadInstance);

                result = THREADAPI_ERROR;
                LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
                break;
            }
        }
    }

    return result;
}

/*Codes_SRS_THREADAPI_FREERTOS_30_005: [ FreeRTOS is not guaranteed to support threading, so ThreadAPI_Join shall return THREADAPI_ERROR. ]*/
THREADAPI_RESULT ThreadAPI_Join(THREAD_HANDLE threadHandle, int* res)
{
    (void)threadHandle;
    (void)res;
    THREADAPI_RESULT result;

    THREAD_INSTANCE* threadInstance = (THREAD_INSTANCE*)threadHandle;
    if (threadInstance == NULL)
    {
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
    }
    else
    {
        void* threadResult;
        if (pthread_join(threadInstance->Pthread_handle, &threadResult) != 0)
        {
            result = THREADAPI_ERROR;
            LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
        }
        else
        {
            if (res != NULL)
            {
                *res = (int)(intptr_t)threadResult;
            }

            result = THREADAPI_OK;
        }

        free(threadInstance);
    }

    return result;
}

/*Codes_SRS_THREADAPI_FREERTOS_30_006: [ FreeRTOS is not guaranteed to support threading, so ThreadAPI_Exit shall do nothing. ]*/
void ThreadAPI_Exit(int res)
{
    (void)res;
    pthread_exit((void*)(intptr_t)res);
}
