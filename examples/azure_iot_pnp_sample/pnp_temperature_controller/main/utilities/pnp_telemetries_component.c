// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Standard C header files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// PnP routines
#include "pnp_protocol.h"
#include "pnp_telemetries_component.h"

// Core IoT SDK utilities
#include "azure_c_shared_utility/xlogging.h"

// Serializer utilities
#include "digitaltwin_serializer.h"

// The default temperature to use before any is set
#define DEFAULT_TEMPERATURE_VALUE 22

// Size of buffer to store ISO 8601 time.
#define TIME_BUFFER_SIZE 128

// Format string to create an ISO 8601 time.  This corresponds to the DTDL datetime schema item.
static const char g_ISO8601Format[] = "%Y-%m-%dT%H:%M:%SZ";
// Format string for sending Roll telemetry
static const char g_rollTelemetryBodyFormat[] = "{\"SensorRoll\":%.04f}";
// Format string for sending Pressure telemetry
static const char g_pressureTelemetryBodyFormat[] = "{\"SensorPressure\":%.02f}";
// Format string for sending Pitch telemetry
static const char g_pitchTelemetryBodyFormat[] = "{\"SensorPitch\":%.04f}";
// Format string for sending MagnetZ telemetry
static const char g_magnetZTelemetryBodyFormat[] = "{\"SensorMagnetZ\":%.04f}";
// Format string for sending MagnetY telemetry
static const char g_magnetYTelemetryBodyFormat[] = "{\"SensorMagnetY\":%.04f}";
// Format string for sending MagnetX telemetry
static const char g_magnetXTelemetryBodyFormat[] = "{\"SensorMagnetX\":%.04f}";
// Format string for sending Light telemetry
static const char g_LightTelemetryBodyFormat[] = "{\"SensorLight\":%.02f}";
// Format string for sending Humidity telemetry
static const char g_HumidityTelemetryBodyFormat[] = "{\"SensorHumid\":%.02f}";
// Format string for sending Altitude telemetry
static const char g_AltitudeTelemetryBodyFormat[] = "{\"SensorAltitude\":%.02f}";

// Start time of the program, stored in ISO 8601 format string for UTC
static char g_programStartTime[TIME_BUFFER_SIZE] = {0};

//
// PNP_TELEMETRIES_COMPONENT simulates a telemetries component
// (as in telemetries1 or telemetries2 in the TemperatureController model).  We need separate data structures
// because the components can be independently controlled.
//
typedef struct PNP_TELEMETRIES_COMPONENT_TAG
{
    // Name of this component
    char componentName[PNP_MAXIMUM_COMPONENT_LENGTH + 1];
    // Current temperature of this telemetries component
    double currentTemperature;
    // Minimum temperature this telemetries has been at during current execution run of this telemetries component
    double minTemperature;
    // Maximum temperature telemetries has been at during current execution run of this telemetries component
    double maxTemperature;
    // Number of times temperature has been updated, counting the initial setting as 1.  Used to determine average temperature of this telemetries component
    int numTemperatureUpdates;
    // Total of all temperature updates during current execution run.  Used to determine average temperature of this telemetries component
    double allTemperatures;
}
PNP_TELEMETRIES_COMPONENT;

typedef struct {
    const char *componentName;
    const char *TelemetryBodyFormat;
    bool (*SensorSerializeTelemetry)(char * payloadBuffer, int size);
} telemetry_body_t;

//
// BuildUtcTimeFromCurrentTime writes the current time, in ISO 8601 format, into the specified buffer
//
static bool BuildUtcTimeFromCurrentTime(char* utcTimeBuffer, size_t utcTimeBufferSize)
{
    bool result;
    time_t currentTime;
    struct tm * currentTimeTm;

    time(&currentTime);
    currentTimeTm = gmtime(&currentTime);

    if (strftime(utcTimeBuffer, utcTimeBufferSize, g_ISO8601Format, currentTimeTm) == 0)
    {
        LogError("snprintf on UTC time failed");
        result = false;
    }
    else
    {
        result = true;
    }

    return result;
}


PNP_TELEMETRIES_COMPONENT_HANDLE PnP_TelemetriesComponent_CreateHandle(const char* componentName)
{
    PNP_TELEMETRIES_COMPONENT* telemetriesComponent;

    if (strlen(componentName) > PNP_MAXIMUM_COMPONENT_LENGTH)
    {
        LogError("componentName=%s is too long.  Maximum length is=%d", componentName, PNP_MAXIMUM_COMPONENT_LENGTH);
        telemetriesComponent = NULL;
    }
    // On initial invocation, store the UTC time into g_programStartTime global.
    else if ((g_programStartTime[0] == 0) && (BuildUtcTimeFromCurrentTime(g_programStartTime, sizeof(g_programStartTime)) == false))
    {
        LogError("Unable to store program start time");
        telemetriesComponent = NULL;
    }
    else if ((telemetriesComponent = (PNP_TELEMETRIES_COMPONENT*)calloc(1, sizeof(PNP_TELEMETRIES_COMPONENT))) == NULL)
    {
        LogError("Unable to allocate telemetries");
    }
    else
    {
        strcpy(telemetriesComponent->componentName, componentName);
        telemetriesComponent->currentTemperature = DEFAULT_TEMPERATURE_VALUE;
        telemetriesComponent->maxTemperature = DEFAULT_TEMPERATURE_VALUE;
        telemetriesComponent->minTemperature = DEFAULT_TEMPERATURE_VALUE;
        telemetriesComponent->numTemperatureUpdates = 1;
        telemetriesComponent->allTemperatures = DEFAULT_TEMPERATURE_VALUE;
    }

    return (PNP_TELEMETRIES_COMPONENT_HANDLE)telemetriesComponent;
}

void PnP_TelemetriesComponent_Destroy(PNP_TELEMETRIES_COMPONENT_HANDLE pnpTelemetriesComponentHandle)
{
    if (pnpTelemetriesComponentHandle != NULL)
    {
        free(pnpTelemetriesComponentHandle);
    }
}

void PnP_TelemetriesComponent_SendTelemetry(PNP_TELEMETRIES_COMPONENT_HANDLE pnpTelemetriesComponentHandle, IOTHUB_DEVICE_CLIENT_LL_HANDLE deviceClientLL)
{
    PNP_TELEMETRIES_COMPONENT* pnpTelemetriesComponent = (PNP_TELEMETRIES_COMPONENT*)pnpTelemetriesComponentHandle;
    IOTHUB_MESSAGE_HANDLE messageHandle = NULL;
    IOTHUB_CLIENT_RESULT iothubResult;

    char temperatureStringBuffer[32];
    char payloadBuffer[TIME_BUFFER_SIZE];

    telemetry_body_t telemetry_body[] = {
        {"SensorAltitude",  g_AltitudeTelemetryBodyFormat       , Sensor_SerializeAltitudeTelemetry},
        {"SensorHumid",     g_HumidityTelemetryBodyFormat       , Sensor_SerializeHumidTelemetry},
        {"SensorLight",     g_LightTelemetryBodyFormat          , Sensor_SerializeLightTelemetry},
        {"SensorMagnetX",   g_magnetXTelemetryBodyFormat        , Sensor_SerializeMagnetXTelemetry},
        {"SensorMagnetY",   g_magnetYTelemetryBodyFormat        , Sensor_SerializeMagnetYTelemetry},
        {"SensorMagnetZ",   g_magnetZTelemetryBodyFormat        , Sensor_SerializeMagnetZTelemetry},
        {"SensorPitch",     g_pitchTelemetryBodyFormat          , Sensor_SerializePitchTelemetry},
        {"SensorPressure",  g_pressureTelemetryBodyFormat       , Sensor_SerializePressureTelemetry},
        {"SensorRoll",      g_rollTelemetryBodyFormat           , Sensor_SerializeRollTelemetry},
    };

    const int telemetry_body_table_size = sizeof(telemetry_body) / sizeof(telemetry_body[0]);
    int ret = -1;

    for (int i = 0; i < telemetry_body_table_size; i ++) {
        if (strncmp(telemetry_body[i].componentName, pnpTelemetriesComponent->componentName, strlen(pnpTelemetriesComponent->componentName)) != 0)
            continue;
        
        if (telemetry_body[i].SensorSerializeTelemetry(payloadBuffer, TIME_BUFFER_SIZE)) {
            pnpTelemetriesComponent->currentTemperature = strtof(payloadBuffer, NULL);
            switch(i) {
                case 3:
                case 4:
                case 5:
                    pnpTelemetriesComponent->currentTemperature = pnpTelemetriesComponent->currentTemperature / 10000000;
                break;
                case 6:
                case 8:
                    pnpTelemetriesComponent->currentTemperature = pnpTelemetriesComponent->currentTemperature * 3.1415f;
                    pnpTelemetriesComponent->currentTemperature = pnpTelemetriesComponent->currentTemperature / 180;
                    break;
                default:
                break;
            }
            ret = snprintf(temperatureStringBuffer, sizeof(temperatureStringBuffer), telemetry_body[i].TelemetryBodyFormat, pnpTelemetriesComponent->currentTemperature);
        }
        break;
    }

    if (ret < 0)
    {
        LogError("snprintf of current temperature telemetry failed");
    }
    else if ((messageHandle = PnP_CreateTelemetryMessageHandle(pnpTelemetriesComponent->componentName, temperatureStringBuffer)) == NULL)
    {
        LogError("Unable to create telemetry message");
    }
    else if ((iothubResult = IoTHubDeviceClient_LL_SendEventAsync(deviceClientLL, messageHandle, NULL, NULL)) != IOTHUB_CLIENT_OK)
    {
        LogError("Unable to send telemetry message, error=%d", iothubResult);
    }

    IoTHubMessage_Destroy(messageHandle);
}
