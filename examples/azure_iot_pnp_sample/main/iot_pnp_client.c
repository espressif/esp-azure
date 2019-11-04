#include <stdio.h>

#include "driver/i2c.h"
#include "esp_system.h"

#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/xlogging.h"
#include "pnp_device.h"

// IoT Central requires DPS.  Include required header and constants
#include "azure_prov_client/iothub_security_factory.h"
#include "azure_prov_client/prov_device_ll_client.h"
#include "azure_prov_client/prov_transport_mqtt_client.h"
#include "azure_prov_client/prov_security_factory.h"

static const char *certificates = NULL;

static bool iotHubConnected = false;
// State of DPS registration process.  We cannot proceed with DPS until we get into the state APP_DPS_REGISTRATION_SUCCEEDED.
typedef enum APP_DPS_REGISTRATION_STATUS_TAG
{
    APP_DPS_REGISTRATION_PENDING,
    APP_DPS_REGISTRATION_SUCCEEDED,
    APP_DPS_REGISTRATION_FAILED
} APP_DPS_REGISTRATION_STATUS;

const SECURE_DEVICE_TYPE secureDeviceTypeForProvisioning = SECURE_DEVICE_TYPE_SYMMETRIC_KEY;
const IOTHUB_SECURITY_TYPE secureDeviceTypeForIotHub = IOTHUB_SECURITY_TYPE_SYMMETRIC_KEY;

// The DPS global device endpoint
static const char *globalDpsEndpoint = "global.azure-devices-provisioning.net";

// TODO: Specify DPS scope ID if you intend on using DPS / IoT Central.
static const char *dpsIdScope = CONFIG_DPS_ID_SCOPE;

// TODO: Specify symmetric keys if you intend on using DPS / IoT Central and symmetric key based auth.
static const char *sasKey = CONFIG_DPS_SYMMETRIC_KEY; //"[DPS symmetric key]";

// TODO: specify your device registration ID
static const char *registrationId = CONFIG_DEVICE_REGISTRATION_ID; //"[device registration Id]";

// TODO: Fill in DIGITALTWIN_DEVICE_CAPABILITY_MODEL_INLINE_DATA if want to make deivce self-describing.
 #define DIGITALTWIN_DEVICE_CAPABILITY_MODEL_INLINE_DATA "{}"

static const char *digitalTwinSample_CustomProvisioningData = "{"
                                                              "\"__iot:interfaces\":"
                                                              "{"
                                                                    "\"CapabilityModelId\": \"urn:pebj:esp32AzureKit:1\" ,"
                                                                    "\"CapabilityModel\": \"" DIGITALTWIN_DEVICE_CAPABILITY_MODEL_INLINE_DATA "\""
                                                              "}"
                                                              "}";

// Amount in ms to sleep between querying state from DPS registration loop
#define dpsRegistrationPollSleep 100

// Maximum amount of times we'll poll for DPS registration being ready, 1 min.
#define dpsRegistrationMaxPolls (60 * 1000 / dpsRegistrationPollSleep)

// State of DigitalTwin registration process.  We cannot proceed with DigitalTwin until we get into the state APP_DIGITALTWIN_REGISTRATION_SUCCEEDED.
typedef enum APP_DIGITALTWIN_REGISTRATION_STATUS_TAG
{
    APP_DIGITALTWIN_REGISTRATION_PENDING,
    APP_DIGITALTWIN_REGISTRATION_SUCCEEDED,
    APP_DIGITALTWIN_REGISTRATION_FAILED
} APP_DIGITALTWIN_REGISTRATION_STATUS;

#define IOT_HUB_CONN_STR_MAX_LEN 512

static char *dpsIotHubUri;
static char *dpsDeviceId;

static void provisioningRegisterCallback(PROV_DEVICE_RESULT register_result, const char *iothub_uri, const char *device_id, void *user_context)
{
    APP_DPS_REGISTRATION_STATUS *appDpsRegistrationStatus = (APP_DPS_REGISTRATION_STATUS *)user_context;

    if (register_result != PROV_DEVICE_RESULT_OK)
    {
        LogError("DPS Provisioning callback called with error state %d", register_result);
        *appDpsRegistrationStatus = APP_DPS_REGISTRATION_FAILED;
    }
    else
    {
        if ((mallocAndStrcpy_s(&dpsIotHubUri, iothub_uri) != 0) ||
            (mallocAndStrcpy_s(&dpsDeviceId, device_id) != 0))
        {
            LogError("Unable to copy provisioning information");
            *appDpsRegistrationStatus = APP_DPS_REGISTRATION_FAILED;
        }
        else
        {
            LogInfo("Provisioning callback indicates success.  iothubUri=%s, deviceId=%s", dpsIotHubUri, dpsDeviceId);
            *appDpsRegistrationStatus = APP_DPS_REGISTRATION_SUCCEEDED;
        }
    }
}

static bool registerDevice(bool traceOn)
{
    PROV_DEVICE_RESULT provDeviceResult;
    PROV_DEVICE_LL_HANDLE provDeviceLLHandle = NULL;
    bool result = false;

    APP_DPS_REGISTRATION_STATUS appDpsRegistrationStatus = APP_DPS_REGISTRATION_PENDING;

    if (IoTHub_Init() != 0)
    {
        LogError("IoTHub_Init failed");
        return false;
    }

    if (prov_dev_set_symmetric_key_info(registrationId, sasKey) != 0)
    {
        LogError("prov_dev_set_symmetric_key_info failed.");
    }
    else if (prov_dev_security_init(secureDeviceTypeForProvisioning) != 0)
    {
        LogError("prov_dev_security_init failed");
    }
    else if ((provDeviceLLHandle = Prov_Device_LL_Create(globalDpsEndpoint, dpsIdScope, Prov_Device_MQTT_Protocol)) == NULL)
    {
        LogError("failed calling Prov_Device_Create");
    }
    else if ((provDeviceResult = Prov_Device_LL_SetOption(provDeviceLLHandle, PROV_OPTION_LOG_TRACE, &traceOn)) != PROV_DEVICE_RESULT_OK)
    {
        LogError("Setting provisioning tracing on failed, error=%d", provDeviceResult);
    }
    else if ((provDeviceResult = Prov_Device_LL_Set_Provisioning_Payload(provDeviceLLHandle, digitalTwinSample_CustomProvisioningData)) != PROV_DEVICE_RESULT_OK)
    {
        LogError("Failed setting provisioning data, error=%d", provDeviceResult);
    }
    else if ((provDeviceResult = Prov_Device_LL_Register_Device(provDeviceLLHandle, provisioningRegisterCallback, &appDpsRegistrationStatus, NULL, NULL)) != PROV_DEVICE_RESULT_OK)
    {
        LogError("Prov_Device_Register_Device failed, error=%d", provDeviceResult);
    }
    else
    {
        // Pulling the registration status
        for (int i = 0; (i < dpsRegistrationMaxPolls) && (appDpsRegistrationStatus == APP_DPS_REGISTRATION_PENDING); i++)
        {
            ThreadAPI_Sleep(dpsRegistrationPollSleep);
            Prov_Device_LL_DoWork(provDeviceLLHandle);
        }

        if (appDpsRegistrationStatus == APP_DPS_REGISTRATION_SUCCEEDED)
        {
            LogInfo("DPS successfully registered.  Continuing on to creation of IoTHub device client handle.");
            result = true;
        }
        else if (appDpsRegistrationStatus == APP_DPS_REGISTRATION_PENDING)
        {
            LogError("Timed out attempting to register DPS device");
        }
        else
        {
            LogError("Error registering device for DPS");
        }
    }

    if (provDeviceLLHandle != NULL)
    {
        Prov_Device_LL_Destroy(provDeviceLLHandle);
    }
    IoTHub_Deinit();

    return result;
}
 
 static void setup()
{
    char buff[IOT_HUB_CONN_STR_MAX_LEN];
    iotHubConnected = false;

    // Initialize device model application
    if (registerDevice(false))
    {
        buff[0] = 0;
        if (secureDeviceTypeForProvisioning == SECURE_DEVICE_TYPE_SYMMETRIC_KEY)
        {
            snprintf(buff, sizeof(buff),
                     "HostName=%s;DeviceId=%s;SharedAccessKey=%s",
                     dpsIotHubUri,
                     dpsDeviceId,
                     sasKey);
        }
        
        if (pnp_device_initialize(buff, certificates) == 0)
        {
            iotHubConnected = true;
            LogInfo("PnP enabled, running...");
        }
    }
}

// main entry point.  Takes one argument, an IoTHub connection string to run the PNP_DEVICE off of.
void pnp_telemetry_task()
{
    setup();
    if (iotHubConnected)
    {
        while (true)
        {
            pnp_device_run();
            ThreadAPI_Sleep(100);
        }
    }

}
