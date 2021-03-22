# Azure Provisioning Demo

This example demonstrates Device Authentication using Symmetric Keys. Refer [this azure documentation](https://docs.microsoft.com/en-us/azure/iot-dps/concepts-symmetric-key-attestation) to learn more about this.

# Provisioning Setup

### Device Provisioning Service

- In the upper left-hand corner of the Azure portal, click Create a resource.
- In the Search box, type "device provisioning" and select `IoT Hub Device Provisioning Service` from the suggestions.
- Fill out the IoT Hub Device Provisioning Service form and click "Create" at the bottom.
- Select this newly created resource, select `Linked IoT hubs` under `Settings` and click on `Add`.
- In the Add link to IoT hub page
	- IoT hub: Select the IoT hub that you want to link with this Device Provisioning Service instance.
   - Access Policy: Select `iothubowner`.
- Go to `Manage Enrollments` under `Settings` and click on `Add individual enrollment`.
- Select Mechanism as "Symmetric Key".
- Enter name under which device will attempt to register under "Registration ID"
- Enter the appropriate IoT Hub Device ID. Mark IoT Edge device as "False".
- Click "Save" at the top.

## Device Configuration

- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up.

> Note: While changing the value, please ensure that you have completely cleared the older value, before pasting the new one. If you face any run time connection issues, double check this value.

- Enter the `Device registration ID` which was set during [device provisioning](#device-provisioning-service)
- Copy the `Primary Key` of the device, which you can find under "Manage Enrollments" section of the service, select "Individual enrollments", then the enrollment you just created
- Copy the ID Scope of the device provisioning service which you can find on the Azure portal under "Overview" section of the service and paste in `ID Scope` field.
- Save and exit `menuconfig`.

## Trying out the example

- Run the following command to flash the example and monitor the output

``` bash
$ make -j8 flash monitor
```

- In a separate window, monitor the Azure IoT events using the following:

```
$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'
```

- Once the device connects to the Wi-Fi network, it starts publishing MQTT messages. The Azure IoT monitor will show these messages like below:

```
{
    "event": {
        "origin": "<azure-iot-device-id>",
        "payload": "{ \"message_index\" : \"0\" }"
    }
}
{
    "event": {
        "origin": "<azure-iot-device-id>",
        "payload": "{ \"message_index\" : \"1\" }"
    }
}

```
