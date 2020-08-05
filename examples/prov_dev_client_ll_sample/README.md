# Azure Provisioning Demo

This example demonstrates Device Authentication using `Symmetric Key` Certificates.

# Provisioning Setup

### Creating a Device

- We will use the same IoT hub that was created as per the steps in the top level [README](../../README.md#setting-up-azure-iot-hub)
- Go to the IoT Hub. Find and click on "IoT devices" under "Explorers" in the menu bar.
- Click on "New".
- Enter name of your IoT Device in "Device ID".
- Select Authentication type as "Symmetric key".
- Click "Save".

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
- Enter the appropriate IoT Hub Registration ID.
- Enter the appropriate IoT Hub Device ID. Mark IoT Edge device as "False".
- Click "Save" at the top.

## Device Configuration

- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up.
- Copy the Symmetric Key which you can find on the Azure portal under "Manage enrollments" section of the enrollments in `REGISTRATION ID` and past in `IOT Hub Device Key` filed.

> Note: While changing the value, please ensure that you have completely cleared the older value, before pasting the new one. If you face any run time connection issues, double check this value.

- Enter the `Registration ID` which was set during Select Mechanism.
- Copy the ID Scope and Global device endpoint of the device provisioning service which you can find on the Azure portal under "Overview" section of the service and paste in `ID Scope` and `endpoint` field.
- Save and exit `menuconfig`.

## Trying out the example

- Run the following command to flash the example and monitor the output

``` bash
$ make -j8 flash monitor
```
> Note that the `CONFIG_FREERTOS_UNICORE` is enabled when work on ESP32.

- In a separate window, monitor the Azure IoT events using the following:

```
$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'
```

- Once the device connects to the Wi-Fi network, it starts publishing MQTT messages which include device's properties or not. You can execute `make menuconfig`, go to `Example Configuration` and configure `IOT Hub Device Property`. The Azure IoT monitor will show these messages like below:

	- DISABLE\_IOTHUB_PROPERTY
	
	```
	{
	    "event": {
	        "origin": "<azure-iot-device-id>",
	        "payload": "{ \"Message ID\" : \"0\" }"
	    }
	}
	{
	    "event": {
	        "origin": "<azure-iot-device-id>",
	        "payload": "{ \"Message ID\" : \"1\" }"
	    }
	}
	
	```
	- ENABLE\_IOTHUB_PROPERTY
	
	```
	{
	    "event": {
	        "origin": "<azure-iot-device-id>",
	        "payload": "propertyA=valueApropertyB=valueB{\"Message ID\":0}"
	    }
	}
	{
	    "event": {
	        "origin": "<azure-iot-device-id>",
	        "payload": "propertyA=valueApropertyB=valueB{\"Message ID\":1}"
	    }
	}
	```