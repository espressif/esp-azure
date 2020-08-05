# Device Twin and Direct Method Example

This example demonstrates Device twin and Direct method features of Azure IoT.


## Device Twin

In this example, we use default object with desired and reported properties as described in the JSON blob below.

```
{
	"desired":{
		"newProperty":{
			"nestedProperty":"newValue"
		},
		"existingProperty":"otherNewValue",
		"$version":109
	},
	"reported":{
		"sample_report":"OK",
		"$version":92
	}
}
```	


### Set Device Twin Desired Properties

- To execute Device Twin, an IoT device will be required. We will use the same Azure IoT device created using the steps defined in top level [README](../../README.md#creating-an-azure-iot-device).
- Set Device Twin desired properties by navigating to `Azure Portal` -> `your IoT Hub` -> `IoT Devices` -> `your IoT device` -> `Device Twin` and paste the following JSON blob under `desired` property. 

	```
   {
     	"properties": {
         	"desired": {
             	"newProperty": {
                 "nestedProperty": "newValue"
             	},
             "existingProperty": "otherNewValue",
             "otherOldProperty": null
       		}
     	}
	}
	```

## Device Configuration
- For this demo we will use the same Azure IoT device created using the steps defined in top level [README](../../README.md#create_device). Copy the connection string for the device from the output of this command:

``` bash
$ az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

Sample output:
```
{
  "connectionString": "HostName=<azure-iot-hub-name>.azure-devices.net;DeviceId=<azure-iot-device-id>;SharedAccessKey=<base64-encoded-shared-access-key>"
}
```
> Note that the double quotes at both the ends of the string are not part of the connection string. So, for the above, just copy `HostName=<azure-iot-hub-name>.azure-devices.net;DeviceId=<azure-iot-device-id>;SharedAccessKey=<base64-encoded-shared-access-key>`
While changing the value, please ensure that you have completely cleared the older value, before pasting the new one. If you face any run time connection issues, double check this value.

- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up. Set `IOT Hub Device Host Name` and `IOT Hub Device ID` with the string copied above. You also need set `IOT Hub Device Key` when choose `Symmetric Key` authenticate which be default


## Trying out the example

Run the following command to flash the example and monitor the output
`$ make -j8 flash monitor`

> Note that the `CONFIG_FREERTOS_UNICORE` is enabled when work on ESP32.

After running the application, you can check updated properties by navigating to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Device Twin`

If you change the above set desired field and click on "Save", they will be mirrored on to your ESP Monitor.

### Direct Method Invocation


Navigate to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Direct Method`

Set the `Method Name` as `getCarVIN` and add some payload. Consider an example payload as below:

```
Receive method call: GET, with payload:{"message":"Hello World"}
```

On invoking the method, the invocation request will be sent to the IoT device, which in turn will respond with a payload like below:

```
{"status":"OK"}
```




