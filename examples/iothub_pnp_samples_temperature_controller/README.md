# Azure IoT HUB PNP Demo

This demonstrates the usability of esp-azure API to connect to Azure IoT and start interacting with Azure IoT services like IoTHub and Device Provisioning Service.

## Device Configuration
- For this demo we will use the same Azure IoT device created using the steps defined in top level [README](../../README.md#creating-an-azure-iot-device). Copy the connection string for the device from the output of this command:

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
> While changing the value, please ensure that you have completely cleared the older value, before pasting the new one. If you face any run time connection issues, double check this value.

- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up. 
- Set `IOT Hub Device Host Name` and `IOT Hub Device ID` with the string copied above when you disable Device Provisioning Service. You also need set `IOT Hub Device Key` when choose `Symmetric Key` authenticate which be default.
- Enter the `Registration ID` which was set during Select Mechanism. Copy the ID Scope and Global device endpoint of the device provisioning service which you can find on the Azure portal under "Overview" section of the service and paste in `ID Scope` and `endpoint` field when you enable Device Provisioning Service.

## IoT Hub PnP Sample

Connect a PnP enabled device with the Digital Twin Model ID (DTMI) detailed [here](https://github.com/Azure/opendigitaltwins-dtdl/blob/master/DTDL/v2/samples/Thermostat.json). In short, the capabilities are listed here:

- **Methods**: Invoke a pnp command called ```getMaxMinReport``` with JSON payload value ```"since"``` with an [ISO8601](https://en.wikipedia.org/wiki/ISO_8601) value for start time for the report. The method sends a response containing the following JSON payload:
```
{
  "maxTemp": 20,
  "minTemp": 20,
  "avgTemp": 20,
  "startTime": "<ISO8601 time>",
  "endTime": "<ISO8601 time>"
}
```
with correct values substituted for each field.
- **Telemetry**: Device sends a JSON message with the field name ```temperature``` and the ```double``` value of the temperature.
- **Twin**: Desired property with the field name ```targetTemperature ``` and the ```double``` value for the desired temperature. Reported property with the field name ```maxTempSinceLastReboot``` and the ```double``` value for the highest temperature. Note that part of the PnP spec is a response to a desired property update from the service. The device will send back a reported property with a similarly named property and a set of "ack" values: ```ac``` for the HTTP-like ack code, ```av``` for ack version of the property, and an optional ```ad`` for an ack description.

## Sample PnP Temperature Controller

This directory contains a sample a temperature controller that implements the model [dtmi:com:example:TemperatureController;1](https://github.com/Azure/opendigitaltwins-dtdl/blob/master/DTDL/v2/samples/TemperatureController.json).

The model consists of:

- The ```reboot``` command, ```serialNumber``` property, and ```workingSet``` telemetry that the temperature controller implements on the root interface.
- Two thermostat subcomponents, ```thermostat1``` and ```thermostat2```.
- A ```deviceInfo``` component that reports properties about the device itself.

- Run the following command to flash the example and monitor the output

## Trying out the example

``` bash
$ make -j8 flash monitor
```

> Note that the `CONFIG_FREERTOS_UNICORE` is enabled when work on ESP32.

- In a separate window, monitor the Azure IoT events using the following:

```
$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'
```

- Once the device connects to the Wi-Fi network, it starts publishing MQTT messages which include device's properties or not. The Azure IoT monitor will show these messages like below:
```
{
	"event": {
		 "origin": "<azure-iot-device-id>",
		 "payload": "{\"temperature\":22}"
   }
}
```
- You can also send messages to your device by Azure IoT Hub. The `make monitor` output will print the received messages like below:
	- **Methods**
		```
		Receive method call: GET, with payload:{"workingSet":1433}
		```	
	- **Twin**
		```
			Receive desired property: {"changeOilReminder":"LOW_FUEL","settings":{"desired_maxSpeed":120,"location":{"longitude":71,"latitude":25}},"$version":124}
		```
	