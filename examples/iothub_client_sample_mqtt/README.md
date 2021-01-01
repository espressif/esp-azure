# IoT HUB MQTT Client

This demonstrates MQTT send received using Azure IoT.

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


- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up. Set `IOT Hub Device Connection String` with the string copied above

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
        "payload": "{\"deviceId\":\"myFirstDevice\",\"windSpeed\":13.00,\"temperature\":22.00,\"humidity\":67.00}"
    }
}
```

- You can also send MQTT messages to your device by using the following command:

```
$ az iot device c2d-message send -d [Device Id] -n [IoTHub Name] --data [Data_to_Send]
```
The `make monitor` output will print the received messages like below:

```
Received Message [1]
 Message ID: 635fd5a9-70a4-422f-9394-4cda9026c2e1
 Correlation ID: <null>
 Data: <<<Hello World>>> & Size=18
```


