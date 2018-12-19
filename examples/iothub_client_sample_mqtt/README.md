#IoT HUB MQTT Client

# Device Configuration

Run `make menuconfig` -> `Example configuration` to configure IoT MQTT client example

Fetch IoT device connection string
```
az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

## Building your demo and flash to ESP device

Run the following command to flash and monitor the output

``` bash
make -j4 flash monitor
```
