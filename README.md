# ESP Azure IoT SDK

# Table of Contents

- [Introduction](#introduction)
- [Preparation](#preparation)
- [Configuring and Building](#configuring-and-building)
- [Checking Result](#checking-result)
- [Troubleshooting](#troubleshooting)

## Introduction

<a name="Introduction"></a>

Espressif offers a wide range of fully-certified Wi-Fi & BT modules powered by our own advanced SoCs. For more details, see [Espressif Modules](https://www.espressif.com/en/products/hardware/modules).

Azure cloud is one of the most wonderful clouds that collects data from lots of devices or pushes data to IoT devices. For more details, see [Azure IoT Hub](https://www.azure.cn/en-us/home/features/iot-hub/).

This demo demonstrates how to firstly connect your device (ESP devices or IoT devices with ESP devices inside) to Azure, using MQTT protocol, then send data to Azure as well as receive message from Azure. 

Main workflow:

 ![esp-azure-workflow](doc/_static/esp-azure-workflow.png)

## Preparation 

<a name="preparation"></a>

### 1. Hardware

- An **ubuntu environment** should be set up to build your demo;
- Any **[ESP device](https://www.espressif.com/en/products/hardware/modules)** can be used to run your demo.

### 2. Azure IoT Hub

- [Get iothub connection string (primary key)](https://azure.microsoft.com/en-in/services/iot-hub/) from the Azure IoT Hub, which will be used later. An example can be seen below:

```
HostName=yourname-ms-lot-hub.azure-devices.cn;SharedAccessKeyName=iothubowner;SharedAccessKey=zMeLQ0JTlZXVcHBVOwRFVmlFtcCz+CtbDpUPBWexbIY=
```
- For step-by-step instructions, please click [here](doc/IoT_Suite.md).

### 3. Azure CLI

- Install [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)

After that, you should be able to use azure CLI to manage your iot-device.

### 4. Device Connection String

- login to Azure CLI
- create your device, and get a **device connection string**. An example can be seen:

``` 
"HostName=esp-hub.azure-devices.net;DeviceId=yourdevice;SharedAccessKey=L7tvFTjFuVTQHtggEtv3rp+tKEJzQLLpDnO0edVGKCg=";
```

For detailed instruction, please click [Here](doc/azure_cli_iot_hub.md).
 
### 5. SDK

- [AZURE-SDK](https://github.com/espressif/esp-azure) can be implemented to connect your ESP devices to Azure, using MQTT protocol.
- Espressif SDK
  - For ESP32 platform: [ESP-IDF](https://github.com/espressif/esp-idf)  
  - For ESP8266 platform: [ESP8266_RTOS_SDK](https://github.com/espressif/ESP8266_RTOS_SDK)

### 6. Compiler

- For ESP32 platform: [Here](https://github.com/espressif/esp-idf/blob/master/README.md)
- For ESP8266 platform: [Here](https://github.com/espressif/ESP8266_RTOS_SDK/blob/master/README.md)

## Configuring and Building

<a name="Configuring_and_Building"></a>

### 1. Cloning Git submodules

This repo uses [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) for its dependancies. To successfully clone these other repositories, after cloning this repo, use the following command in the root:

``` bash
git submodule update --init --recursive
```

## Checking Result

<a name="Checking_Result"></a>

Please check results on both the iothub and device side:

- az iot hub monitor-events -n [IoTHub Name] --login 'HostName=myhub.azuredevices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=12345'

- ESP device: monitor events with command `make monitor`

ESP device would send data to the Azure cloud, and then you would be able to receive data at the iothub side.

## Troubleshooting
<a name="Troubleshooting"></a>

1. Some common problems can be fixed by disabling the firewall.

2. You can try with the followings, if your build fails:
	- git submodule init
	- git submodule update
	- export your compiler path 
	- export your IDF path
	- get start from [Here](https://www.espressif.com/en/support/download/documents)
	
3. Make sure the device connection string you are using, which you get from Azure IoT Hub, is correct.
