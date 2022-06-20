# ESP Azure IoT SDK

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#get-started)
- [Creating an Azure IoT Device](#create-device)
- [Monitoring Results](#monitoring)
- [Troubleshooting](#troubleshooting)

## 2021 Update

<a name="2021 update"></a>

Since this library has been published, Microsoft has created newer versions of the Azure SDK for usage with the Espressif ESP32. This new library is better suited for microcontrollers, great for composition with your own network stack and officially supported by Microsoft. 

The first one, [Azure IoT middleware for FreeRTOS](https://github.com/Azure/azure-iot-middleware-freertos), is based on ESP-IDF and FreeRTOS and it has [samples](https://github.com/Azure-Samples/iot-middleware-freertos-samples) for IoT Hub and IoT Central using the device provisioning service (DPS).

The second one is based on [Azure IoT for C library for Arduino](https://github.com/Azure/azure-sdk-for-c-arduino) and also has samples for IoT Hub. 

If you can, **avoid using this library for any new projects**.  

## Introduction

<a name="introduction"></a>

The ESP Azure IoT SDK is based on [Azure IoT C SDK](https://github.com/Azure/azure-iot-sdk-c) and enables users to connect their ESP32 based devices to the Azure IoT hub. It provides some examples which can help understand most common use cases.

## Getting Started

<a name="get-started"></a>

### Hardware

You will basically just need a development host and an [ESP32 development board](https://www.espressif.com/en/products/hardware/development-boards) to get started.

### Development Host Setup

This project is to be used with Espressif's IoT Development Framework, [ESP IDF](https://github.com/espressif/esp-idf). Follow these steps to get started:

- Setup ESP IDF development environment by following the steps [here](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html).
- In a separate folder, clone the esp-azure project as follows (please note the --recursive option, which is required to clone the various git submodules required by esp-azure)

``` bash
$ git clone --recursive https://github.com/espressif/esp-azure.git
```

> Note that if you ever change the branch or the git head of either esp-idf or esp-azure, ensure that all the submodules of the git repo are in sync by executing `git submodule update --init --recursive`

##

### Setting up Azure IoT Hub

- Create an Azure IoT Hub by following the documentation [here](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-create-through-portal).

> **Note: When selecting the "Pricing and scale tier", there is also an option to select , F1: Free tier, which should be sufficient for basic evaluation.**

- Copy the IoT Hub `Connection string - primary key` from the Azure IoT Hub. This will be required later. The screenshot below will help you locate it.
![](doc/_static/connection_string.png)
- Connection string - primary key sample:

```
HostName=<azure-iot-hub-name>.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=<base64-encoded-access-key>
```

### Setting up Azure CLI

- Install [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)
- From your terminal, execute the `az` command to verify that the installation was successful. Output will be like this:

```
$ az

Welcome to Azure CLI!
---------------------
Use `az -h` to see available commands or go to https://aka.ms/cli.
...
```

- Install the Azure IoT CLI extension using

`$ az extension add --name azure-cli-iot-ext`

After that, you should be able to use azure CLI to manage your iot-device. A list of useful Azure CLIs can be found [here](doc/azure_cli_iot_hub.md) 

## Creating an Azure IoT Device

<a name="create-device"></a>

- Login to Azure CLI using `$ az login`
- Create a new device using `$ az iot hub device-identity create -n [IoTHub Name] -d [Device ID]`
- Get connection string for your device using `$ az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]`
- Device connection string sample:

```
HostName=<azure-iot-hub-name>.azure-devices.net;DeviceId=<azure-iot-device-id>;SharedAccessKey=<base64-encoded-shared-access-key>
```

- This will be required in the examples



## Monitoring Results

<a name="monitoring"></a>

To see various events and the data being exchanged between the device and IoT hub from your command line, run the following command:

 `$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'`
 
 > Note the single quotes for the connection string. Without them, the command wont work as desired.
 
To monitor activity on your ESP device, run:

 `$ make monitor`

## Troubleshooting
<a name="troubleshooting"></a>

1. Some common problems can be fixed by disabling the firewall.

2. You can try with the followings, if your build fails:
	- `$ git submodule update --init --recursive`
	- Check the compiler version and verify that it is the correct one for your ESP IDF version.
	- Check if the IDF_PATH is set correctly
	- Clean the project with `make clean` and if required, using `rm -rf build sdkconfig sdkconfig.old`
	
3. Ensure that the device connection string received from Azure IoT Hub are correct.
