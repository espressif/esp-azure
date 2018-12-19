# Azure Provisioning Demo

This example demonstrates X509 certificate based device access control to provisioning service.
Refer [this](https://docs.microsoft.com/en-us/azure/iot-dps/concepts-security#controlling-device-access-to-the-provisioning-service-with-x509-certificates) to learn more.

## Provisioning Setup

Follow the [step-by-step tutorial](https://docs.microsoft.com/en-us/azure/iot-dps/#step-by-step-tutorials) to setup the provisioning service.

## Device Leaf certificate and key

Copy Device Leaf certificate to `main/certs/leaf_certificate.pem` and `main/certs/leaf_private_key.pem`

## Device Configuration

Run `make menuconfig` -> `Example configuration` to configure provsioning client example

Fetch `IoT Hub Connection String` from [azure portal](https://portal.azure.com) 
or through Azure CLI by using the following command:

```
az iot hub show-connection-string -n <IoT_hub_name>
```

Fetch Unique Device Provisioning Service ID Scope from azure portal

## Building your demo and flash to ESP device

Run the following command to flash and monitor the output

``` bash
make -j4 flash monitor
```

