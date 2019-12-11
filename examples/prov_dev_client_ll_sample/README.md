# Azure Provisioning Demo

This example demonstrates Device Authentication using X.509 CA Certificates. Refer [this azure documentation](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-x509ca-overview) to learn more about this.

# Provisioning Setup

### Creating a Device

- We will use the same IoT hub that was created as per the steps in the top level [README](../../README.md#setting-up-azure-iot-hub)
- Go to the IoT Hub. Find and click on "IoT devices" under "Explorers" in the menu bar.
- Click on "New".
- Enter name of your IoT Device in "Device ID".
- Select Authentication type as "X.509 CA Signed".
- Click "Save".


### Certificate Generation
<a name="cert-gen"></a>

- Here certificates will be generated with [OpenSSL](https://www.openssl.org/). Other services can also be used to generate certificates.These commands are UNIX/Linux specific. For other system, these commands may not work.
- [Download](https://www.openssl.org/source/) and install openSSL.
- After the installation is complete, use following commands:
	- Generate Root CA private key

	```
	$ openssl genrsa -out rootCA.key 4096
	```
	- Generate Root CA certificate:

	```
	$ openssl req -x509 -new -key rootCA.key -days 1024 -out rootCA.pem
	```
	> You can keep all parameters at defaults (by pressing enter) except Common Name (CN). Give any user friendly common name to your root CA certificate.
	
	- Generate key for device (we will call it a leaf):
	
	```
	$ openssl genrsa -out leaf_private_key.pem 4096
	```
	- Generate Certificate Signing Request for the device:

	```
	$ openssl req -new -key leaf_private_key.pem -out leaf.csr
	```
	> You can keep all parameters at defaults (by pressing enter) excpet Common Name (CN). **Give the name which was registered in IoT Hub ([Device ID](#creating-a-device)) as the CN.**

	- Generate device certificate (leaf certificate):
	```
	$ openssl x509 -req -in leaf.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out leaf_certificate.pem
	```

### CA Certificate Registration

- Go to previously created IoT Hub and navigate to "Certificates" under "Settings" in menu bar.
- Click on "Add".
- Give a User friendly certificate name and add the `rootCA.pem` which was created in the above steps. Click on "Save".
- Status of this certificate will be "Unverified". To verify this click on the certificate name. Click on `Generate Verification Code` at the bottom under `Certificate Details`. A verification code will be generated, copy it.
- In the terminal, navigate to directory where `rootCA.key` was created and run following command to generate a certificate signing request:

```
	$ openssl req -new -key rootCA.key -out verification.csr
```
> You can keep all parameters at defaults (by pressing enter) except Common Name (CN). **Give the Verification Code copied in previous step as Common Name.**

- Generate Verification Certificate:

```
$ openssl x509 -req -in verification.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out verification_certificate.pem
```
- Upload this certificate on the Azure Portal under `Certificate Details`.

### Device Provisioning Service

- In the upper left-hand corner of the Azure portal, click Create a resource.
- In the Search box, type "device provisioning" and select `IoT Hub Device Provisioning Service` from the suggestions.
- Fill out the IoT Hub Device Provisioning Service form and click "Create" at the bottom.
- Select this newly created resource, select `Linked IoT hubs` under `Settings` and click on `Add`.
- In the Add link to IoT hub page
	- IoT hub: Select the IoT hub that you want to link with this Device Provisioning Service instance.
   - Access Policy: Select `iothubowner`.
- Go to `Manage Enrollments` under `Settings` and click on `Add individual enrollment`.
- Select Mechanism as "X.509".
- Upload device certificate created earlier (`leaf_certificate.pem`) in place of "Primary Certificate". Leave "Secondary Certificate" blank.
- Enter the appropriate IoT Hub Device ID. Mark IoT Edge device as "False".
- Click "Save" at the top.
- Copy device certificate created earlier (`leaf_certificate.pem`) to `main/certs/`.
- Copy private key (`leaf_private_key.pem`) to `main/certs/`.

## Device Configuration

- Execute `make menuconfig`. In the menu, go to `Example Configuration` and configure `WiFi SSID` and `WiFi Password` so that the device can connect to the appropriate Wi-Fi network on boot up.
- Get the IoT Hub connection string using `az iot hub show-connection-string -n <IoT_hub_name>` and paste in `IoT Hub Device Connection String`.

> Note: While changing the value, please ensure that you have completely cleared the older value, before pasting the new one. If you face any run time connection issues, double check this value.

- Enter the `Device leaf certificate common name` which was set during [certificate generation](#certificate-generation)
- Copy the ID Scope of the device provisioning service which you can find on the Azure portal under "Overview" section of the service and paste in `ID Scope` field.
- Save and exit `menuconfig`.

> Note

> In case following error occurs:
> `cp: embed_txt/leaf_private_key
> .pem: Permission denied`
> give apt permissions to `leaf_certificate.pem` 

> eg: `$ cd main/certs/ && chmod 644 leaf_certificate.pem` 

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