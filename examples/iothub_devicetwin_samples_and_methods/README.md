# Device Twin and Direct Method Example

This example demonstrates Device twin and Direct method feature of Azure IoT.


## Device Twin

In this example, we use car object with desired and reported properties as described in the json blob below.

```
Car: {
	"lastOilChangeDate": "<value>",            \\ reported property
	"changeOilReminder": "<value>",	           \\ desired property
	"maker": {                                 \\ reported property 
		"makerName": "<value>",
		"style": "<value>",
		"year": <value>
   	},
	"state": {                                 \\ reported property
		"reported_maxSpeed": <value>,
      	"softwareVersion": <value>,
      	"vanityPlate": "<value>"
    },
    "settings": {                              \\ desired property
    	"desired_maxSpeed": <value>,
    	"location": {
    		"longitude": <value>,
    		"latitude": <value>
    	},
	},
}
```	


### Set Device Twin Desired Properties
Set Device Twin desired properties by navigating to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Device Twin` and paste the following json blob under `desired` property. 

```
"changeOilReminder": "<value>",
"settings": {
	"desired_maxSpeed": <value>,
    "location": {
    	"longitude": <value>,
       "latitude": <value>
    },
},
```

## Device Configuration

Run `make menuconfig` -> `Example configuration` 

Set `wifi SSID` & `wifi passphrase`

Fetch IoT device connection string with azure CLI
```
az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

## Building your demo and flash to ESP device

Run the following command to flash and monitor the output

``` bash
make -j4 flash monitor
```

After running the application, you can check updated properties by navigating to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Device Twin`

## Direct Method Invocation

Navigate to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Direct Method`

Set the `Method Name` as `getCarVIN` and add some payload.

On invoking the method, you should see the following response:

```
{ "Response": "1HGCM82633A004352" }
```




