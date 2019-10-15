# Azure CLI usage

## Login	[Required for using any of the other commands]
```
az login
```

## Create a device
```
az iot hub device-identity create -n [IoTHub Name] -d [Device ID]
```

## List all devices
```
az iot hub device-identity list --hub-name [IoTHub Name]
```

## Get device connection string
```
az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

## Send message to device
```
az iot device c2d-message send -d [Device Id] -n [IoTHub Name] --data [Data_to_Send]
```

## Delete a device
```
az iot hub device-identity delete -n [IoTHub Name] -d [Device ID]
```

## Monitor events
```
az iot hub monitor-events -n [IoTHub Name] --login 'HostName=myhub.azuredevices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=12345'
```

## Additional Information


Additional information for Azure IoT CLI can be found [here](https://docs.microsoft.com/en-us/cli/azure/ext/azure-cli-iot-ext/iot?view=azure-cli-latest)