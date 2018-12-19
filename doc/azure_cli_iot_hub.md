# Azure CLI usage

## login	[any operation should login first]
```
az login
```

## list all device
```
az iot hub device-identity list --hub-name [IoTHub Name]
```

## get device connection string
```
az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

## create one device
```
az iot hub device-identity create -n [IoTHub Name] -d [Device ID]
```

## delete one device
```
az iot hub device-identity delete -n [IoTHub Name] -d [Device ID]
```

## monitor your device
```
az iot hub monitor-events -n [IoTHub Name] --login 'HostName=myhub.azuredevices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=12345'
```

## send message to device
```
az iot device c2d-message send -d [Device Id] -n [IoTHub Name]
```


