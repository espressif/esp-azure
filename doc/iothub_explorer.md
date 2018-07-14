# iothub-explorer usage

## login	[any operation should login first]
```
iothub-explorer login "HostName=chenwu-ms-lot-hub.azure-devices.cn;SharedAccessKeyName=iothubowner;SharedAccessKey=zMeLQ0JTlZXVcHBVOwRFVmlFtcCz+CtbDpUPBWexbIY="
```

## list all device
```
iothub-explorer list
```

## get special device detail info
```
iothub-explorer get myFirstNodeDevice --connection-string
```

## create one device
```
iothub-explorer create AirConditionDevice_001 --connection-string
```

## delete one device
```
iothub-explorer delete myFirstNodeDevice
```

## monitor your device
```
iothub-explorer monitor-events AirConditionDevice_001 --login 'HostName=chenwu-ms-lot-hub.azure-devices.cn;SharedAccessKeyName=iothubowner;SharedAccessKey=zMeLQ0JTlZXVcHBVOwRFVmlFtcCz+CtbDpUPBWexbIY='
```

## send message to device
```
iothub-explorer send AirConditionDevice_001 "hello,my friends!"
```
```
iothub-explorer send AirConditionDevice_001 quit
```


