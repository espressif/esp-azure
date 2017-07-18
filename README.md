# a MQTT Demo that Connect ESP32 to Azure Cloud 
# Table of Contents
- [Introduction](#Introduction)
- [Part 1: Prerequisites](#prerequisites)
- [Part 2: Prepare your iothub](#prepare)
- [Part 3: SDK and Tools Preparation](tools_prepare)
- [Part 4: Configuring and building](#config_build)
- [Part 5: Result shows](results)
- [TroubleShoot](troubleshoot)

Introduction
------------------------------
###### ESP32 is one of gorgeous ioT device that can interface with other systems to provide Wi-Fi and Bluetooth functionality through the SPI / SDIO or I2C / UART interfaces.for more details, click https://espressif.com/en/products/hardware/esp32/overview
###### Azure cloud is one of wonderful cloud that could collect data from lot device or push data to lot device,for more details, click https://www.azure.cn/home/features/iot-hub/
 **Aim:**
 ##### This page would guide you connecting your device(ESP32 or lot device with ESP32) to Azure by MQTT protocol, and then send data to Azure,receive message from Azure.Main workflow:
 ![ESP32workflow](#https://github.com/ustccw/RepoForShareData/blob/master/Microsoft/AzureData/Photos/ESP32AzureWorkflow.png)
 
 Part 1: Prerequisites
 ------------------------------
- **ubuntu environment** for building your demo.
- **ESP32 device** for running the demo.  
![ESP32 device](#https://github.com/ustccw/RepoForShareData/blob/master/Microsoft/AzureData/Photos/ESP32-DevKitC.png)
 
 
 
 Part 2: Prepare your iothub
 ------------------------------
follow the guide: https://github.com/ustccw/RepoForShareData/blob/master/Microsoft/AzureData/start_Iothub.docx
you would get an **iothub login connect string** like that:
```
HostName=yourname-ms-lot-hub.azure-devices.cn;SharedAccessKeyName=iothubowner;SharedAccessKey=zMeLQ0JTlZXVcHBVOwRFVmlFtcCz+CtbDpUPBWexbIY=
```

 Part 3: SDK and Tools Preparation
 ------------------------------
 #### 3.1 iothub-explorer install
 The iothub-explorer tool enables you to provision, monitor, and delete devices in your IoT hub. It runs on any operating system where Node.js is available.
- Download and install Node.js from here.  https://nodejs.org/en/
- From a command line (Command Prompt on Windows, or Terminal on Mac OS X), execute the following:
  ```
    npm install -g iothub-explorer
  ```
##### if success, you can get version information like:
```shell
$ node -v
v6.9.5
$ iothub-explorer -V
1.1.6
```
##### if failed,please click http://thinglabs.io/workshop/esp8266/setup-azure-iot-hub/
  
##### after finished:
then you can use your iothub-explorer to manager your iot-device.click https://github.com/ustccw/RepoForShareData/blob/master/Microsoft/AzureData/iothub-explorer  

login with:   **iothub login connect string** that gets from Part 2

then you can get one **device connect string** after you create one device like that:
```
"HostName=esp-hub.azure-devices.net;DeviceId=yourdevice;SharedAccessKey=L7tvFTjFuVTQHtggEtv3rp+tKEJzQLLpDnO0edVGKCg=";
```
keep this **device connect string** in mind.

  
 #### 3.2 SDK get
 you can get AZURE-SDK from https://github.com/ustccw/AzureESP32  
 this SDK can implement that connect ESP32 to Azure by MQTT protocol.  
 you can get IDF-SDK from https://github.com/espressif/esp-idf  
 this SDK can make ESP32 work well  

 #### 3.3 Compiler get
 follow the guide: http://esp-idf.readthedocs.io/en/latest/get-started/linux-setup.html
 
 
 Part 4: Configuring and building
 ------------------------------
### 4.1 Update Variables
[/examples/project_template/user/iothub_client_sample_mqtt.c](#)

Update the connectionString variable to the device-specific connection string you got earlier from the Setup Azure IoT step:
```
static const char* connectionString = '[azure connection string]'
```
The azure connection string contains Hostname, DeviceId, and SharedAccessKey in the format:
```
"HostName=<host_name>;DeviceId=<device_id>;SharedAccessKey=<device_key>"
 ```
 ### 4.2 config your Wifi
 ```
 make menuconfig
 ```
 choose example configuration to **set Wifi SSID and Password!**
 
 ### 4.3 build your demo and flash to ESP32
 ```
 $make flash
 ```
 if failed,try:
 - make sure that ESP32 had connect to PC by serial port 
 - make sure you flash to correct serial port
 - try type command:
   > sudo usermod -a -G dialout $USER
 
Part 5: Result shows
 ------------------------------
login iothub-explorer,and monitor events:
```
iothub-explorer monitor-events AirConditionDevice_001 --login 'HostName=youriothub-ms-lot-hub.azure-devices.cn;SharedAccessKeyName=iothubowner;SharedAccessKey=zMeLQ0JTlZXVcHBVOwRFVmlFtcCz+CtbDpUPBWexbIY='
```
-  restart ESP32 after bin had flashed,you would see the ESP32 send data to lothub-explorer by minicom,and iothub-explorer would receive data!
- At the same time,you can send message to ESP32 by iothub-explorer until you send a quit message

 TroubleShoot
 ------------------------------
 - close some firewall settings
 - build failed,try:
   - git submodule init
   - git submodule update
   - export your compiler path 
   - export your SDK path
   - get start with http://espressif.com/en/support/download/documents?keys=&field_type_tid%5B%5D=13
 - make sure you had input correct device connect-string which get from Part 3
 
