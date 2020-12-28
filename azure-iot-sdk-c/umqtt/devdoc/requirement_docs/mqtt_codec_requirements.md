# control_packet Requirements

## Overview

mqtt_codec is the library that encapsulates an handling of the control packet  

## Exposed API

```C
typedef struct MQTTCODEC_INSTANCE_TAG* MQTTCODEC_HANDLE;

typedef void(*ON_PACKET_COMPLETE_CALLBACK)(void* context, CONTROL_PACKET_TYPE packet, int flags, BUFFER_HANDLE headerData);

extern MQTTCODEC_HANDLE mqtt_codec_create(ON_PACKET_COMPLETE_CALLBACK packetComplete, void* callbackCtx);
extern void mqtt_codec_destroy(MQTTCODEC_HANDLE handle);

extern BUFFER_HANDLE mqtt_codec_connect(const MQTTCLIENT_OPTIONS* mqttOptions);
extern BUFFER_HANDLE mqtt_codec_disconnect();
extern BUFFER_HANDLE mqtt_codec_publish(QOS_VALUE qosValue, bool duplicateMsg, bool serverRetain, int packetId, const char* topicName, const int8_t* msgBuffer, size_t buffLen);
extern BUFFER_HANDLE mqtt_codec_publishAck(int packetId);
extern BUFFER_HANDLE mqtt_codec_publishRecieved(int packetId);
extern BUFFER_HANDLE mqtt_codec_publishRelease(int packetId);
extern BUFFER_HANDLE mqtt_codec_publishComplete(int packetId);
extern BUFFER_HANDLE mqtt_codec_ping();
extern BUFFER_HANDLE mqtt_codec_subscribe(int packetId, SUBSCRIBE_PAYLOAD* payloadList, size_t payloadCount);
extern BUFFER_HANDLE mqtt_codec_unsubscribe(int packetId, const char** payloadList, size_t payloadCount);

extern int mqtt_codec_bytesReceived(MQTTCODEC_HANDLE handle, const void* buffer, size_t size);
```

## mqtt_codec_create
```
extern MQTTCODEC_HANDLE mqtt_codec_create(ON_PACKET_COMPLETE_CALLBACK packetComplete, void* callbackCtx);
```
**SRS_MQTT_CODEC_07_001: [** If a failure is encountered then mqtt_codec_create shall return NULL. **]**  
**SRS_MQTT_CODEC_07_002: [** On success mqtt_codec_create shall return a MQTTCODEC_HANDLE value. **]** 

## mqtt_codec_destroy
```
extern void mqtt_codec_destroy(MQTTCODEC_HANDLE handle);
```
**SRS_MQTT_CODEC_07_003: [** If the handle parameter is NULL then mqtt_codec_destroy shall do nothing. **]**  
**SRS_MQTT_CODEC_07_004: [** mqtt_codec_destroy shall deallocate all memory that has been allocated by this object. **]**  

## mqtt_codec_connect
```
extern BUFFER_HANDLE mqtt_codec_connect(const MQTTCLIENT_OPTIONS* mqttOptions);
```
**SRS_MQTT_CODEC_07_008: [** If the parameters mqttOptions is NULL then mqtt_codec_connect shall return a null value. **]**  
**SRS_MQTT_CODEC_07_009: [** mqtt_codec_connect shall construct a BUFFER_HANDLE that represents a MQTT CONNECT packet. **]**  
**SRS_MQTT_CODEC_07_010: [** If any error is encountered then mqtt_codec_connect shall return NULL. **]**  

## mqtt_codec_disconnect
```
extern BUFFER_HANDLE mqtt_codec_disconnect();
```
**SRS_MQTT_CODEC_07_011: [** On success mqtt_codec_disconnect shall construct a BUFFER_HANDLE that represents a MQTT DISCONNECT packet. **]**    
**SRS_MQTT_CODEC_07_012: [** If any error is encountered mqtt_codec_disconnect shall return NULL. **]**  

## mqtt_codec_publish
```
extern BUFFER_HANDLE mqtt_codec_publish(QOS_VALUE qosValue, bool duplicateMsg, bool serverRetain, int packetId, const char* topicName, const int8_t* msgBuffer, size_t buffLen);
```
**SRS_MQTT_CODEC_07_005: [** If the parameters topicName, or msgBuffer is NULL or if buffLen is 0 then mqtt_codec_publish shall return NULL. **]**  
**SRS_MQTT_CODEC_07_006: [** If any error is encountered then mqtt_codec_publish shall return NULL. **]**    
**SRS_MQTT_CODEC_07_007: [** mqtt_codec_publish shall return a BUFFER_HANDLE that represents a MQTT PUBLISH message. **]**  
**SRS_MQTT_CODEC_07_036: [** mqtt_codec_publish shall return NULL if the buffLen variable is greater than the MAX_SEND_SIZE (0xFFFFFF7F). **]**

## mqtt_codec_publishAck
```
extern BUFFER_HANDLE mqtt_codec_publishAck(int packetId);
```
**SRS_MQTT_CODEC_07_013: [** On success mqtt_codec_publishAck shall return a BUFFER_HANDLE representation of a MQTT PUBACK packet. **]**    
**SRS_MQTT_CODEC_07_014: [** If any error is encountered then mqtt_codec_publishAck shall return NULL. **]**  

## mqtt_codec_publishRecieved
```
extern BUFFER_HANDLE mqtt_codec_publishRecieved(int packetId);
```
**SRS_MQTT_CODEC_07_015: [** On success mqtt_codec_publishRecieved shall return a BUFFER_HANDLE representation of a MQTT PUBREC packet. **]**  
**SRS_MQTT_CODEC_07_016: [** If any error is encountered then mqtt_codec_publishRecieved shall return NULL. **]**  

## mqtt_codec_publishRelease
```
extern BUFFER_HANDLE mqtt_codec_publishRelease(int packetId);
```
**SRS_MQTT_CODEC_07_017: [** On success mqtt_codec_publishRelease shall return a BUFFER_HANDLE representation of a MQTT PUBREL packet. **]**  
**SRS_MQTT_CODEC_07_018: [** If any error is encountered then mqtt_codec_publishRelease shall return NULL. **]**  

## mqtt_codec_publishComplete
```
extern BUFFER_HANDLE mqtt_codec_publishComplete(int packetId);
```
**SRS_MQTT_CODEC_07_019: [** On success mqtt_codec_publishComplete shall return a BUFFER_HANDLE representation of a MQTT PUBCOMP packet. **]**  
**SRS_MQTT_CODEC_07_020: [** If any error is encountered then mqtt_codec_publishComplete shall return NULL. **]**  

## mqtt_codec_subscribe
```
extern BUFFER_HANDLE mqtt_codec_subscribe(int packetId, SUBSCRIBE_PAYLOAD* subscribeList, size_t count);
```
**SRS_MQTT_CODEC_07_023: [** If the parameters subscribeList is NULL or if count is 0 then mqtt_codec_subscribe shall return NULL. **]**  
**SRS_MQTT_CODEC_07_024: [** mqtt_codec_subscribe shall iterate through count items in the subscribeList. **]**   
**SRS_MQTT_CODEC_07_025: [** If any error is encountered then mqtt_codec_subscribe shall return NULL. **]**   
**SRS_MQTT_CODEC_07_026: [** mqtt_codec_subscribe shall return a BUFFER_HANDLE that represents a MQTT SUBSCRIBE message. **]**  

## mqtt_codec_unsubscribe
```
extern BUFFER_HANDLE mqtt_codec_unsubscribe(int packetId, const char** unsubscribeList, size_t count);
```
**SRS_MQTT_CODEC_07_027: [** If the parameters unsubscribeList is NULL or if count is 0 then mqtt_codec_unsubscribe shall return NULL. **]**  
**SRS_MQTT_CODEC_07_028: [** mqtt_codec_unsubscribe shall iterate through count items in the unsubscribeList. **]**  
**SRS_MQTT_CODEC_07_029: [** If any error is encountered then mqtt_codec_unsubscribe shall return NULL. **]**  
**SRS_MQTT_CODEC_07_030: [** mqtt_codec_unsubscribe shall return a BUFFER_HANDLE that represents a MQTT SUBSCRIBE message. **]**  

## mqtt_codec_ping
```
extern BUFFER_HANDLE mqtt_codec_ping();
```
**SRS_MQTT_CODEC_07_021: [** On success mqtt_codec_ping shall construct a BUFFER_HANDLE that represents a MQTT PINGREQ packet. **]**    
**SRS_MQTT_CODEC_07_022: [** If any error is encountered mqtt_codec_ping shall return NULL. **]**  

## mqtt_codec_bytesReceived
```
extern int mqtt_codec_bytesReceived(MQTTCODEC_HANDLE handle, const void* buffer, size_t size);
```
**SRS_MQTT_CODEC_07_031: [** If the parameters handle or buffer is NULL then mqtt_codec_bytesReceived shall return a non-zero value. **]**  
**SRS_MQTT_CODEC_07_032: [** If the parameters size is zero then mqtt_codec_bytesReceived shall return a non-zero value. **]**  
**SRS_MQTT_CODEC_07_033: [** mqtt_codec_bytesReceived constructs a sequence of bytes into the corresponding MQTT packets and on success returns zero. **]**  
**SRS_MQTT_CODEC_07_034: [** Upon a constructing a complete MQTT packet mqtt_codec_bytesReceived shall call the ON_PACKET_COMPLETE_CALLBACK function. **]**  
**SRS_MQTT_CODEC_07_035: [** If any error is encountered then the packet state will be marked as error and mqtt_codec_bytesReceived shall return a non-zero value. **]**  
