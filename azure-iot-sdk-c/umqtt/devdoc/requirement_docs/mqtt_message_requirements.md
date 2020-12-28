# Mqtt_Message Requirements

## Overview

Mqtt_Message is the library that encapsulates an MQTT message

## Exposed API

```C
typedef struct MQTT_MESSAGE_TAG* MQTT_MESSAGE_HANDLE;

extern MQTT_MESSAGE_HANDLE mqttmessage_create_in_place(uint16_t packetId, const char* topicName, QOS_VALUE qosValue, const uint8_t* appMsg, size_t appMsgLength);
extern MQTT_MESSAGE_HANDLE mqttmessage_create(PACKET_ID packetId, const char* topicName, QOS_VALUE qosValue, const BYTE* appMsg, size_t appMsgLength, bool duplicateMsg, bool retainMsg);
extern void mqttmessage_destroy(MQTT_MESSAGE_HANDLE handle);
extern MQTT_MESSAGE_HANDLE mqttmessage_clone(MQTT_MESSAGE_HANDLE handle);

extern PACKET_ID mqttmessage_getPacketId(MQTT_MESSAGE_HANDLE handle);
extern const char* mqttmessage_getTopicName(MQTT_MESSAGE_HANDLE handle);
extern QOS_VALUE mqttmessage_getQosType(MQTT_MESSAGE_HANDLE handle);
extern bool mqttmessage_getIsDuplicateMsg(MQTT_MESSAGE_HANDLE handle);
extern bool mqttmessage_getIsRetained(MQTT_MESSAGE_HANDLE handle);
extern int mqttmessage_setIsDuplicateMsg(MQTT_MESSAGE_HANDLE handle, bool duplicateMsg);
extern int mqttmessage_setIsRetained(MQTT_MESSAGE_HANDLE handle, bool retainMsg);
extern const BYTE* mqttmessage_getApplicationMsg(MQTT_MESSAGE_HANDLE handle, size_t* msgLen);
extern int mqttmessage_getTopicLevels(MQTT_MESSAGE_HANDLE handle, char*** levels, size_t* count);
```

## mqttmessage_create_in_place

```C
MQTT_MESSAGE_HANDLE mqttmessage_create_in_place(uint16_t packetId, const char* topicName, QOS_VALUE qosValue, const uint8_t* appMsg, size_t appMsgLength);
```

**SRS_MQTTMESSAGE_07_026: [**If the parameters `topicName` is NULL then `mqttmessage_create_in_place` shall return NULL.**]**

**SRS_MQTTMESSAGE_07_027: [**`mqttmessage_create_in_place` shall use the a pointer to `topicName` or `appMsg` .**]**

**SRS_MQTTMESSAGE_07_028: [**If any memory allocation fails `mqttmessage_create_in_place` shall free any allocated memory and return NULL.**]**

**SRS_MQTTMESSAGE_07_029: [** Upon success, `mqttmessage_create_in_place` shall return a NON-NULL `MQTT_MESSAGE_HANDLE` value.**]**

## mqttmessage_create

```C
MQTT_MESSAGE_HANDLE mqttmessage_create(PACKET_ID packetId, const char* topicName, QOS_VALUE qosValue, const BYTE* appMsg, size_t appMsgLength, bool duplicateMsg, bool retainMsg)
```

**SRS_MQTTMESSAGE_07_001: [**If the parameters topicName is NULL then mqttmessage_create shall return NULL.**]**

**SRS_MQTTMESSAGE_07_002: [**mqttmessage_create shall allocate and copy the topicName and appMsg parameters.**]**

**SRS_MQTTMESSAGE_07_003: [**If any memory allocation fails mqttmessage_create shall free any allocated memory and return NULL.**]**

**SRS_MQTTMESSAGE_07_004: [**If mqttmessage_create succeeds the it shall return a NON-NULL MQTT_MESSAGE_HANDLE value.**]**

## mqttmessage_destroy

```C
extern void mqttmessage_destroy(MQTT_MESSAGE_HANDLE handle)
```

**SRS_MQTTMESSAGE_07_005: [**If the handle parameter is NULL then mqttmessage_destroy shall do nothing**]**

**SRS_MQTTMESSAGE_07_006: [**mqttmessage_destroy shall free all resources associated with the MQTT_MESSAGE_HANDLE value**]**

## mqttmessage_clone

```C
extern MQTT_MESSAGE_HANDLE mqttmessage_clone(MQTT_MESSAGE_HANDLE handle)
```

**SRS_MQTTMESSAGE_07_007: [**If handle parameter is NULL then mqttmessage_clone shall return NULL.**]**

**SRS_MQTTMESSAGE_07_008: [**mqttmessage_clone shall create a new MQTT_MESSAGE_HANDLE with data content identical of the handle value.**]**

**SRS_MQTTMESSAGE_07_009: [**If any memory allocation fails mqttmessage_clone shall free any allocated memory and return NULL.**]**

## mqttmessage_getPacketId

```C
extern PACKET_ID mqttmessage_getPacketId(MQTT_MESSAGE_HANDLE handle)
```

**SRS_MQTTMESSAGE_07_010: [**If handle is NULL then mqttmessage_getPacketId shall return 0.**]**

**SRS_MQTTMESSAGE_07_011: [**mqttmessage_getPacketId shall return the packetId value contained in MQTT_MESSAGE_HANDLE handle.**]**

##mqttmessage_getTopicName

```C

extern const char* mqttmessage_getTopicName(MQTT_MESSAGE_HANDLE handle)
```

**SRS_MQTTMESSAGE_07_012: [**If handle is NULL then mqttmessage_getTopicName shall return a NULL string.**]**  
**SRS_MQTTMESSAGE_07_013: [**mqttmessage_getTopicName shall return the topicName contained in MQTT_MESSAGE_HANDLE handle.**]**  

## mqttmessage_getQosType

```C
extern QOS_VALUE mqttmessage_getQosType(MQTT_MESSAGE_HANDLE handle)
```C

**SRS_MQTTMESSAGE_07_014: [**If handle is NULL then mqttmessage_getQosType shall return the default DELIVER_AT_MOST_ONCE value.**]**

**SRS_MQTTMESSAGE_07_015: [**mqttmessage_getQosType shall return the QOS Type value contained in MQTT_MESSAGE_HANDLE handle.**]**

## mqttmessage_getIsDuplicateMsg

```C
extern bool mqttmessage_getIsDuplicateMsg(MQTT_MESSAGE_HANDLE handle)
```

**SRS_MQTTMESSAGE_07_016: [**If handle is NULL then mqttmessage_getIsDuplicateMsg shall return false.**]**
**SRS_MQTTMESSAGE_07_017: [**mqttmessage_getIsDuplicateMsg shall return the isDuplicateMsg value contained in MQTT_MESSAGE_HANDLE handle.**]**

## mqttmessage_getIsRetained

```C
extern bool mqttmessage_getIsRetained(MQTT_MESSAGE_HANDLE handle)
```
**SRS_MQTTMESSAGE_07_018: [**If handle is NULL then mqttmessage_getIsRetained shall return false.**]**
**SRS_MQTTMESSAGE_07_019: [**mqttmessage_getIsRetained shall return the isRetained value contained in MQTT_MESSAGE_HANDLE handle.**]**  

## mqttmessage_getApplicationMsg

```C
extern const BYTE* mqttmessage_getApplicationMsg(MQTT_MESSAGE_HANDLE handle, size_t* msgLen)
```

**SRS_MQTTMESSAGE_07_020: [**If handle is NULL or if msgLen is 0 then mqttmessage_getApplicationMsg shall return NULL.**]**
**SRS_MQTTMESSAGE_07_021: [**mqttmessage_getApplicationMsg shall return the applicationMsg value contained in MQTT_MESSAGE_HANDLE handle and the length of the appMsg in the msgLen parameter.**]**

## mqttmessage_setIsDuplicateMsg

```C
extern int mqttmessage_setIsDuplicateMsg(MQTT_MESSAGE_HANDLE handle, bool duplicateMsg);
```

**SRS_MQTTMESSAGE_07_022: [**If handle is NULL then mqttmessage_setIsDuplicateMsg shall return a non-zero value.**]**

**SRS_MQTTMESSAGE_07_023: [**mqttmessage_setIsDuplicateMsg shall store the duplicateMsg value in the MQTT_MESSAGE_HANDLE handle.**]**

## mqttmessage_setIsRetained

```C
extern int mqttmessage_setIsRetained(MQTT_MESSAGE_HANDLE handle, bool retainMsg);
```

**SRS_MQTTMESSAGE_07_024: [**If handle is NULL then mqttmessage_setIsRetained shall return a non-zero value.**]**

**SRS_MQTTMESSAGE_07_025: [**mqttmessage_setIsRetained shall store the retainMsg value in the MQTT_MESSAGE_HANDLE handle.**]**


## mqttmessage_getTopicLevels
```c
extern int mqttmessage_getTopicLevels(MQTT_MESSAGE_HANDLE handle, char*** levels, size_t* count);
```

**SRS_MQTTMESSAGE_09_001: [** If `handle`, `levels` or `count` are NULL the function shall return a non-zero value. **]**

**SRS_MQTTMESSAGE_09_002: [** The topic name, excluding the property bag, shall be split into individual tokens using "/" as separator **]**

**SRS_MQTTMESSAGE_09_003: [** If splitting fails the function shall return a non-zero value. **]**

**SRS_MQTTMESSAGE_09_004: [** The split tokens shall be stored in `levels` and its count in `count` **]**

**SRS_MQTTMESSAGE_09_005: [** If no failures occur the function shall return zero. **]**

