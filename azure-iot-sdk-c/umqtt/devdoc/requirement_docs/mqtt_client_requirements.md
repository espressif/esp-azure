# Mqtt_Client Requirements

## Overview

Mqtt_Client is the library that encapsulates the [MQTT Protocol](http://mqtt.org/documentation)

## Exposed API

```C
typedef struct MQTT_CLIENT_DATA_INSTANCE_TAG* MQTT_CLIENT_HANDLE;

#define MQTT_CLIENT_ACTION_VALUES    \
    MQTT_CLIENT_ON_CONNACK,          \
    MQTT_CLIENT_ON_PUBLISH_ACK,      \
    MQTT_CLIENT_ON_PUBLISH_RECV,     \
    MQTT_CLIENT_ON_PUBLISH_REL,      \
    MQTT_CLIENT_ON_PUBLISH_COMP,     \
    MQTT_CLIENT_ON_SUBSCRIBE_ACK,    \
    MQTT_CLIENT_ON_UNSUBSCRIBE_ACK,  \
    MQTT_CLIENT_ON_PING_RESPONSE,    \
    MQTT_CLIENT_ON_DISCONNECT

MU_DEFINE_ENUM(MQTT_CLIENT_ACTION_RESULT, MQTT_CLIENT_ACTION_VALUES);

#define MQTT_CLIENT_EVENT_ERROR_VALUES     \
    MQTT_CLIENT_CONNECTION_ERROR,          \
    MQTT_CLIENT_PARSE_ERROR,               \
    MQTT_CLIENT_MEMORY_ERROR,              \
    MQTT_CLIENT_COMMUNICATION_ERROR,       \
    MQTT_CLIENT_NO_PING_RESPONSE,          \
    MQTT_CLIENT_UNKNOWN_ERROR

MU_DEFINE_ENUM(MQTT_CLIENT_EVENT_ERROR, MQTT_CLIENT_EVENT_ERROR_VALUES);

typedef void(*ON_MQTT_OPERATION_CALLBACK)(MQTT_CLIENT_ACTION_RESULT actionResult, const void* msgInfo, void* callbackCtx);
typedef void(*ON_MQTT_ERROR_CALLBACK)(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_ERROR error, void* callbackCtx);
typedef void(*ON_MQTT_MESSAGE_RECV_CALLBACK)(MQTT_MESSAGE_HANDLE msgHandle, void* callbackCtx);

extern MQTT_CLIENT_HANDLE mqtt_client_init(ON_MQTT_MESSAGE_RECV_CALLBACK msgRecv, ON_MQTT_OPERATION_CALLBACK opCallback, void* callbackCtx, ON_MQTT_ERROR_CALLBACK onErrorCallBack, void* errorCBCtx);
extern void mqtt_client_deinit(MQTT_CLIENT_HANDLE handle);

extern int mqtt_client_connect(MQTT_CLIENT_HANDLE handle, XIO_HANDLE ioHandle, MQTT_CLIENT_OPTIONS* mqttOptions);
extern void mqtt_client_disconnect(MQTT_CLIENT_HANDLE handle, ON_MQTT_DISCONNECTED_CALLBACK callback, void* ctx);

extern int mqtt_client_subscribe(MQTT_CLIENT_HANDLE handle, uint8_t packetId, SUBSCRIBE_PAYLOAD* payloadList, size_t payloadCount);
extern int mqtt_client_unsubscribe(MQTT_CLIENT_HANDLE handle, uint8_t packetId, const char** unsubscribeTopic, size_t payloadCount);

extern int mqtt_client_publish(MQTT_CLIENT_HANDLE handle, MQTT_MESSAGE_HANDLE msgHandle);

extern void mqtt_client_dowork(MQTT_CLIENT_HANDLE handle);
```

## mqtt_client_init

```C
extern MQTT_CLIENT_HANDLE mqtt_client_init(ON_MQTT_MESSAGE_RECV_CALLBACK msgRecv, ON_MQTT_OPERATION_CALLBACK opCallback, void* callbackCtx, ON_MQTT_ERROR_CALLBACK onErrorCallBack, void* errorCBCtx)
```

**SRS_MQTT_CLIENT_07_001: [**If the parameters ON_MQTT_MESSAGE_RECV_CALLBACK is NULL then mqttclient_init shall return NULL.**]**

**SRS_MQTT_CLIENT_07_002: [**If any failure is encountered then mqttclient_init shall return NULL.**]**

**SRS_MQTT_CLIENT_07_003: [**mqttclient_init shall allocate MQTTCLIENT_DATA_INSTANCE and return the MQTTCLIENT_HANDLE on success.**]**

## mqtt_client_deinit

```C
extern void mqtt_client_deinit(MQTT_CLIENT_HANDLE handle);
```

**SRS_MQTT_CLIENT_07_004: [**If the parameter handle is NULL then function mqtt_client_deinit shall do nothing.**]**

**SRS_MQTT_CLIENT_07_005: [**mqtt_client_deinit shall deallocate all memory allocated in this unit.**]**

## mqtt_client_connect

```C
extern int mqtt_client_connect(MQTT_CLIENT_HANDLE handle, XIO_HANDLE ioHandle, MQTT_CLIENT_OPTIONS* mqttOptions);
```

**SRS_MQTT_CLIENT_07_006: [**If any of the parameters handle, ioHandle, or mqttOptions are NULL then mqtt_client_connect shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_007: [**If any failure is encountered then mqtt_client_connect shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_008: [**mqtt_client_connect shall open the XIO_HANDLE by calling into the xio_open interface.**]**

**SRS_MQTT_CLIENT_07_009: [**On success mqtt_client_connect shall send the MQTT CONNECT packet to the endpoint.**]**

**SRS_MQTT_CLIENT_07_036: [** If an error is encountered by the ioHandle the mqtt_client shall call xio_close. **]**

## mqtt_client_disconnect

```C
extern int mqtt_client_disconnect(MQTT_CLIENT_HANDLE handle, ON_MQTT_DISCONNECTED_CALLBACK callback, void* ctx);
```

**SRS_MQTT_CLIENT_07_010: [**If the parameters handle is NULL then mqtt_client_disconnect shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_011: [**If any failure is encountered then mqtt_client_disconnect shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_012: [**On success mqtt_client_disconnect shall send the MQTT DISCONNECT packet to the endpoint.**]**

**SRS_MQTT_CLIENT_07_037: [** if callback is not NULL callback shall be called once the mqtt connection has been disconnected **]**

## mqtt_client_subscribe

```C
int mqtt_client_subscribe(MQTT_CLIENT_HANDLE handle, uint8_t packetId, SUBSCRIBE_PAYLOAD* payloadList, size_t payloadCount);
```

**SRS_MQTT_CLIENT_07_013: [**If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_014: [**If any failure is encountered then mqtt_client_subscribe shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_015: [**On success mqtt_client_subscribe shall send the MQTT SUBCRIBE packet to the endpoint.**]**

## mqtt_client_unsubscribe

```C
extern int mqtt_client_unsubscribe(MQTT_CLIENT_HANDLE handle, uint8_t packetId, const char** unsubscribeList, size_t count);
```

**SRS_MQTT_CLIENT_07_016: [**If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_017: [**If any failure is encountered then mqtt_client_unsubscribe shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_018: [**On success mqtt_client_unsubscribe shall send the MQTT SUBCRIBE packet to the endpoint.**]**

## mqtt_client_publish

```C
extern int mqtt_client_publish(MQTT_CLIENT_HANDLE handle, MQTT_MESSAGE_HANDLE msgHandle);
```

**SRS_MQTT_CLIENT_07_019: [**If one of the parameters handle or msgHandle is NULL then mqtt_client_publish shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_020: [**If any failure is encountered then mqtt_client_publish shall return a non-zero value.**]**

**SRS_MQTT_CLIENT_07_021: [**mqtt_client_publish shall get the message information from the MQTT_MESSAGE_HANDLE.**]**

**SRS_MQTT_CLIENT_07_022: [**On success mqtt_client_publish shall send the MQTT SUBCRIBE packet to the endpoint.**]**

## mqtt_client_dowork

```C
extern void mqtt_client_dowork(MQTT_CLIENT_HANDLE handle);
```

**SRS_MQTT_CLIENT_07_023: [**If the parameter handle is NULL then mqtt_client_dowork shall do nothing.**]**

**SRS_MQTT_CLIENT_18_001: [**If the client is disconnected, mqtt_client_dowork shall do nothing.**]**

**SRS_MQTT_CLIENT_07_024: [**mqtt_client_dowork shall call the xio_dowork function to complete operations.**]**

**SRS_MQTT_CLIENT_07_025: [**mqtt_client_dowork shall retrieve the  the last packet send value and ...**]**

**SRS_MQTT_CLIENT_07_026: [**If keepAliveInternal is > 0 and the send time is greater than the MQTT KeepAliveInterval then it shall construct an MQTT PINGREQ packet.**]**

**SRS_MQTT_CLIENT_07_035: [**If the timeSincePing has expired past the maxPingRespTime then mqtt_client_dowork shall call the Error Callback function with the message MQTT_CLIENT_NO_PING_RESPONSE**]**

## ON_MQTT_OPERATION_CALLBACK

```C
typedef void(*ON_MQTT_OPERATION_CALLBACK)(MQTT_CLIENT_ACTION_RESULT actionResult, const void* msgInfo, void* callbackCtx);
```

**SRS_MQTT_CLIENT_07_027: [**The callbackCtx parameter shall be an unmodified pointer that was passed to the mqtt_client_init function.**]**

**SRS_MQTT_CLIENT_07_028: [**If the actionResult parameter is of type CONNECT_ACK then the msgInfo value shall be a CONNECT_ACK* structure.**]**

**SRS_MQTT_CLIENT_07_029: [**If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK* structure.**]**

**SRS_MQTT_CLIENT_07_030: [**If the actionResult parameter is of type SUBACK_TYPE then the msgInfo value shall be a SUBSCRIBE_ACK* structure.**]**

**SRS_MQTT_CLIENT_07_031: [**If the actionResult parameter is of type UNSUBACK_TYPE then the msgInfo value shall be a UNSUBSCRIBE_ACK* structure.**]**

**SRS_MQTT_CLIENT_07_032: [**If the actionResult parameter is of type MQTT_CLIENT_ON_DISCONNECT the the msgInfo value shall be NULL.**]**

## ON_MQTT_MESSAGE_RECV_CALLBACK

```C
typedef void(*ON_MQTT_MESSAGE_RECV_CALLBACK)(MQTT_MESSAGE_HANDLE msgHandle, void* callbackCtx);
```

**SRS_MQTT_CLIENT_07_033: [**The callbackCtx parameter shall be an unmodified pointer that was passed to the mqtt_client_init function.**]**

**SRS_MQTT_CLIENT_07_034: [**The msgHandle shall be the message that was sent from the MQTT endpoint to the client.**]**
