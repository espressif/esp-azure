// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#else
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#endif

#include "testrunnerswitcher.h"
#include "umock_c/umock_c.h"
#include "umock_c/umock_c_negative_tests.h"
#include "umock_c/umocktypes_bool.h"
#include "umock_c/umocktypes_stdint.h"

#if defined _MSC_VER
#pragma warning(disable: 4054) /* MSC incorrectly fires this */
#endif

static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#define ENABLE_MOCKS

#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/threadapi.h"

#include "azure_umqtt_c/mqtt_codec.h"
#include "azure_umqtt_c/mqtt_message.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/platform.h"

#undef ENABLE_MOCKS

#include "azure_umqtt_c/mqtt_client.h"
#include "azure_umqtt_c/mqttconst.h"

#define ENABLE_MOCKS
#include "umock_c/umock_c_prod.h"

MOCKABLE_FUNCTION(, void, on_mqtt_operation_callback, MQTT_CLIENT_HANDLE, handle, MQTT_CLIENT_EVENT_RESULT, actionResult, const void*, msgInfo, void*, callbackCtx);
MOCKABLE_FUNCTION(, void, on_mqtt_disconnected_callback, void*, callback_ctx);

#undef ENABLE_MOCKS

#ifdef __cplusplus
extern "C"
{
#endif

    int STRING_sprintf(STRING_HANDLE handle, const char* format, ...);
    STRING_HANDLE STRING_construct_sprintf(const char* format, ...);

#ifdef __cplusplus
}
#endif

MU_DEFINE_ENUM_STRINGS_2(QOS_VALUE, QOS_VALUE_VALUES);
TEST_DEFINE_ENUM_2_TYPE(QOS_VALUE, QOS_VALUE_VALUES);
IMPLEMENT_UMOCK_C_ENUM_2_TYPE(QOS_VALUE, QOS_VALUE_VALUES);

static const char* TEST_USERNAME = "testuser";
static const char* TEST_PASSWORD = "testpassword";

static const char* TEST_TOPIC_NAME = "topic Name";
static const APP_PAYLOAD TEST_APP_PAYLOAD = { (uint8_t*)"Message to send", 15 };
static const char* TEST_CLIENT_ID = "test_client_id";
static const char* TEST_WILL_MSG = "test_will_msg";
static const char* TEST_WILL_TOPIC = "test_will_topic";
static const char* TEST_SUBSCRIPTION_TOPIC = "subTopic";
static SUBSCRIBE_PAYLOAD TEST_SUBSCRIBE_PAYLOAD[] = { {"subTopic1", DELIVER_AT_LEAST_ONCE }, {"subTopic2", DELIVER_EXACTLY_ONCE } };
static const char* TEST_UNSUBSCRIPTION_TOPIC[] = { "subTopic1", "subTopic2" };

static const XIO_HANDLE TEST_IO_HANDLE = (XIO_HANDLE)0x11;
static const TICK_COUNTER_HANDLE TEST_COUNTER_HANDLE = (TICK_COUNTER_HANDLE)0x12;
static const MQTTCODEC_HANDLE TEST_MQTTCODEC_HANDLE = (MQTTCODEC_HANDLE)0x13;
static const MQTT_MESSAGE_HANDLE TEST_MESSAGE_HANDLE = (MQTT_MESSAGE_HANDLE)0x14;
static BUFFER_HANDLE TEST_BUFFER_HANDLE = (BUFFER_HANDLE)0x15;
static const uint16_t TEST_KEEP_ALIVE_INTERVAL = 20;
static const uint16_t TEST_PACKET_ID = (uint16_t)0x1234;
static const unsigned char* TEST_BUFFER_U_CHAR = (const unsigned char*)0x19;

static bool g_operationCallbackInvoked;
static bool g_errorCallbackInvoked;
static bool g_msgRecvCallbackInvoked;
static bool g_mqtt_codec_publish_func_fail;
static tickcounter_ms_t g_current_ms;
ON_PACKET_COMPLETE_CALLBACK g_packetComplete;
ON_IO_OPEN_COMPLETE g_openComplete;
ON_BYTES_RECEIVED g_bytesRecv;
ON_IO_ERROR g_ioError;
ON_SEND_COMPLETE g_sendComplete;
void* g_onCompleteCtx;
void* g_onSendCtx;
void* g_bytesRecvCtx;
void* g_ioErrorCtx;
typedef struct TEST_COMPLETE_DATA_INSTANCE_TAG
{
    MQTT_CLIENT_EVENT_RESULT actionResult;
    void* msgInfo;
} TEST_COMPLETE_DATA_INSTANCE;

TEST_MUTEX_HANDLE test_serialize_mutex;

#define TEST_CONTEXT ((const void*)0x4242)
#define MAX_CLOSE_RETRIES               20
#define CLOSE_SLEEP_VALUE               2

#ifdef __cplusplus
extern "C" {
#endif

    static MQTTCODEC_HANDLE my_mqtt_codec_create(ON_PACKET_COMPLETE_CALLBACK packetComplete, void* callContext)
    {
        (void)callContext;
        g_packetComplete = packetComplete;
        return TEST_MQTTCODEC_HANDLE;
    }

    static int my_xio_open(XIO_HANDLE handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
    {
        (void)handle;
        /* Bug? : This is a bit wierd, why are we not using on_io_error and on_bytes_received? */
        g_openComplete = on_io_open_complete;
        g_onCompleteCtx = on_io_open_complete_context;
        g_bytesRecv = on_bytes_received;
        g_bytesRecvCtx = on_bytes_received_context;
        g_ioError = on_io_error;
        g_ioErrorCtx = on_io_error_context;
        return 0;
    }

    static int my_xio_send(XIO_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
    {
        (void)xio;
        (void)buffer;
        (void)size;
        g_sendComplete = on_send_complete;
        g_onSendCtx = callback_context;
        return 0;
    }

    static int my_tickcounter_get_current_ms(TICK_COUNTER_HANDLE tick_counter, tickcounter_ms_t* current_ms)
    {
        (void)tick_counter;
        *current_ms = g_current_ms;
        return 0;
    }

    static BUFFER_HANDLE my_mqtt_codec_publishComplete(uint16_t packetId)
    {
        (void)packetId;
        BUFFER_HANDLE buffer_result = TEST_BUFFER_HANDLE;
        if (g_mqtt_codec_publish_func_fail)
        {
            buffer_result = NULL;
        }
        return buffer_result;
    }

    static BUFFER_HANDLE my_mqtt_codec_publishRelease(uint16_t packetId)
    {
        (void)packetId;
        BUFFER_HANDLE buffer_result = TEST_BUFFER_HANDLE;
        if (g_mqtt_codec_publish_func_fail)
        {
            buffer_result = NULL;
        }
        return buffer_result;
    }

    static int my_xio_close(XIO_HANDLE xio, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
    {
        (void)xio;
        if (on_io_close_complete != NULL)
        {
            on_io_close_complete(callback_context);
        }
        return 0;
    }

    static MQTT_MESSAGE_HANDLE my_mqttmessage_create(uint16_t packetId, const char* topicName, QOS_VALUE qosValue, const uint8_t* appMsg, size_t appMsgLength)
    {
        (void)packetId;
        (void)topicName;
        (void)qosValue;
        (void)appMsg;
        (void)appMsgLength;
        return (MQTT_MESSAGE_HANDLE)my_gballoc_malloc(1);
    }

    static MQTT_MESSAGE_HANDLE my_mqttmessage_create_in_place(uint16_t packetId, const char* topicName, QOS_VALUE qosValue, const uint8_t* appMsg, size_t appMsgLength)
    {
        (void)packetId;
        (void)topicName;
        (void)qosValue;
        (void)appMsg;
        (void)appMsgLength;
        return (MQTT_MESSAGE_HANDLE)my_gballoc_malloc(1);
    }

    static MQTT_MESSAGE_HANDLE my_mqttmessage_clone(MQTT_MESSAGE_HANDLE handle)
    {
        (void)handle;
        return (MQTT_MESSAGE_HANDLE)my_gballoc_malloc(1);
    }

    static void my_mqttmessage_destroy(MQTT_MESSAGE_HANDLE handle)
    {
        my_gballoc_free(handle);
    }

    static STRING_HANDLE my_STRING_new(void)
    {
        return (STRING_HANDLE)my_gballoc_malloc(1);
    }

    static void my_STRING_delete(STRING_HANDLE handle)
    {
        (void)handle;
        my_gballoc_free(handle);
    }

    int STRING_sprintf(STRING_HANDLE handle, const char* format, ...)
    {
        (void)handle;
        (void)format;
        return 0;
    }

    STRING_HANDLE STRING_construct_sprintf(const char* format, ...)
    {
        (void)format;
        return (STRING_HANDLE)my_gballoc_malloc(1);
    }

    static int TEST_mallocAndStrcpy_s(char** destination, const char* source)
    {
        size_t src_len = strlen(source);
        *destination = (char*)my_gballoc_malloc(src_len + 1);
        memcpy(*destination, source, src_len + 1);
        return 0;
    }

#ifdef __cplusplus
}
#endif

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

BEGIN_TEST_SUITE(mqtt_client_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    int result;

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);
    result = umocktypes_bool_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

    result = umocktypes_stdint_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

    REGISTER_UMOCK_ALIAS_TYPE(ON_PACKET_COMPLETE_CALLBACK, void*);
    REGISTER_UMOCK_ALIAS_TYPE(TICK_COUNTER_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MQTTCODEC_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(XIO_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_SEND_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(BUFFER_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MQTT_MESSAGE_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_OPEN_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_BYTES_RECEIVED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_ERROR, void*);
    REGISTER_UMOCK_ALIAS_TYPE(STRING_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_CLOSE_COMPLETE, void*)

    REGISTER_TYPE(QOS_VALUE, QOS_VALUE);

    REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, TEST_mallocAndStrcpy_s);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

    REGISTER_GLOBAL_MOCK_HOOK(STRING_new, my_STRING_new);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(STRING_new, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_delete, my_STRING_delete);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_c_str, "Test");

    REGISTER_GLOBAL_MOCK_HOOK(mqtt_codec_create, my_mqtt_codec_create);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_create, NULL);

    REGISTER_GLOBAL_MOCK_HOOK(xio_open, my_xio_open);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_open, MU_FAILURE);
    REGISTER_GLOBAL_MOCK_HOOK(xio_send, my_xio_send);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_send, MU_FAILURE);
    REGISTER_GLOBAL_MOCK_HOOK(xio_close, my_xio_close);

    REGISTER_GLOBAL_MOCK_HOOK(tickcounter_get_current_ms, my_tickcounter_get_current_ms);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(tickcounter_get_current_ms, MU_FAILURE);

    REGISTER_GLOBAL_MOCK_HOOK(mqtt_codec_publishRelease, my_mqtt_codec_publishRelease);
    REGISTER_GLOBAL_MOCK_HOOK(mqtt_codec_publishComplete, my_mqtt_codec_publishComplete);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_connect, TEST_BUFFER_HANDLE);

    REGISTER_GLOBAL_MOCK_RETURN(get_time, time(NULL) );

    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_publish, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_publish, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_subscribe, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_subscribe, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_unsubscribe, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_unsubscribe, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_disconnect, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_disconnect, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_ping, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_ping, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_publishAck, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_publishAck, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_publishReceived, TEST_BUFFER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_publishReceived, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqtt_codec_bytesReceived, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqtt_codec_bytesReceived, MU_FAILURE);
    REGISTER_GLOBAL_MOCK_RETURN(xio_close, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_close, MU_FAILURE);

    REGISTER_GLOBAL_MOCK_RETURN(platform_init, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(platform_init, MU_FAILURE);

    REGISTER_GLOBAL_MOCK_RETURN(tickcounter_create, TEST_COUNTER_HANDLE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(tickcounter_create, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_u_char, (unsigned char*)TEST_BUFFER_U_CHAR);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_length, 11);

    REGISTER_GLOBAL_MOCK_HOOK(mqttmessage_create, my_mqttmessage_create);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqttmessage_create, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mqttmessage_create_in_place, my_mqttmessage_create_in_place);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqttmessage_create_in_place, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mqttmessage_clone, my_mqttmessage_clone);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqttmessage_clone, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getPacketId, TEST_PACKET_ID);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getTopicName, TEST_TOPIC_NAME);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getQosType, DELIVER_AT_LEAST_ONCE);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getIsDuplicateMsg, true);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getIsRetained, true);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_setIsDuplicateMsg, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqttmessage_setIsDuplicateMsg, MU_FAILURE);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_setIsRetained, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mqttmessage_setIsRetained, MU_FAILURE);
    REGISTER_GLOBAL_MOCK_RETURN(mqttmessage_getApplicationMsg, &TEST_APP_PAYLOAD);
    REGISTER_GLOBAL_MOCK_HOOK(mqttmessage_destroy, my_mqttmessage_destroy);

    REGISTER_GLOBAL_MOCK_RETURN(mallocAndStrcpy_s, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mallocAndStrcpy_s, MU_FAILURE);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    if (TEST_MUTEX_ACQUIRE(test_serialize_mutex))
    {
        ASSERT_FAIL("Could not acquire test serialization mutex.");
    }

    g_current_ms = 0;
    g_packetComplete = NULL;
    g_operationCallbackInvoked = false;
    g_errorCallbackInvoked = false;
    g_msgRecvCallbackInvoked = false;
    g_mqtt_codec_publish_func_fail = false;
    g_openComplete = NULL;
    g_onCompleteCtx = NULL;
    g_sendComplete = NULL;
    g_onSendCtx = NULL;
    g_bytesRecv = NULL;
    g_ioError = NULL;
    g_bytesRecvCtx = NULL;
    g_ioErrorCtx = NULL;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    umock_c_reset_all_calls();
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

static int should_skip_index(size_t current_index, const size_t skip_array[], size_t length)
{
    int result = 0;
    for (size_t index = 0; index < length; index++)
    {
        if (current_index == skip_array[index])
        {
            result = MU_FAILURE;
            break;
        }
    }
    return result;
}

static void setup_publish_callback_mocks(unsigned char* PUBLISH_RESP, size_t length, QOS_VALUE qos_value)
{
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(TEST_PACKET_ID, IGNORED_PTR_ARG, qos_value, IGNORED_PTR_ARG, TEST_APP_PAYLOAD.length));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, true));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, true));
    STRICT_EXPECTED_CALL(mqtt_codec_publishReceived(TEST_PACKET_ID));
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG)).SetReturn(length);
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG)).SetReturn(PUBLISH_RESP);
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void setup_mqtt_clear_options_mocks(MQTT_CLIENT_OPTIONS* mqttOptions)
{
    if (mqttOptions->clientId != NULL)
    {
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    if (mqttOptions->willTopic != NULL)
    {
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    if (mqttOptions->willMessage != NULL)
    {
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    if (mqttOptions->username != NULL)
    {
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    if (mqttOptions->password != NULL)
    {
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }
}

static void setup_mqtt_client_disconnect_mocks(MQTT_CLIENT_OPTIONS* mqttOptions)
{
    STRICT_EXPECTED_CALL(mqtt_codec_disconnect());
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    setup_mqtt_clear_options_mocks(mqttOptions);
}

static void setup_mqtt_client_subscribe_mocks()
{
    STRICT_EXPECTED_CALL(mqtt_codec_subscribe(TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 2, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument_current_ms();
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));
}

static void setup_mqtt_client_connect_mocks(MQTT_CLIENT_OPTIONS* mqttOptions)
{
    if (mqttOptions->clientId != NULL)
    {
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, mqttOptions->clientId));
    }

    if (mqttOptions->willTopic != NULL)
    {
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, mqttOptions->willTopic));
    }

    if (mqttOptions->willMessage != NULL)
    {
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, mqttOptions->willMessage));
    }

    if (mqttOptions->username != NULL)
    {
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, mqttOptions->username));
    }

    if (mqttOptions->password != NULL)
    {
        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, mqttOptions->password));
    }

    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(mqtt_codec_connect(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));
}

static void setup_mqtt_client_connect_retry_mocks(MQTT_CLIENT_OPTIONS* mqttOptions)
{
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_CLIENT_ID));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_WILL_MSG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_USERNAME));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_PASSWORD));
    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG))
        .SetReturn(MU_FAILURE);

    setup_mqtt_clear_options_mocks(mqttOptions);

    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_CLIENT_ID));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_WILL_MSG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_USERNAME));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_PASSWORD));
    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
}

static void TestRecvCallback(MQTT_MESSAGE_HANDLE msgHandle, void* context)
{
    (void)msgHandle;
    (void)context;
    g_msgRecvCallbackInvoked = true;
}

static void TestOpCallback(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_RESULT actionResult, const void* msgInfo, void* context)
{
    (void)handle;
    switch (actionResult)
    {
        default:
            ASSERT_FAIL("Unexpected enum value: %d", actionResult);
            break;

        case MQTT_CLIENT_ON_CONNACK:
        {
            if (context != NULL && msgInfo != NULL)
            {
                const CONNECT_ACK* connack = (CONNECT_ACK*)msgInfo;
                TEST_COMPLETE_DATA_INSTANCE* testData = (TEST_COMPLETE_DATA_INSTANCE*)context;
                CONNECT_ACK* validate = (CONNECT_ACK*)testData->msgInfo;
                if (connack->isSessionPresent == validate->isSessionPresent &&
                    connack->returnCode == validate->returnCode)
                {
                    g_operationCallbackInvoked = true;
                }
            }
            break;
        }
        case MQTT_CLIENT_ON_PUBLISH_ACK:
        case MQTT_CLIENT_ON_PUBLISH_RECV:
        case MQTT_CLIENT_ON_PUBLISH_REL:
        case MQTT_CLIENT_ON_PUBLISH_COMP:
        {
            if (context != NULL && msgInfo != NULL)
            {
                const PUBLISH_ACK* puback = (PUBLISH_ACK*)msgInfo;
                TEST_COMPLETE_DATA_INSTANCE* testData = (TEST_COMPLETE_DATA_INSTANCE*)context;
                PUBLISH_ACK* validate = (PUBLISH_ACK*)testData->msgInfo;
                if (testData->actionResult == actionResult && puback->packetId == validate->packetId)
                {
                    g_operationCallbackInvoked = true;
                }
            }
            break;
        }
        case MQTT_CLIENT_ON_SUBSCRIBE_ACK:
        {
            if (context != NULL && msgInfo != NULL)
            {
                const SUBSCRIBE_ACK* suback = (SUBSCRIBE_ACK*)msgInfo;
                TEST_COMPLETE_DATA_INSTANCE* testData = (TEST_COMPLETE_DATA_INSTANCE*)context;
                SUBSCRIBE_ACK* validate = (SUBSCRIBE_ACK*)testData->msgInfo;
                if (testData->actionResult == actionResult && validate->packetId == suback->packetId && validate->qosCount == suback->qosCount)
                {
                    for (size_t index = 0; index < suback->qosCount; index++)
                    {
                        if (suback->qosReturn[index] == validate->qosReturn[index])
                        {
                            g_operationCallbackInvoked = true;
                        }
                        else
                        {
                            g_operationCallbackInvoked = false;
                            break;
                        }
                    }
                }
            }
            break;
        }
        case MQTT_CLIENT_ON_UNSUBSCRIBE_ACK:
        {
            if (context != NULL && msgInfo != NULL)
            {
                const UNSUBSCRIBE_ACK* suback = (UNSUBSCRIBE_ACK*)msgInfo;
                TEST_COMPLETE_DATA_INSTANCE* testData = (TEST_COMPLETE_DATA_INSTANCE*)context;
                UNSUBSCRIBE_ACK* validate = (UNSUBSCRIBE_ACK*)testData->msgInfo;
                if (testData->actionResult == actionResult && validate->packetId == suback->packetId)
                {
                    g_operationCallbackInvoked = true;
                }
            }
            break;
        }
        case MQTT_CLIENT_ON_DISCONNECT:
        {
            if (msgInfo == NULL)
            {
                g_operationCallbackInvoked = true;
            }
            break;
        }
        case MQTT_CLIENT_ON_PING_RESPONSE:
        {
            if (msgInfo == NULL)
            {
                g_operationCallbackInvoked = true;
            }
            break;
        }
    }
}

static void TestErrorCallback(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_ERROR error, void* context)
{
    (void)handle;
    (void)context;
    switch (error)
    {
        default:
            ASSERT_FAIL("Unexpected enum value: %d", error);
            break;

        case MQTT_CLIENT_CONNECTION_ERROR:
        case MQTT_CLIENT_PARSE_ERROR:
        case MQTT_CLIENT_MEMORY_ERROR:
        case MQTT_CLIENT_COMMUNICATION_ERROR:
        case MQTT_CLIENT_NO_PING_RESPONSE:
        case MQTT_CLIENT_UNKNOWN_ERROR:
        {
            g_errorCallbackInvoked = true;
        }
        break;
    }
}

static void SetupMqttLibOptions(MQTT_CLIENT_OPTIONS* options, const char* clientId,
    const char* willMsg,
    const char* willTopic,
    const char* username,
    const char* password,
    uint16_t keepAlive,
    bool messageRetain,
    bool cleanSession,
    QOS_VALUE qos)
{
    options->clientId = (char*)clientId;
    options->willMessage = (char*)willMsg;
    options->willTopic = (char*)willTopic;
    options->username = (char*)username;
    options->password = (char*)password;
    options->keepAliveInterval = keepAlive;
    options->useCleanSession = cleanSession;
    options->qualityOfServiceValue = qos;
    options->messageRetain = messageRetain;
}

static void make_connack(MQTT_CLIENT_HANDLE mqttHandle, MQTT_CLIENT_OPTIONS* mqttOptions)
{
    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, mqttOptions);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
}

/* mqttclient_connect */

/*Tests_SRS_MQTT_CLIENT_07_003: [mqttclient_init shall allocate MQTTCLIENT_DATA_INSTANCE and return the MQTTCLIENT_HANDLE on success.]*/
TEST_FUNCTION(mqtt_client_init_succeeds)
{
    // arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(tickcounter_create());
    EXPECTED_CALL(mqtt_codec_create(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    // act
    MQTT_CLIENT_HANDLE result = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    // assert
    ASSERT_IS_NOT_NULL(result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(result);
}

/*Tests_SRS_MQTT_CLIENT_07_001: [If the parameters ON_MQTT_MESSAGE_RECV_CALLBACK is NULL then mqttclient_init shall return NULL.]*/
TEST_FUNCTION(mqtt_client_init_fail)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(tickcounter_create());
    EXPECTED_CALL(mqtt_codec_create(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        // act
        MQTT_CLIENT_HANDLE result = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

        // assert
        ASSERT_IS_NULL(result, "IoTHubClient_LL_SendReportedState failure in test %zu/%zu", index, count);
    }

    // cleanup
    umock_c_negative_tests_deinit();
}

/*Tests_SRS_MQTT_CLIENT_07_001: [If the parameters ON_MQTT_MESSAGE_RECV_CALLBACK is NULL then mqttclient_init shall return NULL.]*/
TEST_FUNCTION(mqtt_client_init_ON_MQTT_MESSAGE_RECV_CALLBACK_NULL_fails)
{
    // arrange

    // act
    MQTT_CLIENT_HANDLE result = mqtt_client_init(NULL, TestOpCallback, NULL, TestErrorCallback, NULL);

    // assert
    ASSERT_IS_NULL(result);
}

/*Tests_SRS_MQTT_CLIENT_07_004: [If the parameter handle is NULL then function mqtt_client_deinit shall do nothing.]*/
TEST_FUNCTION(mqtt_client_deinit_handle_NULL_succeeds)
{
    // arrange

    // act
    mqtt_client_deinit(NULL);

    // assert
}

/*Tests_SRS_MQTT_CLIENT_07_005: [mqtt_client_deinit shall deallocate all memory allocated in this unit.]*/
TEST_FUNCTION(mqtt_client_deinit_succeeds)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(tickcounter_destroy(TEST_COUNTER_HANDLE));
    EXPECTED_CALL(mqtt_codec_destroy(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(mqttHandle));

    // act
    mqtt_client_deinit(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(mqtt_client_clear_xio_handle_NULL_succeeds)
{
    // arrange

    // act
    mqtt_client_clear_xio(NULL);

    // assert
}

TEST_FUNCTION(mqtt_client_clear_xio_succeeds)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    umock_c_reset_all_calls();

    // act
    mqtt_client_clear_xio(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_clear_xio_after_connect_and_do_work_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
    umock_c_reset_all_calls();

    g_current_ms = TEST_KEEP_ALIVE_INTERVAL * 2 * 1000;

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    STRICT_EXPECTED_CALL(mqtt_codec_ping());
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);

    // act
    mqtt_client_dowork(mqttHandle);
    mqtt_client_clear_xio(mqttHandle);
    //This should be a NOP and therefore all above expected calls are for the first _dowork()
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_006: [If any of the parameters handle, ioHandle, or mqttOptions are NULL then mqtt_client_connect shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_connect_MQTT_CLIENT_HANDLE_NULL_fails)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    // act
    int result = mqtt_client_connect(NULL, TEST_IO_HANDLE, &mqttOptions);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

/*Tests_SRS_MQTT_CLIENT_07_006: [If any of the parameters handle, ioHandle, or mqttOptions are NULL then mqtt_client_connect shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_connect_XIO_HANDLE_NULL_fails)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    // act
    int result = mqtt_client_connect(mqttHandle, NULL, &mqttOptions);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_006: [If any of the parameters handle, ioHandle, or mqttOptions are NULL then mqtt_client_connect shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_connect_MQTT_CLIENT_OPTIONS_NULL_fails)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange

    // act
    int result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_007: [If any failure is encountered then mqtt_client_connect shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_connect_fails)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_CLIENT_ID));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_WILL_TOPIC));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_WILL_MSG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_USERNAME));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_PASSWORD));
    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    umock_c_negative_tests_snapshot();

    // act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        int result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
        if (result == 0)
        {
            g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
        }

        // assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result, "mqtt_client_connect failure in test %zu/%zu", index, count);
    }

    // cleanup
    mqtt_client_deinit(mqttHandle);
    umock_c_negative_tests_deinit();
}

/*Tests_SRS_MQTT_CLIENT_07_009: [On success mqtt_client_connect shall send the MQTT CONNECT to the endpoint.]*/
TEST_FUNCTION(mqtt_client_connect_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, NULL, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    setup_mqtt_client_connect_mocks(&mqttOptions);

    // act
    int result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);

    ASSERT_IS_NOT_NULL(g_openComplete);
    ASSERT_IS_NOT_NULL(g_bytesRecv);
    ASSERT_IS_NOT_NULL(g_ioError);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_009: [On success mqtt_client_connect shall send the MQTT CONNECT to the endpoint.]*/
TEST_FUNCTION(mqtt_client_connect_retries_twice_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, NULL, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    setup_mqtt_client_connect_retry_mocks(&mqttOptions);

    // act
    int result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_009: [On success mqtt_client_connect shall send the MQTT CONNECT to the endpoint.]*/
TEST_FUNCTION(mqtt_client_on_bytes_received_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    umock_c_reset_all_calls();

    EXPECTED_CALL(mqtt_codec_bytesReceived(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));

    // act
    g_bytesRecv(g_bytesRecvCtx, TEST_BUFFER_U_CHAR, 1);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_009: [On success mqtt_client_connect shall send the MQTT CONNECT to the endpoint.]*/
TEST_FUNCTION(mqtt_client_on_bytes_received_context_NULL_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    umock_c_reset_all_calls();

    // act
    g_bytesRecv(NULL, TEST_BUFFER_U_CHAR, 1);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_009: [On success mqtt_client_connect shall send the MQTT CONNECT to the endpoint.]*/
TEST_FUNCTION(mqtt_client_on_bytes_received_bytesReceived_fail_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    make_connack(mqttHandle, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);

    umock_c_reset_all_calls();

    EXPECTED_CALL(mqtt_codec_bytesReceived(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG))
        .SetReturn(MU_FAILURE);
    STRICT_EXPECTED_CALL(mqtt_codec_reset(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    g_bytesRecv(g_bytesRecvCtx, TEST_BUFFER_U_CHAR, 1);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_on_open_complete_fail_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    make_connack(mqttHandle, &mqttOptions);
    umock_c_reset_all_calls();

    // Arrange
    STRICT_EXPECTED_CALL(mqtt_codec_connect(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(__LINE__);
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    // act
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_connect_multiple_completes_one_connect_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, NULL, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    setup_mqtt_client_connect_mocks(&mqttOptions);
    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    int result = mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);

    ASSERT_IS_NOT_NULL(g_openComplete);
    ASSERT_IS_NOT_NULL(g_bytesRecv);
    ASSERT_IS_NOT_NULL(g_ioError);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_connect_completes_IO_OPEN_ERROR_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    umock_c_reset_all_calls();

    // act
    ASSERT_IS_NOT_NULL(g_openComplete);
    ASSERT_IS_NOT_NULL(g_bytesRecv);
    ASSERT_IS_NOT_NULL(g_ioError);
    g_openComplete(g_onCompleteCtx, IO_OPEN_ERROR);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_07_036: [ If an error is encountered by the ioHandle the mqtt_client shall call xio_close. ] */
TEST_FUNCTION(mqtt_client_ioerror_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);
    make_connack(mqttHandle, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    g_ioError(g_ioErrorCtx);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


/* Tests_SRS_MQTT_CLIENT_07_013: [If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_subscribe_handle_NULL_fail)
{
    // arrange

    // act
    int result = mqtt_client_subscribe(NULL, TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

/*Tests_SRS_MQTT_CLIENT_07_013: [If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_subscribe_subscribeList_NULL_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange

    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_subscribe(mqttHandle, TEST_PACKET_ID, NULL, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_07_013: [If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_subscribe_count_0_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange

    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_subscribe(mqttHandle, TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 0);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_07_013: [If any of the parameters handle, subscribeList is NULL or count is 0 then mqtt_client_subscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_subscribe_packet_id_0_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // Arrange

    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_subscribe(mqttHandle, 0, TEST_SUBSCRIBE_PAYLOAD, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_015: [On success mqtt_client_subscribe shall send the MQTT SUBCRIBE packet to the endpoint.]*/
TEST_FUNCTION(mqtt_client_subscribe_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqtt_codec_subscribe(TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 2, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    // act
    int result = mqtt_client_subscribe(mqttHandle, TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 2);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_subscribe_fails)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    setup_mqtt_client_subscribe_mocks();

    umock_c_negative_tests_snapshot();

    // act
    size_t calls_cannot_fail[] = { 1, 2, 5 };

    // act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        int result = mqtt_client_subscribe(mqttHandle, TEST_PACKET_ID, TEST_SUBSCRIBE_PAYLOAD, 2);

        // assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result, "mqtt_client_subscribe failure in test %zu/%zu", index, count);
    }

    // cleanup
    mqtt_client_deinit(mqttHandle);
    umock_c_negative_tests_deinit();
}

/*Tests_SRS_MQTT_CLIENT_07_016: [If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_unsubscribe_handle_NULL_fails)
{
    // arrange

    // act
    int result = mqtt_client_unsubscribe(NULL, TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

/*Tests_SRS_MQTT_CLIENT_07_016: [If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_unsubscribe_unsubscribeList_NULL_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_unsubscribe(mqttHandle, TEST_PACKET_ID, NULL, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_016: [If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_unsubscribe_count_0_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_unsubscribe(mqttHandle, TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 0);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_016: [If any of the parameters handle, unsubscribeList is NULL or count is 0 then mqtt_client_unsubscribe shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_unsubscribe_packet_id_0_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_unsubscribe(mqttHandle, 0, TEST_UNSUBSCRIPTION_TOPIC, 2);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_018: [On success mqtt_client_unsubscribe shall send the MQTT SUBCRIBE packet to the endpoint.]*/
TEST_FUNCTION(mqtt_client_unsubscribe_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqtt_codec_unsubscribe(TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 2, NULL));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    // act
    int result = mqtt_client_unsubscribe(mqttHandle, TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 2);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_unsubscribe_fail)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqtt_codec_unsubscribe(TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 2, NULL));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    umock_c_negative_tests_snapshot();

    // act
    size_t calls_cannot_fail[] = { 1, 2, 5 };
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        int result = mqtt_client_unsubscribe(mqttHandle, TEST_PACKET_ID, TEST_UNSUBSCRIPTION_TOPIC, 2);

        // assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result, "mqtt_client_unsubscribe failure in test %zu/%zu", index, count);
    }

    // cleanup
    mqtt_client_deinit(mqttHandle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(mqtt_client_publish_handle_NULL_fail)
{
    // arrange

    // act
    int result = mqtt_client_publish(NULL, TEST_MESSAGE_HANDLE);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(mqtt_client_publish_MQTT_MESSAGE_HANDLE_NULL_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    int result = mqtt_client_publish(mqttHandle, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_publish_getApplicationMsg_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqttmessage_getApplicationMsg(TEST_MESSAGE_HANDLE)).SetReturn((const APP_PAYLOAD*)NULL);

    // act
    int result = mqtt_client_publish(mqttHandle, TEST_MESSAGE_HANDLE);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_publish_mqtt_codec_publish_fail)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqttmessage_getApplicationMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getQosType(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsDuplicateMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsRetained(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getPacketId(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getTopicName(TEST_MESSAGE_HANDLE));

    EXPECTED_CALL(mqtt_codec_publish(DELIVER_AT_MOST_ONCE, true, true, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .SetReturn((BUFFER_HANDLE)NULL);

    // act
    int result = mqtt_client_publish(mqttHandle, TEST_MESSAGE_HANDLE);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_020: [If any failure is encountered then mqtt_client_publish shall return a non-zero value.]*/
TEST_FUNCTION(mqtt_client_publish_xio_send_fails)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqttmessage_getApplicationMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getQosType(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsDuplicateMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsRetained(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getPacketId(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getTopicName(TEST_MESSAGE_HANDLE));

    EXPECTED_CALL(mqtt_codec_publish(DELIVER_AT_MOST_ONCE, true, true, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(MU_FAILURE);
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    // act
    int result = mqtt_client_publish(mqttHandle, TEST_MESSAGE_HANDLE);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_publish_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(mqttmessage_getApplicationMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getQosType(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsDuplicateMsg(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getIsRetained(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getPacketId(TEST_MESSAGE_HANDLE));
    STRICT_EXPECTED_CALL(mqttmessage_getTopicName(TEST_MESSAGE_HANDLE));

    EXPECTED_CALL(mqtt_codec_publish(DELIVER_AT_MOST_ONCE, true, true, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));

    // act
    int result = mqtt_client_publish(mqttHandle, TEST_MESSAGE_HANDLE);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_disconnect_handle_NULL_fail)
{
    // arrange

    // act
    int result = mqtt_client_disconnect(NULL, NULL, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

TEST_FUNCTION(mqtt_client_disconnect_fail)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    make_connack(mqttHandle, &mqttOptions);
    umock_c_reset_all_calls();

    setup_mqtt_client_disconnect_mocks(&mqttOptions);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 1, 2, 5, 6, 7, 8, 9, 10 };

    // act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        int result = mqtt_client_disconnect(mqttHandle, NULL, NULL);

        // assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result, "mqtt_client_disconnect failure in test %zu/%zu", index, count);
    }

    // cleanup
    mqtt_client_deinit(mqttHandle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(mqtt_client_disconnect_succeeds)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    make_connack(mqttHandle, &mqttOptions);
    umock_c_reset_all_calls();

    setup_mqtt_client_disconnect_mocks(&mqttOptions);

    // act
    int result = mqtt_client_disconnect(mqttHandle, NULL, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_07_037: [ if callback is not NULL callback shall be called once the mqtt connection has been disconnected ] */
TEST_FUNCTION(mqtt_client_disconnect_callback_succeeds)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    make_connack(mqttHandle, &mqttOptions);
    umock_c_reset_all_calls();

    setup_mqtt_client_disconnect_mocks(&mqttOptions);

    // act
    int result = mqtt_client_disconnect(mqttHandle, on_mqtt_disconnected_callback, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_disconnect_send_complete_SEND_OK_succeeds)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    make_connack(mqttHandle, &mqttOptions);
    (void)mqtt_client_disconnect(mqttHandle, NULL, NULL);
    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_close(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));

    // act
    ASSERT_IS_NOT_NULL(g_sendComplete);
    g_sendComplete(g_onSendCtx, IO_SEND_OK);

    // assert

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_disconnect_send_complete_SEND_ERROR_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    make_connack(mqttHandle, &mqttOptions);

    (void)mqtt_client_disconnect(mqttHandle, NULL, NULL);
    umock_c_reset_all_calls();

    // act
    ASSERT_IS_NOT_NULL(g_sendComplete);
    g_sendComplete(g_onSendCtx, IO_SEND_ERROR);

    // assert
    ASSERT_IS_TRUE(g_errorCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_023: [If the parameter handle is NULL then mqtt_client_dowork shall do nothing.]*/
TEST_FUNCTION(mqtt_client_dowork_ping_handle_NULL_fails)
{
    // arrange

    // act
    mqtt_client_dowork(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

/*Tests_SRS_MQTT_CLIENT_07_024: [mqtt_client_dowork shall call the xio_dowork function to complete operations.]*/
/*Tests_SRS_MQTT_CLIENT_07_025: [mqtt_client_dowork shall retrieve the the last packet send value and ...]*/
/*Tests_SRS_MQTT_CLIENT_07_026: [if keepAliveInternal is > 0 and the send time is greater than the MQTT KeepAliveInterval then it shall construct an MQTT PINGREQ packet.]*/
TEST_FUNCTION(mqtt_client_dowork_ping_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
    umock_c_reset_all_calls();

    g_current_ms = TEST_KEEP_ALIVE_INTERVAL * 2 * 1000;

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    STRICT_EXPECTED_CALL(mqtt_codec_ping());
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BUFFER_delete(TEST_BUFFER_HANDLE));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);

    // act
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_07_035: [If the timeSincePing has expired past the maxPingRespTime then mqtt_client_dowork shall call the Operation Callback function with the message MQTT_CLIENT_NO_PING_RESPONSE] */
TEST_FUNCTION(mqtt_client_dowork_ping_No_ping_response_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions ={ 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, NULL, NULL, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] ={ 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);

    g_current_ms = TEST_KEEP_ALIVE_INTERVAL * 2 * 1000;
    mqtt_client_dowork(mqttHandle);

    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    g_current_ms = TEST_KEEP_ALIVE_INTERVAL * 8 * 1000;

    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_024: [mqtt_client_dowork shall call the xio_dowork function to complete operations.]*/
/*Tests_SRS_MQTT_CLIENT_07_025: [mqtt_client_dowork shall retrieve the the last packet send value and ...]*/
/*Tests_SRS_MQTT_CLIENT_07_026: [if keepAliveInternal is > 0 and the send time is greater than the MQTT KeepAliveInterval then it shall construct an MQTT PINGREQ packet.]*/
TEST_FUNCTION(mqtt_client_dowork_no_keepalive_no_ping_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, NULL, NULL, TEST_USERNAME, TEST_PASSWORD, 0, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
    umock_c_reset_all_calls();

    g_current_ms = TEST_KEEP_ALIVE_INTERVAL * 2 * 1000;

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));

    // act
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_07_024: [mqtt_client_dowork shall call the xio_dowork function to complete operations.]*/
/*Tests_SRS_MQTT_CLIENT_07_025: [mqtt_client_dowork shall retrieve the the last packet send value and ...]*/
TEST_FUNCTION(mqtt_client_dowork_no_ping_succeeds)
{
    // arrange
    g_current_ms = (TEST_KEEP_ALIVE_INTERVAL-5)*1000;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);

    // act
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_dowork_tickcounter_fails_succeeds)
{
    // arrange
    g_current_ms = (TEST_KEEP_ALIVE_INTERVAL - 5) * 1000;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);
    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2).SetReturn(MU_FAILURE);

    // act
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Tests_SRS_MQTT_CLIENT_18_001: [If the client is disconnected, mqtt_client_dowork shall do nothing.]*/
TEST_FUNCTION(mqtt_client_dowork_does_nothing_if_disconnected_1)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);

    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    SetupMqttLibOptions(&mqttOptions, TEST_CLIENT_ID, TEST_WILL_MSG, TEST_WILL_TOPIC, TEST_USERNAME, TEST_PASSWORD, TEST_KEEP_ALIVE_INTERVAL, false, true, DELIVER_AT_MOST_ONCE);

    umock_c_reset_all_calls();
    setup_mqtt_client_connect_mocks(&mqttOptions);

    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);

    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);

    mqtt_client_disconnect(mqttHandle, NULL, NULL);

    g_sendComplete(g_onSendCtx, IO_SEND_OK);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    mqtt_client_dowork(mqttHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/* Tests_SRS_MQTT_CLIENT_18_001: [ If the client is disconnected, mqtt_client_dowork shall do nothing. ] */
TEST_FUNCTION(mqtt_client_dowork_does_nothing_if_disconnected_2)
{
    // arrange
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    (void)mqtt_client_connect(mqttHandle, TEST_IO_HANDLE, &mqttOptions);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));

    // act
    int result = mqtt_client_disconnect(mqttHandle, NULL, NULL);
    mqtt_client_dowork(mqttHandle);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


/*Test_SRS_MQTT_CLIENT_07_027: [The callbackCtx parameter shall be an unmodified pointer that was passed to the mqtt_client_init function.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_context_NULL_fails)
{
    // arrange
    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;


    CONNECT_ACK connack = { 0 };
    connack.isSessionPresent = true;
    connack.returnCode = CONNECTION_ACCEPTED;
    testData.actionResult = MQTT_CLIENT_ON_CONNACK;
    testData.msgInfo = &connack;

    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    g_packetComplete(NULL, CONNACK_TYPE, 0, connack_handle);

    // assert
    ASSERT_IS_FALSE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_context_and_handle_NULL_fails)
{
    // arrange
    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;


    CONNECT_ACK connack = { 0 };
    connack.isSessionPresent = true;
    connack.returnCode = CONNECTION_ACCEPTED;
    testData.actionResult = MQTT_CLIENT_ON_CONNACK;
    testData.msgInfo = &connack;

    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    g_packetComplete(NULL, PINGRESP_TYPE, 0, NULL);

    // assert
    ASSERT_IS_FALSE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_027: [The callbackCtx parameter shall be an unmodified pointer that was passed to the mqtt_client_init function.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_BUFFER_HANDLE_NULL_fails)
{
    // arrange
    TEST_COMPLETE_DATA_INSTANCE testData;

    CONNECT_ACK connack = { 0 };
    connack.isSessionPresent = true;
    connack.returnCode = CONNECTION_ACCEPTED;
    testData.actionResult = MQTT_CLIENT_ON_CONNACK;
    testData.msgInfo = &connack;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, NULL);

    // assert
    ASSERT_IS_FALSE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_028: [If the actionResult parameter is of type CONNECT_ACK then the msgInfo value shall be a CONNECT_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_CONNACK_succeeds)
{
    // arrange
    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;

    CONNECT_ACK connack = { 0 };
    connack.isSessionPresent = true;
    connack.returnCode = CONNECTION_ACCEPTED;
    testData.actionResult = MQTT_CLIENT_ON_CONNACK;
    testData.msgInfo = &connack;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);

    // act
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_028: [If the actionResult parameter is of type CONNECT_ACK then the msgInfo value shall be a CONNECT_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_CONNACK_auth_reject_succeeds)
{
    // arrange
    unsigned char CONNACK_RESP[] ={ 0x00, 0x05 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;

    CONNECT_ACK connack = { 0 };
    connack.isSessionPresent = false;
    connack.returnCode = CONN_REFUSED_NOT_AUTHORIZED;
    testData.actionResult = MQTT_CLIENT_ON_CONNACK;
    testData.msgInfo = &connack;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);

    // act
    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_EXACTLY_ONCE_succeeds)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00, 0x0a, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, \
        0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x6e, 0x64 };
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    setup_publish_callback_mocks(PUBLISH_RESP, length, DELIVER_EXACTLY_ONCE);

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_EXACTLY_ONCE_fail)
{
    // arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    unsigned char PUBLISH_RESP[] ={ 0x00, 0x0a, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, \
        0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x6e, 0x64 };
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;

    setup_publish_callback_mocks(PUBLISH_RESP, length, DELIVER_EXACTLY_ONCE);

    umock_c_negative_tests_snapshot();

    // act
    size_t calls_cannot_fail[] = { 0, 1, 7, 8, 11, 12, 13 };
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

        if (index == 2 || index == 3 || index == 4 || index == 5 || index == 6)
            ASSERT_IS_TRUE(g_errorCallbackInvoked, "IoTHubClient_LL_Create failure in test %zu/%zu", index, count);
    }

    // cleanup
    mqtt_client_deinit(mqttHandle);
    umock_c_negative_tests_deinit();
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_AT_LEAST_ONCE_succeeds)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00, 0x0a, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, \
        0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x6e, 0x64 };
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0a;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(TEST_PACKET_ID, IGNORED_PTR_ARG, DELIVER_AT_LEAST_ONCE, IGNORED_PTR_ARG, TEST_APP_PAYLOAD.length));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, true));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqtt_codec_publishAck(TEST_PACKET_ID));
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_AT_LEAST_ONCE_no_body_succeeds)
{
    // arrange
    // Packet contains a topic name, PacketID, but no body.  This is legal mqtt for AT_LEAST_ONCE PUBLISH.
    unsigned char PUBLISH_RESP[] = { 0x00, 0x0a, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0a;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(TEST_PACKET_ID, IGNORED_PTR_ARG, DELIVER_AT_LEAST_ONCE, IGNORED_PTR_ARG, 0));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, true));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqtt_codec_publishAck(TEST_PACKET_ID));
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_AT_MOST_ONCE_succeeds)
{
    // arrange
    unsigned char PUBLISH_VALUE[] = { 0x00, 0x04, 0x6d, 0x73, 0x67, 0x41, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x70, 0x70, 0x20, 0x6d, 0x73, 0x67, 0x20, 0x41, 0x2e };
    size_t length = sizeof(PUBLISH_VALUE) / sizeof(PUBLISH_VALUE[0]);

    uint8_t flag = 0x00;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_VALUE, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_VALUE);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(0, IGNORED_PTR_ARG, DELIVER_AT_MOST_ONCE, IGNORED_PTR_ARG, 22));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_AT_MOST_ONCE_with_two_zeros_body_data_succeeds)
{
    // arrange
    // This is legal publish.  The 0x00 0x00 would be illegal PacketID if we were using PacketID's, which AT_MOST_ONCE does not.
    unsigned char PUBLISH_VALUE[] = { 0x00, 0x04, 0x6d, 0x73, 0x67, 0x41, 0x00, 0x00 };
    size_t length = sizeof(PUBLISH_VALUE) / sizeof(PUBLISH_VALUE[0]);

    uint8_t flag = 0x00;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_VALUE, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_VALUE);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(0, IGNORED_PTR_ARG, DELIVER_AT_MOST_ONCE, IGNORED_PTR_ARG, 2));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_AT_MOST_ONCE_no_body_succeeds)
{
    // arrange
    // The topic name is the only data sent; no follow on packet ID or body.  This is legaly.
    unsigned char PUBLISH_VALUE[] = { 0x00, 0x04, 0x6d, 0x73, 0x67, 0x41 };
    size_t length = sizeof(PUBLISH_VALUE) / sizeof(PUBLISH_VALUE[0]);

    uint8_t flag = 0x00;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_VALUE, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_VALUE);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(0, IGNORED_PTR_ARG, DELIVER_AT_MOST_ONCE, IGNORED_PTR_ARG, 0));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, false));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_IS_TRUE(g_msgRecvCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_ACK_succeeds)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_ACK;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);

    // act
    g_packetComplete(mqttHandle, PUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_RECEIVE_succeeds)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_RECV;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);
    EXPECTED_CALL(mqtt_codec_publishRelease(IGNORED_NUM_ARG));
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBREC_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_RECEIVE_fails)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback ={ 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_RECV;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);
    EXPECTED_CALL(mqtt_codec_publishRelease(IGNORED_NUM_ARG));

    // act
    g_mqtt_codec_publish_func_fail = true;
    g_packetComplete(mqttHandle, PUBREC_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_RELEASE_succeeds)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_REL;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);
    EXPECTED_CALL(mqtt_codec_publishComplete(IGNORED_NUM_ARG));
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBREL_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_RELEASE_fails)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] ={ 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback ={ 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_REL;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    MQTT_CLIENT_OPTIONS mqttOptions = { 0 };
    make_connack(mqttHandle, &mqttOptions);
    g_openComplete(g_onCompleteCtx, IO_OPEN_OK);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);
    EXPECTED_CALL(mqtt_codec_publishComplete(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(xio_close(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_dowork(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ThreadAPI_Sleep(CLOSE_SLEEP_VALUE));

    // act
    g_mqtt_codec_publish_func_fail = true;
    g_packetComplete(mqttHandle, PUBREL_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_029: [If the actionResult parameter are of types PUBACK_TYPE, PUBREC_TYPE, PUBREL_TYPE or PUBCOMP_TYPE then the msgInfo value shall be a PUBLISH_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_COMPLETE_succeeds)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_COMP;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);

    // act
    g_packetComplete(mqttHandle, PUBCOMP_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_too_long_topic_name_length_fails)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00, 0x01}; // Topic length is 1, but there is not a byte following
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_IS_FALSE(g_msgRecvCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_invalid_topic_name_length_fails)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00 }; // Topic length needs to contain at least two bytes
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_IS_FALSE(g_msgRecvCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_too_short_packetID_fails)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00, 0x01, 0x0A, 0x00 }; // PacketId needed to be 2 bytes, but only 1 (after 0x0A) is supplied.
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));


    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_IS_FALSE(g_msgRecvCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_PUBLISH_packetId_is_zero_fails)
{
    // arrange
    unsigned char PUBLISH_RESP[] = { 0x00, 0x01, 0x0A, 0x00, 0x00 }; // packetId has enough bytes, but it can't be 0
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&PUBLISH_RESP, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_TRUE(g_errorCallbackInvoked);
    ASSERT_IS_FALSE(g_msgRecvCallbackInvoked);

    // cleanup
    mqtt_client_deinit(mqttHandle);
}


/*Test_SRS_MQTT_CLIENT_07_031: [If the actionResult parameter is of type UNSUBACK_TYPE then the msgInfo value shall be a UNSUBSCRIBE_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_SUBACK_succeeds)
{
    // arrange
    const size_t PACKET_RETCODE_COUNT = 4;
    unsigned char SUBSCRIBE_ACK_RESP[] = { 0x12, 0x34, 0x00, 0x02, 0x01, 0x80 };
    size_t length = sizeof(SUBSCRIBE_ACK_RESP) / sizeof(SUBSCRIBE_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    SUBSCRIBE_ACK suback = { 0 };
    suback.packetId = 0x1234;
    suback.qosReturn = (QOS_VALUE*)malloc(sizeof(QOS_VALUE)*PACKET_RETCODE_COUNT);
    suback.qosCount = PACKET_RETCODE_COUNT;
    suback.qosReturn[0] = DELIVER_AT_MOST_ONCE;
    suback.qosReturn[1] = DELIVER_EXACTLY_ONCE;
    suback.qosReturn[2] = DELIVER_AT_LEAST_ONCE;
    suback.qosReturn[3] = DELIVER_FAILURE;

    testData.actionResult = MQTT_CLIENT_ON_SUBSCRIBE_ACK;
    testData.msgInfo = &suback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(SUBSCRIBE_ACK_RESP);

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, SUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    free(suback.qosReturn);
    mqtt_client_deinit(mqttHandle);
}

/*Test_SRS_MQTT_CLIENT_07_031: [If the actionResult parameter is of type UNSUBACK_TYPE then the msgInfo value shall be a UNSUBSCRIBE_ACK structure.]*/
TEST_FUNCTION(mqtt_client_recvCompleteCallback_UNSUBACK_succeeds)
{
    // arrange
    unsigned char UNSUBSCRIBE_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(UNSUBSCRIBE_ACK_RESP) / sizeof(UNSUBSCRIBE_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    UNSUBSCRIBE_ACK unsuback = { 0 };
    unsuback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_UNSUBSCRIBE_ACK;
    testData.msgInfo = &unsuback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(UNSUBSCRIBE_ACK_RESP);

    // act
    g_packetComplete(mqttHandle, UNSUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_TRUE(g_operationCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_recvCompleteCallback_PINGRESP_succeeds)
{
    // arrange
    unsigned char PINGRESP_ACK_RESP[] = { 0x0d, 0x00 };
    size_t length = sizeof(PINGRESP_ACK_RESP) / sizeof(PINGRESP_ACK_RESP[0]);

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PINGRESP_ACK_RESP);

    // act
    g_packetComplete(mqttHandle, PINGRESP_TYPE, 0, packet_handle);

    // assert
    ASSERT_IS_FALSE(g_errorCallbackInvoked);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_set_trace_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    umock_c_reset_all_calls();

    // act
    mqtt_client_set_trace(mqttHandle, true, true);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_set_trace_traceOn_NULL_fail)
{
    // arrange

    // act
    mqtt_client_set_trace(NULL, true, true);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(mqtt_client_trace_CONNACK_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    mqtt_client_set_trace(mqttHandle, true, true);
    umock_c_reset_all_calls();

    // act
    unsigned char CONNACK_RESP[] = { 0x1, 0x0 };
    size_t length = sizeof(CONNACK_RESP) / sizeof(CONNACK_RESP[0]);
    BUFFER_HANDLE connack_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(CONNACK_RESP);
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
#endif

    g_packetComplete(mqttHandle, CONNACK_TYPE, 0, connack_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_trace_PUBLISH_succeeds)
{
    // arrange
    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, NULL, TestErrorCallback, NULL);
    mqtt_client_set_trace(mqttHandle, true, true);
    umock_c_reset_all_calls();

    // act
    unsigned char PUBLISH_RESP[] = { 0x00, 0x0a, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, \
        0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x65, 0x6e, 0x64 };
    size_t length = sizeof(PUBLISH_RESP) / sizeof(PUBLISH_RESP[0]);

    uint8_t flag = 0x0d;

    BUFFER_HANDLE publish_handle = TEST_BUFFER_HANDLE;

    //setup_publish_callback_mocks(PUBLISH_RESP, length, DELIVER_EXACTLY_ONCE);
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_RESP);
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_create_in_place(TEST_PACKET_ID, IGNORED_PTR_ARG, DELIVER_EXACTLY_ONCE, IGNORED_PTR_ARG, TEST_APP_PAYLOAD.length));
    STRICT_EXPECTED_CALL(mqttmessage_setIsDuplicateMsg(IGNORED_PTR_ARG, true));
    STRICT_EXPECTED_CALL(mqttmessage_setIsRetained(IGNORED_PTR_ARG, true));
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
#endif
    STRICT_EXPECTED_CALL(mqtt_codec_publishReceived(TEST_PACKET_ID)).SetReturn((BUFFER_HANDLE)0x111111);
    EXPECTED_CALL(BUFFER_length(IGNORED_PTR_ARG)).SetReturn(length);
    EXPECTED_CALL(BUFFER_u_char(IGNORED_PTR_ARG)).SetReturn(PUBLISH_RESP);
    STRICT_EXPECTED_CALL(tickcounter_get_current_ms(TEST_COUNTER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);
    EXPECTED_CALL(xio_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(mqttmessage_destroy(IGNORED_PTR_ARG));
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
#endif
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    g_packetComplete(mqttHandle, PUBLISH_TYPE, flag, publish_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_trace_PUBLISH_ACK_succeeds)
{
    // arrange
    unsigned char PUBLISH_ACK_RESP[] = { 0x12, 0x34 };
    size_t length = sizeof(PUBLISH_ACK_RESP) / sizeof(PUBLISH_ACK_RESP[0]);
    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_ACK;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    mqtt_client_set_trace(mqttHandle, true, true);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(PUBLISH_ACK_RESP);
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
#endif

    // act
    g_packetComplete(mqttHandle, PUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_trace_SUBSCRIBE_ACK_succeeds)
{
    // arrange
    unsigned char SUBSCRIBE_ACK_RESP[] = { 0x12, 0x34, 0x00, 0x02, 0x01, 0x80 };
    size_t length = sizeof(SUBSCRIBE_ACK_RESP) / sizeof(SUBSCRIBE_ACK_RESP[0]);

    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_ACK;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    mqtt_client_set_trace(mqttHandle, true, true);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(SUBSCRIBE_ACK_RESP);
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
#endif
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    g_packetComplete(mqttHandle, SUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

TEST_FUNCTION(mqtt_client_trace_UNSUBSCRIBE_ACK_succeeds)
{
    // arrange
    unsigned char UNSUBSCRIBE_ACK_RESP[] = { 0xB0, 0x02, 0x12, 0x34 };
    size_t length = sizeof(UNSUBSCRIBE_ACK_RESP) / sizeof(UNSUBSCRIBE_ACK_RESP[0]);

    TEST_COMPLETE_DATA_INSTANCE testData;
    PUBLISH_ACK puback = { 0 };
    puback.packetId = 0x1234;

    testData.actionResult = MQTT_CLIENT_ON_PUBLISH_ACK;
    testData.msgInfo = &puback;

    MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(TestRecvCallback, TestOpCallback, (void*)&testData, TestErrorCallback, NULL);
    mqtt_client_set_trace(mqttHandle, true, true);
    umock_c_reset_all_calls();

    BUFFER_HANDLE packet_handle = TEST_BUFFER_HANDLE;
    STRICT_EXPECTED_CALL(BUFFER_length(TEST_BUFFER_HANDLE)).SetReturn(length);
    STRICT_EXPECTED_CALL(BUFFER_u_char(TEST_BUFFER_HANDLE)).SetReturn(UNSUBSCRIBE_ACK_RESP);
#ifdef ENABLE_RAW_TRACE
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
#endif
#ifndef NO_LOGGING
    STRICT_EXPECTED_CALL(get_time(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
#endif

    // act
    g_packetComplete(mqttHandle, UNSUBACK_TYPE, 0, packet_handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    mqtt_client_deinit(mqttHandle);
}

END_TEST_SUITE(mqtt_client_ut)
