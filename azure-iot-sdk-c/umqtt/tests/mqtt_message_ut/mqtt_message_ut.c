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
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umocktypes_stdint.h"
#include "umock_c/umocktypes_bool.h"
#include "umock_c/umocktypes.h"
#include "umock_c/umocktypes_c.h"

#ifdef __cplusplus
extern "C" {
#endif

    void* my_gballoc_malloc(size_t size)
    {
        return malloc(size);
    }

    void my_gballoc_free(void* ptr)
    {
        free(ptr);
    }

    int my_mallocAndStrcpy_s(char** destination, const char* source)
    {
        size_t len = strlen(source);
        *destination = (char*)malloc(len + 1);
        strcpy(*destination, source);
        return 0;
    }

#ifdef __cplusplus
}
#endif

#define ENABLE_MOCKS

#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/string_token.h"

#undef ENABLE_MOCKS

#include "azure_umqtt_c/mqtt_message.h"

#ifdef __cplusplus
extern "C" {
#endif

    extern STRING_TOKEN_HANDLE real_StringToken_GetFirst(const char* source, size_t length, const char** delimiters, size_t n_delims);
    extern bool real_StringToken_GetNext(STRING_TOKEN_HANDLE token, const char** delimiters, size_t n_delims);
    extern const char* real_StringToken_GetValue(STRING_TOKEN_HANDLE token);
    extern size_t real_StringToken_GetLength(STRING_TOKEN_HANDLE token);
    extern const char* real_StringToken_GetDelimiter(STRING_TOKEN_HANDLE token);
    extern int real_StringToken_Split(const char* source, size_t length, const char** delimiters, size_t n_delims, bool include_empty, char*** tokens, size_t* token_count);
    extern void real_StringToken_Destroy(STRING_TOKEN_HANDLE token);

#ifdef __cplusplus
}
#endif

static bool g_fail_alloc_calls;

static const uint8_t TEST_PACKET_ID = (uint8_t)0x12;
static const char* TEST_TOPIC_NAME = "$subTopic1/subTopic2/subTopic3/?$prop1=value1&$prop2=value2";
static const uint8_t* TEST_MESSAGE = (const uint8_t*)"Message to send";
static const int TEST_MSG_LEN = sizeof(TEST_MESSAGE)/sizeof(TEST_MESSAGE[0]);

typedef struct TEST_COMPLETE_DATA_INSTANCE_TAG
{
    unsigned char* dataHeader;
    size_t Length;
} TEST_COMPLETE_DATA_INSTANCE;

MU_DEFINE_ENUM_STRINGS_2(QOS_VALUE, QOS_VALUE_VALUES);
TEST_DEFINE_ENUM_2_TYPE(QOS_VALUE, QOS_VALUE_VALUES);
IMPLEMENT_UMOCK_C_ENUM_2_TYPE(QOS_VALUE, QOS_VALUE_VALUES);

TEST_MUTEX_HANDLE test_serialize_mutex;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

BEGIN_TEST_SUITE(mqtt_message_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    ASSERT_ARE_EQUAL(int, 0, umocktypes_bool_register_types());

    REGISTER_UMOCK_ALIAS_TYPE(STRING_TOKEN_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
    REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_GetFirst, real_StringToken_GetFirst);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_GetNext, real_StringToken_GetNext);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_GetDelimiter, real_StringToken_GetDelimiter);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_GetValue, real_StringToken_GetValue);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_GetLength, real_StringToken_GetLength);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_Split, real_StringToken_Split);
    REGISTER_GLOBAL_MOCK_HOOK(StringToken_Destroy, real_StringToken_Destroy);

    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_GetFirst, NULL);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_GetNext, false);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_GetDelimiter, NULL);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_GetValue, NULL);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_GetLength, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(StringToken_Split, 1);
    REGISTER_GLOBAL_MOCK_RETURN(mallocAndStrcpy_s, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mallocAndStrcpy_s, 1);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    TEST_MUTEX_DESTROY(test_serialize_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    if (TEST_MUTEX_ACQUIRE(test_serialize_mutex))
    {
        ASSERT_FAIL("Could not acquire test serialization mutex.");
    }
    g_fail_alloc_calls = false;
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

/* Test_SRS_MQTTMESSAGE_07_001:[If the parameters topicName is NULL then mqttmessage_createMessage shall return NULL.] */
TEST_FUNCTION(mqttmessage_create_Topicname_NULL_fail)
{
    // arrange

    // act
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, NULL, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    // assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

/* Test_SRS_MQTTMESSAGE_07_001:[If the parameters topicName is NULL then mqttmessage_create shall return NULL.] */
TEST_FUNCTION(mqttmessage_create_appMsgLength_NULL_succeed)
{
    // arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_TOPIC_NAME))
        .IgnoreArgument(1);

    // act
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, NULL, 0);

    // assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_002: [mqttmessage_create shall allocate and copy the topicName and appMsg parameters.]*/
/* Test_SRS_MQTTMESSAGE_07_004: [If mqttmessage_create succeeds the it shall return a NON-NULL MQTT_MESSAGE_HANDLE value.] */
TEST_FUNCTION(mqttmessage_create_succeed)
{
    // arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_TOPIC_NAME))
        .IgnoreArgument(1);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    // act
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    // assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Tests_SRS_MQTTMESSAGE_07_028: [If any memory allocation fails mqttmessage_create_in_place shall free any allocated memory and return NULL.] */
TEST_FUNCTION(mqttmessage_create_in_place_topic_name_name_fail)
{
    // arrange

    // act
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create_in_place(TEST_PACKET_ID, NULL, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    // assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

/* Tests_SRS_MQTTMESSAGE_07_027: [mqttmessage_create_in_place shall use the a pointer to topicName or appMsg .] */
/* Tests_SRS_MQTTMESSAGE_07_029: [ Upon success, mqttmessage_create_in_place shall return a NON-NULL MQTT_MESSAGE_HANDLE value.] */
/* Tests_SRS_MQTTMESSAGE_07_026: [If the parameters topicName is NULL then mqttmessage_create_in_place shall return NULL.].] */
TEST_FUNCTION(mqttmessage_create_in_place_succeed)
{
    // arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    // act
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create_in_place(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    // assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_006: [mqttmessage_destroyMessage shall free all resources associated with the MQTT_MESSAGE_HANDLE value] */
TEST_FUNCTION(mqttmessage_destroy_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    mqttmessage_destroy(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(mqttmessage_destroy_inplace_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create_in_place(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    mqttmessage_destroy(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

/* Test_SRS_MQTTMESSAGE_07_005: [If the handle parameter is NULL then mqttmessage_destroyMessage shall do nothing] */
TEST_FUNCTION(mqttmessage_destroy_handle_NULL_fail)
{
    // arrange

    // act
    mqttmessage_destroy(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

/* Test_SRS_MQTTMESSAGE_07_008: [mqttmessage_clone shall create a new MQTT_MESSAGE_HANDLE with data content identical of the handle value.] */
TEST_FUNCTION(mqttmessage_clone_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_TOPIC_NAME));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    // act
    MQTT_MESSAGE_HANDLE cloneHandle = mqttmessage_clone(handle);

    // assert
    ASSERT_IS_NOT_NULL(cloneHandle);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
    mqttmessage_destroy(cloneHandle);
}

/* Test_SRS_MQTTMESSAGE_07_007: [If handle parameter is NULL then mqttmessage_clone shall return NULL.] */
TEST_FUNCTION(mqttmessage_clone_handle_fails)
{
    // arrange

    // act
    MQTT_MESSAGE_HANDLE cloneHandle = mqttmessage_clone(NULL);

    // assert
    ASSERT_IS_NULL(cloneHandle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

/* Test_SRS_MQTTMESSAGE_07_010: [If handle is NULL then mqttmessage_getPacketId shall return 0.] */
TEST_FUNCTION(mqttmessage_getPacketId_handle_fails)
{
    // arrange

    // act
    uint16_t packetId = mqttmessage_getPacketId(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, 0, packetId);
}

/* Test_SRS_MQTTMESSAGE_07_011: [mqttmessage_getPacketId shall return the packetId value contained in MQTT_MESSAGE_HANDLE handle.] */
TEST_FUNCTION(mqttmessage_getPacketId_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    uint16_t packetId = mqttmessage_getPacketId(handle);

    // assert
    ASSERT_ARE_EQUAL(int, TEST_PACKET_ID, packetId);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_012: [If handle is NULL then mqttmessage_getTopicName shall return a NULL string.] */
TEST_FUNCTION(mqttmessage_getTopicName_handle_fails)
{
    // arrange

    // act
    const char* topicName = mqttmessage_getTopicName(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NULL(topicName);
}

/* Test_SRS_MQTTMESSAGE_07_013: [mqttmessage_getTopicName shall return the topicName contained in MQTT_MESSAGE_HANDLE handle.] */
TEST_FUNCTION(mqttmessage_getTopicName_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    const char* topicName = mqttmessage_getTopicName(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, TEST_TOPIC_NAME, topicName);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_014: [If handle is NULL then mqttmessage_getQosType shall return the default DELIVER_AT_MOST_ONCE value.] */
TEST_FUNCTION(mqttmessage_getQosType_handle_fails)
{
    // arrange

    // act
    QOS_VALUE value = mqttmessage_getQosType(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(QOS_VALUE, DELIVER_AT_MOST_ONCE, value);
}

/* Test_SRS_MQTTMESSAGE_07_015: [mqttmessage_getQosType shall return the QOS Type value contained in MQTT_MESSAGE_HANDLE handle.] */
TEST_FUNCTION(mqttmessage_getQosType_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_LEAST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    QOS_VALUE value = mqttmessage_getQosType(handle);

    // assert
    ASSERT_ARE_EQUAL(QOS_VALUE, DELIVER_AT_LEAST_ONCE, value);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_016: [If handle is NULL then mqttmessage_getIsDuplicateMsg shall return false.] */
TEST_FUNCTION(mqttmessage_getIsDuplicateMsg_handle_fails)
{
    // arrange

    // act
    bool value = mqttmessage_getIsDuplicateMsg(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_FALSE(value);
}

/* Tests_SRS_MQTTMESSAGE_07_022: [If handle is NULL then mqttmessage_setIsDuplicateMsg shall return a non-zero value.] */
TEST_FUNCTION(mqttmessage_setIsDuplicateMsg_handle_fails)
{
    // arrange

    // act
    int value = mqttmessage_setIsDuplicateMsg(NULL, false);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, value);
}

/* Test_SRS_MQTTMESSAGE_07_017: [mqttmessage_getIsDuplicateMsg shall return the isDuplicateMsg value contained in MQTT_MESSAGE_HANDLE handle.] */
/* Test_SRS_MQTTMESSAGE_07_023: [mqttmessage_setIsDuplicateMsg shall store the duplicateMsg value in the MQTT_MESSAGE_HANDLE handle.] */
TEST_FUNCTION(mqttmessage_set_and_get_IsDuplicateMsg_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_LEAST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    int value = mqttmessage_setIsDuplicateMsg(handle, true);

    bool dupMsg = mqttmessage_getIsDuplicateMsg(handle);

    // assert
    ASSERT_ARE_EQUAL(int, 0, value);
    ASSERT_IS_TRUE(dupMsg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_018: [If handle is NULL then mqttmessage_getIsRetained shall return false.] */
TEST_FUNCTION(mqttmessage_getIsRetained_handle_fails)
{
    // arrange

    // act
    bool value = mqttmessage_getIsRetained(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_FALSE(value);
}

/* Tests_SRS_MQTTMESSAGE_07_024: [If handle is NULL then mqttmessage_setIsRetained shall return a non-zero value.] */
TEST_FUNCTION(mqttmessage_setIsRetained_handle_fails)
{
    // arrange

    // act
    int value = mqttmessage_setIsRetained(NULL, false);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, value);
}

/* Test_SRS_MQTTMESSAGE_07_019: [mqttmessage_getIsRetained shall return the isRetained value contained in MQTT_MESSAGE_HANDLE handle.] */
/* Test_SRS_MQTTMESSAGE_07_025: [mqttmessage_setIsRetained shall store the retainMsg value in the MQTT_MESSAGE_HANDLE handle.] */
TEST_FUNCTION(mqttmessage_set_and_get_IsRetained_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_LEAST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    int value = mqttmessage_setIsRetained(handle, true);

    bool retainMsg = mqttmessage_getIsRetained(handle);

    // assert
    ASSERT_ARE_EQUAL(int, 0, value);
    ASSERT_IS_TRUE(retainMsg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

/* Test_SRS_MQTTMESSAGE_07_020: [If handle is NULL or if msgLen is 0 then mqttmessage_applicationMsg shall return NULL.] */
TEST_FUNCTION(mqttmessage_getApplicationMsg_handle_fails)
{
    // arrange

    // act
    const APP_PAYLOAD* payload = mqttmessage_getApplicationMsg(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NULL(payload);
}

/* Test_SRS_MQTTMESSAGE_07_021: [mqttmessage_getApplicationMsg shall return the applicationMsg value contained in MQTT_MESSAGE_HANDLE handle and the length of the appMsg in the msgLen parameter.] */
TEST_FUNCTION(mqttmessage_getApplicationMsg_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_LEAST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);
    umock_c_reset_all_calls();

    // act
    const APP_PAYLOAD* payload = mqttmessage_getApplicationMsg(handle);

    // assert
    ASSERT_IS_NOT_NULL(payload);
    ASSERT_ARE_EQUAL(int, 0, memcmp(payload->message, TEST_MESSAGE, TEST_MSG_LEN) );
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    mqttmessage_destroy(handle);
}

// Tests_SRS_MQTTMESSAGE_09_001: [ If `handle`, `levels` or `count` are NULL the function shall return a non-zero value. ]
TEST_FUNCTION(mqttmessage_getTopicLevels_NULL_handle)
{
    // arrange
    char** levels;
    size_t count;
    int result;

    umock_c_reset_all_calls();

    // act
    result = mqttmessage_getTopicLevels(NULL, &levels, &count);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

// Tests_SRS_MQTTMESSAGE_09_001: [ If `handle`, `levels` or `count` are NULL the function shall return a non-zero value. ]
TEST_FUNCTION(mqttmessage_getTopicLevels_NULL_levels)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = (MQTT_MESSAGE_HANDLE)0x4444;
    size_t count;
    int result;

    umock_c_reset_all_calls();

    // act
    result = mqttmessage_getTopicLevels(handle, NULL, &count);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

// Tests_SRS_MQTTMESSAGE_09_001: [ If `handle`, `levels` or `count` are NULL the function shall return a non-zero value. ]
TEST_FUNCTION(mqttmessage_getTopicLevels_NULL_count)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle = (MQTT_MESSAGE_HANDLE)0x4444;
    char** levels;
    int result;

    umock_c_reset_all_calls();

    // act
    result = mqttmessage_getTopicLevels(handle, &levels, NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
}

// Tests_SRS_MQTTMESSAGE_09_002: [ The topic name, excluding the property bag, shall be split into individual tokens using "/" as separator ]
// Tests_SRS_MQTTMESSAGE_09_004: [ The split tokens shall be stored in `levels` and its count in `count` ]
// Tests_SRS_MQTTMESSAGE_09_005: [ If no failures occur the function shall return zero. ]
TEST_FUNCTION(mqttmessage_getTopicLevels_succeed)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle;
    char** levels;
    size_t count;
    int result;

    umock_c_reset_all_calls();
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_TOPIC_NAME))
        .IgnoreArgument(1);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    STRICT_EXPECTED_CALL(StringToken_Split(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, 1, false, IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    // act
    result = mqttmessage_getTopicLevels(handle, &levels, &count);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 4, count);
    ASSERT_ARE_EQUAL(char_ptr, "$subTopic1", levels[0]);
    ASSERT_ARE_EQUAL(char_ptr, "subTopic2", levels[1]);
    ASSERT_ARE_EQUAL(char_ptr, "subTopic3", levels[2]);
    ASSERT_ARE_EQUAL(char_ptr, "?$prop1=value1&$prop2=value2", levels[3]);

    // cleanup
    mqttmessage_destroy(handle);

    while (count > 0)
    {
        free(levels[--count]);
    }
    free(levels);
}

// Tests_SRS_MQTTMESSAGE_09_003: [ If splitting fails the function shall return a non-zero value. ]
TEST_FUNCTION(mqttmessage_getTopicLevels_negative_tests)
{
    // arrange
    MQTT_MESSAGE_HANDLE handle;
    char** levels;
    size_t count;
    size_t i;

    ASSERT_ARE_EQUAL(int, 0, umock_c_negative_tests_init());

    umock_c_reset_all_calls();
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, TEST_TOPIC_NAME))
        .IgnoreArgument(1);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    handle = mqttmessage_create(TEST_PACKET_ID, TEST_TOPIC_NAME, DELIVER_AT_MOST_ONCE, TEST_MESSAGE, TEST_MSG_LEN);

    umock_c_reset_all_calls();
    STRICT_EXPECTED_CALL(StringToken_Split(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, 1, false, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    umock_c_negative_tests_snapshot();

    for (i = 0; i < umock_c_negative_tests_call_count(); i++)
    {
        // arrange
        int result;

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        // act
        result = mqttmessage_getTopicLevels(handle, &levels, &count);

        // assert
        ASSERT_ARE_NOT_EQUAL(int, 0, result, "On failed call %zu", i);
    }

    // cleanup
    mqttmessage_destroy(handle);
    umock_c_negative_tests_deinit();
}

END_TEST_SUITE(mqtt_message_ut)
