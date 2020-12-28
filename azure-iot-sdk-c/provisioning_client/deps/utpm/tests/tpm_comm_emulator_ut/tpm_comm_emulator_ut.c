// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#else
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#endif

#undef DECLSPEC_IMPORT
#pragma warning(disable: 4273)
#ifdef WIN32
#include <Winsock2.h>
typedef unsigned long   htonl_type;
#else
#include <arpa/inet.h>
typedef uint32_t        htonl_type;
#endif

static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void my_gballoc_free(void* ptr)
{
    free(ptr);
}

static void* my_gballoc_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

#include "testrunnerswitcher.h"
#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umocktypes_stdint.h"
#include "umock_c/umock_c_negative_tests.h"
#include "azure_macro_utils/macro_utils.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "umock_c/umock_c_prod.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_utpm_c/tpm_socket_comm.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#undef ENABLE_MOCKS

#include "azure_utpm_c/tpm_comm.h"

static htonl_type g_htonl_value = 1;
static const char* const TEST_SOCKET_ENDPOINT = "127.0.0.1";

#ifdef WIN32
MOCK_FUNCTION_WITH_CODE(WSAAPI, htonl_type, htonl, htonl_type, hostlong)
#else
MOCK_FUNCTION_WITH_CODE(, htonl_type, htonl, htonl_type, hostlong)
#endif
htonl_type tmp_rtn = hostlong;
MOCK_FUNCTION_END(tmp_rtn)

#ifdef __cplusplus
extern "C"
{
#endif
#ifdef __cplusplus
}
#endif

static const unsigned char* TEMP_TPM_COMMAND = (const unsigned char*)0x00012345;
#define TEMP_CMD_LENGTH         128
static const unsigned char RECV_DATA[] = { 0x11, 0x11, 0x11, 0x11 };
#define RECV_DATA_LEN           4

static ON_SEND_COMPLETE g_on_send_complete = NULL;
static void* g_on_send_context = NULL;
static ON_BYTES_RECEIVED g_on_bytes_received = NULL;
static void* g_on_bytes_received_context = NULL;

static bool g_send_was_last_called;
static bool g_closing_xio = false;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

TEST_DEFINE_ENUM_TYPE(TPM_COMM_TYPE, TPM_COMM_TYPE_VALUES);
IMPLEMENT_UMOCK_C_ENUM_TYPE(TPM_COMM_TYPE, TPM_COMM_TYPE_VALUES);

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

static int my_mallocAndStrcpy_s(char** destination, const char* source)
{
    (void)source;
    size_t src_len = strlen(source);
    *destination = (char*)my_gballoc_malloc(src_len + 1);
    strcpy(*destination, source);
    return 0;
}

static TPM_SOCKET_HANDLE my_tpm_socket_create(const char* address, unsigned short port)
{
    (void)address;
    (void)port;
    return (TPM_SOCKET_HANDLE)my_gballoc_malloc(1);
}

static void my_tpm_socket_destroy(TPM_SOCKET_HANDLE handle)
{
    my_gballoc_free(handle);
}

static TEST_MUTEX_HANDLE g_testByTest;

BEGIN_TEST_SUITE(tpm_comm_emulator_ut)

    TEST_SUITE_INITIALIZE(suite_init)
    {
        int result;

        g_testByTest = TEST_MUTEX_CREATE();
        ASSERT_IS_NOT_NULL(g_testByTest);

        (void)umock_c_init(on_umock_c_error);

        result = umocktypes_charptr_register_types();
        ASSERT_ARE_EQUAL(int, 0, result);
        result = umocktypes_stdint_register_types();
        ASSERT_ARE_EQUAL(int, 0, result);

        REGISTER_UMOCK_ALIAS_TYPE(TPM_COMM_HANDLE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(TPM_SOCKET_HANDLE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(htonl_type, unsigned long);

        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_realloc, my_gballoc_realloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_realloc, NULL);

        REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(mallocAndStrcpy_s, __LINE__);

        REGISTER_GLOBAL_MOCK_HOOK(tpm_socket_create, my_tpm_socket_create);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(tpm_socket_create, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(tpm_socket_destroy, my_tpm_socket_destroy);
        REGISTER_GLOBAL_MOCK_RETURN(tpm_socket_read, 0);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(tpm_socket_read, __LINE__);
        REGISTER_GLOBAL_MOCK_RETURN(tpm_socket_send, 0);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(tpm_socket_send, __LINE__);
}

    TEST_SUITE_CLEANUP(suite_cleanup)
    {
        umock_c_deinit();

        TEST_MUTEX_DESTROY(g_testByTest);
    }

    TEST_FUNCTION_INITIALIZE(method_init)
    {
        if (TEST_MUTEX_ACQUIRE(g_testByTest))
        {
            ASSERT_FAIL("Could not acquire test serialization mutex.");
        }
        umock_c_reset_all_calls();
        g_htonl_value = 1;
    }

    TEST_FUNCTION_CLEANUP(method_cleanup)
    {
        TEST_MUTEX_RELEASE(g_testByTest);
    }

    static int should_skip_index(size_t current_index, const size_t skip_array[], size_t length)
    {
        int result = 0;
        for (size_t index = 0; index < length; index++)
        {
            if (current_index == skip_array[index])
            {
                result = __LINE__;
                break;
            }
        }
        return result;
    }

    static void setup_socket_send_mocks()
    {
        STRICT_EXPECTED_CALL(htonl(IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(tpm_socket_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
    }

    static void setup_socket_read_mocks(htonl_type* htonl_reply)
    {
        STRICT_EXPECTED_CALL(tpm_socket_read(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG))
            .CopyOutArgumentBuffer_tpm_bytes(htonl_reply, sizeof(htonl_type));
        STRICT_EXPECTED_CALL(htonl(IGNORED_NUM_ARG));
    }

    static void setup_comm_create_mocks(void)
    {
        htonl_type client_ver = 1;
        htonl_type unused = 0;

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

        STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(tpm_socket_create(IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        setup_socket_send_mocks();
        setup_socket_send_mocks();

        setup_socket_read_mocks(&client_ver);
        setup_socket_read_mocks(&unused);
        setup_socket_read_mocks(&unused);

        // Power on simulator
        STRICT_EXPECTED_CALL(tpm_socket_create(IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(htonl(IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(htonl(IGNORED_NUM_ARG));

        STRICT_EXPECTED_CALL(tpm_socket_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        setup_socket_read_mocks(&unused);

        STRICT_EXPECTED_CALL(tpm_socket_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));

        setup_socket_read_mocks(&unused);
        STRICT_EXPECTED_CALL(tpm_socket_destroy(IGNORED_PTR_ARG));
    }

    static void setup_tpm_comm_submit_command_mocks(void)
    {
        htonl_type resp_len = RECV_DATA_LEN;
        htonl_type ack_cmd = 0;

        setup_socket_send_mocks();
        STRICT_EXPECTED_CALL(tpm_socket_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        setup_socket_send_mocks();
        STRICT_EXPECTED_CALL(tpm_socket_send(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        setup_socket_read_mocks(&resp_len);
        STRICT_EXPECTED_CALL(tpm_socket_read(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        setup_socket_read_mocks(&ack_cmd);

    }

    TEST_FUNCTION(tpm_comm_create_succeed)
    {
        //arrange
        setup_comm_create_mocks();

        //act
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(TEST_SOCKET_ENDPOINT);

        //assert
        ASSERT_IS_NOT_NULL(tpm_handle);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_create_fail)
    {
        int negativeTestsInitResult = umock_c_negative_tests_init();
        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        //arrange
        setup_comm_create_mocks();

        umock_c_negative_tests_snapshot();

        size_t calls_cannot_fail[] = { 3, 5, 8, 10, 12, 14, 15, 16, 18, 21, 22 };

        //act
        size_t count = umock_c_negative_tests_call_count();
        for (size_t index = 0; index < count; index++)
        {
            if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0])) != 0)
            {
                continue;
            }

            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            char tmp_msg[128];
            sprintf(tmp_msg, "tpm_comm_create failure in test %zu/%zu", index, count);

            TPM_COMM_HANDLE tpm_handle = tpm_comm_create(TEST_SOCKET_ENDPOINT);

            //assert
            ASSERT_IS_NULL(tpm_handle, tmp_msg);
        }

        //cleanup
        umock_c_negative_tests_deinit();
    }

    TEST_FUNCTION(tpm_comm_destroy_succeed)
    {
        //arrange
        setup_comm_create_mocks();
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(TEST_SOCKET_ENDPOINT);
        umock_c_reset_all_calls();

        setup_socket_send_mocks();
        STRICT_EXPECTED_CALL(tpm_socket_destroy(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

        //act
        tpm_comm_destroy(tpm_handle);

        //assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(tpm_comm_destroy_handle_NULL_succeed)
    {
        //arrange

        //act
        tpm_comm_destroy(NULL);

        //assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(tpm_comm_get_type_succeed)
    {
        //arrange

        //act
        TPM_COMM_TYPE comm_type = tpm_comm_get_type(NULL);

        //assert
        ASSERT_ARE_EQUAL(TPM_COMM_TYPE, TPM_COMM_TYPE_EMULATOR, comm_type);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(tpm_comm_submit_command_succeed)
    {
        int result;

        TPM_COMM_HANDLE tpm_handle;
        unsigned char response[RECV_DATA_LEN];
        uint32_t length = RECV_DATA_LEN;

        //arrange
        setup_comm_create_mocks();
        tpm_handle = tpm_comm_create(TEST_SOCKET_ENDPOINT);
        umock_c_reset_all_calls();

        setup_tpm_comm_submit_command_mocks();

        //act
        result = tpm_comm_submit_command(tpm_handle, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, &length);

        //assert
        ASSERT_ARE_EQUAL(int, 0, result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_submit_command_fail)
    {
        int result;

        TPM_COMM_HANDLE tpm_handle;
        unsigned char response[RECV_DATA_LEN];
        uint32_t length = RECV_DATA_LEN;

        int negativeTestsInitResult = umock_c_negative_tests_init();
        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        //arrange
        setup_comm_create_mocks();
        tpm_handle = tpm_comm_create(TEST_SOCKET_ENDPOINT);
        umock_c_reset_all_calls();

        setup_tpm_comm_submit_command_mocks();

        umock_c_negative_tests_snapshot();

        size_t calls_cannot_fail[] = { 0, 3, 7, 10 };

        //act
        size_t count = umock_c_negative_tests_call_count();
        for (size_t index = 0; index < count; index++)
        {
            if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0])) != 0)
            {
                continue;
            }

            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            result = tpm_comm_submit_command(tpm_handle, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, &length);

            //assert
            ASSERT_ARE_NOT_EQUAL(int, 0, result, "tpm_comm_submit_command failure in test %zu/%zu", index, count);
        }

        //cleanup
        tpm_comm_destroy(tpm_handle);
        umock_c_negative_tests_deinit();
    }


END_TEST_SUITE(tpm_comm_emulator_ut)
