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

static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#include "testrunnerswitcher.h"
#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umocktypes_stdint.h"
#include "umock_c/umock_c_negative_tests.h"
#include "azure_macro_utils/macro_utils.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include <windows.h>
#include <tbs.h>
#include "umock_c/umock_c_prod.h"

MOCKABLE_FUNCTION(WINAPI, TBS_RESULT, Tbsi_Context_Create, PCTBS_CONTEXT_PARAMS, pContextParams, PTBS_HCONTEXT, phContext);
MOCKABLE_FUNCTION(WINAPI, TBS_RESULT, Tbsi_GetDeviceInfo, uint32_t, size, PVOID, info);
MOCKABLE_FUNCTION(WINAPI, TBS_RESULT, Tbsip_Context_Close, TBS_HCONTEXT, hContext);
MOCKABLE_FUNCTION(WINAPI, TBS_RESULT, Tbsip_Submit_Command, TBS_HCONTEXT, hContext, TBS_COMMAND_LOCALITY, Locality, TBS_COMMAND_PRIORITY, Priority, PCBYTE, pabCommand, UINT32, cbCommand, PBYTE, pabResult, UINT32*, pcbResult);

#undef ENABLE_MOCKS

#include "azure_utpm_c/tpm_comm.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
}
#endif

static const unsigned char* TEMP_TPM_COMMAND = (const unsigned char*)0x00012345;
#define TEMP_CMD_LENGTH         128
static UINT32 g_tpm_version = TPM_VERSION_20;

static TBS_RESULT my_Tbsi_GetDeviceInfo(UINT32 size, PVOID info)
{
    (void)size;
    TPM_DEVICE_INFO* device_info = (TPM_DEVICE_INFO*)info;
    device_info->tpmVersion = g_tpm_version;
    return TBS_SUCCESS;
}

static TBS_RESULT my_Tbsi_Context_Create(PCTBS_CONTEXT_PARAMS pContextParams, PTBS_HCONTEXT phContext)
{
    (void)pContextParams;
    *phContext = (PTBS_HCONTEXT)my_gballoc_malloc(1);
    return TBS_SUCCESS;
}

static TBS_RESULT my_Tbsip_Context_Close(TBS_HCONTEXT hContext)
{
    my_gballoc_free(hContext);
    return TBS_SUCCESS;
}

TEST_DEFINE_ENUM_TYPE(TPM_COMM_TYPE, TPM_COMM_TYPE_VALUES);
IMPLEMENT_UMOCK_C_ENUM_TYPE(TPM_COMM_TYPE, TPM_COMM_TYPE_VALUES);

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

static TEST_MUTEX_HANDLE g_testByTest;

BEGIN_TEST_SUITE(tpm_comm_win32_ut)

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

        REGISTER_UMOCK_ALIAS_TYPE(PCTBS_CONTEXT_PARAMS, void*);
        REGISTER_UMOCK_ALIAS_TYPE(TPM_COMM_HANDLE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(PTBS_HCONTEXT, void*);
        REGISTER_UMOCK_ALIAS_TYPE(PVOID, void*);
        REGISTER_UMOCK_ALIAS_TYPE(TBS_HCONTEXT, void*);
        REGISTER_UMOCK_ALIAS_TYPE(TBS_COMMAND_LOCALITY, unsigned int);
        REGISTER_UMOCK_ALIAS_TYPE(TBS_COMMAND_PRIORITY, unsigned int);
        REGISTER_UMOCK_ALIAS_TYPE(PCBYTE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(PBYTE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(UINT32, unsigned int);
        REGISTER_UMOCK_ALIAS_TYPE(TBS_RESULT, unsigned int);

        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

        REGISTER_GLOBAL_MOCK_HOOK(Tbsi_Context_Create, my_Tbsi_Context_Create);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(Tbsi_Context_Create, (TBS_RESULT)TBS_E_TPM_NOT_FOUND);
        REGISTER_GLOBAL_MOCK_HOOK(Tbsi_GetDeviceInfo, my_Tbsi_GetDeviceInfo);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(Tbsi_GetDeviceInfo, (TBS_RESULT)TBS_E_INVALID_CONTEXT);
        REGISTER_GLOBAL_MOCK_HOOK(Tbsip_Context_Close, my_Tbsip_Context_Close);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(Tbsip_Context_Close, (TBS_RESULT)TBS_E_TPM_NOT_FOUND);
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
        g_tpm_version = TPM_VERSION_20;
    }

    TEST_FUNCTION_CLEANUP(method_cleanup)
    {
        TEST_MUTEX_RELEASE(g_testByTest);
    }

    static void setup_comm_create_mocks()
    {
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(Tbsi_Context_Create(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(Tbsi_GetDeviceInfo(IGNORED_NUM_ARG, IGNORED_PTR_ARG));
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

    TEST_FUNCTION(tpm_comm_create_succeed)
    {
        //arrange
        setup_comm_create_mocks();

        //act
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);

        //assert
        ASSERT_IS_NOT_NULL(tpm_handle);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_create_invalid_version_fail)
    {
        //arrange
        setup_comm_create_mocks();
        STRICT_EXPECTED_CALL(Tbsip_Context_Close(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

        g_tpm_version = TPM_VERSION_12;

        //act
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);

        //assert
        ASSERT_IS_NULL(tpm_handle);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(tpm_comm_create_fail)
    {
        int negativeTestsInitResult = umock_c_negative_tests_init();
        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        //arrange
        setup_comm_create_mocks();

        umock_c_negative_tests_snapshot();

        //act
        size_t count = umock_c_negative_tests_call_count();
        for (size_t index = 0; index < count; index++)
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            char tmp_msg[128];
            sprintf(tmp_msg, "tpm_comm_create failure in test %zu/%zu", index, count);

            TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);

            //assert
            ASSERT_IS_NULL(tpm_handle, tmp_msg);
        }
    }

    TEST_FUNCTION(tpm_comm_destroy_succeed)
    {
        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(Tbsip_Context_Close(IGNORED_PTR_ARG));
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

    TEST_FUNCTION(tpm_comm_get_type_succees)
    {
        TPM_COMM_TYPE comm_type;

        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        //act
        comm_type = tpm_comm_get_type(tpm_handle);

        //assert
        ASSERT_ARE_EQUAL(TPM_COMM_TYPE, TPM_COMM_TYPE_WINDOW, comm_type);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_submit_command_handle_NULL_fail)
    {
        //arrange

        //act
        unsigned char response[TEMP_CMD_LENGTH];
        uint32_t resp_len = TEMP_CMD_LENGTH;
        int tpm_result = tpm_comm_submit_command(NULL, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, &resp_len);

        //assert
        ASSERT_ARE_NOT_EQUAL(int, 0, tpm_result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(tpm_comm_submit_command_cmd_NULL_fail)
    {
        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        //act
        unsigned char response[TEMP_CMD_LENGTH];
        uint32_t resp_len = TEMP_CMD_LENGTH;
        int tpm_result = tpm_comm_submit_command(tpm_handle, NULL, TEMP_CMD_LENGTH, response, &resp_len);

        //assert
        ASSERT_ARE_NOT_EQUAL(int, 0, tpm_result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_submit_command_response_NULL_fail)
    {
        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        //act
        uint32_t resp_len = 0;
        int tpm_result = tpm_comm_submit_command(tpm_handle, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, NULL, &resp_len);

        //assert
        ASSERT_ARE_NOT_EQUAL(int, 0, tpm_result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_submit_command_fail)
    {
        unsigned char response[TEMP_CMD_LENGTH];
        uint32_t resp_len = TEMP_CMD_LENGTH;

        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(Tbsip_Submit_Command(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, IGNORED_PTR_ARG))
            .SetReturn((TBS_RESULT)TBS_E_SERVICE_NOT_RUNNING);

        //act
        int tpm_result = tpm_comm_submit_command(tpm_handle, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, &resp_len);

        //assert
        ASSERT_ARE_NOT_EQUAL(int, 0, tpm_result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

    TEST_FUNCTION(tpm_comm_submit_command_succees)
    {
        unsigned char response[TEMP_CMD_LENGTH];
        uint32_t resp_len = TEMP_CMD_LENGTH;

        //arrange
        TPM_COMM_HANDLE tpm_handle = tpm_comm_create(NULL);
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(Tbsip_Submit_Command(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, IGNORED_PTR_ARG));

        //act
        int tpm_result = tpm_comm_submit_command(tpm_handle, TEMP_TPM_COMMAND, TEMP_CMD_LENGTH, response, &resp_len);

        //assert
        ASSERT_ARE_EQUAL(int, 0, tpm_result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
        tpm_comm_destroy(tpm_handle);
    }

END_TEST_SUITE(tpm_comm_win32_ut)
