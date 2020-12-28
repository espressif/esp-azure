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

#include "testrunnerswitcher.h"

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

#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umocktypes_stdint.h"
#include "umock_c/umock_c_negative_tests.h"
#include "azure_macro_utils/macro_utils.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "umock_c/umock_c_prod.h"
#undef ENABLE_MOCKS

#include "azure_utpm_c/Memory_fp.h"
#include "azure_utpm_c/TpmTypes.h"

#ifdef __cplusplus
extern "C"
{
#endif
#ifdef __cplusplus
}
#endif

#define BUFFER_LENGTH       10

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

static TEST_MUTEX_HANDLE g_testByTest;

BEGIN_TEST_SUITE(tpm_memory_ut)

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

        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_realloc, my_gballoc_realloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_realloc, NULL);
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

    TEST_FUNCTION(MemoryCopy_dest_NULL_fail)
    {
        //arrange
        unsigned char src[BUFFER_LENGTH] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA };

        //act
        MemoryCopy(NULL, src, sizeof(src) );

        //assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(MemoryCopy_src_NULL_fail)
    {
        //arrange
        unsigned char dest[BUFFER_LENGTH];

        //act
        MemoryCopy(dest, NULL, sizeof(dest));

        //assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(MemoryCopy_succeed)
    {
        //arrange
        unsigned char src[BUFFER_LENGTH] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA };
        unsigned char dest[BUFFER_LENGTH];

        //act
        MemoryCopy(dest, src, sizeof(dest));

        //assert
        ASSERT_ARE_EQUAL(int, 0, memcmp(src, dest, 10));
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

    TEST_FUNCTION(MemoryCopy2B_succeed)
    {
        //arrange
        TPM2B_DIGEST src = { BUFFER_LENGTH, { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA } };
        TPM2B_DIGEST dest;

        //act
        int16_t result = MemoryCopy2B(&dest.b, &src.b, sizeof(dest));

        //assert
        ASSERT_ARE_EQUAL(int16_t, 10, result);
        ASSERT_ARE_EQUAL(int, 0, memcmp(dest.b.buffer, src.b.buffer, BUFFER_LENGTH));
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        //cleanup
    }

END_TEST_SUITE(tpm_memory_ut)
