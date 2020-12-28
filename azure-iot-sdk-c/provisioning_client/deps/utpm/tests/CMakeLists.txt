#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.12)

usePermissiveRulesForSamplesAndTests()


if (WIN32)
    add_subdirectory(tpm_comm_emulator_ut)
    add_subdirectory(tpm_comm_win32_ut)
else()
    if (IOS)
    else()
        add_subdirectory(tpm_comm_linux_ut)
    endif()
endif()

add_subdirectory(tpm_codec_ut)
add_subdirectory(tpm_memory_ut)