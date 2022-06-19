#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.5)

set(theseTestsName tpm_comm_linux_ut)

add_definitions(-DGB_DEBUG_FILEDESCRIPT)

set(${theseTestsName}_test_files
${theseTestsName}.c
)

set(${theseTestsName}_c_files
../../src/tpm_comm_linux.c
)

set(${theseTestsName}_h_files
)

build_c_test_artifacts(${theseTestsName} ON "tests/utpm_tests")

compile_c_test_artifacts_as(${theseTestsName} C99)
