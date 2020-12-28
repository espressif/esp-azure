#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

set(theseTestsName uhttp_ut)

if(${use_openssl})
    add_definitions(-DUSE_OPENSSL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_OPENSSL")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_OPENSSL")
endif()

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

include_directories(${SHARED_UTIL_REAL_TEST_FOLDER})

set(${theseTestsName}_c_files
    ../../src/uhttp.c
    ${SHARED_UTIL_REAL_TEST_FOLDER}/real_buffer.c
)

set(${theseTestsName}_h_files
)

build_c_test_artifacts(${theseTestsName} ON "tests/uhttp_tests")

compile_c_test_artifacts_as(${theseTestsName} C99)
