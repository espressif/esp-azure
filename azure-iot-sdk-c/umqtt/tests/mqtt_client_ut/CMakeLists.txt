#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.5)

set(theseTestsName mqtt_client_ut)

set(${theseTestsName}_test_files
${theseTestsName}.c
)

set(${theseTestsName}_c_files
../../src/mqtt_client.c
)

set(${theseTestsName}_h_files
)

include_directories(${MQTT_SRC_FOLDER})

build_c_test_artifacts(${theseTestsName} ON "tests/umqtt_tests")

compile_c_test_artifacts_as(${theseTestsName} C99)
