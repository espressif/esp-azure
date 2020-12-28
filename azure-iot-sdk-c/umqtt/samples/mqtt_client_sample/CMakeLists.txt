#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

set(mqtt_client_sample_c_files
    mqtt_client_sample.c
)

if(WIN32)
    set(mqtt_client_sample_c_files ${mqtt_client_sample_c_files} ./windows/main.c)
else()
    set(mqtt_client_sample_c_files ${mqtt_client_sample_c_files} ./linux/main.c)
endif()

set(mqtt_client_sample_h_files
    mqtt_client_sample.h
)

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
ENDIF(WIN32)

include_directories(.)

add_executable(mqtt_client_sample ${mqtt_client_sample_c_files} ${mqtt_client_sample_h_files})

compileTargetAsC99(mqtt_client_sample)

if (WIN32)
    target_link_libraries(mqtt_client_sample
        aziotsharedutil
        umqtt
        secur32
        ws2_32)
    if(${use_openssl})
        target_link_libraries(mqtt_client_sample $ENV{OpenSSLDir}/lib/ssleay32.lib $ENV{OpenSSLDir}/lib/libeay32.lib)
        file(COPY $ENV{OpenSSLDir}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
        file(COPY $ENV{OpenSSLDir}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
    endif()
    if(${use_wolfssl})
        target_link_libraries(mqtt_client_sample $ENV{WolfSSLDir}/Debug/wolfssl.lib)
    endif()
else()
    target_link_libraries(mqtt_client_sample
        aziotsharedutil
        pthread
        umqtt)
    #if(${use_openssl})
        target_link_libraries(mqtt_client_sample ${OPENSSL_LIBRARIES})
    #endif()
endif()

