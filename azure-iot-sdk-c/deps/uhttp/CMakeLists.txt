#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

project(uhttp)

set(UHTTP_VERSION 1.0.1)

option(run_e2e_tests "set run_e2e_tests to ON to run e2e tests (default is OFF)" OFF)
option(run_unittests "set run_unittests to ON to run unittests (default is OFF)" OFF)
option(skip_samples "set skip_samples to ON to skip building samples (default is OFF)[if possible, they are always built]" OFF)
option(use_installed_dependencies "set use_installed_dependencies to ON to use installed packages instead of building dependencies from submodules" OFF)
option(use_custom_heap "use externally defined heap functions instead of the malloc family" OFF)

if(${use_custom_heap})
    add_definitions(-DGB_USE_CUSTOM_HEAP)
endif()

if(${no_logging})
    add_definitions(-DNO_LOGGING)
endif()

#do not add or build any tests of the dependencies
set(original_run_e2e_tests ${run_e2e_tests})
set(original_run_int_tests ${run_int_tests})
set(original_run_unittests ${run_unittests})
set(original_skip_samples ${skip_samples})

set(run_e2e_tests OFF)
set(run_int_tests OFF)
set(run_unittests OFF)
set(skip_samples ON)

if (NOT ${use_installed_dependencies})
    if (NOT TARGET azure_macro_utils_c AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/deps/azure-macro-utils-c/CMakeLists.txt")
        add_subdirectory(deps/azure-macro-utils-c)
        include_directories(${MACRO_UTILS_INC_FOLDER})
    endif()
    if (NOT TARGET umock_c)
        add_subdirectory(deps/umock-c)
        include_directories(${MACRO_UTILS_INC_FOLDER})
        include_directories(${UMOCK_C_INC_FOLDER})
    endif()
    if (${original_run_e2e_tests} OR ${original_run_unittests})
        if (NOT TARGET testrunnerswitcher)
            add_subdirectory(deps/azure-c-testrunnerswitcher)
        endif()
        if (NOT TARGET ctest)
            add_subdirectory(deps/azure-ctest)
        endif()
        enable_testing()
    endif()
    if (NOT TARGET aziotsharedutil AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/deps/c-utility/CMakeLists.txt")
        add_subdirectory(deps/c-utility)
        if (${original_run_unittests})
            set(SHARED_UTIL_REAL_TEST_FOLDER ${CMAKE_CURRENT_LIST_DIR}/deps/c-utility/tests/real_test_files CACHE INTERNAL "this is what needs to be included when doing test sources" FORCE)
        endif()
    endif()
else()
    if (NOT azure_macro_utils_cFOUND)
        find_package(azure_macro_utils_c REQUIRED CONFIG)
    endif ()
    if (NOT umock_cFOUND)
        find_package(umock_c REQUIRED CONFIG)
    endif ()
    if (NOT azure_c_shared_utility_FOUND)
        find_package(azure_c_shared_utility REQUIRED CONFIG)
    endif ()

    include(${azure_c_shared_utility_DIR}/azure_c_shared_utilityConfig.cmake)
    include(${azure_c_shared_utility_DIR}/azure_c_shared_utilityFunctions.cmake)
    include(${azure_c_shared_utility_DIR}/azure_iot_build_rules.cmake)
endif()

set(run_e2e_tests ${original_run_e2e_tests})
set(run_int_tests ${original_run_int_tests})
set(run_unittests ${original_run_unittests})
set(skip_samples ${original_skip_samples})

if(${use_openssl})
    add_definitions(-DUSE_OPENSSL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_OPENSSL")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_OPENSSL")
endif()

#Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(${memory_trace})
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
endif()

IF((WIN32) AND (NOT(MINGW)))
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    # Make warning as error
    add_definitions(/WX)
ELSE()
    # Make warning as error
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
ENDIF()

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
endif()

set(UHTTP_C_INC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/inc CACHE INTERNAL "this is what needs to be included if using sharedLib lib" FORCE)

set(use_cppunittest ON)
set_platform_files(${SHARED_UTIL_FOLDER})

set(uhttp_c_files
    ./src/uhttp.c
)

set(uhttp_h_files
    ./inc/azure_uhttp_c/uhttp.h
)

include_directories(./inc)
include_directories(${SHARED_UTIL_INC_FOLDER} ${MACRO_UTILS_INC_FOLDER} ${UMOCK_C_INC_FOLDER})

include("configs/azure_uhttpFunctions.cmake")

add_library(uhttp ${uhttp_c_files} ${uhttp_h_files})
setTargetBuildProperties(uhttp)
target_link_libraries(uhttp aziotsharedutil)

if (${run_unittests})
    #include("dependencies-test.cmake")
    add_subdirectory(tests)
endif()

if (NOT ${skip_samples})
    add_subdirectory(samples)
endif()

# Install uhttp
set(package_location "cmake")

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(TARGETS uhttp EXPORT uhttpTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/../bin
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/azureiot
)
install(FILES ${uhttp_h_files} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/azureiot/azure_uhttp_c)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${UHTTP_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION
        ${package_location}
)

compileTargetAsC99(uhttp)
