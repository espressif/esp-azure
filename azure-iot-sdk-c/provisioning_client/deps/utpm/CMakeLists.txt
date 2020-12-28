#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

project(utpm)

set(UTPM_VERSION 1.0.1)

option(use_emulator "build using the tpm emulator" ON)
option(run_e2e_tests "set run_e2e_tests to ON to run e2e tests (default is OFF)" OFF)
option(run_unittests "set run_unittests to ON to run unittests (default is OFF)" OFF)
option(run_int_tests "set run_int_tests to ON to integration tests (default is OFF)." OFF)
option(skip_samples "set skip_samples to ON to skip building samples (default is OFF)[if possible, they are always built]" OFF)
option(use_installed_dependencies "set use_installed_dependencies to ON to use installed packages instead of building dependencies from submodules" OFF)
option(use_custom_heap "use externally defined heap functions instead of the malloc family" OFF)

if(${use_custom_heap})
    add_definitions(-DGB_USE_CUSTOM_HEAP)
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

if(NOT ${use_installed_dependencies})
    if (NOT TARGET azure_macro_utils_c AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/deps/azure-macro-utils-c/CMakeLists.txt")
        add_subdirectory(deps/azure-macro-utils-c)
        include_directories(${MACRO_UTILS_INC_FOLDER})
    endif()
    if (NOT TARGET umock_c)
        add_subdirectory(deps/umock-c)
        include_directories(${UMOCK_C_INC_FOLDER})
    endif()
    if(${original_run_e2e_tests} OR ${original_run_unittests})
        if (NOT TARGET testrunnerswitcher)
            add_subdirectory(deps/azure-c-testrunnerswitcher)
        endif()
        if (NOT TARGET ctest)
            add_subdirectory(deps/azure-ctest)
        endif()
    endif()
    if (NOT TARGET aziotsharedutil AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/deps/c-utility/CMakeLists.txt")
        add_subdirectory(deps/c-utility)
        include_directories(${SHARED_UTIL_INC_FOLDER})
    endif()

    enable_testing()
else() 
    if (NOT azure_macro_utils_cFOUND) 
        find_package(azure_macro_utils_c REQUIRED CONFIG) 
        include_directories(${MACRO_UTILS_INC_FOLDER}) 
    endif () 
    if (NOT umock_cFOUND) 
        find_package(umock_c REQUIRED CONFIG) 
        include_directories(${UMOCK_C_INC_FOLDER}) 
    endif () 
    if (NOT azure_c_shared_utility_FOUND) 
        find_package(azure_c_shared_utility REQUIRED CONFIG) 
        include_directories(${SHARED_UTIL_INC_FOLDER}) 
    endif () 

    include(${azure_c_shared_utility_DIR}/azure_c_shared_utilityConfig.cmake) 
    include(${azure_c_shared_utility_DIR}/azure_c_shared_utilityFunctions.cmake) 
    include(${azure_c_shared_utility_DIR}/azure_iot_build_rules.cmake)
endif()

set(run_e2e_tests ${original_run_e2e_tests})
set(run_int_tests ${original_run_int_tests})
set(run_unittests ${original_run_unittests})
set(skip_samples ${original_skip_samples})

set(TPM_C_INC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/inc CACHE INTERNAL "this is what needs to be included if using sharedLib lib" FORCE)

set_platform_files(${SHARED_UTIL_FOLDER})

if (NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-field-initializers ")
endif()

set(utpm_c_files
    ./src/Marshal.c
    ./src/Memory.c
    ./src/tpm_codec.c
    ./src/gbfiledescript.c
)

set(utpm_h_files
    ./inc/azure_utpm_c/BaseTypes.h
    ./inc/azure_utpm_c/Capabilities.h
    ./inc/azure_utpm_c/CompilerDependencies.h
    ./inc/azure_utpm_c/GpMacros.h
    ./inc/azure_utpm_c/gbfiledescript.h
    ./inc/azure_utpm_c/Implementation.h
    ./inc/azure_utpm_c/Marshal_fp.h
    ./inc/azure_utpm_c/Memory_fp.h
    ./inc/azure_utpm_c/swap.h
    ./inc/azure_utpm_c/Tpm.h
    ./inc/azure_utpm_c/TPMB.h
    ./inc/azure_utpm_c/TpmBuildSwitches.h
    ./inc/azure_utpm_c/TpmError.h
    ./inc/azure_utpm_c/TpmTypes.h
    ./inc/azure_utpm_c/tpm_codec.h
    ./inc/azure_utpm_c/tpm_comm.h
)

if (APPLE)
    # For apple don't include file decript
else()
    set(utpm_h_files
        ${utpm_h_files}
        ./inc/azure_utpm_c/gbfiledescript.h
    )

    set(utpm_c_files
        ${utpm_c_files}
        ./src/gbfiledescript.c
    )
endif()

if (${use_emulator})
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

    set(utpm_h_files
        ${utpm_h_files}
        ./inc/azure_utpm_c/tpm_socket_comm.h
    )
    set(utpm_c_files
        ${utpm_c_files}
        ./src/tpm_comm_emulator.c
        ./src/tpm_socket_comm.c
    )
else()
    if (WIN32)
        set(utpm_c_files
            ${utpm_c_files}
            ./src/tpm_comm_win32.c
        )
    else()
        set(utpm_c_files
            ${utpm_c_files}
            ./src/tpm_comm_linux.c
            ./src/tpm_socket_comm.c
        )
    endif()
endif()

include_directories(./inc)

if (WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
endif (WIN32)

add_library(utpm ${utpm_c_files} ${utpm_h_files})
target_link_libraries(utpm aziotsharedutil)

if (${use_emulator})
else ()
    if (WIN32)
        target_link_libraries(utpm tbs)
    else()
        target_link_libraries(utpm dl)
    endif()
endif()

if (${run_unittests})
    add_subdirectory(tests)
endif()

if (NOT ${skip_samples})
    add_subdirectory(samples)
endif()

# Set CMAKE_INSTALL_LIBDIR if not defined
include(GNUInstallDirs)

# Install utpm
set(package_location "cmake")

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(TARGETS utpm EXPORT utpmTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/../bin
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/azureiot
)
install(FILES ${utpm_h_files} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/azureiot/azure_utpm_c)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${UTPM_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(EXPORT utpmTargets
    FILE
	"${PROJECT_NAME}Targets.cmake"
    DESTINATION
	${package_location}
)

install(
    FILES
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION
	${package_location}
)

compileTargetAsC99(utpm)
