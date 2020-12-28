#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

function(linkSharedUtil whatIsBuilding)
    target_link_libraries(${whatIsBuilding} aziotsharedutil)
endfunction(linkSharedUtil)

function(add_unittest_directory test_directory)
    if (${run_unittests})
        add_subdirectory(${test_directory})
    endif()
endfunction()
