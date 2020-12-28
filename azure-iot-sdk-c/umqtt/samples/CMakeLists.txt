#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists.txt for samples. There's nothing here, except redirections to
#individual protocol samples

usePermissiveRulesForSamplesAndTests()

function(add_sample_directory whatIsBuilding)
	add_subdirectory(${whatIsBuilding})

	set_target_properties(${whatIsBuilding}
			   PROPERTIES
			   FOLDER "uMQTT_Samples")
endfunction()

add_sample_directory(mqtt_client_sample)

