#!/bin/bash
# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
#

set -e

script_dir=$(cd "$(dirname "$0")" && pwd)
build_root=$(cd "${script_dir}/.." && pwd)
log_dir=$build_root
make_install=
build_folder=$build_root"/cmake/utpm_linux"

#check stuff
echo script_dir $script_dir #/mnt/c/Users/catinney/source/repos/azure-uhttp-c/jenkins
echo build_root $build_root #/mnt/c/Users/catinney/source/repos/azure-uhttp-c
echo build_folder $build_folder #/mnt/c/Users/catinney/source/repos/azure-uhttp-c/cmake
#end check stuff

rm -r -f $build_folder
mkdir -p $build_folder
pushd $build_folder
cmake ../.. -Drun_unittests:BOOL=ON -Drun_valgrind:BOOL=ON
cmake --build . -- --jobs=$(nproc)
ctest -C "debug" -V

popd
:
