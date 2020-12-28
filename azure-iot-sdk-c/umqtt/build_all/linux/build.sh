#!/bin/bash
#set -o pipefail
#

set -e

script_dir=$(cd "$(dirname "$0")" && pwd)
build_root=$(cd "${script_dir}/../.." && pwd)
run_unit_tests=ON
run_valgrind=0
build_folder=$build_root"/cmake/umqtt_linux"
toolchainfile=" "
cmake_install_prefix=" "
run_unittests=OFF

usage ()
{
    echo "build.sh [options]"
    echo "options"
    echo " -cl, --compileoption <value> specify a compile option to be passed to gcc"
    echo " Example: -cl -O1 -cl ..."
    echo "-rv, --run_valgrind will execute ctest with valgrind"
    echo "--toolchain-file <file>       pass cmake a toolchain file for cross compiling"
    echo "--run-unittests do not build or run unit tests"
    echo ""
    exit 1
}

process_args ()
{
    save_next_arg=0
    extracloptions=" "
    for arg in $*
    do
      if [ $save_next_arg == 1 ]
      then
        # save arg to pass to gcc
        extracloptions="$arg $extracloptions"
        save_next_arg=0
      elif [ $save_next_arg == 2 ]
      then
        # save arg to pass as toolchain file
        toolchainfile="$arg"
        save_next_arg=0
      else
          case "$arg" in
              "-cl" | "--compileoption" ) save_next_arg=1;;
              "-rv" | "--run_valgrind" ) run_valgrind=1;;
              "--toolchain-file" ) save_next_arg=2;;
              "--run-unittests" ) run_unittests=ON;;
              * ) usage;;
          esac
      fi
    done

    if [ "$toolchainfile" != " " ]
    then
      toolchainfile=$(readlink -f $toolchainfile)
      toolchainfile="-DCMAKE_TOOLCHAIN_FILE=$toolchainfile"
    fi
   
   if [ "$cmake_install_prefix" != " " ]
   then
     cmake_install_prefix="-DCMAKE_INSTALL_PREFIX=$cmake_install_prefix"
   fi
}

process_args $*

rm -r -f $build_folder
mkdir -p $build_folder
pushd $build_folder

cmake $toolchainfile $cmake_install_prefix -Drun_valgrind:BOOL=$run_valgrind -DcompileOption_C:STRING="$extracloptions" $build_root -Drun_unittests:BOOL=$run_unittests
make --jobs=$(nproc)

if [[ $run_valgrind == 1 ]] ;
then
    #use doctored openssl
    export LD_LIBRARY_PATH=/usr/local/ssl/lib
    ctest -j $(nproc) --output-on-failure
    export LD_LIBRARY_PATH=
else
    ctest -j $(nproc) -C "Debug" --output-on-failure
fi

popd
