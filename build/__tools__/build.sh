#!/bin/bash

# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh
check_pdo_build_env
check_python_version

# Automatically determine how many cores the host system has
# (for use with multi-threaded make)
NUM_CORES=$(grep -c '^processor' /proc/cpuinfo)
if [ "$NUM_CORES " == " " ]; then
    NUM_CORES=4
fi

F_CLIENT='no'

TEMP=$(getopt -o '' --long 'client,trusted,untrusted' -n "build.sh" -- "$@")
if [ $? != 0 ] ; then echo "Usage: build.sh [--client]" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        --client) F_CLIENT="yes" ; shift 1 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

if [ ${F_CLIENT} == "yes" ]; then
    CMAKE_ARGS="-DBUILD_CLIENT=1 -DBUILD_TRUSTED=0 -DBUILD_UNTRUSTED=0"
    MAKE_ARGS="-j${NUM_CORES} BUILD_CLIENT=1"
else
    CMAKE_ARGS="-DBUILD_CLIENT=0 -DBUILD_TRUSTED=1 -DBUILD_UNTRUSTED=1"
    MAKE_ARGS="-j${NUM_CORES} BUILD_CLIENT=0"
fi

# Set options for cmake build
# The build type is set to affect the SGX debug flag.
# Build type "Release" defines NDEBUG, which causes sgx_urts.h to set SGX_DEBUG_FLAG to 0.
# Build type "Debug" does not define NDEBUG, which causes sgx_urts.h to set SGX_DEBUG_FLAG to 1.
if [ ${PDO_DEBUG_BUILD} == "0" ]; then
    MAKE_ARGS+=" CMAKE_OPTS=-DCMAKE_BUILD_TYPE=Release"
else
    MAKE_ARGS+=" CMAKE_OPTS=-DCMAKE_BUILD_TYPE=Debug"
fi

# -----------------------------------------------------------------
# BUILD
# -----------------------------------------------------------------

yell --------------- COMMON ---------------

# now build the rest of common
cd $SRCDIR/common

if [ ! -d build ]; then
    yell create the build directory
    mkdir -p build
    pushd build
    try cmake ${CMAKE_ARGS} ..
    popd
fi

cd build
#try cmake ${CMAKE_ARGS} ..
#try make ${MAKE_ARGS}
try cmake --build . -- ${MAKE_ARGS}

yell --------------- BIN ---------------
cd $SRCDIR/bin
try make ${MAKE_ARGS}
try make ${MAKE_ARGS} install

yell --------------- PYTHON ---------------
cd $SRCDIR/python
try make ${MAKE_ARGS}
try make ${MAKE_ARGS} install

yell --------------- SSERVICE ---------------
cd $SRCDIR/sservice
try make "-j$NUM_CORES" BUILD_CLIENT=${BUILD_CLIENT}
try make install BUILD_CLIENT=${BUILD_CLIENT}

yell --------------- ESERVICE ---------------
if [ ${F_CLIENT} == "no" ]; then
    cd $SRCDIR/eservice
    try make ${MAKE_ARGS}
    try make ${MAKE_ARGS} install
fi

yell --------------- PSERVICE ---------------
if [ ${F_CLIENT} == "no" ]; then
    cd $SRCDIR/pservice
    try make ${MAKE_ARGS}
    try make ${MAKE_ARGS} install
fi

yell --------------- CLIENT ---------------
cd $SRCDIR/client
try make ${MAKE_ARGS}
try make ${MAKE_ARGS} install

yell --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
try make ${MAKE_ARGS} all
try make ${MAKE_ARGS} install
