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

# -----------------------------------------------------------------
# -----------------------------------------------------------------
PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    die activate python3 first
fi

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
TEMP

BUILD_CLIENT=0
if [ ${F_CLIENT} == "yes" ]; then
    CMAKE_ARGS="-DBUILD_CLIENT=1 -DBUILD_TRUSTED=0 -DBUILD_UNTRUSTED=0"
    BUILD_CLIENT=1
fi

# -----------------------------------------------------------------
# BUILD
# -----------------------------------------------------------------

yell --------------- COMMON ---------------

# now build the rest of common
cd $SRCDIR/common

mkdir -p build
cd build
try cmake ${CMAKE_ARGS} ..
try make "-j$NUM_CORES"

yell --------------- BIN ---------------
cd $SRCDIR/bin
try make "-j$NUM_CORES"
try make install

yell --------------- PYTHON ---------------
cd $SRCDIR/python
try make "-j$NUM_CORES" BUILD_CLIENT=${BUILD_CLIENT}
try make BUILD_CLIENT=${BUILD_CLIENT} install

yell --------------- ESERVICE ---------------
if [ ${F_CLIENT} == "no" ]; then
    cd $SRCDIR/eservice
    try make "-j$NUM_CORES"
    try make install
fi

yell --------------- PSERVICE ---------------
if [ ${F_CLIENT} == "no" ]; then
    cd $SRCDIR/pservice
    try make "-j$NUM_CORES"
    try make install
fi

yell --------------- CLIENT ---------------
cd $SRCDIR/client
try make "-j$NUM_CORES" BUILD_CLIENT=${BUILD_CLIENT}
try make BUILD_CLIENT=${BUILD_CLIENT} install

yell --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
try make BUILD_CLIENT=${BUILD_CLIENT} "-j$NUM_CORES" all
try make BUILD_CLIENT=${BUILD_CLIENT} install
