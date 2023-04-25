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
check_python_version

# Automatically determine how many cores the host system has
# (for use with multi-threaded make)
NUM_CORES=$(grep -c '^processor' /proc/cpuinfo)
if [ "$NUM_CORES " == " " ]; then
    NUM_CORES=4
fi

CLIENT_ONLY='no'

TEMP=$(getopt -o '' --long 'client,trusted,untrusted' -n "build.sh" -- "$@")
if [ $? != 0 ] ; then echo "Usage: build.sh [--client]" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        --client) CLIENT_ONLY="yes" ; shift 1 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done
TEMP=""

if [ ${CLIENT_ONLY} == "yes" ]; then
    CMAKE_ARGS="-DBUILD_CLIENT=1 -DBUILD_TRUSTED=0 -DBUILD_UNTRUSTED=0"
    MAKE_ARGS="-j${NUM_CORES} BUILD_CLIENT=1"
else
    CMAKE_ARGS="-DBUILD_CLIENT=1 -DBUILD_TRUSTED=1 -DBUILD_UNTRUSTED=1"
    MAKE_ARGS="-j${NUM_CORES} BUILD_CLIENT=1"
fi

# -----------------------------------------------------------------
# BUILD
# -----------------------------------------------------------------

yell --------------- COMMON ---------------
cd $SRCDIR/common
try cmake -S . -B build ${CMAKE_ARGS}
try cmake --build build -- ${MAKE_ARGS}

yell --------------- BIN ---------------
cd $SRCDIR/bin
try make ${MAKE_ARGS}
try make ${MAKE_ARGS} install

yell --------------- PYTHON ---------------
cd $SRCDIR/python
try cmake -S . -B build ${CMAKE_ARGS}
try cmake --build build -- ${MAKE_ARGS}

yell temporarily installing pdo as part of build
pip install dist/pdo-0.2.0-py3-none-any.whl

yell --------------- SSERVICE ---------------
cd $SRCDIR/sservice
try cmake -S . -B build ${CMAKE_ARGS}
try cmake --build build -- ${MAKE_ARGS}

yell temporarily installing pdo_sservice as part of build
pip install dist/pdo_sservice-0.2.0-py3-none-any.whl

yell --------------- ESERVICE ---------------
if [ ${CLIENT_ONLY} == "no" ]; then
    cd $SRCDIR/eservice
    try make ${MAKE_ARGS}
    try make ${MAKE_ARGS} install
fi

yell --------------- PSERVICE ---------------
if [ ${CLIENT_ONLY} == "no" ]; then
    cd $SRCDIR/pservice
    try make ${MAKE_ARGS}
    try make ${MAKE_ARGS} install
fi

yell --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
try make ${MAKE_ARGS} all
try make ${MAKE_ARGS} install
