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

CMAKE_ARGS=

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
try make "-j$NUM_CORES"
try make install

yell --------------- ESERVICE ---------------
cd $SRCDIR/eservice
try make "-j$NUM_CORES"
try make install

yell --------------- PSERVICE ---------------
cd $SRCDIR/pservice
try make "-j$NUM_CORES"
try make install

yell --------------- CLIENT ---------------
cd $SRCDIR/client
try make "-j$NUM_CORES"
try make install

yell --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
try make all "-j$NUM_CORES"
try make install
