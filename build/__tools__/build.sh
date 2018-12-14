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
cred=`tput setaf 1`
cgrn=`tput setaf 2`
cblu=`tput setaf 4`
cmag=`tput setaf 5`
cwht=`tput setaf 7`
cbld=`tput bold`
bred=`tput setab 1`
bgrn=`tput setab 2`
bblu=`tput setab 4`
bwht=`tput setab 7`
crst=`tput sgr0`

function recho () {
    echo "${cbld}${cred}" $@ "${crst}" >&2
}

function becho () {
    echo "${cbld}${cblu}" $@ "${crst}" >&2
}

function yell() {
    becho "$(basename $0): $*" >&2
}

function die() {
    recho "$(basename $0): $*" >&2
    exit 111
}

function try() {
    "$@" || die "test failed: $*"
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    die activate python3 first
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

# Automatically determine how many cores the host system has
# (for use with multi-threaded make)
NUM_CORES=$(grep -c '^processor' /proc/cpuinfo)
if [ "$NUM_CORES " == " " ]; then
    NUM_CORES=4
fi

# allow opting out of running tests, primarily so we can skip 
# sgx hw-mode based tests which fail in docker test 
if [ ! -z "${NO_SGX_RUN_DURING_BUILD}" ]; then
    CMAKE_ARGS="-D DISABLE_TESTS=true"
fi

# -----------------------------------------------------------------
# BUILD
# -----------------------------------------------------------------

yell --------------- COMMON ---------------

# create the ias-certificates.cpp from the templates
cd $SRCDIR/common/crypto/verify_ias_report
if [ ! -f ias-certificates.cpp ]; then
    try ./build_ias_certificates_cpp.sh
fi

# now build the rest of common
cd $SRCDIR/common

mkdir -p build
cd build
try cmake ${CMAKE_ARGS} ..
try make "-j$NUM_CORES"

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
