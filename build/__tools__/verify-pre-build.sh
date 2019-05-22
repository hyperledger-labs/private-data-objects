#!/bin/bash

# Copyright 2019 Intel Corporation
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

# This script performs several tests on the environment to ensure
# that it is set up correctly. It should be run prior to building

F_VERIFIED=0

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

function warn () {
    recho "WARNING: $*"
    F_VERIFIED=-1
}

function try() {
    "$@" || warn "$*"
}

# -----------------------------------------------------------------
# CHECK ENVIRONMENT
# -----------------------------------------------------------------

yell --------------- CONFIG AND ENVIRONMENT PRE-BUILD CHECK ---------------

: "${TINY_SCHEME_SRC:-$(warn Missing environment variable TINY_SCHEME_SRC)}"
: "${PDO_INSTALL_ROOT:-$(warn Missing environment variable PDO_INSTALL_ROOT)}"
: "${PDO_HOME:-$(warn Missing environment variable PDO_HOME)}"
: "${PDO_ENCLAVE_CODE_SIGN_PEM:-$(warn Missing environment variable PDO_ENCLAVE_CODE_SIGN_PEM)}"
: "${SGX_SSL:-$(warn Missing environment variable SGX_SSL)}"
: "${SGX_SDK:-$(warn Missing environment variable SGXSDKInstallPath)}"
: "${SGX_MODE:-$(warn Missing environment variable SGX_MODE, set it to HW or SIM)}"
: "${PKG_CONFIG_PATH:-$(warn Missing environment variable PKG_CONFIG_PATH)}"

try command -v openssl
OPENSSL_VERSION=$(openssl version -v | sed 's/.*OpenSSL \([^ ]*\) .*/\1/')
OPENSSL_VERSION_MAJOR=$(echo ${OPENSSL_VERSION} | cut -d . -f 1)
OPENSSL_VERSION_MINOR=$(echo ${OPENSSL_VERSION} | cut -d . -f 2)
OPENSSL_VERSION_BUGFIX=$(echo ${OPENSSL_VERSION} | cut -d . -f 3)
if [[ ${OPENSSL_VERSION_MAJOR} -lt 1 || ( ${OPENSSL_VERSION_MAJOR} -eq 1  &&  ${OPENSSL_VERSION_MINOR} -lt 1 ) ]]; then
   warn "WARNING: Openssl version is $OPENSSL_VERSION, should be 1.1.0 or greater"
   warn "Note: openssl can be a different version as long as libssl and libssl-dev are >= 1.1.0"
fi

try command -v protoc
PROTOC_VERSION=$(protoc --version | sed 's/libprotoc \([0-9]\).*/\1/')
if [[ "$PROTOC_VERSION" -lt 3 ]]; then
    warn "protoc must be version3 or higher"
fi

try command -v python3
try command -v cmake
try command -v swig
try command -v make
try command -v g++
try command -v ${TINY_SCHEME_SRC}/scheme

if [ ! -d "${PDO_INSTALL_ROOT}" ]; then
    warn "PDO_INSTALL_ROOT directory does not exist"
fi

if [ ! -d "${TINY_SCHEME_SRC}" ]; then
    warn "TINY_SCHEME_SRC directory does not exist"
fi

if [ ! -f "${PDO_ENCLAVE_CODE_SIGN_PEM}" ]; then
    warn "PDO_ENCLAVE_CODE_SIGN_PEM file does not exist"
fi

exit $F_VERIFIED
