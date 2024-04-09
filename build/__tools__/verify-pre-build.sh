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
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh
check_pdo_build_env

function warn () {
    recho "WARNING: $*"
    F_VERIFIED=-1
}


# -----------------------------------------------------------------
# CHECK ENVIRONMENT
# -----------------------------------------------------------------

yell --------------- CONFIG AND ENVIRONMENT PRE-BUILD CHECK ---------------

: "${PDO_INSTALL_ROOT:-$(warn Missing environment variable PDO_INSTALL_ROOT)}"
: "${PDO_HOME:-$(warn Missing environment variable PDO_HOME)}"
([ ! -z "${SGX_SSL}" ] && [ -f ${SGX_SSL}/include/openssl/err.h ] ) || warn "Missing or invalid environment variable SGX_SSL"
([ ! -z "${SGX_SDK}" ] && [ -f ${SGX_SDK}/include/sgx.h ] ) || warn "Missing or invalid environment variable SGX_SDK"
: "${SGX_MODE:-$(warn Missing environment variable SGX_MODE, set it to HW or SIM)}"
: "${PKG_CONFIG_PATH:-$(warn Missing environment variable PKG_CONFIG_PATH)}"

$(pkg-config --atleast-version=1.1.0g openssl) || warn "WARNING: Openssl version found in PKG_CONFIG_PATH must be 1.1.0g or greater"

try command -v python3
try command -v cmake
try command -v swig
try command -v make
try command -v g++

if [ ! -d "${PDO_INSTALL_ROOT}" ]; then
    warn "PDO_INSTALL_ROOT directory does not exist"
fi

exit $F_VERIFIED
