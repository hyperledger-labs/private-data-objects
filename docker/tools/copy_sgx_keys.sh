#!/bin/bash

# Copyright 2024 Intel Corporation
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


# This script prepares the sgx keys on the host for the docker container build.
# environment.sh is not imported, as this script is meant to run on the host.

if [ $# != 2 ] && [ $# != 3 ]; then
    echo "$(basename $0 '${PDO_SOURCE_ROOT} ${DOCKER_DIR} [ ${PDO_SGX_KEY_ROOT} ]')"
    echo "PDO_SOURCE_ROOT and DOCKER_DIR are required, PDO_SGX_KEY_ROOT is optional"
    exit 1
fi

PDO_SOURCE_ROOT=$1
DOCKER_DIR=$2
PDO_SGX_KEY_ROOT=$3

source ${PDO_SOURCE_ROOT}/bin/lib/common.sh

# check for sgx keys in PDO_SGX_KEY_ROOT and copy that in xfer
# or, copy anything in the default folder to xfer

if [ ! -z "${PDO_SGX_KEY_ROOT}" ]; then
    # PDO_SGX_KEY_ROOT is set
    yell "SGX keys: checking for source SGX keys in ${PDO_SGX_KEY_ROOT}"
    if [ ! -f ${PDO_SGX_KEY_ROOT}/sgx_spid_api_key.txt ] ||
        [ ! -f ${PDO_SGX_KEY_ROOT}/sgx_spid.txt ] ||
        [ ! -f ${PDO_SGX_KEY_ROOT}/sgx_ias_key.pem ]; then
            die "SGX keys: missing - check PDO_SGX_KEY_ROOT and SGX keys in it"
    fi

    yell "SGX keys: found ... copying them to docker"
    try cp ${PDO_SGX_KEY_ROOT}/* ${DOCKER_DIR}/xfer/services/keys/sgx/

else
    yell "SGX keys: PDO_SGX_KEY_ROOT undefined"
    yell "SGX keys: copying default folder ${PDO_SOURCE_ROOT}/build/keys/sgx_mode_hw/ to docker"
    # copy anything in the default folder, and ignore errors if no keys exist
    ls ${PDO_SOURCE_ROOT}/build/keys/sgx_mode_hw/*
    cp ${PDO_SOURCE_ROOT}/build/keys/sgx_mode_hw/* ${DOCKER_DIR}/xfer/services/keys/sgx/ 2>/dev/null
    echo $?
    ls ${DOCKER_DIR}/xfer/services/keys/sgx/
fi

# test sgx keys availability in xfer
# this succeeds if it was copied above, or if it was already in place
yell "SGX keys: checking for SGX keys in docker"
if [ ! -f ${DOCKER_DIR}/xfer/services/keys/sgx/sgx_spid_api_key.txt ] ||
    [ ! -f ${DOCKER_DIR}/xfer/services/keys/sgx/sgx_spid.txt ] ||
    [ ! -f ${DOCKER_DIR}/xfer/services/keys/sgx/sgx_ias_key.pem ]; then
        yell "SGX keys: not found in docker -- set PDO_SGX_KEY_ROOT and check sgx keys"
        exit 1
fi
yell "SGX keys: docker-ready"

exit 0

