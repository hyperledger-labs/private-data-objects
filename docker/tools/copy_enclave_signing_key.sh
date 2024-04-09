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


# This script copies the enclave signing key on the host (if any) for the docker container build.
# environment.sh is not imported, as this script is meant to run on the host.
# Note: the key (if any) is copied into the default folder for HW mode builds;
#       so for SIM mode builds, this will have no effect.

if [ $# != 2 ] && [ $# != 3 ]; then
    echo "$(basename $0 '<PDO source repo path> <PDO dest repo path> [ ${PDO_SGX_KEY_ROOT} ]')"
    echo "PDO source and dest paths are required, PDO_SGX_KEY_ROOT is optional"
    exit 1
fi

PDO_SOURCE_ROOT=$1
PDO_DEST_ROOT=$2
PDO_SGX_KEY_ROOT=$3

source ${PDO_SOURCE_ROOT}/bin/lib/common.sh

# If an enclave signing key is available on the host, copy that under build/keys in the repo
# Note: on the host, the key must be in ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem,
# and the env variable must be defined.
# Note: in the docker container, the host key (or a new key) will be placed on the same path,
# but the PDO_SGX_KEY_ROOT default value is defined in docker/tools/environment.sh

KEY_REL_PATH="build/keys/sgx_mode_hw/enclave_code_sign.pem"

if [ ! -z "${PDO_SGX_KEY_ROOT}" ] && [ -e "${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem" ]; then
    yell "Enclave signing key: using host-provided key: ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem"
    yell "Enclave signing key: copying it to ${PDO_DEST_ROOT}/${KEY_REL_PATH}"
    try cp ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem ${PDO_DEST_ROOT}/${KEY_REL_PATH}
else
    yell "Enclave signing key: none available, now checking default path ${PDO_SOURCE_ROOT}/${KEY_REL_PATH}"
    if [ -e "${PDO_SOURCE_ROOT}/${KEY_REL_PATH}" ]; then
        yell "Enclave signing key: key available, copying it to ${PDO_DEST_ROOT}/${KEY_REL_PATH}"
        try cp ${PDO_SOURCE_ROOT}/${KEY_REL_PATH} ${PDO_DEST_ROOT}/${KEY_REL_PATH}
    else
        yell "Enclave signing key: no default key, a new one will be generated"
    fi
fi

exit 0

