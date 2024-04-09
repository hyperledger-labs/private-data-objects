#!/bin/bash
# Copyright 2023 Intel Corporation
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

# Tests are run EXCLUSIVELY with all services running on localhost
source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export PDO_HOSTNAME=localhost
export PDO_LEDGER_ADDRESS=$(force_to_ip ${PDO_HOSTNAME})
export PDO_LEDGER_URL="http://${PDO_LEDGER_ADDRESS}:6600"

check_pdo_runtime_env

export no_proxy=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$NO_PROXY

# -----------------------------------------------------------------
yell copy sgx keys
# -----------------------------------------------------------------
# copy any keys in the SGX directory, ignore any errors if no keys exist
cp ${XFER_DIR}/services/keys/sgx/* ${PDO_SGX_KEY_ROOT} 2>/dev/null

# -----------------------------------------------------------------
yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
try ${PDO_INSTALL_ROOT}/bin/pdo-configure-services -t ${PDO_SOURCE_ROOT}/build/template -o ${PDO_HOME}\
    --count 5 5 5

# we need some client stuff for the unit tests
try ${PDO_INSTALL_ROOT}/bin/pdo-configure-users -t ${PDO_SOURCE_ROOT}/build/template -o ${PDO_HOME} \
    --key-count 1 --key-base user --host ${PDO_HOSTNAME}

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
# need to wait for the ledger to get going so we can grab the
# keys and copy them into the correct location, in theory the
# healthcheck in the docker-compose configuration file should
# ensure that the keys are already present
mkdir -p ${PDO_LEDGER_KEY_ROOT}
while [ ! -f ${XFER_DIR}/ccf/keys/networkcert.pem ]; do
    say "waiting for ledger keys"
    sleep 5
done
try cp ${XFER_DIR}/ccf/keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/

# -----------------------------------------------------------------
yell check for registration
# -----------------------------------------------------------------
# this probably requires additional CCF keys, need to test this
if [ "$SGX_MODE" == "HW" ]; then
    if [ ! -f ${XFER_DIR}/ccf/keys/memberccf_privk.pem ] ; then
        die unable to locate CCF policies keys
    fi

    try cp ${XFER_DIR}/ccf/keys/memberccf_cert.pem ${PDO_LEDGER_KEY_ROOT}/
    try cp ${XFER_DIR}/ccf/keys/memberccf_privk.pem ${PDO_LEDGER_KEY_ROOT}/

    try make -C ${PDO_SOURCE_ROOT}/build register
fi

# -----------------------------------------------------------------
yell run the unit test suite
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate
try ${PDO_SOURCE_ROOT}/build/tests/unit-test.sh

# -----------------------------------------------------------------
yell start the services
# -----------------------------------------------------------------
try ${PDO_HOME}/bin/ss-start.sh --output ${PDO_HOME}/logs --clean
try ${PDO_HOME}/bin/ps-start.sh --output ${PDO_HOME}/logs --clean
try ${PDO_HOME}/bin/es-start.sh --output ${PDO_HOME}/logs --clean

function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh > /dev/null
    ${PDO_HOME}/bin/es-stop.sh > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh > /dev/null
}

trap cleanup EXIT

try cp ${PDO_HOME}/etc/site.toml ${XFER_DIR}/services/etc/site.toml

# -----------------------------------------------------------------
yell wait for client completion
# -----------------------------------------------------------------
sleep infinity
