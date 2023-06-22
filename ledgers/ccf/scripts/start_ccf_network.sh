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
F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/lib/pdo_common.sh

check_python_version


if [ -f ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid ]; then
    if ps -p $(cat ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid) > /dev/null
    then
        yell cchost appears to be running already
        exit -1
    fi
fi


rm -f ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
rm -f ${PDO_LEDGER_KEY_ROOT}/ledger_authority_pub.pem

say attempt to start ccf node
HOST_PORT="$(echo ${PDO_LEDGER_URL} | awk -F/ '{print $3}')"
try ${CCF_BASE}/bin/sandbox.sh -p ${PDO_HOME}/ccf/lib/libpdoenc -n local://${HOST_PORT} -e virtual -t virtual --workspace ${PDO_HOME}/ccf/workspace --initial-node-cert-validity-days 365 --initial-service-cert-validity-days 365 &

sleep 30

say copy the keys
cp ${PDO_HOME}/ccf/workspace/sandbox_common/service_cert.pem ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
cp ${PDO_HOME}/ccf/workspace/sandbox_common/member0_cert.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_cert.pem
cp ${PDO_HOME}/ccf/workspace/sandbox_common/member0_privk.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_privk.pem

sleep 5

echo generate the ledger authority
try ${F_SERVICEHOME}/bin/generate_ledger_authority.py --logfile __screen__ --loglevel WARNING

#Set the enclave attestation policy while operating under SGX SIM mode. When operating in the HW mode, the rpc gets invoked after the enclave is built.
if [ "${SGX_MODE}" == "SIM" ]; then
    echo set check_attestation to false in SGX SIM mode
    try ${F_SERVICEHOME}/bin/register_enclave_attestation_verification_policy.py --logfile __screen__ --loglevel WARNING
fi

sleep 5

echo save the ledger authority key
try ${F_SERVICEHOME}/bin/fetch_ledger_authority.py --logfile __screen__ --loglevel WARNING
