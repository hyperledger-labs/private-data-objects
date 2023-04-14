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

if [ -f ${F_SERVICEHOME}/run/cchost.pid ]; then
    if ps -p $(cat ${F_SERVICEHOME}/run/cchost.pid) > /dev/null
    then
        yell cchost appears to be running already
        exit -1
    fi
fi

rm -rf ${F_SERVICEHOME}/run/*
rm -f ${F_SERVICEHOME}/logs/*.log

rm -f ${PDO_LEDGER_KEY_ROOT}/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/network_enc_pubk.pem
rm -f ${PDO_LEDGER_KEY_ROOT}/ledger_authority_pub.pem

say attempt to start ccf node
try ${F_SERVICEHOME}/bin/start_cchost.sh

sleep 5

say configure ccf network : ACK the member, open network, add user
try ${F_SERVICEHOME}/bin/configure_ccf_network.py --logfile __screen__ --loglevel WARNING

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
