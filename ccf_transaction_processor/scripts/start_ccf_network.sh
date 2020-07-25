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

NUM_NODES_IN_NETWORK=${1:-1}

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit 1
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/lib/pdo_common.sh

if [ -f ${F_SERVICEHOME}/run/cchost_start.pid ]; then
    if ps -p $(cat ${F_SERVICEHOME}/run/cchost_start.pid) > /dev/null
    then
        yell cchost appears to be running already
        exit -1
    fi
fi

rm -rf ${F_SERVICEHOME}/run/*
rm -f ${F_SERVICEHOME}/logs/*.log

rm -f ${F_SERVICEHOME}/keys/networkcert.pem ${F_SERVICEHOME}/keys/network_enc_pubk.pem
rm -f ${F_SERVICEHOME}/keys/ledger_authority_pub.pem

say attempt to start first ccf node
try ${F_SERVICEHOME}/bin/start_cchost.sh start

sleep 5

say configure ccf network : ACK the member, open network, add user
try ${F_SERVICEHOME}/bin/configure_ccf_network.py --logfile __screen__ --loglevel WARNING --ccf-config cchost_start.toml

sleep 5

echo generate the ledger authority
try ${F_SERVICEHOME}/bin/generate_ledger_authority.py --logfile __screen__ --loglevel WARNING

sleep 5

echo save the ledger authority key
try ${F_SERVICEHOME}/bin/fetch_ledger_authority.py --loglevel WARNING

if [[ $NUM_NODES_IN_NETWORK -gt 1 ]]; then
    sleep 5
    echo starting and joining extra nodes to CCF network
    try ${F_SERVICEHOME}/bin/add_node_to_ccf_network.sh $(($NUM_NODES_IN_NETWORK - 1))
fi

echo CCF service ready for use
