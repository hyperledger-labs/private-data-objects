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

NUM_NODES_TO_JOIN=${1:-2}

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit 1
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/lib/pdo_common.sh

for (( node_id=1; node_id<=${NUM_NODES_TO_JOIN}; node_id++ ))
do
    
    if [ -f ${F_SERVICEHOME}/run/cchost_join${node_id}.pid ]; then
        if ps -p $(cat ${F_SERVICEHOME}/run/cchost_join${node_id}.pid) > /dev/null
        then
            yell cchost appears to be running already
            exit -1
        fi
    fi

    say attempt to start additional ccf node ${node_id}
    try ${F_SERVICEHOME}/bin/start_cchost.sh join${node_id}

    sleep 5

    say attempt to join node ${node_id} to existing ccf network
    try ${F_SERVICEHOME}/bin/configure_ccf_network.py --add-node --logfile __screen__ --loglevel WARNING --ccf-config cchost_start.toml --node-id ${node_id}

done


echo All extra nodes added
