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


PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit 1
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/lib/pdo_common.sh

if [ -f ${F_SERVICEHOME}/run/cchost.pid ]; then
    if ps -p $(cat ${F_SERVICEHOME}/run/cchost.pid) > /dev/null
    then
        yell cchost appears to be running already
        exit -1
    fi
fi

rm -rf ${F_SERVICEHOME}/run/*
rm -f ${F_SERVICEHOME}/logs/*.log

say attempt to start a new ccf node
try ${F_SERVICEHOME}/bin/start_cchost.sh _join

sleep 5

# need to get node_id from the logs after starting the network.
# CCF network will assign a unique node_id to every node that joins the network
node_id=`grep -oP "Node \K.*" ${F_SERVICEHOME}/logs/output.log | grep -m1 "is waiting for votes of members to be trusted" | awk '{print $1;}'`

say attempt to join node ${node_id} to existing ccf network
try ${F_SERVICEHOME}/bin/configure_ccf_network.py --add-node --logfile __screen__ --loglevel WARNING --ccf-config ${F_SERVICEHOME}/etc/cchost_join.toml --node-id ${node_id}

echo Added a New Node to the CCF network
