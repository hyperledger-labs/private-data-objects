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

F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/lib/pdo_common.sh

CCHOST=${CCF_BASE}/bin/cchost.virtual

EFILE="${F_SERVICEHOME}/logs/error.log"
OFILE="${F_SERVICEHOME}/logs/output.log"

cd ${F_SERVICEHOME}/run
# Notes:
# - The dnsname for CCF is necessary for adding an alternative subject name to the node certificate.
#   This allows clients to connect to, and authenticate correctly, the CCF node
# - The dnsname is assumed to be the same as the one used in the ledger url (or PDO_LEDGER_URL),
#   e.g., http://<dnsname>:6600
${CCHOST} --san dNSName:${PDO_HOSTNAME:-${HOSTNAME}} --config ${F_SERVICEHOME}/etc/cchost.toml --node-pid-file ${F_SERVICEHOME}/run/cchost.pid > $OFILE 2> $EFILE &
echo $! > ${F_SERVICEHOME}/run/cchost.pid
