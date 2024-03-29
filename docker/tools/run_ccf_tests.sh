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
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export PDO_HOSTNAME=localhost
export PDO_LEDGER_ADDRESS=$(force_to_ip ${PDO_HOSTNAME})
export PDO_LEDGER_URL="http://${PDO_LEDGER_ADDRESS}:6600"

check_pdo_runtime_env

export no_proxy=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$NO_PROXY

# this is ridiculous. we need to canonicalize the ledger and
# sgx keys into the keys directory hierarchy NOT the etc
# hierarchy. future PR.
mkdir -p ${PDO_LEDGER_KEY_ROOT}

# -----------------------------------------------------------------
yell start the ccf service
# -----------------------------------------------------------------
yell ${CCF_LEDGER_DIR}/bin/start_ccf_network.sh -i ${PDO_LEDGER_ADDRESS}  \
    --pdo-dir ${CCF_PDO_DIR} --ledger-dir ${CCF_LEDGER_DIR}
try ${CCF_LEDGER_DIR}/bin/start_ccf_network.sh -i ${PDO_LEDGER_ADDRESS}  \
    --pdo-dir ${CCF_PDO_DIR} --ledger-dir ${CCF_LEDGER_DIR}

# -----------------------------------------------------------------
yell copy the ledger keys
# -----------------------------------------------------------------
try cp ${PDO_LEDGER_KEY_ROOT}/* ${XFER_DIR}/ccf/keys
try chmod a+r ${XFER_DIR}/ccf/keys/*

# -----------------------------------------------------------------
yell wait for client completion
# -----------------------------------------------------------------
sleep infinity
