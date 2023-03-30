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
export PDO_HOSTNAME=localhost
export PDO_LEDGER_URL=http://localhost:6600

source /project/pdo/tools/environment.sh
source ${PDO_HOME}/ccf/bin/lib/pdo_common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$POD_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
rm -f ${PDO_HOME}/ccf/etc/cchost.toml ${PDO_HOME}/ccf/etc/constitution.js
make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor keys
make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor config

# -----------------------------------------------------------------
yell start the ccf service
# -----------------------------------------------------------------
. ${PDO_HOME}/ccf/bin/activate
${PDO_HOME}/ccf/bin/start_ccf_network.sh
STATUS=$?
if [ $STATUS != 0 ] ; then
    echo $STATUS > ${XFER_DIR}/status
    exit $STATUS
fi

# -----------------------------------------------------------------
yell copy the ledger keys
# -----------------------------------------------------------------
cp ${PDO_LEDGER_KEY_ROOT}/* ${XFER_DIR}/ccf/keys
chmod a+rw ${XFER_DIR}/ccf/keys/*

# -----------------------------------------------------------------
# we need the CCF container to continue running until the client
# is finished with all of the tests
# -----------------------------------------------------------------
while [ ! -f ${XFER_DIR}/status ]; do
    say "waiting for client completion"
    sleep 5
done

exit $(cat ${XFER_DIR}/status)
