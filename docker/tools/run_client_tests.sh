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
source ${PDO_HOME}/bin/lib/common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure client for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------

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
yell create client configuration files
# -----------------------------------------------------------------
try ${PDO_INSTALL_ROOT}/bin/pdo-configure-users -t ${PDO_SOURCE_ROOT}/build/template -o ${PDO_HOME} \
    --key-count 10 --key-base user --host ${PDO_HOSTNAME}

# for now the site.toml is just a way to notify
# that the services are running; in the future
# the client should be able to incorporate this
# file and begin to use the information, again
# in theory this should be taken care of by the
# health checks in the docker compose configuration
while [ ! -f ${XFER_DIR}/services/etc/site.toml ]; do
    say "waiting for site configuration"
    sleep 5
done

try cp ${XFER_DIR}/services/etc/site.toml ${PDO_HOME}/etc/site.toml

# -----------------------------------------------------------------
yell run the service test suite
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate
try ${PDO_SOURCE_ROOT}/build/tests/service-test.sh
