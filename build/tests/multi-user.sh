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
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh
source ${SRCDIR}/bin/lib/common_service.sh
check_python_version

PDO_LOG_LEVEL=${PDO_LOG_LEVEL:-info}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

: "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"
: "${PDO_LEDGER_URL:-$(die Missing environment variable PDO_LEDGER_URL)}"

SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)

# -----------------------------------------------------------------
# some checks to make sure we are ready to run
# -----------------------------------------------------------------
if [ "${PDO_LEDGER_TYPE}" == "ccf" ]; then
    if [ ! -f "${PDO_LEDGER_KEY_ROOT}/networkcert.pem" ]; then
        die "CCF ledger keys are missing, please copy and try again"
    fi
fi

declare CONFIG_FILE=${PDO_HOME}/etc/pcontract.toml
if [ ! -f ${CONFIG_FILE} ]; then
    die missing client configuration file, ${CONFIG_FILE}
fi

declare CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.b64
if [ ! -f ${CONTRACT_FILE} ]; then
    die missing contract source file, ${CONTRACT_FILE}
fi

declare PLIST=$(pgrepf  "${PDO_INSTALL_ROOT}/bin/eservice .* --config eservice[0-9].toml")
if [ -z "${PLIST}" ] ; then
    die "unable to locate services"
fi

declare -i NUM_SERVICES=$(echo "${PLIST}" | wc -w)
if [ ${NUM_SERVICES} -lt 3 ]; then
    die "insufficient services; minimum of 3 required"
fi

## -----------------------------------------------------------------
## -----------------------------------------------------------------

# enclave service group e3 uses ports 7103, 7104, and 7105
say create the contract
try ${PDO_HOME}/bin/pdo-create.psh \
    --loglevel ${PDO_LOG_LEVEL} \
    --identity user1 --psgroup default --esgroup e3 --ssgroup default \
    --pdo_file ${SAVE_FILE} --source ${CONTRACT_FILE} --class mock-contract

# this will invoke the increment operation 5 times on each enclave round robin
# fashion; the objective of this test is to ensure that the client touches
# multiple, independent enclave services and pushes missing state correctly
declare -i user_count=3
declare -i base_user=2
declare -i port_count=3
declare -i base_port=7103
declare -i iterations=$((NUM_SERVICES*5))
declare -i u p v value

say increment the value with a simple expression ${iterations} times, querying enclaves in round robin
for v in $(seq 1 ${iterations}) ; do
    u=$((v % user_count + base_user))
    p=$((v % port_count + base_port))
    value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                       --wait yes \
                       --logfile __screen__ --loglevel ${PDO_LOG_LEVEL} \
                       --enclave "http://localhost:${p}" --identity user${u} \
                       --pdo_file ${SAVE_FILE} --method anonymous_inc_value)
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

say get the value and check it
for v in $(seq 1 ${port_count}) ; do
    p=$((v % port_count + base_port))
    value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                       --logfile __screen__ --loglevel ${PDO_LOG_LEVEL} \
                       --enclave "http://localhost:${p}" --identity user1 \
                       --pdo_file ${SAVE_FILE} --method get_value)
    if [ $value != $iterations ]; then
        die "contract has the wrong value ($value instead of $iterations for enclave $e"
    fi
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
