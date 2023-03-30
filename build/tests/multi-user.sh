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
source ${PDO_SOURCE_ROOT}/bin/lib/common.sh
check_python_version

# -----------------------------------------------------------------
# -----------------------------------------------------------------
if [ "${PDO_INTERPRETER}" == "wawaka-aot" ]; then
    die Automated tests for the wawaka-aot interpreter are currently not supported.
fi

if [ "${PDO_LEDGER_TYPE}" == "ccf" ]; then
    if [ ! -f "${PDO_LEDGER_KEY_ROOT}/networkcert.pem" ]; then
        die "CCF ledger keys are missing, please copy and try again"
    fi
fi

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_SCRIPT=$(basename ${BASH_SOURCE[-1]} )
F_SERVICE_HOST=${PDO_HOSTNAME}
F_LEDGER_URL=${PDO_LEDGER_URL}
F_LOGLEVEL=${PDO_LOG_LEVEL:-info}
F_COUNT=5

F_USAGE='--count services | --host service-host | --ledger url | --loglevel [debug|info|warn]'
SHORT_OPTS='c:h:l:'
LONG_OPTS='count:,host:,ledger:,loglevel:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${F_SCRIPT}" -- "$@")
if [ $? != 0 ] ; then die "Usage: ${F_SCRIPT} ${F_USAGE}" >&2 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -c|--count) F_COUNT="$2" ; shift 2 ;;
        -h|--host) F_SERVICE_HOST="$2" ; shift 2 ;;
        -l|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        --help) say "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) die "Internal error; $1!" ;;
    esac
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SAVE_FILE=$(mktemp /tmp/pdo-contract.XXXXXXXXX)

function cleanup {
    rm -f ${SAVE_FILE}
}

trap cleanup EXIT

# -----------------------------------------------------------------
# some checks to make sure we are ready to run
# -----------------------------------------------------------------
declare CONFIG_FILE=${PDO_HOME}/etc/pcontract.toml
if [ ! -f ${CONFIG_FILE} ]; then
    die missing client configuration file, ${CONFIG_FILE}
fi

declare CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.b64
if [ ! -f ${CONTRACT_FILE} ]; then
    die missing contract source file, ${CONTRACT_FILE}
fi

# -----------------------------------------------------------------
say verify that services are running
# -----------------------------------------------------------------
CURL_CMD='curl --ipv4 --retry 10 --connect-timeout 5 --max-time 10  -sL -w %{http_code} -o /dev/null'

function check_service() {
    url="http://${F_SERVICE_HOST}:$1/info"
    resp=$(${CURL_CMD} ${url})
    if [ $? != 0 ] || [ $resp != "200" ]; then
    	die "unable to contact service at $url"
    fi
}

declare -i port_count=$F_COUNT
declare -i pservice_base_port=7001
declare -i eservice_base_port=7101
declare -i sservice_base_port=7201
declare -i v

for v in $(seq 0 $((${port_count} - 1))) ; do
    check_service $((pservice_base_port + v)) pservice $PGROUP
    check_service $((sservice_base_port + v)) sservice $SGROUP
    check_service $((eservice_base_port + v)) eservice $EGROUP
done

## -----------------------------------------------------------------
## -----------------------------------------------------------------

# enclave service group e3 uses ports 7103, 7104, and 7105
# this code makes the assumption that the eservice database contains
# entries for $F_SERVICE_HOST.
say create the contract
try ${PDO_HOME}/bin/pdo-create.psh \
    --service_host ${F_SERVICE_HOST} \
    --loglevel ${F_LOGLEVEL} --logfile __screen__ \
    --identity user1 --psgroup all --esgroup all --ssgroup all \
    --pdo_file ${SAVE_FILE} --source ${CONTRACT_FILE} --class mock-contract

# this will invoke the increment operation 5 times on each enclave round robin
# fashion; the objective of this test is to ensure that the client touches
# multiple, independent enclave services and pushes missing state correctly
declare -i user_count=3
declare -i base_user=2
declare -i port_count=3
declare -i base_port=7103
declare -i iterations=$((F_COUNT*5))
declare -i u p v value

say increment the value with a simple expression ${iterations} times, querying enclaves in round robin
for v in $(seq 1 ${iterations}) ; do
    say pass $v
    u=$((v % user_count + base_user))
    p=$((v % port_count + base_port))
    value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                       --wait yes \
                       --service_host ${F_SERVICE_HOST} \
                       --logfile __screen__ --loglevel ${F_LOGLEVEL} \
                       --enclave "es${p}" --identity user${u} \
                       --pdo_file ${SAVE_FILE} --method anonymous_inc_value)
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

say get the value and check it
for v in $(seq 1 ${port_count}) ; do
    p=$((v % port_count + base_port))
    value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                       --service_host ${F_SERVICE_HOST} \
                       --logfile __screen__ --loglevel ${F_LOGLEVEL} \
                       --enclave "es${p}" --identity user1 \
                       --pdo_file ${SAVE_FILE} --method get_value)
    if [ $value != $iterations ]; then
        die "contract has the wrong value ($value instead of $iterations for enclave $e"
    fi
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
