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

F_USAGE='--host service-host | --ledger url | --loglevel [debug|info|warn]'
SHORT_OPTS='h:l:'
LONG_OPTS='host:,ledger:,loglevel:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${F_SCRIPT}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${F_SCRIPT} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -h|--host) F_SERVICE_HOST="$2" ; shift 2 ;;
        -1|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)
ESDB_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)

function cleanup {
    rm -f ${SAVE_FILE} ${ESDB_FILE}
}

trap cleanup EXIT

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

declare -i port_count=5
declare -i pservice_base_port=7001
declare -i sservice_base_port=7101
declare -i eservice_base_port=7201
declare -i p s e v

for v in $(seq 0 $((${port_count} - 1))) ; do
    check_service $((pservice_base_port + v))
    check_service $((sservice_base_port + v))
    check_service $((eservice_base_port + v))
done

# -----------------------------------------------------------------
say run unit tests for eservice database
# -----------------------------------------------------------------
try python ${PDO_SOURCE_ROOT}/python/pdo/test/servicedb.py --logfile __screen__ --loglevel ${F_LOGLEVEL} \
    --eservice-db ${ESDB_FILE} \
    --url http://${F_SERVICE_HOST}:7101/ http://${F_SERVICE_HOST}:7102/ http://${F_SERVICE_HOST}:7103/ \
    --ledger ${F_LEDGER_URL}

say create the eservice database using database CLI
try pdo-eservicedb --loglevel ${F_LOGLEVEL} reset --create
try pdo-eservicedb --loglevel ${F_LOGLEVEL} add -u http://${F_SERVICE_HOST}:7101 -n es7101
try pdo-eservicedb --loglevel ${F_LOGLEVEL} add -u http://${F_SERVICE_HOST}:7102 -n es7102
try pdo-eservicedb --loglevel ${F_LOGLEVEL} add -u http://${F_SERVICE_HOST}:7103 -n es7103
try pdo-eservicedb --loglevel ${F_LOGLEVEL} add -u http://${F_SERVICE_HOST}:7104 -n es7104
try pdo-eservicedb --loglevel ${F_LOGLEVEL} add -u http://${F_SERVICE_HOST}:7105 -n es7105

# -----------------------------------------------------------------
say start storage service test
# -----------------------------------------------------------------
try pdo-test-storage --url http://${F_SERVICE_HOST}:7201 --loglevel ${F_LOGLEVEL} --logfile __screen__

# -----------------------------------------------------------------
say start request test
# -----------------------------------------------------------------
try pdo-test-request \
    --config pcontract.toml \
    --pservice http://${F_SERVICE_HOST}:7001/ http://${F_SERVICE_HOST}:7002 http://${F_SERVICE_HOST}:7003 \
    --eservice-url http://${F_SERVICE_HOST}:7101/ \
    --ledger ${F_LEDGER_URL} \
    --logfile __screen__ --loglevel ${F_LOGLEVEL}

# execute the common tests
for test_file in ${PDO_SOURCE_ROOT}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} with services
    try pdo-test-contract \
        --config pcontract.toml \
        --contract ${test_contract} --expressions ${test_file} \
        --pservice http://${F_SERVICE_HOST}:7001/ http://${F_SERVICE_HOST}:7002 http://${F_SERVICE_HOST}:7003 \
        --eservice-url http://${F_SERVICE_HOST}:7101/ \
        --logfile __screen__ --loglevel ${F_LOGLEVEL}
done

# execute interpreter specific tests
INTERPRETER_NAME=${PDO_INTERPRETER}
if [[ "$PDO_INTERPRETER" =~ ^"wawaka-" ]]; then
    INTERPRETER_NAME="wawaka"
fi

for test_file in ${PDO_SOURCE_ROOT}/build/tests/${INTERPRETER_NAME}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} with services
    try pdo-test-contract \
        --config pcontract.toml \
        --contract ${test_contract} --expressions ${test_file} \
        --pservice http://${F_SERVICE_HOST}:7001/ http://${F_SERVICE_HOST}:7002 http://${F_SERVICE_HOST}:7003 \
        --eservice-url http://${F_SERVICE_HOST}:7101/ \
        --logfile __screen__ --loglevel ${F_LOGLEVEL}
done

## -----------------------------------------------------------------
## -----------------------------------------------------------------
if [[ "$PDO_INTERPRETER" =~ ^"wawaka" ]]; then
    yell start multi-user tests
    try ${PDO_SOURCE_ROOT}/build/tests/multi-user.sh -h ${F_SERVICE_HOST} -l ${F_LEDGER_URL} --loglevel ${F_LOGLEVEL}
else
    yell no multi-user test for ${PDO_INTERPRETER}
fi

## -----------------------------------------------------------------
yell test failure conditions to ensure they are caught
## -----------------------------------------------------------------
say invalid method, this should fail
${PDO_HOME}/bin/pdo-invoke.psh \
           --service_host ${F_SERVICE_HOST} --identity user1 --pdo_file ${SAVE_FILE} --method no-such-method
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say policy violation with identity, this should fail
${PDO_HOME}/bin/pdo-invoke.psh \
           --service_host ${F_SERVICE_HOST} --identity user2 --pdo_file ${SAVE_FILE} --method get_value
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

# -----------------------------------------------------------------
yell test pdo-shell
# -----------------------------------------------------------------
try ${PDO_SOURCE_ROOT}/build/tests/shell-test.psh -m host ${F_SERVICE_HOST} --loglevel ${F_LOGLEVEL}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
if [[ "$PDO_INTERPRETER" =~ ^"wawaka" ]]; then
    yell run system tests for contracts

    cd ${PDO_SOURCE_ROOT}/contracts/wawaka
    try make system-test TEST_LOG_LEVEL=${F_LOGLEVEL}
else
    yell no system tests for "${PDO_INTERPRETER}"
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
cd ${PDO_SOURCE_ROOT}/build
yell run tests for state replication
say start mock-contract test with replication 3 eservices 2 replicas needed before txn.

try pdo-test-request \
    --config pcontract.toml \
    --pservice http://${F_SERVICE_HOST}:7001/ http://${F_SERVICE_HOST}:7002 http://${F_SERVICE_HOST}:7003 \
    --eservice-url http://${F_SERVICE_HOST}:7101/ http://${F_SERVICE_HOST}:7102/ http://${F_SERVICE_HOST}:7103/ \
    --ledger ${F_LEDGER_URL} \
    --logfile __screen__ --loglevel ${F_LOGLEVEL} --iterations 100 \
    --num-provable-replicas 2 --availability-duration 100 --randomize-eservice

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all service tests
exit 0
