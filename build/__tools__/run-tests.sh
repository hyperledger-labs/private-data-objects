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

# -----------------------------------------------------------------
# -----------------------------------------------------------------
# if [ "${PDO_INTERPRETER}" == "wawaka" ]; then
#     die automated tests not enabled for the wawaka interpreter
# fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    die activate python3 first
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

: "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"
: "${PDO_LEDGER_URL:-$(die Missing environment variable PDO_LEDGER_URL)}"

SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)
ESDB_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)

declare -i NUM_SERVICES=5 # must be at least 3 for pconntract update test to work
function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/es-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh --count ${NUM_SERVICES} > /dev/null
    rm -f ${SAVE_FILE} ${ESDB_FILE}
}

trap cleanup EXIT

# -----------------------------------------------------------------
yell run unit tests for python, common, contracts and eservice
# -----------------------------------------------------------------
say run unit tests for python package
cd ${SRCDIR}/python
try make test > /dev/null

say run unit tests for common library
cd ${SRCDIR}/common/build
try make test > /dev/null

say run unit tests for eservice
cd ${SRCDIR}/eservice
try make test > /dev/null

say run unit tests for contracts
cd ${SRCDIR}/contracts
try make test > /dev/null

# -----------------------------------------------------------------
yell start enclave and provisioning services
# -----------------------------------------------------------------
try ${PDO_HOME}/bin/ss-start.sh --count ${NUM_SERVICES} > /dev/null
try ${PDO_HOME}/bin/ps-start.sh --count ${NUM_SERVICES} --ledger ${PDO_LEDGER_URL} --clean > /dev/null
try ${PDO_HOME}/bin/es-start.sh --count ${NUM_SERVICES} --ledger ${PDO_LEDGER_URL} --clean > /dev/null

cd ${SRCDIR}/build

# -----------------------------------------------------------------
yell start tests without provisioning or enclave services
# -----------------------------------------------------------------
say start request test
try pdo-test-request --no-ledger --iterations 100 \
    --logfile __screen__ --loglevel warn

# execute the common tests
for test_file in ${SRCDIR}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel warn
done

# execute interpreter specific tests
for test_file in ${SRCDIR}/build/tests/${PDO_INTERPRETER}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel warn
done

say start request test with tampered block order, this should fail
pdo-test-request --no-ledger \
    --tamper-block-order \
    --logfile __screen__ --loglevel warn
if [ $? == 0 ]; then
    die request test with tampered block order succeeded though it should have failed
fi

## -----------------------------------------------------------------
yell start tests with provisioning and enclave services
## -----------------------------------------------------------------
say run unit tests for eservice database
cd ${SRCDIR}/python/pdo/test
try python servicedb.py --logfile $PDO_HOME/logs/client.log --loglevel info \
    --eservice-db ${ESDB_FILE} \
    --url http://localhost:7101/ http://localhost:7102/ http://localhost:7103/ \
    --ledger ${PDO_LEDGER_URL}
try rm -f ${ESDB_FILE}

cd ${SRCDIR}/build

say create the eservice database using database CLI
try pdo-eservicedb --loglevel warn reset --create
try pdo-eservicedb --loglevel warn add -u http://localhost:7101 -n es7101
try pdo-eservicedb --loglevel warn add -u http://localhost:7102 -n es7102
try pdo-eservicedb --loglevel warn add -u http://localhost:7103 -n es7103
try pdo-eservicedb --loglevel warn add -u http://localhost:7104 -n es7104
try pdo-eservicedb --loglevel warn add -u http://localhost:7105 -n es7105

say start storage service test
try pdo-test-storage --url http://localhost:7201 --loglevel warn --logfile __screen__

say start request test
try pdo-test-request --ledger ${PDO_LEDGER_URL} \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ \
    --logfile __screen__ --loglevel warn

# execute the common tests
for test_file in ${SRCDIR}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} with services
    try pdo-test-contract --contract ${test_contract} \
        --expressions ${test_file} \
        --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
        --eservice-url http://localhost:7101/ \
        --logfile __screen__ --loglevel warn
done

# execute interpreter specific tests
for test_file in ${SRCDIR}/build/tests/${PDO_INTERPRETER}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} with services
    try pdo-test-contract --contract ${test_contract} \
        --expressions ${test_file} \
        --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
        --eservice-url http://localhost:7101/ \
        --logfile __screen__ --loglevel warn
done

## -----------------------------------------------------------------
yell start pdo-create and pdo-update tests
## -----------------------------------------------------------------

# make sure we have the necessary files in place
CONFIG_FILE=${PDO_HOME}/etc/pcontract.toml
if [ ! -f ${CONFIG_FILE} ]; then
    die missing client configuration file, ${CONFIG_FILE}
fi

if [ "$PDO_INTERPRETER" == "gipsy" ]; then
    CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.scm
else
    CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.b64
fi

if [ ! -f ${CONTRACT_FILE} ]; then
    die missing contract source file, ${CONTRACT_FILE}
fi

say create the contract
try ${PDO_HOME}/bin/pdo-create.psh \
    --identity user1 --ps_group default --es_group all \
    --pdo_file ${SAVE_FILE} --source ${CONTRACT_FILE} --class mock-contract

# this will invoke the increment operation 5 times on each enclave round robin
# fashion; the objective of this test is to ensure that the client touches
# multiple, independent enclave services and pushes missing state correctly
declare -i pcontract_es=3 #.see ../opt/pdo/etc/template/pcontract.toml
declare -i n=$((NUM_SERVICES*pcontract_es)) e v value
say increment the value with a simple expression ${n} times, querying enclaves in round robin
for v in $(seq 1 ${n}) ; do
    e=$((v % pcontract_es + 1))
    value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                       --enclave "http://localhost:710${e}" --identity user1 \
                       --pdo_file ${SAVE_FILE} --method inc_value)
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

say get the value and check it
v=$((v+1)); e=$((v % pcontract_es + 1))
value=$(${PDO_HOME}/bin/pdo-invoke.psh \
                   --enclave "http://localhost:710${e}" --identity user1 \
                   --pdo_file ${SAVE_FILE} --method get_value)
if [ $value != $((n)) ]; then
    die "contract has the wrong value ($value instead of $((n+1))) for enclave $e"
fi

## -----------------------------------------------------------------
yell test failure conditions to ensure they are caught
## -----------------------------------------------------------------
say invalid method, this should fail
${PDO_HOME}/bin/pdo-invoke.psh --identity user1 --pdo_file ${SAVE_FILE} --method no-such-method
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say policy violation with identity, this should fail
${PDO_HOME}/bin/pdo-invoke.psh --identity user2 --pdo_file ${SAVE_FILE} --method get_value
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

# -----------------------------------------------------------------
yell test pdo-shell
# -----------------------------------------------------------------
try ${SRCDIR}/build/tests/shell-test.psh --loglevel warning

# -----------------------------------------------------------------
# -----------------------------------------------------------------
cd ${SRCDIR}/build
yell run tests for state replication
say start mock-contract test with replication 3 eservices 2 replicas needed before txn.

try pdo-test-request --ledger ${PDO_LEDGER_URL} \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ http://localhost:7102/ http://localhost:7103/ \
    --logfile __screen__ --loglevel warn --iterations 100 \
    --num-provable-replicas 2 --availability-duration 100 --randomize-eservice

if [ "${PDO_INTERPRETER}" == "gipsy" ]; then
    say start memory test test with replication 3 eservices 2 replicas needed before txn
    try pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract memory-test \
        --expressions ${SRCDIR}/build/tests/${PDO_INTERPRETER}/memory-test.json \
        --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
        --eservice-url http://localhost:7101/ http://localhost:7102/ http://localhost:7103/ \
        --logfile __screen__ --loglevel warn \
        --num-provable-replicas 2 --availability-duration 100 --randomize-eservice
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
