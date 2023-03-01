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
check_python_version

PDO_LOG_LEVEL=${PDO_LOG_LEVEL:-info}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
if [ "${PDO_INTERPRETER}" == "wawaka-aot" ]; then
    die Automated tests for the wawaka-aot interpreter are currently not supported.
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

: "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"
: "${PDO_LEDGER_URL:-$(die Missing environment variable PDO_LEDGER_URL)}"

SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)
ESDB_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)

function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh > /dev/null
    ${PDO_HOME}/bin/es-stop.sh > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh > /dev/null
    rm -f ${SAVE_FILE} ${ESDB_FILE}
}

trap cleanup EXIT

# -----------------------------------------------------------------
# some checks to make sure we are ready to run
# -----------------------------------------------------------------
if [ "${PDO_LEDGER_TYPE}" == "ccf" ]; then
    if [ ! -f "${PDO_LEDGER_KEY_ROOT}/networkcert.pem" ]; then
        die "CCF ledger keys are missing, please copy and try again"
    fi
fi

# -----------------------------------------------------------------
yell run unit tests for python, common, contracts and eservice
# -----------------------------------------------------------------
say run unit tests for python package
cd ${SRCDIR}/python
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for common library
cd ${SRCDIR}/common/build
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for eservice
cd ${SRCDIR}/eservice
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for contracts
cd ${SRCDIR}/contracts
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

# -----------------------------------------------------------------
yell start enclave and provisioning services
# -----------------------------------------------------------------
try ${PDO_HOME}/bin/ss-start.sh --loglevel ${PDO_LOG_LEVEL}
try ${PDO_HOME}/bin/ps-start.sh --loglevel ${PDO_LOG_LEVEL} --ledger ${PDO_LEDGER_URL} --clean
try ${PDO_HOME}/bin/es-start.sh --loglevel ${PDO_LOG_LEVEL} --ledger ${PDO_LEDGER_URL} --clean

cd ${SRCDIR}/build

# -----------------------------------------------------------------
yell start tests without provisioning or enclave services
# -----------------------------------------------------------------
say start request test
try pdo-test-request --no-ledger --iterations 100 \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}

# execute the common tests
for test_file in ${SRCDIR}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

# execute interpreter specific tests
INTERPRETER_NAME=${PDO_INTERPRETER}
if [[ "$PDO_INTERPRETER" =~ ^"wawaka-" ]]; then
    INTERPRETER_NAME="wawaka"
fi

for test_file in ${SRCDIR}/build/tests/${INTERPRETER_NAME}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

say start request test with tampered block order, this should fail
pdo-test-request --no-ledger \
    --tamper-block-order \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
if [ $? == 0 ]; then
    die request test with tampered block order succeeded though it should have failed
fi

## -----------------------------------------------------------------
yell start tests with provisioning and enclave services
## -----------------------------------------------------------------
say run unit tests for eservice database
cd ${SRCDIR}/python/pdo/test
try python servicedb.py --logfile __screen__ --loglevel ${PDO_LOG_LEVEL} \
    --eservice-db ${ESDB_FILE} \
    --url http://${PDO_HOSTNAME}:7101/ http://${PDO_HOSTNAME}:7102/ http://${PDO_HOSTNAME}:7103/ \
    --ledger ${PDO_LEDGER_URL}
try rm -f ${ESDB_FILE}

cd ${SRCDIR}/build

say create the eservice database using database CLI
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} reset --create
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} add -u http://${PDO_HOSTNAME}:7101 -n es7101
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} add -u http://${PDO_HOSTNAME}:7102 -n es7102
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} add -u http://${PDO_HOSTNAME}:7103 -n es7103
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} add -u http://${PDO_HOSTNAME}:7104 -n es7104
try pdo-eservicedb --loglevel ${PDO_LOG_LEVEL} add -u http://${PDO_HOSTNAME}:7105 -n es7105

say start storage service test
try pdo-test-storage --url http://${PDO_HOSTNAME}:7201 --loglevel ${PDO_LOG_LEVEL} --logfile __screen__

say start request test
try pdo-test-request --ledger ${PDO_LEDGER_URL} \
    --pservice http://${PDO_HOSTNAME}:7001/ http://${PDO_HOSTNAME}:7002 http://${PDO_HOSTNAME}:7003 \
    --eservice-url http://${PDO_HOSTNAME}:7101/ \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}

# execute the common tests
for test_file in ${SRCDIR}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} with services
    try pdo-test-contract --contract ${test_contract} \
        --expressions ${test_file} \
        --pservice http://${PDO_HOSTNAME}:7001/ http://${PDO_HOSTNAME}:7002 http://${PDO_HOSTNAME}:7003 \
        --eservice-url http://${PDO_HOSTNAME}:7101/ \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

# execute interpreter specific tests
INTERPRETER_NAME=${PDO_INTERPRETER}
if [[ "$PDO_INTERPRETER" =~ ^"wawaka-" ]]; then
    INTERPRETER_NAME="wawaka"
fi

for test_file in ${SRCDIR}/build/tests/${INTERPRETER_NAME}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} with services
    try pdo-test-contract --contract ${test_contract} \
        --expressions ${test_file} \
        --pservice http://${PDO_HOSTNAME}:7001/ http://${PDO_HOSTNAME}:7002 http://${PDO_HOSTNAME}:7003 \
        --eservice-url http://${PDO_HOSTNAME}:7101/ \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

## -----------------------------------------------------------------
## -----------------------------------------------------------------
if [[ "$PDO_INTERPRETER" =~ ^"wawaka" ]]; then
    yell start multi-user tests
    try ${SRCDIR}/build/tests/multi-user.sh
else
    yell no multi-user test for ${PDO_INTERPRETER}
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
try ${SRCDIR}/build/tests/shell-test.psh -m host ${PDO_HOSTNAME} --loglevel ${PDO_LOG_LEVEL}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
if [[ "$PDO_INTERPRETER" =~ ^"wawaka" ]]; then
    yell run system tests for contracts

    cd ${SRCDIR}/contracts/wawaka
    try make system-test TEST_LOG_LEVEL=${PDO_LOG_LEVEL}
else
    yell no system tests for "${PDO_INTERPRETER}"
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
cd ${SRCDIR}/build
yell run tests for state replication
say start mock-contract test with replication 3 eservices 2 replicas needed before txn.

try pdo-test-request --ledger ${PDO_LEDGER_URL} \
    --pservice http://${PDO_HOSTNAME}:7001/ http://${PDO_HOSTNAME}:7002 http://${PDO_HOSTNAME}:7003 \
    --eservice-url http://${PDO_HOSTNAME}:7101/ http://${PDO_HOSTNAME}:7102/ http://${PDO_HOSTNAME}:7103/ \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL} --iterations 100 \
    --num-provable-replicas 2 --availability-duration 100 --randomize-eservice

if [ "${PDO_INTERPRETER}" == "gipsy" ]; then
    say start memory test test with replication 3 eservices 2 replicas needed before txn
    try pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract memory-test \
        --expressions ${SRCDIR}/build/tests/${PDO_INTERPRETER}/memory-test.json \
        --pservice http://${PDO_HOSTNAME}:7001/ http://${PDO_HOSTNAME}:7002 http://${PDO_HOSTNAME}:7003 \
        --eservice-url http://${PDO_HOSTNAME}:7101/ http://${PDO_HOSTNAME}:7102/ http://${PDO_HOSTNAME}:7103/ \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL} \
        --num-provable-replicas 2 --availability-duration 100 --randomize-eservice
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
