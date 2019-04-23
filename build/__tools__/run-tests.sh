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
cred=`tput setaf 1`
cgrn=`tput setaf 2`
cblu=`tput setaf 4`
cmag=`tput setaf 5`
cwht=`tput setaf 7`
cbld=`tput bold`
bred=`tput setab 1`
bgrn=`tput setab 2`
bblu=`tput setab 4`
bwht=`tput setab 7`
crst=`tput sgr0`

function recho () {
    echo "${cbld}${cred}" $@ "${crst}" >&2
}

function becho () {
    echo "${cbld}${cblu}" $@ "${crst}" >&2
}

function say () {
    echo "$(basename $0): $*" >&2;
}

function yell () {
    becho "$(basename $0): $*" >&2;
}

function die() {
    recho "$(basename $0): $*" >&2
    exit 111
}

try() {
    "$@" || die "test failed: $*"
}

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

# check for existing enclave and provisioning services
# to handle some docker oddities, define our own pgrep rather than the normal one ..
pgrep() { ps -ef | egrep -v '<defunct>|grep' | grep "$1"; }
pgrep eservice
if [ $? == 0 ] ; then
    die existing enclave services detected, please shutdown
fi

pgrep pservice
if [ $? == 0 ] ; then
    die existing provisioning services detected, please shutdown
fi

SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)

declare -i NUM_SERVICES=5 # must be at least 3 for pconntract update test to work
function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/es-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh --count ${NUM_SERVICES} > /dev/null
    rm -f ${SAVE_FILE}
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

say start request test with tampered block order, this should fail
pdo-test-request --no-ledger \
    --tamper-block-order \
    --logfile __screen__ --loglevel warn
if [ $? == 0 ]; then
    die request test with tampered block order succeeded though it should have failed
fi

say start integer-key contract test
try pdo-test-contract --no-ledger --contract integer-key \
    --logfile __screen__ --loglevel warn

say start mock-contract contract test
try pdo-test-contract --no-ledger --contract mock-contract \
    --logfile __screen__ --loglevel warn

say start key value store test
try pdo-test-contract --no-ledger --contract key-value-test \
    --logfile __screen__ --loglevel warn

say start memory test
try pdo-test-contract --no-ledger --contract memory-test \
    --logfile __screen__ --loglevel warn

## -----------------------------------------------------------------
yell start tests with provisioning and enclave services
## -----------------------------------------------------------------

say run unit tests for eservice database
cd ${SRCDIR}/python/pdo/test
try python servicedb.py --logfile $PDO_HOME/logs/client.log --loglevel info \
    --eservice-db $PDO_HOME/data/db-test.json --url http://localhost:7101/ http://localhost:7102/ http://localhost:7103/ --ledger ${PDO_LEDGER_URL}
try rm $PDO_HOME/data/db-test.json

cd ${SRCDIR}/build

say create the eservice database using database CLI
# add all enclaves listed in pcontract.toml
try pdo-eservicedb --logfile $PDO_HOME/logs/client.log --loglevel info create

say start storage service test
try pdo-test-storage --url http://localhost:7201 --loglevel warn --logfile __screen__

say start request test
try pdo-test-request --ledger ${PDO_LEDGER_URL} \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ \
    --logfile __screen__ --loglevel warn

say start integer-key contract test
try pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract integer-key \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ \
    --logfile __screen__ --loglevel warn

say start key value store test
try pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract key-value-test \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ \
    --logfile __screen__ --loglevel warn

say start memory test
try pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract memory-test \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice-url http://localhost:7101/ \
    --logfile __screen__ --loglevel warn

## -----------------------------------------------------------------
yell start pdo-create and pdo-update tests
## -----------------------------------------------------------------

# make sure we have the necessary files in place
CONFIG_FILE=${PDO_HOME}/etc/pcontract.toml
if [ ! -f ${CONFIG_FILE} ]; then
    die missing client configuration file, ${CONFIG_FILE}
fi

CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.scm
if [ ! -f ${CONTRACT_FILE} ]; then
    die missing contract source file, ${CONTRACT_FILE}
fi

say create the contract
try pdo-create --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
     --logfile __screen__ --loglevel warn \
    --identity user1 --save-file ${SAVE_FILE} \
    --contract mock-contract --source _mock-contract.scm

# this will invoke the increment operation 5 times on each enclave round robin
# fashion; the objective of this test is to ensure that the client touches
# multiple, independent enclave services and pushes missing state correctly
declare -i pcontract_es=3 #.see ../opt/pdo/etc/template/pcontract.toml
declare -i n=$((NUM_SERVICES*pcontract_es)) e v value
say increment the value with a simple expression ${n} times, querying enclaves in round robin
for v in $(seq 1 ${n}) ; do
    e=$((v % pcontract_es + 1))
    value=$(pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
                       --enclave "http://localhost:710${e}" \
                       --logfile __screen__ --loglevel warn \
                       --identity user1 --save-file ${SAVE_FILE} \
                       "'(inc-value)")
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

say increment the value with a evaluated expression
v=$((v+1)); e=$((v % pcontract_es + 1))
value=$(pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
                   --enclave "http://localhost:710${e}" \
                   --logfile __screen__ --loglevel warn \
                   --identity user1 --save-file ${SAVE_FILE} \
                   "(list 'inc-value)")
if [ $value != $((n+1)) ]; then
    die "contract has the wrong value ($value instead of $((n+1))) for enclave $e"
fi

say get the value and check it
v=$((v+1)); e=$((v % pcontract_es + 1))
value=$(pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
                   --enclave "http://localhost:710${e}" \
                   --logfile __screen__ --loglevel warn \
                   --identity user1 --save-file ${SAVE_FILE} \
                   "'(get-value)")
if [ $value != $((n+1)) ]; then
    die "contract has the wrong value ($value instead of $((n+1))) for enclave $e"
fi

## -----------------------------------------------------------------
yell test failure conditions to ensure they are caught
## -----------------------------------------------------------------
say start mock contract test with ledger, this should fail dependency check
pdo-test-contract --ledger ${PDO_LEDGER_URL} --contract mock-contract \
    --logfile __screen__ --loglevel warn
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say start broken contract test, this should fail
pdo-test-contract --no-ledger --contract mock-contract-bad \
    --expressions mock-contract.exp \
    --logfile __screen__ --loglevel warn
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say invalid method, this should fail
pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
           --logfile __screen__ --loglevel warn \
           --identity user1 --save-file ${SAVE_FILE} \
           "'(no-such-method)"
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say invalid expression, this should fail
pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
           --logfile __screen__ --loglevel warn \
           --identity user1 --save-file ${SAVE_FILE} \
           "'(no-such-method"
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

say policy violation with identity, this should fail
pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
           --logfile __screen__ --loglevel warn \
           --identity user2 --save-file ${SAVE_FILE} \
           "'(get-value)"
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

#-----------------------------------------
yell run tests with the eservice database
#------------------------------------------

say run various pdo scripts - test-request, test-contract, create, update, shell - using database
try pdo-test-request --eservice-name e1 --logfile $PDO_HOME/logs/client.log --loglevel info
try pdo-test-contract --contract integer-key --eservice-name e2 --logfile $PDO_HOME/logs/client.log --loglevel info

# make sure we have the necessary files in place
CONFIG_FILE=${PDO_HOME}/etc/pcontract.toml
if [ ! -f ${CONFIG_FILE} ]; then
    die missing client configuration file, ${CONFIG_FILE}
fi

CONTRACT_FILE=${PDO_HOME}/contracts/_mock-contract.scm
if [ ! -f ${CONTRACT_FILE} ]; then
    die missing contract source file, ${CONTRACT_FILE}
fi

try pdo-create --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
     --logfile $PDO_HOME/logs/client.log --loglevel info \
    --identity user1 --save-file ${SAVE_FILE} \
    --contract mock-contract --source _mock-contract.scm --eservice-name e1 e2 e3

# this will invoke the increment operation 5 times on each enclave round robin
# fashion; the objective of this test is to ensure that the client touches
# multiple, independent enclave services and pushes missing state correctly
declare -i pcontract_es=3 #.see ../opt/pdo/etc/template/pcontract.toml
declare -i n=$((NUM_SERVICES*pcontract_es)) e v value
for v in $(seq 1 ${n}) ; do
    e=$((v % pcontract_es + 1))
    value=$(pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
                       --eservice-name e${e} \
                       --logfile $PDO_HOME/logs/client.log --loglevel info \
                       --identity user1 --save-file ${SAVE_FILE} \
                       "'(inc-value)")
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
KEYGEN=${SRCDIR}/build/__tools__/make-keys
if [ ! -f ${PDO_HOME}/keys/red_type_private.pem ]; then
    for color in red green blue ; do
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_type --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_vetting --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_issuer --format pem
    done
fi

try pdo-shell --logfile $PDO_HOME/logs/client.log --loglevel info  \
    --eservice-name e1 e2 e3  -s ${SRCDIR}/contracts/exchange/scripts/create.psh -m color red

for p in $(seq 1 3); do
    pdo-shell --logfile $PDO_HOME/logs/client.log --loglevel info \
    --eservice-name e${p} -s ${SRCDIR}/contracts/exchange/scripts/issue.psh -m color red -m issuee user$p -m count $(($p * 10))
done

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
