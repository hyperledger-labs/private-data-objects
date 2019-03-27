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
pgrep eservice
if [ $? == 0 ] ; then
    die existing enclave services detected, please shutdown
fi

pgrep pservice
if [ $? == 0 ] ; then
    die existing provisioning services detected, please shutdown
fi

SAVE_FILE=$(mktemp /tmp/pdo-test.XXXXXXXXX)
ESERVICE_DB=${PDO_HOME}/data/eservice-db.json

declare -i NUM_SERVICES=5 # must be at least 3 for pconntract update test to work
function cleanup {
    read -p "Enter any key to shutdown services."
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/es-stop.sh --count ${NUM_SERVICES} > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh --count ${NUM_SERVICES} > /dev/null
    rm -f ${SAVE_FILE}
    rm -r ${ESERVICE_DB}
}

trap cleanup EXIT


# -----------------------------------------------------------------
yell start enclave and provisioning services
# -----------------------------------------------------------------
try ${PDO_HOME}/bin/ss-start.sh --count ${NUM_SERVICES} > /dev/null
try ${PDO_HOME}/bin/ps-start.sh --count ${NUM_SERVICES} --ledger ${PDO_LEDGER_URL} --clean > /dev/null
try ${PDO_HOME}/bin/es-start.sh --count ${NUM_SERVICES} --ledger ${PDO_LEDGER_URL} --clean > /dev/null

cd ${SRCDIR}/build 

#-----------------------------------------
yell test the eservice database 
#------------------------------------------
say run module level tests for database manager
cd ${SRCDIR}/python/pdo/test
try python servicedb.py --logfile $PDO_HOME/logs/client.log --loglevel info \
    --eservice-db $PDO_HOME/data/db-test.json --url http://localhost:7101 http://localhost:7102 http://localhost:7103
try rm $PDO_HOME/data/db-test.json

cd ${SRCDIR}/build

say create the eservice database using database CLI 
try pdo-create-eservicedb --logfile $PDO_HOME/logs/client.log --loglevel info \
    --eservice-db ${ESERVICE_DB} --eservice-url http://localhost:7101 --eservice-name e1
# add more entires
for v in $(seq 2 ${NUM_SERVICES}) ; do
    try pdo-add-to-eservicedb --logfile $PDO_HOME/logs/client.log --loglevel info \
        --eservice-db ${ESERVICE_DB} --eservice-url http://localhost:710${v} --eservice-name e${v}
done

say run various pdo scripts - test-request, test-contract, create, update, shell - using database


try pdo-test-request --no-ledger   \
    --eservice-name e1 --logfile $PDO_HOME/logs/client.log --loglevel info --eservice-db ${ESERVICE_DB}

try pdo-test-contract --no-ledger --contract integer-key \
    --eservice-name e2 --logfile $PDO_HOME/logs/client.log --loglevel info --eservice-db ${ESERVICE_DB}

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
    --contract mock-contract --source _mock-contract.scm --eservice-name e1 e2 e3 --eservice-db ${ESERVICE_DB}

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
                       --identity user1 --save-file ${SAVE_FILE} --eservice-db ${ESERVICE_DB} \
                       "'(inc-value)")
    if [ $value != $v ]; then
        die "contract has the wrong value ($value instead of $v) for enclave $e"
    fi
done

KEYGEN=${SRCDIR}/build/__tools__/make-keys
if [ ! -f ${PDO_HOME}/keys/red_type_private.pem ]; then
    for color in red green blue ; do
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_type --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_vetting --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_issuer --format pem
    done
fi
# -----------------------------------------------------------------
# -----------------------------------------------------------------
try pdo-shell --logfile $PDO_HOME/logs/client.log --loglevel info --ledger $PDO_LEDGER_URL \
    --eservice-name e1 e2 e3 e4 e5 --eservice-db ${ESERVICE_DB} -s ${SRCDIR}/contracts/exchange/scripts/create.psh -m color red 

for p in $(seq 1 5); do
    pdo-shell --logfile $PDO_HOME/logs/client.log --loglevel info --ledger $PDO_LEDGER_URL \
    --eservice-name e${p} --eservice-db ${ESERVICE_DB} -s ${SRCDIR}/contracts/exchange/scripts/issue.psh -m color red -m issuee user$p -m count $(($p * 10))
done

yell completed all tests
exit 0
