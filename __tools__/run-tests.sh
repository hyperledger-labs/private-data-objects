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

: ${LEDGER_URL:=http://127.0.0.1:8008}

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/..)"

yell() {
    echo "$0: $*" >&2;
}

die() {
    yell "$*"
    exit 111
}

try() {
    "$@" || die "test failed: $*"
}

function cleanup {
    yell "shutdown services"
    ${VIRTUAL_ENV}/opt/pdo/bin/ps-stop.sh --count 3 > /dev/null
    ${VIRTUAL_ENV}/opt/pdo/bin/es-stop.sh --count 3 > /dev/null
}

trap cleanup EXIT

# start the provisioning and enclave services
yell start enclave and provisioning services
try ${VIRTUAL_ENV}/opt/pdo/bin/ps-start.sh --count 3 --ledger ${LEDGER_URL} > /dev/null
try ${VIRTUAL_ENV}/opt/pdo/bin/es-start.sh --count 1 --ledger ${LEDGER_URL} --clean > /dev/null

cd ${SRCDIR}/eservice/tests
yell start secrets test
try python test-secrets.py \
     --logfile __screen__ --loglevel warn

yell start simple request test
try python test-request.py --no-ledger --iterations 100 \
     --logfile __screen__ --loglevel warn

yell start simple integer-key contract test
try python test-contract.py --no-ledger --contract integer-key \
     --logfile __screen__ --loglevel warn

yell start simple mock-contract contract test
try python test-contract.py --no-ledger --contract mock-contract \
     --logfile __screen__ --loglevel warn

yell start request test with provisioning and enclave services
try python test-request.py --ledger ${LEDGER_URL} \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice http://localhost:7101/ \
     --logfile __screen__ --loglevel warn

yell start contract test with provisioning and enclave services
try python test-contract.py --ledger ${LEDGER_URL} --contract integer-key \
    --pservice http://localhost:7001/ http://localhost:7002 http://localhost:7003 \
    --eservice http://localhost:7101/ \
     --logfile __screen__ --loglevel warn

yell start mock contract test with ledger, this should fail dependency check
python test-contract.py --ledger ${LEDGER_URL} --contract mock-contract \
       --logfile __screen__ --loglevel warn
if [ $? == 0 ]; then
    die mock contract test succeeded though it should have failed
fi

yell completed all tests
exit 0
