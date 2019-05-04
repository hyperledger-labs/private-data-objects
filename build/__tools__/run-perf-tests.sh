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
PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    die activate python3 first
fi

: "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_COUNT=5
F_ITERATIONS=1000
F_LEDGERURL=--no-ledger
F_LOGLEVEL=info
F_SERVICES=1
F_SERVICEURL=http://localhost:7101
F_USAGE='[-c|--count client] [-i|--iterations count] [--ledger url]'

TEMP=`getopt -o c:i:l: --long count:,iterations:,help,ledger:,loglevel: \
     -n 'run-perf-tests.sh' -- "$@"`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -c|--count) F_COUNT="$2" ; shift 2 ;;
        -i|--iterations) F_ITERATIONS="$2" ; shift 2 ;;
        --ledger) F_LEDGERURL="--ledger $2" ; shift 2 ;;
        -l|--loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        --help) echo $F_USAGE ; exit 1 ;;
	--) shift ; break ;;
	*) echo "Internal error!" ; exit 1 ;;
    esac
done

function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/es-stop.sh --count ${F_SERVICES} > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh --count ${F_SERVICES} > /dev/null
}

trap cleanup EXIT

# -----------------------------------------------------------------
yell start enclave and storage services
# -----------------------------------------------------------------
try ${PDO_HOME}/bin/ss-start.sh --count ${F_SERVICES} > /dev/null
try ${PDO_HOME}/bin/es-start.sh --count ${F_SERVICES} --loglevel info --output /tmp/logs ${F_LEDGER_URL} --clean > /dev/null

sleep 10

## -----------------------------------------------------------------
yell start tests
## -----------------------------------------------------------------
for c in $(seq 1 ${F_COUNT}) ; do
    say start request test ${c}

    F_LOGFILE="${PDO_HOME}/logs/test${c}.log"
    F_EFILE="${PDO_HOME}/logs/test${c}.err"
    F_OFILE="${PDO_HOME}/logs/test${c}.out"
    rm -f "${F_LOGFILE}" "${F_EFILE}" "${F_OFILE}"

    pdo-test-request ${F_LEDGERURL} --eservice ${F_SERVICEURL} --iterations ${F_ITERATIONS} \
                     --logfile "${F_LOGFILE}" --loglevel info 2> ${F_EFILE} > ${F_OFILE} &
done

## -----------------------------------------------------------------
yell wait for test processes to finish
## -----------------------------------------------------------------
for instance in $(seq 1 ${F_COUNT}) ; do
    wait
    say process finished with result $?
done
