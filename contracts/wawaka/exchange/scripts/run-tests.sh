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
SRCDIR="${PDO_SOURCE_ROOT:-$(realpath ${SCRIPTDIR}/../../../..)}"
EXCHANGE_ROOT="$(realpath ${SCRIPTDIR}/..)"

source ${SRCDIR}/bin/lib/common.sh

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    die activate python3 first
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
KEYGEN=${SRCDIR}/build/__tools__/make-keys
if [ ! -f ${PDO_HOME}/keys/red_type_private.pem ]; then
    yell create keys for the contracts
    for color in red green blue white; do
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_type --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_vetting --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_issuer --format pem
    done

    for color in green1 green2 green3; do
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_issuer --format pem
    done

fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
: "${PDO_LEDGER_URL?Missing environment variable PDO_LEDGER_URL}"

if [ ! -f ${PDO_HOME}/data/eservice-db.json ]; then
    ${SCRIPTDIR}/create_eservice_db.psh
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
cd "${EXCHANGE_ROOT}"

rm -f ./functional_test.log
try scripts/functional_test.psh --loglevel info --logfile ./functional_test.log --ledger ${PDO_LEDGER_URL}
