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

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../../..)"

source ${SRCDIR}/bin/lib/common.sh

KEYGEN=${SRCDIR}/build/__tools__/make-keys
if [ ! -f ${PDO_HOME}/keys/red_type_private.pem ]; then
    yell create keys for the contracts
    for color in red green blue ; do
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_type --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_vetting --format pem
        ${KEYGEN} --keyfile ${PDO_HOME}/keys/${color}_issuer --format pem
    done
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
: "${PDO_LEDGER_URL?Missing environment variable PDO_LEDGER_URL}"

if [ ! -f ${PDO_HOME}/data/eservice-db.json ]; then
    scripts/create_eservice_db.psh
fi

yell create the green issuer contracts
try scripts/create_type.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color green
try scripts/create_vetting.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color green
try scripts/create_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color green
try scripts/approve_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color green
try scripts/initialize_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color green

yell create the red issuer contracts
try scripts/create_type.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color red
try scripts/create_vetting.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color red
try scripts/create_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color red
try scripts/approve_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color red
try scripts/initialize_issuer.psh --loglevel warn --ledger $PDO_LEDGER_URL -m color red

yell issue green marbles
for p in $(seq 1 5); do
    scripts/issue.psh --loglevel warn --ledger $PDO_LEDGER_URL \
                      -m color green -m issuee user$p -m count $(($p * 10))
done

yell issue red marbles
for p in $(seq 6 10); do
    scripts/issue.psh --loglevel warn --ledger $PDO_LEDGER_URL \
                      -m color red -m issuee user$p -m count $(($p * 10))
done
