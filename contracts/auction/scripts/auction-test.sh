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
SRCDIR="$(realpath ${SCRIPTDIR}/../../..)"

source ${SRCDIR}/bin/lib/common.sh

KEYGEN=${SRCDIR}/build/__tools__/make-keys

# -----------------------------------------------------------------
# -----------------------------------------------------------------
function require-key() {
    KEYFILE=${PDO_HOME}/keys/$1
    if [ ! -f ${KEYFILE}_private.pem ]; then
        echo create key ${KEYFILE}
        ${KEYGEN} --keyfile ${KEYFILE} --format pem
    fi
}

yell ensure that required keys exist
for i in $(seq 1 20) ; do
    require-key user${i}
done

require-key ledger
require-key auction

# -----------------------------------------------------------------
# -----------------------------------------------------------------
: "${PDO_LEDGER_URL?Missing environment variable PDO_LEDGER_URL}"

if [ ! -f ${PDO_HOME}/data/eservice-db.json ]; then
    scripts/create_eservice_db.psh
fi

try scripts/create_ledger.psh -m user ledger
try scripts/create.psh -m user auction -m key auction -m val 100

# nothing particularly magical about this, want to test values
# that are not ordered, make sure that MAXVALUE is the largest
VALUES=(122 133 155 144 166 181 12 113 133 135 199 146 150 161 172 183 14 115 126 17 119)
MAXVALUE=13
VALUES[${MAXVALUE}]=200

for i in $(seq 1 20); do
    try scripts/create.psh -m user user${i} -m key key${i} -m val ${VALUES[$i]}
done

try scripts/create_auction.psh -m user auction -m key auction

for i in $(seq 1 20); do
    try scripts/bid.psh -m user user${i} -m key key${i}
done

yell ledger state before close
try scripts/get.psh -m user auction -m key auction
try scripts/get.psh -m user user${MAXVALUE} -m key key${MAXVALUE}

try scripts/close.psh -m user auction

yell ledger state after close
try scripts/get.psh -m user user${MAXVALUE} -m key auction
try scripts/get.psh -m user auction -m key key${MAXVALUE}

yell final ledger state
try scripts/dump.psh -m user ledger
