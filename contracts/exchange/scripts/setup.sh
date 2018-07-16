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

function yell() {
    becho "$(basename $0): $*" >&2
}

function die() {
    recho "$(basename $0): $*" >&2
    exit 111
}

function try() {
    "$@" || die "test failed: $*"
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
: "${LEDGER_URL?Missing environment variable LEDGER_URL}"

pdo-shell --ledger $LEDGER_URL -s scripts/create.psh -m color red
pdo-shell --ledger $LEDGER_URL -s scripts/create.psh -m color green

for p in $(seq 1 5); do
    pdo-shell --ledger $LEDGER_URL -s scripts/issue.psh -m color green -m issuee user$p -m count $(($p * 10))
done

for p in $(seq 6 10); do
    pdo-shell --ledger $LEDGER_URL -s scripts/issue.psh -m color red -m issuee user$p -m count $(($p * 10))
done
