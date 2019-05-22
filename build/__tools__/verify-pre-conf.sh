#!/bin/bash

# Copyright 2019 Intel Corporation
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

# This script performs several tests on the environment to ensure
# that it is set up correctly. It should be run prior to building

F_VERIFIED=0

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

function warn () {
    recho "WARNING: $*"
    F_VERIFIED=-1
}

function try() {
    "$@" || warn "$*"
}

# -----------------------------------------------------------------
# CHECK ENVIRONMENT
# -----------------------------------------------------------------

yell --------------- CONFIG AND ENVIRONMENT PRE-CONF CHECK ---------------

# the SPID should be a 32 byte hex string
if [[ ! "${PDO_SPID}" =~ ^[A-Fa-f0-9]{32}$ ]]; then
    warn "PDO_SPID is not defined correctly, should be a a 32-byte hex key"
fi

if [ "${SGX_MODE}" = "HW" ]; then
    # the SPID_API_KEY should be a 32 byte hex string
    if [[ ! "${PDO_SPID_API_KEY}" =~ ^[A-Fa-f0-9]{32}$ ]]; then
	warn "PDO_SPID_API_KEY is not defined correctly, should be a a 32-byte hex key"
    fi
fi

exit $F_VERIFIED
