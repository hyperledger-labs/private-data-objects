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
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh

function warn () {
    recho "WARNING: $*"
    F_VERIFIED=-1
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

    if [[ ! "${PDO_ATTESTATION_TYPE}" = "epid-linkable" ]] && [[ ! "${PDO_ATTESTATION_TYPE}" = "dcap" ]]; then
        die "PDO_ATTESTATION_TYPE=${PDO_ATTESTATION_TYPE} not defined epid-linkable or dcap in HW mode"
    fi
fi

if [ "${SGX_MODE}" = "SIM" ]; then
    if [[ ! "${PDO_ATTESTATION_TYPE}" = "simulated" ]]; then
        die "PDO_ATTESTATION_TYPE=${PDO_ATTESTATION_TYPE} not defined simulated in SIM mode"
    fi
fi


exit $F_VERIFIED
