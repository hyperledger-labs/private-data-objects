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

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/..)"

function yell {
    echo "$0: $*" >&2;
}

function die {
    yell "$*"
    exit 111
}

function try {
    "$@" || die "operation failed: $*"
}

template_file="${SRCDIR}/pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp.template"
actual_file="${SRCDIR}/pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp"
eservice_enclave_info_file=$(mktemp /tmp/pdo-test.XXXXXXXXX)

function cleanup {
    yell "Clean up temporary files"
    rm -f ${eservice_enclave_info_file}
}

trap cleanup EXIT

# Store MR_ENCLAVE & MR_BASENAME to eservice_enclave_info_file
function Store {
    yell "Compute the enclave information"
    PYTHONPATH= try python ./pdo/eservice/scripts/EServiceEnclaveInfoCLI.py --save $eservice_enclave_info_file --loglevel warn
}

# Load MR_ENCLAVE to be built into PService
function Load {
    yell Load MR_ENCLAVE into PLACEMARK at $(basename ${actual_file})
    if [ ! -f ${eservice_enclave_info_file} ]; then
        yell Load failed! eservice_enclave_info_file not found!
    else
        cmd=`echo "sed 's/MR_ENCLAVE_PLACEMARK/\`cat $eservice_enclave_info_file | grep -o 'MRENCLAVE:.*' | cut -f2- -d:\`/' < $template_file > $actual_file"`
        try eval $cmd
    fi
}

if [ "$SGX_MODE" = "HW" ]; then
    Store
    Load
else
    yell This script is only necessary when SGX_MODE is set to HW
fi
