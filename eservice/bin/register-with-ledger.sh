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
    exit 101
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"
DSTDIR=${PDO_INSTALL_ROOT}
ETCDIR=${DSTDIR}/opt/pdo/etc/

ESERVICE_IDENTITY=eservice1
ESERVICE_TOML=${ESERVICE_IDENTITY}.toml
ENCLAVE_TOML=enclave.toml

PDO_IAS_SIGNING_CERT_PATH=${PDO_SGX_KEY_ROOT}/ias_signing.cert
PDO_IAS_KEY_PEM=${PDO_SGX_KEY_ROOT}/sgx_ias_key.pem

eservice_enclave_info_file=$(mktemp /tmp/pdo-test.XXXXXXXXX)

source ${SRCDIR}/bin/lib/common.sh

function cleanup {
    yell "Clean up temporary files"
    rm -f ${eservice_enclave_info_file}
}

trap cleanup EXIT

#Set SPID to parameter if passed
SPID=$PDO_SPID
if (( "$#" == 1 )) ; then
    SPID=$1
fi

#Set ATTESTATION_TYPE to parameter if passed
ATTESTATION_TYPE=$PDO_ATTESTATION_TYPE
if (( "$#" == 2 )) ; then
    ATTESTATION_TYPE=$2
fi

function DeriveIasPublicKey {
    try test -e ${PDO_IAS_SIGNING_CERT_PATH}
    try openssl x509 -pubkey -noout -in ${PDO_IAS_SIGNING_CERT_PATH} > ${PDO_IAS_KEY_PEM}
}

# Store MR_ENCLAVE & MR_BASENAME to eservice_enclave_info_file
# Note: an alternative way without any enclave invocations would be the following.
#
#    if [ -z "${SPID}" -o ${#SPID} != 32 ]; then
#	echo "No valid (length 32) SPID pass as argument or PDO_SPID environment variable"
#	exit 1
#    fi
#    perl -0777 -ne 'if (/metadata->enclave_css.body.enclave_hash.m:([a-fx0-9 \n]+)/) { $eh = $1; $eh=~s/0x| |\n//g; $eh=~tr/a-z/A-Z/; $bn="'${SPID}'"; $bn .= "0" x (64 - length $bn); print "MRENCLAVE:${eh}\nBASENAME:${bn}\n"; }' ./build/lib/libpdo-enclave.signed.so.meta > $eservice_enclave_info_file
#    # Note: group id is always zero, hence the zero-padding ...
#
# This would also allow removing in eservice/pservice the code related to CreateErsatzEnclaveReport and GetEnclave Characteristics
# However, getting basename via enclave invocation & quote is somewhat cleaner than below ..
function Store {
    : "${SPID:?Need PDO_SPID environment variable set or passed in for valid MR_BASENAME}"
    : "${ATTESTATION_TYPE:?Need PDO_ATTESTATION_TYPE environment variable set or passed in}"
    try test -e ${ETCDIR}/${ESERVICE_TOML}
    try test -e ${ETCDIR}/${ENCLAVE_TOML}
    yell Download IAS certificates and Compute the enclave information
    try eservice-enclave-info \
        --spid ${SPID} \
        --attestation-type ${ATTESTATION_TYPE} \
        --save ${eservice_enclave_info_file} \
        --loglevel warn \
        --logfile __screen__ \
        --identity ${ESERVICE_IDENTITY} \
        --config ${ESERVICE_TOML} ${ENCLAVE_TOML} \
        --config-dir ${ETCDIR}
}

# Registers MR_ENCLAVE & BASENAMES with Ledger
function Register {
    if [ ! -f $eservice_enclave_info_file ]; then
        yell Registration failed! eservice_enclave_info_file not found!
    else
        VAR_MRENCLAVE=$(grep -o 'MRENCLAVE:.*' ${eservice_enclave_info_file} | cut -f2- -d:)
        VAR_BASENAME=$(grep -o 'BASENAME:.*' ${eservice_enclave_info_file} | cut -f2- -d:)

        : "${PDO_LEDGER_URL:?Registration failed! PDO_LEDGER_URL environment variable not set}"
        : "PDO_IAS_KEY_PEM" "${PDO_IAS_KEY_PEM:?Registration failed! PDO_IAS_KEY_PEM environment variable not set}"

        # FIXME: Replace when CCF TP has been updated for HW mode.
        yell WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
        yell ""
        yell Skipping registration to the ledger ${PDO_LEDGER_URL} of
        yell "MRENCLAVE=${VAR_MRENCLAVE}"
        yell "BASENAME=${VAR_BASENAME}"
        yell "PDO_IAS_KEY_PEM=${PDO_IAS_KEY_PEM}"
        yell ""
        yell WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
    fi
}

if [ "$SGX_MODE" = "HW" ]; then
    if [ "$ATTESTATION_TYPE" = "epid-linkable" ]; then
        Store
        DeriveIasPublicKey
        Register
    else
        yell Registration failed! attestation type not set to epid-linkable
    fi
else
    yell Registration failed! SGX_MODE not set to HW
fi
