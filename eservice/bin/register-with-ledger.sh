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
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"
DSTDIR=${PDO_INSTALL_ROOT}
ETCDIR=${DSTDIR}/opt/pdo/etc/

ESERVICE_IDENTITY=eservice1
ESERVICE_TOML=${ESERVICE_IDENTITY}.toml

SGX_KEY_ROOT=${PDO_SGX_KEY_ROOT:-${SRCDIR}/build/keys/sgx_mode_${SGX_MODE,,}}

IAS_SIGNING_CERT_PATH=${SGX_KEY_ROOT}/ias_signing.cert
IAS_KEY_PEM=${SGX_KEY_ROOT}/sgx_ias_key.pem

eservice_enclave_info_file=$(mktemp /tmp/pdo-test.XXXXXXXXX)

source ${SRCDIR}/bin/lib/common.sh
check_pdo_runtime_env
check_python_version

function cleanup {
    yell "Clean up temporary files"
    rm -f ${eservice_enclave_info_file}
}

trap cleanup EXIT

function DeriveIasPublicKey {
    yell Derive IAS public to be registered on the ledger
    try test -e ${IAS_SIGNING_CERT_PATH}
    try openssl x509 -pubkey -noout -in ${IAS_SIGNING_CERT_PATH} > ${IAS_KEY_PEM}
    yell IAS public derived in ${IAS_KEY_PEM}
}

function Store {
    try test -e ${ETCDIR}/${ESERVICE_TOML}
    yell Download IAS certificates and Compute the enclave information
    if [ "${PDO_FORCE_IAS_PROXY}" == "true" ]; then
        yell PDO_FORCE_IAS_PROXY is true
        NO_PROXY='' no_proxy='' try eservice-enclave-info \
            --save ${eservice_enclave_info_file} \
            --loglevel info \
            --logfile __screen__ \
            --identity ${ESERVICE_IDENTITY} \
            --config ${ESERVICE_TOML} \
            --config-dir ${ETCDIR}
    else
        try eservice-enclave-info \
            --save ${eservice_enclave_info_file} \
            --loglevel info \
            --logfile __screen__ \
            --identity ${ESERVICE_IDENTITY} \
            --config ${ESERVICE_TOML} \
            --config-dir ${ETCDIR}
    fi
    yell Enclave info are ready
}

# Registers MR_ENCLAVE & BASENAMES with Ledger
function Register {
    if [ ! -f $eservice_enclave_info_file ]; then
        yell Registration failed! eservice_enclave_info_file not found!
    else
        VAR_MRENCLAVE=$(grep -o 'MRENCLAVE:.*' ${eservice_enclave_info_file} | cut -f2- -d:)
        VAR_BASENAME=$(grep -o 'BASENAME:.*' ${eservice_enclave_info_file} | cut -f2- -d:)

        : "${PDO_LEDGER_URL:?Registration failed! PDO_LEDGER_URL environment variable not set}"
        : "IAS_KEY_PEM" "${IAS_KEY_PEM:?Registration failed! PDO_IAS_KEY_PEM environment variable not set}"

        if [ ${PDO_LEDGER_TYPE} == "ccf" ]; then
            yell Register enclave with CCF ledger: mrenclave=${VAR_MRENCLAVE} basename=${VAR_BASENAME}
            source ${PDO_INSTALL_ROOT}/bin/activate
            try ${PDO_INSTALL_ROOT}/bin/ccf_set_expected_sgx_measurements \
                --logfile __screen__ --loglevel INFO --mrenclave ${VAR_MRENCLAVE} \
                --basename  ${VAR_BASENAME} --ias-public-key "$(cat $IAS_KEY_PEM)"
        else
            die unsupported ledger ${PDO_LEDGER_TYPE}
        fi
    fi
}

if [ "$SGX_MODE" = "HW" ]; then
    Store
    DeriveIasPublicKey
    Register
else
    yell Registration failed! SGX_MODE not set to HW
fi
