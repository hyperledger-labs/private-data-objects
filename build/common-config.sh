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
# This file can be used to set the environment variables that are
# used in the build and installation process. While the build should
# progress with only the default values specified, commonly four
# variables are set and then this file is evaluated. These four
# variables are: TINY_SCHEME_SRC, PDO_LEDGER_URL, PDO_INSTALL_ROOT,
# and PDO_KEY_ROOT. For example, local configuration file may be
# constructed as:
#
# export PDO_KEY_ROOT=${HOME}/keys
# export PDO_INSTALL_ROOT=${HOME}/pdo-test-env
# export PDO_LEDGER_URL=http://127.0.0.1:8008
# export TINY_SCHEME_SRC=${HOME}/tinyscheme-1.41
#
# source ${HOME}/pdo-source-git/__tools__/common-config.sh
# -----------------------------------------------------------------

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
PDO_SOURCE_ROOT="$(realpath ${SCRIPTDIR}/..)"

# -----------------------------------------------------------------
# if you change the PDO_KEY_ROOT variable and re-source this file
# you should unset all of the variables that depend on PDO_KEY_ROOT
# -----------------------------------------------------------------
if [ "$1" = "--reset-keys" ]; then
    unset PDO_ENCLAVE_PEM
    unset PDO_IAS_KEY
    unset PDO_LEDGER_KEY
    unset PDO_SPID
    unset PDO_SPID_CERT_FILE
fi

# -----------------------------------------------------------------
# TINY_SCHEME_SRC points to the installation of the tinyscheme
# source in order to build the library used to debug and test
# contracts outside of the contract enclave
# -----------------------------------------------------------------
export TINY_SCHEME_SRC="${TINY_SCHEME_SRC:-/}"

# -----------------------------------------------------------------
# SGX_MODE determines the SGX mode of operation. When the variable is
# set to "SIM", then the SGX enclaves will be compiled for simulator
# mode. When the variable is set to "HW", the enclaves will be compiled
# to run in a real SGX enclave.
# -----------------------------------------------------------------
export SGX_MODE="${SGX_MODE:-SIM}"

# -----------------------------------------------------------------
# SGX_DEBUG determines whether additional debugging functions
# will be compiled into the enclaves. Since SGX_DEBUG potentially
# exposes information about what is happening inside a contract, do
# not use with confidential contracts.
# -----------------------------------------------------------------
export SGX_DEBUG="${SGX_DEBUG:-1}"

# -----------------------------------------------------------------
# PDO_PDO_LEDGER_URL is the URL is to submit transactions to the
# Sawtooth ledger.
# -----------------------------------------------------------------
export PDO_LEDGER_URL="${PDO_LEDGER_URL:-http://127.0.0.1:8008}"

# -----------------------------------------------------------------
# PDO_INSTALL_ROOT is the root of the directory in which the virtual
# enviroment will be built; this is equivalent to the old DSTDIR,
# generally PDO_HOME will point to PDO_INSTALL_ROOT/opt/pdo
# -----------------------------------------------------------------
export PDO_INSTALL_ROOT="${PDO_INSTALL_ROOT:-${PDO_SOURCE_ROOT}/__tools__/build/_dev}"

# -----------------------------------------------------------------
# PDO_HOME is the directory where PDO-specific files
# are stored include configuration files, data files, compiled
# contracts, contract user keys and service scripts.
# -----------------------------------------------------------------
export PDO_HOME="${PDO_HOME:-${PDO_INSTALL_ROOT}/opt/pdo}"

# -----------------------------------------------------------------
# PDO_KEY_ROOT is the root directory where the system keys are stored
# for SGX, IAS, and Sawtooth integration; files in this directory
# are not automatically generated.
# -----------------------------------------------------------------
export PDO_KEY_ROOT="${PDO_KEY_ROOT:-${PDO_INSTALL_ROOT}/opt/pdo/etc/keys}"

# -----------------------------------------------------------------
# PDO_ENCLAVE_PEM contains the name of the file containing the key
# used to sign the enclave. The key is generated by the command:
# openssl genrsa -3 -out ${PDO_ENCLAVE_PEM} 3072
# -----------------------------------------------------------------
export PDO_ENCLAVE_PEM="${PDO_ENCLAVE_PEM:-${PDO_KEY_ROOT}/pdo_enclave.pem}"

# -----------------------------------------------------------------
# The path of the PEM file containing the public key used to verify
# quotes from the Intel Attestation Service.
# <<HOW TO GET>>
# -----------------------------------------------------------------
export PDO_IAS_KEY="${PDO_IAS_KEY:-${PDO_KEY_ROOT}/pdo_ias_key.pem}"

# -----------------------------------------------------------------
# PDO_LEDGER_KEY is used to update settings in the Sawtooth validator.
# This is the key used by the Sawtooth ledger and is generally
# found in the file .sawtooth/keys/sawtooth.priv in the
# Sawtooth installation directory hiearchy.
# -----------------------------------------------------------------
export PDO_LEDGER_KEY="${PDO_LEDGER_KEY:-${PDO_KEY_ROOT}/pdo_validator.priv}"

# -----------------------------------------------------------------
# PDO_SPID is the ID that accompanies the certificate registered
# with the Intel Attestation Service. This should be a 32 character
# hex string.
# -----------------------------------------------------------------
export PDO_SPID="${PDO_SPID:-$(cat ${PDO_KEY_ROOT}/sgx_spid.txt)}"

# -----------------------------------------------------------------
# PDO_SPID_CERT_FILE is the name of the file that contains the
# PEM-encoded certificate that was submitted to Intel in order to
# obtain the SPID
# -----------------------------------------------------------------
export PDO_SPID_CERT_FILE="${PDO_SPID_CERT_FILE:-${PDO_KEY_ROOT}/sgx_spid_cert.pem}"
