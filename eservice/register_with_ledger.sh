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


eservice_enclave_info_file=$CONTRACTHOME"/data/EServiceEnclaveInfo.tmp"
SPID=$PDO_SPID

#Set SPID to parameter if passed
if (( "$#" == 1 ))
then
    SPID=$1
fi

# Store MR_ENCLAVE & MR_BASENAME to eservice_enclave_info_file
Store(){
    echo "PDO_SPID" "${SPID:?Need PDO_SPID environment variable set or passed in for valid MR_BASENAME}"
    echo "Store eservice_enclave_info_file to "$eservice_enclave_info_file
    python ./pdo/eservice/scripts/EServiceEnclaveInfoCLI.py --spid $SPID --save $eservice_enclave_info_file
    ret=$?
    if [[ $ret -ne 0 ]]; then
        echo "Failed to run eservice to retrieve enclave information - is the virtual environment active?"
        exit $ret
    fi
}

# Registers MR_ENCLAVE & BASENAMES with Ledger
Register(){
    echo "Register with ledger"
    if [ ! -f $eservice_enclave_info_file ]; then
        echo "Registration failed! eservice_enclave_info_file not found!"
    else
        echo "LEDGER_URL " "${LEDGER_URL:?Registration failed! LEDGER_URL environment variable not set}"
        echo "PDO_LEDGER_KEY" "${PDO_LEDGER_KEY:?Registration failed! PDO_LEDGER_KEY environment variable not set}"
        echo "PDO_IAS_KEY" "${PDO_IAS_KEY:?Registration failed! PDO_IAS_KEY environment variable not set}"

        eval "../sawtooth/bin/pdo-cli set-setting --keyfile $PDO_LEDGER_KEY --url $LEDGER_URL pdo.test.registry.measurements \`cat $eservice_enclave_info_file | grep -o 'MRENCLAVE:.*' | cut -f2- -d:\`"
        eval "../sawtooth/bin/pdo-cli set-setting --keyfile $PDO_LEDGER_KEY --url $LEDGER_URL pdo.test.registry.basenames \`cat $eservice_enclave_info_file | grep -o 'BASENAME:.*' | cut -f2- -d:\`"
        eval "../sawtooth/bin/pdo-cli set-setting --keyfile $PDO_LEDGER_KEY --url $LEDGER_URL pdo.test.registry.public_key \"$(cat $PDO_IAS_KEY)\""
    fi
}

if [ "$SGX_MODE" = "HW" ]; then
    Store
    Register
else
    echo "Registration failed! SGX_MODE not set to HW"
fi
