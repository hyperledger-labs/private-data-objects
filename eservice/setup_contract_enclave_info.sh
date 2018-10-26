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
template_file="../pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp.template"
actual_file="../pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp"

# Store MR_ENCLAVE & MR_BASENAME to eservice_enclave_info_file
Store(){
    echo "Store eservice_enclave_info_file to "$eservice_enclave_info_file
    python ./pdo/eservice/scripts/EServiceEnclaveInfoCLI.py --save $eservice_enclave_info_file
    ret=$?
    if [[ $ret -ne 0 ]]; then
        echo "Failed to run eservice to retrieve enclave information - is the virtual environment active?"
        exit $ret
    fi
}

# Load MR_ENCLAVE to be built into PService
Load(){
    echo "Load MR_ENCLAVE into PLACEMARK at "$actual_file
    if [ ! -f $eservice_enclave_info_file ]; then
        echo "Load failed! eservice_enclave_info_file not found!"
    else
        cmd=`echo "sed 's/MR_ENCLAVE_PLACEMARK/\`cat $eservice_enclave_info_file | grep -o 'MRENCLAVE:.*' | cut -f2- -d:\`/' < $template_file > $actual_file"`
        eval $cmd
    fi
}

if [ "$SGX_MODE" = "HW" ]; then
    Store
    Load
else
    echo "This script is only necessary when SGX_MODE is set to HW"
fi
