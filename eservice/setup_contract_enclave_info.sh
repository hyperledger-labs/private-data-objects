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



contract_enclave_info_file=$CONTRACTHOME"/data/contract_enclave_info.tmp"
config_dir=`sed s:"build"/.*:"build": <<< "$CONTRACTHOME"`"/opt/pdo/etc/template"
template_file="../pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp.template"
actual_file="../pservice/lib/libpdo_enclave/contract_enclave_mrenclave.cpp"


Store(){
	echo "Store contract_enclave_info to "$contract_enclave_info_file
	python ./pdo/eservice/scripts/EServiceEnclaveInfoCLI.py --config-dir $config_dir --save $contract_enclave_info_file --logfile __screen__ --loglevel DEBUG
}

Load(){
	echo "Load MR_ENCLAVE into PLACEMARK at "$actual_file
	if [ ! -f $contract_enclave_info_file ]; then
	    echo "Load failed! contract_enclave_info_file not found!"
	else
		cmd=`echo "sed 's/MR_ENCLAVE_PLACEMARK/\`cat $contract_enclave_info_file | grep -o 'MRENCLAVE:.*' | cut -f2- -d:\`/' < $template_file > $actual_file"`
		eval $cmd
	fi
}

Register(){
	echo "Register with ledger"
	if [ ! -f $contract_enclave_info_file ]; then
	    echo "Register failed! contract_enclave_info_file not found!"
	else
		cmd=`echo "../sawtooth/bin/pdo-cli set-setting --keyfile $PDO_LEDGER_KEY --url $LEDGER_URL pdo.test.registry.measurements \`cat $contract_enclave_info_file | grep -o 'MRENCLAVE:.*' | cut -f2- -d:\`"`
		eval $cmd
		cmd=`echo "../sawtooth/bin/pdo-cli set-setting --keyfile $PDO_LEDGER_KEY --url $LEDGER_URL pdo.test.registry.basenames \`cat $contract_enclave_info_file | grep -o 'BASENAME:.*' | cut -f2- -d:\`"`
		eval $cmd
	fi
}

Cleanup(){
	rm $contract_enclave_info_file
	echo "$contract_enclave_info_file Removed"
}


if [ "$SGX_MODE" = "HW" ];
then
	Store
	Load
	Register
	Cleanup
fi

