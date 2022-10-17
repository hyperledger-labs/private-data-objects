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
PDO_SOURCE_ROOT="$(realpath ${SCRIPTDIR}/..)"

typeset -a env_key_sort
typeset -A env_val env_desc
typeset -i i

# Note: this is function so we can delay until optional -r is evaluated ...
var_set() {

	i=0

	env_val[WASM_SRC]="${WASM_SRC:-${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime}"
	env_desc[WASM_SRC]="
		WASM_SRC points to the installation of the wasm micro runtime
		source in order to build the wasm interpreter
	"
	env_key_sort[$i]="WASM_SRC"; i=$i+1; export WASM_SRC=${env_val[WASM_SRC]};

	env_val[WASM_MEM_CONFIG]="${WASM_MEM_CONFIG:-MEDIUM}"
	env_desc[WASM_MEM_CONFIG]="
		WASM_MEM_CONFIG indicates the memory configuration for the
		WASM runtime: the runtime's global memory pool size,
		and a module's operand stack and heap size.
		When the variable is set to 'SMALL', the runtime's memory pool
		size is set to 1MB. If the variable is set to 'MEDIUM', the
		runtime's memory pool size is set to 2MB.
		When the variable is set to 'LARGE', the runtime's
		memory pool size is set to 4MB. See
		common/interpreter/wawaka_wasm/README.md for further details.
	"
	env_key_sort[$i]="WASM_MEM_CONFIG"; i=$i+1; export WASM_MEM_CONFIG=${env_val[WASM_MEM_CONFIG]};

	env_val[PDO_INTERPRETER]="${PDO_INTERPRETER:-gipsy}"
	env_desc[PDO_INTERPRETER]="
		PDO_INTERPRETER contains the name of the interpreter to use
                for processing contracts. 'gipsy' is the default and is the Scheme-based,
                functional language. 'wawaka' is an experimental interpreter that executes
                WASM-based contracts. 'wawaka-opt' is a version of wawaka with optimizations
                enabled. 'wawaka-aot' is a WASM runtime that
                executes ahead-of-time compiled WASM contracts.
	"
	env_key_sort[$i]="PDO_INTERPRETER"; i=$i+1; export PDO_INTERPRETER=${env_val[PDO_INTERPRETER]};

	env_val[SGX_MODE]="${SGX_MODE:-SIM}"
	env_desc[SGX_MODE]="
		SGX_MODE determines the SGX mode of operation. When the variable is
		set to 'SIM', then the SGX enclaves will be compiled for simulator
		mode. When the variable is set to 'HW', the enclaves will be compiled
		to run in a real SGX enclave.
	"
	env_key_sort[$i]="SGX_MODE"; i=$i+1; export SGX_MODE=${env_val[SGX_MODE]}

	env_val[PDO_LEDGER_URL]="${PDO_LEDGER_URL:-http://127.0.0.1:6600}"
	env_desc[PDO_LEDGER_URL]="
		PDO_LEDGER_URL is the URL is to submit transactions to the ledger.
	"
	env_key_sort[$i]="PDO_LEDGER_URL"; i=$i+1; export PDO_LEDGER_URL=${env_val[PDO_LEDGER_URL]}

	env_val[PDO_LEDGER_TYPE]="${PDO_LEDGER_TYPE:-ccf}"
	env_desc[PDO_LEDGER_TYPE]="
		PDO_LEDGER_TYPE is the ledger used by PDO. Available options: ccf
	"
	env_key_sort[$i]="PDO_LEDGER_TYPE"; i=$i+1; export PDO_LEDGER_TYPE=${env_val[PDO_LEDGER_TYPE]}

	if [ ${PDO_LEDGER_TYPE} == "ccf" ];
	then
		env_val[PDO_DEFAULT_SIGCURVE]="${PDO_DEFAULT_SIGCURVE:-SECP384R1}"
		env_desc[PDO_DEFAULT_SIGCURVE]="
			PDO_DEFAULT_SIGCURVE is the ECDSA curve used by PDO for generating signatures.
			Choose SECP384R1 for ccf. If not set, the crypto library uses SECP256K1 by default."
		env_key_sort[$i]="PDO_DEFAULT_SIGCURVE"; i=$i+1; export PDO_DEFAULT_SIGCURVE=${env_val[PDO_DEFAULT_SIGCURVE]}
	fi

	env_val[PDO_INSTALL_ROOT]="${PDO_INSTALL_ROOT:-${SCRIPTDIR}/_dev}"
	env_desc[PDO_INSTALL_ROOT]="
		PDO_INSTALL_ROOT is the root of the directory in which the virtual
		enviroment will be built; this is equivalent to the old DSTDIR,
		generally PDO_HOME will point to PDO_INSTALL_ROOT/opt/pdo
	"
	env_key_sort[$i]="PDO_INSTALL_ROOT"; i=$i+1; export PDO_INSTALL_ROOT=${env_val[PDO_INSTALL_ROOT]}

	env_val[PDO_HOME]="${PDO_HOME:-${PDO_INSTALL_ROOT}/opt/pdo}"
	env_desc[PDO_HOME]="
		PDO_HOME is the directory where PDO-specific files
		are stored include configuration files, data files, compiled
		contracts, contract user keys and service scripts.
	"
	env_key_sort[$i]="PDO_HOME"; i=$i+1; export PDO_HOME=${env_val[PDO_HOME]}

	env_val[PDO_HOSTNAME]="${PDO_HOSTNAME:-${HOSTNAME}}"
	env_desc[PDO_HOSTNAME]="
		PDO_HOSTNAME identifies the hostname where service interfaces
                will be exported. Defaults to HOSTNAME.
	"
	env_key_sort[$i]="PDO_HOSTNAME"; i=$i+1; export PDO_HOSTNAME=${env_val[PDO_HOSTNAME]}

    env_val[PDO_SGX_KEY_ROOT]="${PDO_SGX_KEY_ROOT:-${SCRIPTDIR}/keys/sgx_mode_${SGX_MODE,,}}"
	env_desc[PDO_SGX_KEY_ROOT]="
		PDO_SGX_KEY_ROOT is the root directory where SGX & IAS related keys are stored.
		The default points to a directory which contains values which are good
		enough for SGX simulator mode.  However, for SGX HW mode you
		should provide your own version, at least for PDO_SPID and PDO_SPID_API_KEY
	"
	env_key_sort[$i]="PDO_SGX_KEY_ROOT"; i=$i+1; export PDO_SGX_KEY_ROOT=${env_val[PDO_SGX_KEY_ROOT]}

	env_val[PDO_ENCLAVE_CODE_SIGN_PEM]="${PDO_ENCLAVE_CODE_SIGN_PEM:-${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem}"
	env_desc[PDO_ENCLAVE_CODE_SIGN_PEM]="
		PDO_ENCLAVE_CODE_SIGN_PEM contains the name of the file containing the key
		used to sign the enclave. This key must be white-listed with IAS to work for
                production-mode/default launch-control.  For non-production use, in simulator or HW mode,
                the key can generated by the command:
		    openssl genrsa -3 -out ${PDO_ENCLAVE_CODE_SIGN_PEM} 3072.
                The default path points to a key which is generated during built on-demand.
	"
	env_key_sort[$i]="PDO_ENCLAVE_CODE_SIGN_PEM"; i=$i+1; export PDO_ENCLAVE_CODE_SIGN_PEM=${env_val[PDO_ENCLAVE_CODE_SIGN_PEM]}

	env_val[PDO_SPID]="${PDO_SPID:-$(cat ${PDO_SGX_KEY_ROOT}/sgx_spid.txt)}"
	env_desc[PDO_SPID]="
		PDO_SPID is the ID that accompanies the certificate registered
		with the Intel Attestation Service. This should be a 32 character
		hex string.
	"
	env_key_sort[$i]="PDO_SPID"; i=$i+1; export PDO_SPID=${env_val[PDO_SPID]}

	env_val[PDO_SPID_API_KEY]="${PDO_SPID_API_KEY:-$(cat ${PDO_SGX_KEY_ROOT}/sgx_spid_api_key.txt)}"
	env_desc[PDO_SPID_API_KEY]="
		PDO_SPID_API_KEY is API-key associated with the SPID.
	"
	env_key_sort[$i]="PDO_SPID_API_KEY"; i=$i+1; export PDO_SPID_API_KEY=${env_val[PDO_SPID_API_KEY]}

	env_val[PDO_LEDGER_KEY_ROOT]="${PDO_LEDGER_KEY_ROOT:-${PDO_INSTALL_ROOT}/opt/pdo/etc/keys/ledger}"
	env_desc[PDO_LEDGER_KEY_ROOT]="
		PDO_LEDGER_KEY_ROOT is the root directory where the system keys are stored
		for ledger integration; files in this directory are not automatically generated. When ccf is used
		as ledger, the ccf network cert {networkcert.pem} must be
		placed under this folder. These keys get generated during ccf deployment.
	"
	env_key_sort[$i]="PDO_LEDGER_KEY_ROOT"; i=$i+1; export PDO_LEDGER_KEY_ROOT=${env_val[PDO_LEDGER_KEY_ROOT]}
	}

do_export() {
	for i in "${!env_key_sort[@]}"
	do
		ki="${env_key_sort[$i]}"
		export "$ki=${env_val[$ki]}"
	done
}

print_export() {
	for i in "${!env_key_sort[@]}"
	do
		ki="${env_key_sort[$i]}"
		echo "export $ki=${env_val[$ki]}"
	done
}

help() {
    echo 'common-config.sh -[--reset-keys|-r] [--evalable-export|-e] [--help|-h|-?]

This script can be used to set the environment variables that are used
in the build, installation & execution process. While the build should
progress with only the default values specified, commonly five variables
are set and then this file is evaluated. These five variables are:
WASM_SRC, PDO_LEDGER_URL, PDO_INSTALL_ROOT, and
PDO_LEDGER_KEY_ROOT. In case you run in SGX HW mode you usally will define
PDO_SGX_KEY_ROOT. See further down information on these variables and
others you could override from defaults.

The default usage of this script is to be sourced. For example,
local configuration file may be constructed as:

   export PDO_LEDGER_KEY_ROOT=${HOME}/keys/ledger
   export PDO_INSTALL_ROOT=${HOME}/pdo-test-env
   export PDO_LEDGER_URL=http://127.0.0.1:6600
   export PDO_LEDGER_TYPE=ccf
   export WASM_SRC=${HOME}/wasm

and before buidling it you call script as

   source ${SCRIPTDIR}/common-config.sh

If passed the parameter --evalable-export it will
return a list of export commands of the variables
instead of directly exporting them to the environment.
Passing parameter --reset-keys will unset keying variables
PDO_ENCLAVE_CODE_SIGN_PEM,
PDO_SPID and PDO_SPID_API_KEY before setting variables.

The list of variables set (in order they are defined, their defaults
and semantics is as follows:

'

	for i in "${!env_key_sort[@]}"
	do
		ki="${env_key_sort[$i]}"
		echo "$ki (default: ${env_val[$ki]}): ${env_desc[$ki]}"
	done
}

is_sourced=1

while [[ $# > 0 ]]
do
    opt=$1
    case $opt in
        --reset-keys|-r)
	    # -----------------------------------------------------------------
	    # if you change either PDO_SGX_KEY_ROOT or PDO_LEDGER_KEY_ROOT variable
            # and re-source this file you should unset all of the variables that
            # depend on those variables
	    # -----------------------------------------------------------------
	    unset PDO_ENCLAVE_CODE_SIGN_PEM
	    unset PDO_SPID
	    unset PDO_SPID_API_KEY
            ;;
        --evalable-export|-e)
	    is_sourced=0
	    ;;
        --help|-h|-\?)
	    var_set
	    help
	    exit 0
	    ;;
	*)
            echo "ERROR: unknown option $opt. Run with option -h to get valid options"
	    exit 1
    esac
    shift # past argument or value
done

var_set
if [ $is_sourced == 1 ]; then
    do_export
else
    print_export
fi
