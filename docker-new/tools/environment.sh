#!/bin/bash

# these variables may be configured to change the behavior of the image
export SGX_MODE=${SGX_MODE:-SIM}
export PDO_LEDGER_TYPE=${PDO_LEDGER_TYPE:-ccf}
export PDO_INTERPRETER=${PDO_INTERPRETER:-wawaka}
export WASM_MEM_CONFIG=${WASM_MEM_CONFIG:-MEDIUM}

# these variables are internal to the layout of the container and immutable
export PDO_SOURCE_ROOT=/project/pdo/src
export PDO_INSTALL_ROOT=/project/pdo/run
export PDO_HOME=${PDO_INSTALL_ROOT}/opt/pdo

export PDO_LEDGER_KEY_ROOT=${PDO_HOME}/keys/ledger
export PDO_LEDGER_KEY_SKF=${PDO_LEDGER_KEY_ROOT}/pdo_validator.priv
export WASM_SRC="${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime"

if [ ${PDO_LEDGER_TYPE,,} = "ccf" ]; then
    export PDO_DEFAULT_SIGCURVE=SECP384R1
else
    export PDO_DEFAULT_SIGCURVE=SECP256K1
fi

export PDO_SGX_KEY_ROOT=${PDO_SOURCE_ROOT}/build/keys/sgx_mode_${SGX_MODE,,}
export PDO_ENCLAVE_CODE_SIGN_PEM=${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem}
export PDO_SPID="$(cat ${PDO_SGX_KEY_ROOT}/sgx_spid.txt)"
export PDO_SPID_API_KEY="$(cat ${PDO_SGX_KEY_ROOT}/sgx_spid_api_key.txt)"

export CCF_BASE=/opt/ccf
export XFER_DIR=${XFER_DIR:-/project/pdo/xfer}
