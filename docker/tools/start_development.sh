#!/bin/bash

export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
export PDO_LEDGER_URL=${PDO_LEDGER_URL:-http://${PDO_HOSTNAME}:6600}

# when we are developing CCF we won't have the sgx environment
if [ -f /opt/intel/sgxsdk/environment ]; then
    source /opt/intel/sgxsdk/environment
else
    echo SGXSDK not installed, skipping initialization
fi

source /project/pdo/tools/environment.sh
source ${PDO_SOURCE_ROOT}/bin/lib/common.sh

check_pdo_runtime_env

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
mkdir -p ${PDO_LEDGER_KEY_ROOT}
cp ${XFER_DIR}/ccf/keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/
