#!/bin/bash

export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
export PDO_LEDGER_URL=${PDO_LEDGER_URL:-http://${PDO_HOSTNAME}:6600}

source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
make -C ${PDO_SOURCE_ROOT}/build config
make -C ${PDO_SOURCE_ROOT}/build keys

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
mkdir -p ${PDO_LEDGER_KEY_ROOT}
while [ ! -f ${XFER_DIR}/ccf_keys/networkcert.pem ]; do
    say "waiting for ledger keys"
    sleep 5
done
cp ${XFER_DIR}/ccf_keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/

# -----------------------------------------------------------------
yell register the enclave
# -----------------------------------------------------------------
if [ "$SGX_MODE" == "HW" ]; then
    make -C ${PDO_SOURCE_ROOT}/build register
fi

# -----------------------------------------------------------------
yell start the services
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate

try ${PDO_HOME}/bin/ss-start.sh --output ${PDO_HOME}/logs --clean
try ${PDO_HOME}/bin/ps-start.sh --output ${PDO_HOME}/logs --clean
try ${PDO_HOME}/bin/es-start.sh --output ${PDO_HOME}/logs --clean

# -----------------------------------------------------------------
yell all services started
# -----------------------------------------------------------------
sleep infinity
