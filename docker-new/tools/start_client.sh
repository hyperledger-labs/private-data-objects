#!/bin/bash

export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
export PDO_LEDGER_URL=${PDO_LEDGER_URL:-http://${PDO_HOSTNAME}:6600}

source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export no_proxy=10.54.66.43,$PDO_HOSTNAME,$no_proxy
export NO_PROXY=10.54.66.43,$POD_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
mkdir -p ${PDO_LEDGER_KEY_ROOT}
cp ${XFER_DIR}/ccf/keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/

# -----------------------------------------------------------------
yell create client configuration files
# -----------------------------------------------------------------
make -C ${PDO_SOURCE_ROOT}/build config-client

# -----------------------------------------------------------------
yell run the service test
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate
${PDO_SOURCE_ROOT}/build/tests/service-test.sh
