#!/bin/bash

# note that we are ignoring the incoming PDO_LEDGER_URL. the
# endpoint built by this container defines what the URL should
# be so just specify it as is
export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
export PDO_LEDGER_URL=http://${PDO_HOSTNAME}:6600

source /project/pdo/tools/environment.sh
source ${PDO_HOME}/ccf/bin/lib/pdo_common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$POD_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
try make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor config

# -----------------------------------------------------------------
say start and configure the ccf network
# -----------------------------------------------------------------
. ${PDO_HOME}/ccf/bin/activate
try ${PDO_HOME}/ccf/bin/start_ccf_network.sh

# -----------------------------------------------------------------
say copy the network keys
# -----------------------------------------------------------------
# For the moment, we are assuming that enclave registration will
# happen in a separate container. We are copying all of the CCF
# keys into the transfer directory to make them available for the
# registration. However, only the network certificate should be made
# available for typical client and service operation.
cp ${PDO_LEDGER_KEY_ROOT}/* ${XFER_DIR}/ccf_keys
chmod a+rw ${XFER_DIR}/ccf_keys/*

# -----------------------------------------------------------------
say ccf service ready
# -----------------------------------------------------------------
sleep infinity
