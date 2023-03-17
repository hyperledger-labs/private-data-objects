#!/bin/bash

export PDO_HOSTNAME=localhost
export PDO_LEDGER_URL=http://localhost:6600

source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure client for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
# the sleep here just gives CCF a chance to get started
sleep 20

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
yell create client configuration files
# -----------------------------------------------------------------
make -C ${PDO_SOURCE_ROOT}/build config-client

# for now the site.psh is just a way to notify
# that the services are running; in the future
# the client should be able to incorporate this
# file and begin to use the information
while [ ! -f ${XFER_DIR}/site.psh ]; do
    say "waiting for site configuration"
    if [ -f ${XFER_DIR}/status ]; then
        exit $(cat ${XFER_DIR}/status)
    fi
    sleep 5
done

# -----------------------------------------------------------------
yell run the service test suite
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate
${PDO_SOURCE_ROOT}/build/tests/service-test.sh

# -----------------------------------------------------------------
# write the result status to the output file
# -----------------------------------------------------------------
STATUS=$?
echo $STATUS > ${XFER_DIR}/status
exit $STATUS
