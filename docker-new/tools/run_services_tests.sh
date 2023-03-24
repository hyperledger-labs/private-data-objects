#!/bin/bash

export PDO_HOSTNAME=localhost
export PDO_LEDGER_URL=http://localhost:6600

source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
# -----------------------------------------------------------------
# the sleep here just gives CCF a chance to get started
sleep 20

make -C ${PDO_SOURCE_ROOT}/build force-config
make -C ${PDO_SOURCE_ROOT}/build keys

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
mkdir -p ${PDO_LEDGER_KEY_ROOT}
while [ ! -f ${XFER_DIR}/ccf/keys/networkcert.pem ]; do
    say "waiting for ledger keys"
    sleep 5
done
cp ${XFER_DIR}/ccf/keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/

# -----------------------------------------------------------------
yell check for registration
# -----------------------------------------------------------------
# this probably requires additional CCF keys, need to test this
if [ "$SGX_MODE" == "HW" ]; then
    make -C ${PDO_SOURCE_ROOT}/build register
fi

# -----------------------------------------------------------------
yell run the unit test suite
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate

${PDO_SOURCE_ROOT}/build/tests/unit-test.sh
STATUS=$?
if [ $STATUS != 0 ] ; then
    echo $STATUS > ${XFER_DIR}/status
    exit $STATUS
fi

# -----------------------------------------------------------------
yell start the services
# -----------------------------------------------------------------
${PDO_HOME}/bin/ss-start.sh --output ${PDO_HOME}/logs --clean
STATUS=$?
if [ $STATUS != 0 ] ; then
    echo $STATUS > ${XFER_DIR}/status
    exit $STATUS
fi

${PDO_HOME}/bin/ps-start.sh --output ${PDO_HOME}/logs --clean
STATUS=$?
if [ $STATUS != 0 ] ; then
    echo $STATUS > ${XFER_DIR}/status
    exit $STATUS
fi

${PDO_HOME}/bin/es-start.sh --output ${PDO_HOME}/logs --clean
STATUS=$?
if [ $STATUS != 0 ] ; then
    echo $STATUS > ${XFER_DIR}/status
    exit $STATUS
fi

function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh > /dev/null
    ${PDO_HOME}/bin/es-stop.sh > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh > /dev/null
}

trap cleanup EXIT

cp ${PDO_HOME}/etc/site.psh ${XFER_DIR}

# -----------------------------------------------------------------
yell wait for client completion
# -----------------------------------------------------------------
while [ ! -f ${XFER_DIR}/status ]; do
    say "waiting for client completion"
    sleep 5
done

exit $(cat ${XFER_DIR}/status)
