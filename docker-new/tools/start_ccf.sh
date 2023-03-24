#!/bin/bash

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )

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
# Process command line arguments
# -----------------------------------------------------------------
F_MODE=build

F_USAGE='-i|--interface [hostname] -1|--ledger [url] -m|--mode [build|copy|skip]'
SHORT_OPTS='i:l:m:'
LONG_OPTS='interface:,ledger:,mode:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) PDO_HOSTNAME="$2" ; shift 2 ;;
        -l|--ledger) PDO_LEDGER_URL="$2" ; shift 2 ;;
        -m|--mode) F_MODE="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# Handle the configuration of the services
#
# Note the environment should have been created during the build
# process for the ccf image
# -----------------------------------------------------------------
if [ "${F_MODE,,}" == "build" ]; then
    yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
    try make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor keys
    try make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor config
elif [ "${F_MODE,,}" == "copy" ]; then
    yell copy the configuration from xfer/ccf/etc and xfer/ccf/keys
    cp ${XFER_DIR}/ccf/etc/* ${PDO_HOME}/ccf/etc/
    cp ${XFER_DIR}/ccf/keys/* ${PDO_LEDGER_KEY_ROOT}/
elif [ "${F_MODE,,}" == "skip" ]; then
    yell restart with existing configuration
else
    die "invalid restart mode; ${F_MODE}"
fi

# -----------------------------------------------------------------
say start the ccf network
# -----------------------------------------------------------------
. ${PDO_HOME}/ccf/bin/activate
try ${PDO_HOME}/ccf/bin/start_ccf_network.sh

# -----------------------------------------------------------------
# -----------------------------------------------------------------
if [ "${F_MODE}" == "build" ]; then
    yell copy the network keys
    cp ${PDO_LEDGER_KEY_ROOT}/* ${XFER_DIR}/ccf/keys
    chmod a+rw ${XFER_DIR}/ccf/keys/*
fi

# -----------------------------------------------------------------
yell ccf service ready
# -----------------------------------------------------------------
sleep infinity
