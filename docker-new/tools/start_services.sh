#!/bin/bash

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_LOGLEVEL=
F_MODE=build
F_REGISTER=no
F_CLEAN="--clean"
F_INTERFACE=
F_LEDGER_URL=

F_USAGE='-i|--interface [hostname] -1|--ledger [url] --loglevel [debug|info|warn] -m|--mode [build|copy|skip] -r|--register'
SHORT_OPTS='i:l:m:r'
LONG_OPTS='interface:,ledger:,loglevel:,mode:,register'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) F_INTERFACE="$2" ; shift 2 ;;
        -l|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="--loglevel $2" ; shift 2 ;;
        -m|--mode) F_MODE="$2" ; shift 2 ;;
        -r|--register) F_REGISTER='yes' ; shift 1 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# Set up the interface, ledger url and proxy configuration
# -----------------------------------------------------------------
export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
if [ ! -z "${F_INTERFACE}" ] ; then
    export PDO_HOSTNAME=${F_INTERFACE}
fi

export PDO_LEDGER_ADDRESS=$(dig +short ${PDO_HOSTNAME})
export PDO_LEDGER_URL=${PDO_LEDGER_URL:-http://${PDO_LEDGER_ADDRESS}:6600}
if [ ! -z "${F_LEDGER_URL}" ] ; then
    export PDO_LEDGER_URL=${F_LEDGER_URL}
fi

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

# -----------------------------------------------------------------
# Handle the configuration of the services
# -----------------------------------------------------------------
if [ "${F_MODE,,}" == "build" ]; then
    yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
    make -C ${PDO_SOURCE_ROOT}/build config
    make -C ${PDO_SOURCE_ROOT}/build keys
elif [ "${F_MODE,,}" == "copy" ]; then
    yell copy the configuration from xfer/services/etc and xfer/services/keys
    mkdir -p ${PDO_HOME}/etc ${PDO_HOME}/keys
    cp ${XFER_DIR}/services/etc/* ${PDO_HOME}/etc/
    cp ${XFER_DIR}/services/keys/* ${PDO_HOME}/keys/
elif [ "${F_MODE,,}" == "skip" ]; then
    yell restart with existing configuration
    F_CLEAN=""
else
    die "invalid restart mode; ${F_MODE}"
fi

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
yell register the enclave if necessary
# -----------------------------------------------------------------
if [ "${F_REGISTER,,}" == 'yes' ]; then
    make -C ${PDO_SOURCE_ROOT}/build register
fi

# -----------------------------------------------------------------
yell start the services
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate

try ${PDO_HOME}/bin/ss-start.sh --output ${PDO_HOME}/logs ${F_LOG_LEVEL} ${CLEAN}
try ${PDO_HOME}/bin/ps-start.sh --output ${PDO_HOME}/logs ${F_LOG_LEVEL} ${CLEAN}
try ${PDO_HOME}/bin/es-start.sh --output ${PDO_HOME}/logs ${F_LOG_LEVEL} ${CLEAN}

# save the site.psh file if the configuration files were generated here
if [ "${F_MODE,,}" == "build" ]; then
    cp ${PDO_HOME}/etc/site.psh ${XFER_DIR}
    chmod a+rw ${XFER_DIR}/site.psh
fi

# -----------------------------------------------------------------
yell all services started
# -----------------------------------------------------------------
sleep infinity
