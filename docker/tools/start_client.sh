#!/bin/bash
# Copyright 2023 Intel Corporation
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

# -----------------------------------------------------------------
# This script sets up an interactive client environment. It would
# generally be sourced when the container is first entered. It will
# build the necessary configuration files or copy them from the xfer
# directory. Parameters can be used to override the default ledger
# and interface variables.
# -----------------------------------------------------------------

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_LOGLEVEL=
F_MODE=build
F_INTERFACE=
F_LEDGER_URL=

F_USAGE='-i|--interface [hostname] -1|--ledger [url] --loglevel [debug|info|warn] -m|--mode [build|copy|skip]'
SHORT_OPTS='i:l:m:'
LONG_OPTS='interface:,ledger:,loglevel:,mode:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) F_INTERFACE="$2" ; shift 2 ;;
        -l|--ledger) F_LEDGER_URL="$2" ; shift 2 ;;
        --loglevel) F_LOGLEVEL="--loglevel $2" ; shift 2 ;;
        -m|--mode) F_MODE="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# Set up the interface, ledger url and proxy configuration
# -----------------------------------------------------------------
source /project/pdo/tools/environment.sh
source ${PDO_HOME}/bin/lib/common.sh

export PDO_HOSTNAME=${PDO_HOSTNAME:-$HOSTNAME}
if [ ! -z "${F_INTERFACE}" ] ; then
    export PDO_HOSTNAME=${F_INTERFACE}
fi

export PDO_LEDGER_ADDRESS=$(force_to_ip ${PDO_HOSTNAME})
export PDO_LEDGER_URL=${PDO_LEDGER_URL:-http://${PDO_LEDGER_ADDRESS}:6600}
if [ ! -z "${F_LEDGER_URL}" ] ; then
    export PDO_LEDGER_URL=${F_LEDGER_URL}
fi

export no_proxy=$PDO_HOSTNAME,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$NO_PROXY

# -----------------------------------------------------------------
# Handle the configuration of the services
# -----------------------------------------------------------------
if [ "${F_MODE,,}" == "build" ]; then
    yell configure services for host $PDO_HOSTNAME and ledger $PDO_LEDGER_URL
    try ${PDO_INSTALL_ROOT}/bin/pdo-configure-users -t ${PDO_SOURCE_ROOT}/build/template -o ${PDO_HOME} \
        --key-count 10 --key-base user --host ${PDO_HOSTNAME}
elif [ "${F_MODE,,}" == "copy" ]; then
    yell copy the configuration from xfer/client/etc and xfer/client/keys
    mkdir -p ${PDO_HOME}/etc ${PDO_HOME}/keys
    cp ${XFER_DIR}/client/etc/* ${PDO_HOME}/etc/
    cp ${XFER_DIR}/client/keys/* ${PDO_HOME}/keys/
elif [ "${F_MODE,,}" == "skip" ]; then
    yell restart with existing configuration
else
    die "invalid restart mode; ${F_MODE}"
fi

# -----------------------------------------------------------------
yell copy ledger keys
# -----------------------------------------------------------------
mkdir -p ${PDO_LEDGER_KEY_ROOT}
if [ ! -f ${XFER_DIR}/ccf/keys/networkcert.pem ]; then
    die "unlable to locate ledger keys in in the host directory ${XFER_DIR}/ccf/keys/networkcert.pem"
fi

cp ${XFER_DIR}/ccf/keys/networkcert.pem ${PDO_LEDGER_KEY_ROOT}/

# -----------------------------------------------------------------
yell activate the PDO environment
# -----------------------------------------------------------------
. ${PDO_INSTALL_ROOT}/bin/activate
