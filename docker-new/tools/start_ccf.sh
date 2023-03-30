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
# This script starts the ccf service. It will be run by default when
# the pdo_ccf container starts. The necessary configuration files and
# service keys will be constructed by default or they can be copied
# in from the xfer directory.
#
# Note that support for joining an existing CCF network is not yet
# supported by this script but will be in the future.
# -----------------------------------------------------------------

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_MODE=build
F_INTERFACE=
F_NETWORK_MODE=start

F_USAGE='-i|--interface [hostname] --join -m|--mode [build|copy|skip] --start'
SHORT_OPTS='i:m:'
LONG_OPTS='interface:,join,mode:,start'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) F_INTERFACE="$2" ; shift 2 ;;
        --join) F_NETWORK_MODE=join ; shift 1 ;;
        -m|--mode) F_MODE="$2" ; shift 2 ;;
        --start) F_NETWORK_MODE=start ; shift 1 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# Set up the ledger url and proxy configuration
# -----------------------------------------------------------------
export PDO_HOSTNAME=${PDO_HOSTNAME:-${HOSTNAME}}
if [ ! -z "${F_INTERFACE}" ] ; then
    export PDO_HOSTNAME=$F_INTERFACE
fi

export PDO_LEDGER_ADDRESS=$(dig +short ${PDO_HOSTNAME})
export PDO_LEDGER_URL="http://${PDO_LEDGER_ADDRESS}:6600"

export no_proxy=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$no_proxy
export NO_PROXY=$PDO_HOSTNAME,$PDO_LEDGER_ADDRESS,$NO_PROXY

source /project/pdo/tools/environment.sh
source ${PDO_HOME}/ccf/bin/lib/pdo_common.sh

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
if [ ${F_NETWORK_MODE} == "start" ] ; then
    try ${PDO_HOME}/ccf/bin/start_ccf_network.sh
elif [ ${F_NETWORK_MODE} == "join" ] ; then
    die "joining a network is not yet supported"
else
    die "unknown network mode"
fi

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
