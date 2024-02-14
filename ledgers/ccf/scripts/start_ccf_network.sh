#!/bin/bash

# Copyright 2018 Intel Corporation
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
# -----------------------------------------------------------------
source ${PDO_HOME}/bin/lib/common.sh

check_pdo_runtime_env
check_python_version

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_CCF_PDO_DIR=${CCF_PDO_DIR:-${PDO_INSTALL_ROOT}}
F_CCF_LEDGER_DIR=${CCF_LEDGER_DIR:-${PDO_HOME}/ccf}
F_INTERFACE=${PDO_HOSTNAME:-${HOSTNAME}}
F_PORT=6600

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )
USAGE='-i|--interface [hostname] -p|--port [port] --pdo-dir [path] --ledger-dir [path]'
SHORT_OPTS='i:p:'
LONG_OPTS='interface:,port:,pdo-dir:,ledger-dir:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) F_INTERFACE="$2" ; shift 2 ;;
        -p|--port) F_PORT="$2" ; shift 2 ;;
        --pdo-dir) F_CCF_PDO_DIR="$2" ; shift 2 ;;
        --ledger-dir) F_CCF_LEDGER_DIR="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# -----------------------------------------------------------------
# make sure that we have a completely prepared environment
# -----------------------------------------------------------------
if [ ! -f ${F_CCF_PDO_DIR}/bin/activate ]; then
    die incomplete configuration, unable to locate CCF_PDO_DIR virtual environment
fi

if [ ! -f ${F_CCF_LEDGER_DIR}/bin/activate ]; then
    die incomplete configuration, unable to locate CCF_LEDGER_DIR virtual environment
fi

# -----------------------------------------------------------------
# check to see if there is an instance already running
# -----------------------------------------------------------------
if [ -f ${PDO_LEDGER_DIR}/workspace/pdo_tp_0/node.pid ]; then
    if ps -p $(<"${PDO_LEDGER_DIR}/workspace/pdo_tp_0/node.pid")
    then
        yell cchost appears to be running already
        exit -1
    fi
fi

if lsof -Pi "@${F_INTERFACE}:${F_PORT}" -sTCP:LISTEN -t > /dev/null
then
    yell interface "local:${F_INTERFACE}:${F_PORT}" appears to be in use
    exit -1
fi

# -----------------------------------------------------------------
# clean up any old ledger keys
# -----------------------------------------------------------------
rm -f ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
rm -f ${PDO_LEDGER_KEY_ROOT}/ledger_authority_pub.pem

# ensure that we use an IP address for the interface
F_INTERFACE_ADDRESS=$(force_to_ip ${F_INTERFACE})
yell start ccf network with "local://${F_INTERFACE_ADDRESS}:${F_PORT}"

# -----------------------------------------------------------------
# run the CCF script to start the network. this script must operate
# in the python virtual environment created for it in ${F_CCF_LEDGER_DIR}
# note that simply executing python out of the ccf ledger virtual env
# is not sufficient since ccf code has expectations for the PATH which
# is only changed when you activate.
# -----------------------------------------------------------------
say attempt to start ccf node

source ${F_CCF_LEDGER_DIR}/bin/activate
CURL_CLIENT=ON INITIAL_MEMBER_COUNT=1 \
    ${F_CCF_LEDGER_DIR}/bin/python ${CCF_BASE}/bin/start_network.py \
        --binary-dir ${CCF_BASE}/bin \
        --enclave-type virtual \
        --enclave-platform virtual \
        --constitution ${CCF_BASE}/bin/actions.js \
        --constitution ${CCF_BASE}/bin/validate.js \
        --constitution ${CCF_BASE}/bin/resolve.js \
        --constitution ${CCF_BASE}/bin/apply.js \
        --ledger-chunk-bytes 5000000 \
        --snapshot-tx-interval 10000 \
        --initial-node-cert-validity-days 365 \
        --initial-service-cert-validity-days 365 \
        --label pdo_tp \
        --verbose \
        --host-log-level info \
        --workspace ${F_CCF_LEDGER_DIR}/workspace \
        -p ${F_CCF_LEDGER_DIR}/lib/libpdoenc \
        -n "local://${F_INTERFACE_ADDRESS}:${F_PORT}" &
deactivate

# the ledger keys are the indicator that the service has started successfully
while [ ! -f ${F_CCF_LEDGER_DIR}/workspace/pdo_tp_common/service_cert.pem ]; do
    say "wait for cchost to write the ledger keys"
    sleep 5
done

# -----------------------------------------------------------------
say ledger keys written, copy the keys to PDO_LEDGER_KEY_ROOT
# -----------------------------------------------------------------
cp ${F_CCF_LEDGER_DIR}/workspace/pdo_tp_common/service_cert.pem ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
cp ${F_CCF_LEDGER_DIR}/workspace/pdo_tp_common/member0_cert.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_cert.pem
cp ${F_CCF_LEDGER_DIR}/workspace/pdo_tp_common/member0_privk.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_privk.pem

# -----------------------------------------------------------------
# Generate authority needs to check to make sure that the ledger
# is open and delay briefly if it is not open; this operation and
# all of the following operations are ccf *client* operations and
# require the client python virtual environment that was created
# in ${F_CCF_PDO_DIR}
# -----------------------------------------------------------------
source ${F_CCF_PDO_DIR}/bin/activate

say generate the ledger authority
try ${F_CCF_PDO_DIR}/bin/generate_ledger_authority.py \
    --logfile __screen__ --loglevel WARNING \
    --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}

# Set the enclave attestation policy while operating under SGX SIM
# mode. When operating in the HW mode, the rpc gets invoked after the
# enclave is built.

if [ "${SGX_MODE}" == "SIM" ]; then
    say set check_attestation to false in SGX SIM mode
    try ${F_CCF_PDO_DIR}/bin/register_enclave_attestation_verification_policy.py \
        --logfile __screen__ --loglevel WARNING \
        --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}
fi

say save the ledger authority key
try ${F_CCF_PDO_DIR}/bin/fetch_ledger_authority.py \
    --logfile __screen__ --loglevel WARNING \
    --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}

deactivate

# -----------------------------------------------------------------
yell ledger URL is http://${F_INTERFACE_ADDRESS}:${F_PORT}
# -----------------------------------------------------------------
