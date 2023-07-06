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
check_python_version

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
F_INTERFACE=${PDO_HOSTNAME:-${HOSTNAME}}
F_PORT=6600

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )
USAGE='-i|--interface [hostname] -p|--port [port]'
SHORT_OPTS='i:p:'
LONG_OPTS='interface:,port:'

TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${USAGE}" >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -i|--interface) F_INTERFACE="$2" ; shift 2 ;;
        -p|--port) F_PORT="$2" ; shift 2 ;;
        --help) echo "Usage: ${SCRIPT_NAME} ${USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# the CCF sandbox script creates the python virtual environment
# in the directory from which it is executed so we need to make
# sure we run it in the install directory... this is generally bad
# practice and we should probably move away from sandbox.
cd ${PDO_HOME}/ccf

if [ -f ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid ]; then
    if ps -p $(cat ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid) > /dev/null
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

rm -f ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
rm -f ${PDO_LEDGER_KEY_ROOT}/ledger_authority_pub.pem

# ensure that we use an IP address for the interface
F_INTERFACE_ADDRESS=$(force_to_ip ${F_INTERFACE})

yell start ccf network with "local://${F_INTERFACE_ADDRESS}:${F_PORT}"

say attempt to start ccf node
${CCF_BASE}/bin/sandbox.sh \
    --verbose \
    --host-log-level info \
    -p ${PDO_HOME}/ccf/lib/libpdoenc \
    -n "local://${F_INTERFACE_ADDRESS}:${F_PORT}" \
    -e virtual -t virtual \
    --workspace ${PDO_HOME}/ccf/workspace \
    --initial-node-cert-validity-days 365 \
    --initial-service-cert-validity-days 365 &

sleep 5

while [ ! -f ${PDO_HOME}/ccf/workspace/sandbox_common/service_cert.pem ]; do
    say "wait for cchost to write the ledger keys"
    sleep 5
done

say ledger keys written, copy the keys to PDO_LEDGER_KEY_ROOT
cp ${PDO_HOME}/ccf/workspace/sandbox_common/service_cert.pem ${PDO_LEDGER_KEY_ROOT}/networkcert.pem
cp ${PDO_HOME}/ccf/workspace/sandbox_common/member0_cert.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_cert.pem
cp ${PDO_HOME}/ccf/workspace/sandbox_common/member0_privk.pem ${PDO_LEDGER_KEY_ROOT}/memberccf_privk.pem

# Generate authority needs to check to make sure that the ledger
# is open and delay briefly if it is not open
say generate the ledger authority
try ${PDO_HOME}/ccf/bin/generate_ledger_authority.py \
    --logfile __screen__ --loglevel WARNING \
    --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}

# Set the enclave attestation policy while operating under SGX SIM
# mode. When operating in the HW mode, the rpc gets invoked after the
# enclave is built.

if [ "${SGX_MODE}" == "SIM" ]; then
    say set check_attestation to false in SGX SIM mode
    try ${PDO_HOME}/ccf/bin/register_enclave_attestation_verification_policy.py \
        --logfile __screen__ --loglevel WARNING \
        --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}

fi

say save the ledger authority key
try ${PDO_HOME}/ccf/bin/fetch_ledger_authority.py \
    --logfile __screen__ --loglevel WARNING \
    --interface ${F_INTERFACE_ADDRESS} --port ${F_PORT}

yell ledger URL is http://${F_INTERFACE_ADDRESS}:${F_PORT}
