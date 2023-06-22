#!/usr/bin/env python

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

import argparse
import http
import os
import sys
import toml

from ccf.clients import Identity
from ccf.clients import CCFClient

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

# -----------------------------------------------------------------
def register_enclave_attestation_policy(client, options):
    try :
        params = {}
        params['check_attestation'] = options.check_attestation
        if options.check_attestation:
            params['mrenclave'] = options.mrenclave
            params['basename'] = options.basename
            params['ias_public_key'] = options.ias_public_key
        else:
            params['mrenclave'] = ""
            params['basename'] = ""
            params['ias_public_key'] = ""

        r = client.post("/app/set_contract_enclave_attestatation_verification_policy", params)
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to register enclave expected measurements: {}, code: {}'.format(
                r.body, r.status_code))
            sys.exit(-1)
    except Exception as e:
        LOG.error('failed to register enclave expected measurements: {}'.format(str(e)))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    default_output = os.path.join(CCF_Keys, 'ledger_authority.pem')

    parser = argparse.ArgumentParser(description='Fetch the ledger authority key from a CCF server')

    parser.add_argument(
        '--logfile',
        help='Name of the log file, __screen__ for standard output',
        default='__screen__',
        type=str)
    parser.add_argument(
        '--loglevel',
        help='Logging level',
        default='WARNING',
        type=str)


    parser.add_argument('--interface', help='Host interface where CCF is listening', required=True)
    parser.add_argument('--member-name', help="Name of the user being added", default = "memberccf", type=str)
    parser.add_argument('--port', help='Port where CCF is listening', type=int, default=6600)

    parser.add_argument('--check-attestation', default=False, help="enable attestation verification", action='store_true')
    parser.add_argument('--mrenclave', help="Expected MRENCLAVE of pdo enclaves", type=str)
    parser.add_argument('--basename', help="PDO enclave basename", type=str)
    parser.add_argument('--ias-public-key', help="IAS public key derived from cert used to verify report signatures", type=str)

    options = parser.parse_args()

    if options.check_attestation:
        if (not options.mrenclave) or (not options.basename) or (not options.ias_public_key):
            parser.print_help()
            sys.exit(-1)

    # -----------------------------------------------------------------
    LOG.remove()
    if options.logfile == '__screen__' :
        LOG.add(sys.stderr, level=options.loglevel)
    else :
        LOG.add(options.logfile)

    # -----------------------------------------------------------------
    network_cert = os.path.join(CCF_Keys, "networkcert.pem")
    if not os.path.exists(network_cert) :
        LOG.error('network certificate ({}) does not exist'.format(network_cert))
        sys.exit(-1)

    member_cert = os.path.join(CCF_Keys, "{}_cert.pem".format(options.member_name))
    if not os.path.exists(member_cert) :
        LOG.error('member certificate ({}) does not exist'.format(member_cert))
        sys.exit(-1)

    member_key = os.path.join(CCF_Keys, "{}_privk.pem".format(options.member_name))
    if not os.path.exists(member_key) :
        LOG.error('member key ({}) does not exist'.format(member_key))
        sys.exit(-1)

    try:
        member_client = CCFClient(
            options.interface,
            options.port,
            network_cert,
            session_auth=Identity(member_key, member_cert, "member"),
            signing_auth=Identity(member_key, member_cert, "member"),
        )
    except Exception as e:
        LOG.error('failed to connect to CCF service : {}'.format(str(e)))
        sys.exit(-1)

    register_enclave_attestation_policy(member_client, options)

    LOG.info('successfully registered enclave expected measurements')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
