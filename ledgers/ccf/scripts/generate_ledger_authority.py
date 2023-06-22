#!/usr/bin/env python

# Copyright 2020 Intel Corporation
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
import time

from ccf.clients import Identity
from ccf.clients import CCFClient

from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

# -----------------------------------------------------------------
def generate_ledger_authority(client):
    try :
        for attempt in range(0,10) :
            r = client.post("/app/generate_signing_key_for_read_payloads", dict())
            if r.status_code == http.HTTPStatus.OK.value :
                return
            if r.body.json()['error']['code'] == 'FrontendNotOpen' :
                LOG.warning('ledger not yet open')
                time.sleep(5)
            else :
                LOG.error("RESPONSE: {}".format(str(r)))
                LOG.error('failed to generate ledger authority the member: {}'.format(r.body))
                sys.exit(-1)

        LOG.error('Ledger unavailable')
        sys.exit(-1)

    except Exception as e:
        LOG.error('failed to generate ledger authority the member: {}'.format(str(e)))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
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

    parser.add_argument('-i', '--interface', help='Host interface where CCF is listening', required=True)
    parser.add_argument('-m', '--member-name', help="Name of the user being added", default = "memberccf", type=str)
    parser.add_argument('-p', '--port', help='Port where CCF is listening', type=int, default=6600)

    options = parser.parse_args()

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

    LOG.warning('generate ledger authority for {}:{}'.format(options.interface, options.port))
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

    generate_ledger_authority(member_client)

    LOG.info('successfully generated ledger authority')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
