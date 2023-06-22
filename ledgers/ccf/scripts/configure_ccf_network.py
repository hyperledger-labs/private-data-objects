#!/usr/bin/env python

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

"""
Return the number of registered endpoints in the exit status
"""

import argparse
import http
import os
import sys

from ccf.proposal_generator import transition_service_to_open
from ccf.clients import Identity
from ccf.clients import CCFClient

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def open_network_script(client) :

    # activate the member first
    try:
        r = client.post("/gov/ack/update_state_digest")
        if r.status_code != http.HTTPStatus.OK.value :
            LOG.error('failed to update state digest; {}'.format(r.status_code))
            sys.exit(-1)

        r = client.post("/gov/ack", {"state_digest": r.body.json()["state_digest"]})
        if r.status_code != http.HTTPStatus.OK.value and r.status_code != http.HTTPStatus.NO_CONTENT.value:
            LOG.error('failed to activate the member: {}, code: {}'.format(r.body, r.status_code))
            sys.exit(-1)

    except Exception as e:
        LOG.error('failed to activate the member: {}', e)
        sys.exit(-1)

    LOG.info('CCF member activated')

    try:
        proposal, vote = transition_service_to_open()
        r = client.post("/gov/proposals", proposal)

        LOG.info(f'proposal {r}')
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to open network: {}, code: {}'.format(r.body, r.status_code))
            sys.exit(-1)

        LOG.info('successfully created proposal to open network with proposal id {}'.format(
            r.body.json()["proposal_id"]))

    except Exception as e:
        LOG.error('failed to open network: {}', e)
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    default_config = os.path.join(CCF_Etc, 'cchost.toml')
    parser = argparse.ArgumentParser(description='Script to enable the CCF network')

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

    # these options are forward looking when we support multiple node ccf networks
    parser.add_argument('--user-name', help="Name of the user being added", default = "userccf", type=str)
    parser.add_argument('--add-node', help="Add a new node to existing CCF network", action="store_true")
    parser.add_argument('--node-id', help="id of the node to be added to the ccf network", type=int)

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

    open_network_script(member_client)

    LOG.info('CCF network ready for use')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
