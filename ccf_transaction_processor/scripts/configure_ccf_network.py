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
import toml
import time

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Bin = os.path.join(ContractHome, "ccf", "bin")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")
CCF_Keys = os.path.join(ContractHome, "ccf", "keys")

sys.path.insert(1, CCF_Bin)
from infra.clients import CCFClient
import infra.node

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def open_network_script(client, options, config) :

    # activate the member (new from ccf release 0.11)
    try:
        r = client.rpc("ack/update_state_digest")
        state_digest = bytearray(r.result["state_digest"])
        r = client.rpc("ack", params={"state_digest": list(state_digest)}, signed=True)
        if r.error is not None:
            LOG.error('failed to activate the member {}'.format(r.error))
            sys.exit(-1)
    except :
        LOG.error('failed to activate the member')
        sys.exit(-1)

    script = """
    tables = ...
    return Calls:call("open_network")
    """

    rpc_params = dict()
    rpc_params['parameter'] = {}
    rpc_params['script'] = {"text": script}
    rpc_params['ballot'] = {"text": "return true"}

    try :
        r = client.rpc("propose", rpc_params, signed=True)
    except :
        LOG.error('failed to open network')
        sys.exit(-1)

    if r.status != http.HTTPStatus.OK.value:
        LOG.info(r)
        LOG.error('failed to open network: {}'.format(r.status))
        sys.exit(-1)

    LOG.info('successfully created proposal to open network with proposal id {}'.format(r.result["proposal_id"]))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_node_script(client, options, config) :

    node_id = options.node_id

    # create the rpc to propose the new node as a trusted node
    script = """
    tables, node_id = ...
    return Calls:call("trust_node", node_id)
    """

    rpc_params = dict()
    rpc_params['parameter'] = node_id
    rpc_params['script'] = {"text": script}
    rpc_params['ballot'] = {"text": ("return true")}

    try :
        r = client.rpc("propose", rpc_params, signed=True)
    except :
        LOG.error('ccf add_node invocation failed')
        sys.exit(-1)

    if r.status != http.HTTPStatus.OK.value:
        LOG.error('failed to propose new node: {}'.format(r.status))
        sys.exit(-1)

    LOG.info('successfully created proposal to add user node proposal id {}'.format(r.result["proposal_id"]))


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_user_script(client, options, config) :

    user_cert_file = os.path.join(CCF_Keys, "{}_cert.pem".format(options.user_name))

    try :
        with open(user_cert_file) as fp :
            user_cert_unicode = [ord(c) for c in fp.read()]
    except :
        LOG.error('failed to read user certificate file {0}'.format(user_cert_file))
        sys.exit(-1)

    script = """
    tables, user_cert = ...
    return Calls:call("new_user", user_cert)
    """

    rpc_params = dict()
    rpc_params['parameter'] = user_cert_unicode
    rpc_params['script'] = {"text": script}
    rpc_params['ballot'] = {"text": "return true"}

    try :
        r = client.rpc("propose", rpc_params, signed=True)
    except :
        LOG.error('ccf add_user invocation failed')
        sys.exit(-1)

    if r.status != http.HTTPStatus.OK.value:
        LOG.error('failed to add user: {}'.format(r.status))
        sys.exit(-1)

    LOG.info('successfully created proposal to add user with proposal id {}'.format(r.result["proposal_id"]))


# -----------------------------------------------------------------
def Main() :
    parser = argparse.ArgumentParser(description='Script to enable the CCF network')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', default='WARNING', type=str)
    parser.add_argument('--ccf-config-path', help='Path to locate the ccf config file', default = CCF_Etc, type=str)
    parser.add_argument('--ccf-config', help='Name of the CCF configuration file', required=True, type=str)
    parser.add_argument('--member-name', help="Name of the member adding the user", default = "memberccf", type=str)
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
    try :
        config = toml.load(os.path.join(options.ccf_config_path, options.ccf_config))
    except :
        LOG.error('unable to load ccf configuration file {0}'.format(options.ccf_config))
        pass

    member_cert = os.path.join(CCF_Keys, "{}_cert.pem".format(options.member_name))
    member_key = os.path.join(CCF_Keys, "{}_privk.pem".format(options.member_name))
    network_cert = config["start"]["network-cert-file"]
    (host, port) = config["rpc-address"].split(':')

    try :
        member_client = CCFClient(
            host=host,
            port=port,
            cert=member_cert,
            key=member_key,
            ca = network_cert,
            format='json',
            prefix='gov',
            description="none",
            version="2.0",
            connection_timeout=3,
            request_timeout=3)
    except :
        LOG.error('failed to connect to CCF service')
        sys.exit(-1)

    if options.add_node:
        add_node_script(member_client, options, config)
    else:
        open_network_script(member_client, options, config)
        add_user_script(member_client, options, config)

    LOG.info('CCF network ready for use')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
