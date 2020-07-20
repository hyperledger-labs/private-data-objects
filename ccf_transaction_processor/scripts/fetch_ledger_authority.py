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
import toml

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Bin = os.path.join(ContractHome, "ccf", "bin")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")
CCF_Keys = os.path.join(ContractHome, "ccf", "keys")

sys.path.insert(1, CCF_Bin)
from infra.clients import CCFClient

# -----------------------------------------------------------------
def fetch_ledger_authority(client, options, config):
    try :
        result = client.rpc("get_ledger_verifying_key", dict())

        if result.status != http.HTTPStatus.OK.value :
            LOG.error('failed to contact ledger: {0}'.format(result.status))
            sys.exit(-1)

        if result.result is None :
            LOG.error('failed to generate ledger authority: {0}, '.format(result.error['message']))
            sys.exit(-1)

    except :
        LOG.exception('invocation failed')
        sys.exit(-1)

    ledger_authority = result.result['verifying_key']
    if options.output_file == '__screen__' :
        LOG.info(ledger_authority)
    else :
        with open(options.output_file, "w") as of :
            of.write(ledger_authority)

# -----------------------------------------------------------------
def Main() :
    default_config = os.path.join(CCF_Etc, 'cchost.toml')
    default_output = os.path.join(CCF_Keys, 'ledger_authority_pub.pem')

    parser = argparse.ArgumentParser(description='Fetch the ledger authority key from a CCF server')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', default='__screen__', type=str)
    parser.add_argument('--loglevel', help='Logging level', default='WARNING', type=str)

    parser.add_argument('--ccf-config', help='Name of the CCF configuration file', default = default_config, type=str)
    parser.add_argument('--user-name', help="Name of the user being added", default = "user0", type=str)
    parser.add_argument("--output-file", help="Name of the file where the key will be saved", default = default_output, type=str)

    options = parser.parse_args()

    # -----------------------------------------------------------------
    LOG.remove()
    if options.logfile == '__screen__' :
        LOG.add(sys.stderr, level=options.loglevel)
    else :
        LOG.add(options.logfile)

    # -----------------------------------------------------------------
    try :
        config = toml.load(options.ccf_config)
    except :
        LOG.error('unable to load ccf configuration file {0}'.format(options.ccf_config))
        pass

    network_cert = config["start"]["network-cert-file"]
    (host, port) = config["rpc-address"].split(':')

    user_cert_file = os.path.join(CCF_Keys, "{}_cert.pem".format(options.user_name))
    user_key_file = os.path.join(CCF_Keys, "{}_privk.pem".format(options.user_name))

    try :
        user_client = CCFClient(
            host=host,
            port=port,
            cert=user_cert_file,
            key=user_key_file,
            ca = network_cert,
            format='json',
            prefix='users',
            description="none",
            version="2.0",
            connection_timeout=3,
            request_timeout=3)
    except :
        LOG.error('failed to connect to CCF service')
        sys.exit(-1)

    fetch_ledger_authority(user_client, options, config)

    LOG.info('successfully fetched ledger authority')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
