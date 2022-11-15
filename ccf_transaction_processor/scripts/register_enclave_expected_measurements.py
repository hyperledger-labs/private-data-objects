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
from urllib.parse import urlparse

from ccf.clients import Identity
from ccf.clients import CCFClient

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("CCF_HOME") or os.path.realpath("/opt/pdo")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

# -----------------------------------------------------------------
def register_enclave_expected_measurements(client, options, config):
    try :
        params = {}
        params['mrenclave'] = options.mrenclave
        params['basename'] = options.basename
        params['ias_public_key'] = options.ias_public_key

        r = client.post("/app/register_enclave_expected_measurements", params)
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to register enclave expected measurements: {}, code: {}'.format(
                r.body, r.status_code))
            sys.exit(-1)
    except Exception as e:
        LOG.error('failed to register enclave expected measurements: {}'.format(str(e)))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    default_config = os.path.join(CCF_Etc, 'cchost.toml')
    default_output = os.path.join(CCF_Keys, 'ledger_authority.pem')

    parser = argparse.ArgumentParser(description='Fetch the ledger authority key from a CCF server')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', default='__screen__', type=str)
    parser.add_argument('--loglevel', help='Logging level', default='INFO', type=str)

    parser.add_argument('--ccf-config', help='Name of the CCF configuration file', default = default_config, type=str)
    parser.add_argument('--member-name', help="Name of the user being added", default = "memberccf", type=str)

    parser.add_argument('--mrenclave', help="Expected MRENCLAVE of pdo enclaves", required=True, type=str)
    parser.add_argument('--basename', help="Pdo enclave basename", required=True, type=str)
    parser.add_argument('--ias-public-key', help="IAS public derived from IAS cert used to verify singature on IAS reports", required=True, type=str)

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
        sys.exit(-1)

    network_cert = config["start"]["network-cert-file"]
    if os.environ.get("PDO_LEDGER_URL") is not None:
        url =  os.environ.get("PDO_LEDGER_URL")
        (host, port) = urlparse(url).netloc.split(':')
    else :
        (host, port) = config["rpc-address"].split(':')

    member_cert = os.path.join(CCF_Keys, "{}_cert.pem".format(options.member_name))
    member_key = os.path.join(CCF_Keys, "{}_privk.pem".format(options.member_name))

    try:
        member_client = CCFClient(
            host,
            port,
            network_cert,
            session_auth=Identity(member_key, member_cert, "member"),
            signing_auth=Identity(member_key, member_cert, "member"),
        )
    except Exception as e:
        LOG.error('failed to connect to CCF service : {}'.format(str(e)))
        sys.exit(-1)

    try:
        register_enclave_expected_measurements(member_client, options, config)
    except Exception as e:
        raise

    LOG.info('successfully registered enclave expected measurements')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()