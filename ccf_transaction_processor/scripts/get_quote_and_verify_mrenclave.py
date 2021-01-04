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

"""
Get the quote of a running CCF node and compare against the expected mrenclave
"""

import argparse
import os
import sys
import toml
import subprocess

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_BASE = os.environ.get("CCF_BASE")
CCF_Bin = os.path.join(CCF_BASE, "bin")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")

sys.path.insert(1, CCF_Bin)
from infra.clients import CCFClient

def get_quote_and_verify_mrenclave(node_client, options, config):
    
    enclave_file = config["enclave-file"]

    # compute expected mrenclave
    oed = subprocess.run(
                [options.oesign, "dump", "-e", enclave_file],
                capture_output=True,
                check=True,
            )
    lines = [
        line
        for line in oed.stdout.decode().split(os.linesep)
        if line.startswith("mrenclave=")
    ]
    expected_mrenclave = lines[0].strip().split("=")[1] 
    LOG.info("Expected mrenclave {}".format(expected_mrenclave))

    # get quote from ccf node
    r = node_client.get("quote")
    quotes = r.result["quotes"]
    assert len(quotes) == 1
    primary_quote = quotes[0]
    assert primary_quote["node_id"] == 0
        
    # get mrenclave from quote and compare the two mrenclaves
    primary_mrenclave = primary_quote["mrenclave"]
    LOG.info("mrenclave from quote from CCF node {}".format(primary_mrenclave))

    assert primary_mrenclave == expected_mrenclave, (
        primary_mrenclave,
        expected_mrenclave,
    )

    LOG.info("successfully verified that the primary mrenclave is same as the expected mrenclave")


# -----------------------------------------------------------------
def Main() :
    default_config = os.path.join(CCF_Etc, 'cchost.toml')
    parser = argparse.ArgumentParser(description='Script to enable the CCF network')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', default='INFO', type=str)
    parser.add_argument('--ccf-config', help='Name of the CCF configuration file', default = default_config, type=str)
    parser.add_argument('--oesign', help="Path for oesign binary", type=str, required=True)
    
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

    (host, port) = config["rpc-address"].split(':')

    if "start" in config:
        network_cert = config["start"]["network-cert-file"]
    else:
        network_cert = config["join"]["network-cert-file"]

    try :
        node_client = CCFClient(
            host=host,
            port=port,
            cert=None,
            key=None,
            ca = network_cert,
            format='json',
            prefix='node',
            description="none",
            version="2.0",
            connection_timeout=3,
            request_timeout=3)
    except :
        LOG.error('failed to connect to CCF service')
        sys.exit(-1)

    get_quote_and_verify_mrenclave(node_client, options, config)

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
