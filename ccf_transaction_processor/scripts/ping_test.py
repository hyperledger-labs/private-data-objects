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

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Bin = os.path.join(ContractHome, "ccf", "bin")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

sys.path.insert(1, CCF_Bin)
sys.path.insert(1, "../CCF/tests")

from infra.clients import CCFClient

# -----------------------------------------------------------------
def ping_test(client, options):
    num_pings = options.num_pings

    start_time = time.time()

    for _ in range(num_pings):
        client.rpc("ping", dict())

    end_time = time.time()

    total_time = end_time - start_time
    txn_throuput = num_pings/total_time

    LOG.info("Performed {0} pings. Average txn_throuput is {1} pings per second".format(num_pings, txn_throuput))

# -----------------------------------------------------------------
def Main() :
    parser = argparse.ArgumentParser(description='Script to enable the CCF network')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', default='INFO', type=str)
    parser.add_argument('--ccf-config', help='Name of the CCF configuration file', default = os.path.join(CCF_Etc, 'cchost.toml'), type=str)
    parser.add_argument('--user-name', help="Name of the user being added", default = "userccf", type=str)
    parser.add_argument("--num-pings", help="Number of ping operations to do", default = 100, type=int)

    options = parser.parse_args()

    # -----------------------------------------------------------------
    LOG.remove()
    LOG.add(sys.stderr, level=options.loglevel)

    # -----------------------------------------------------------------
    try :
        config = toml.load(options.ccf_config)
    except :
        LOG.info('unable to load ccf configuration file {0}'.format(options.ccf_config))
        pass

    network_cert = os.path.join(CCF_Keys, "networkcert.pem")

    if os.environ.get("PDO_LEDGER_URL") is not None:
        url =  os.environ.get("PDO_LEDGER_URL")
        (host, port) = urlparse(url).netloc.split(':')
    else :
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
            prefix='app',
            description="none",
            version="2.0",
            connection_timeout=3,
            request_timeout=3)
    except :
        LOG.error('failed to connect to CCF service')
        sys.exit(-1)

    ping_test(user_client, options)

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
