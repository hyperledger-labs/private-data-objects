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

from ccf.clients import CCFClient

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
CCF_Etc = os.path.join(ContractHome, "ccf", "etc")
CCF_Keys = os.environ.get("PDO_LEDGER_KEY_ROOT") or os.path.join(ContractHome, "ccf", "keys")

# -----------------------------------------------------------------
def ping_test(client, options):
    num_pings = options.num_pings

    start_time = time.time()

    for _ in range(num_pings):
        client.post("/app/ping", dict())

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

    try :
        user_client = CCFClient(
            host,
            port,
            network_cert)
    except Exception as e:
        LOG.error('failed to connect to CCF service: {}'.format(str(e)))
        sys.exit(-1)

    ping_test(user_client, options)

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
