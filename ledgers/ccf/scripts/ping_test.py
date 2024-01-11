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
from urllib.parse import urlparse

from ccf.clients import CCFClient
from loguru import logger as LOG

# -----------------------------------------------------------------
def ping_test(client, options):
    num_pings = options.num_pings

    start_time = time.time()

    for _ in range(num_pings):
        client.post("/app/ping", dict())

    end_time = time.time()

    total_time = end_time - start_time
    txn_throuput = num_pings/total_time

    if options.verbose :
        LOG.warning("Performed {0} pings. Average throughput is {1} pings per second".format(num_pings, txn_throuput))

# -----------------------------------------------------------------
def Main() :
    parser = argparse.ArgumentParser(description='Test the connection to a CCF server')

    parser.add_argument('--loglevel', help='Logging level', default='WARNING', type=str)
    parser.add_argument("--num-pings", help="Number of ping operations to do", default = 1, type=int)
    parser.add_argument('--url', type=str, required=True)
    parser.add_argument('--cert', type=str, required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--verbose', action='store_true', default=True)
    group.add_argument('--quiet', action='store_false', dest='verbose')
    options = parser.parse_args()

    # -----------------------------------------------------------------
    LOG.remove()
    LOG.add(sys.stderr, level=options.loglevel)

    # -----------------------------------------------------------------
    try :
        (host, port) = urlparse(options.url).netloc.split(':')
    except Exception as e:
        if options.verbose :
            LOG.error('failed to parse ledger URL: {}'.format(str(e)))
        sys.exit(-1)

    try :
        user_client = CCFClient(host, port, options.cert)
    except Exception as e:
        if options.verbose :
            LOG.error('failed to connect to CCF service: {}'.format(str(e)))
        sys.exit(-1)

    try :
        ping_test(user_client, options)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        if options.verbose :
            while e.__context__ : e = e.__context__
            LOG.error('ping test failed: {}', str(e))
        sys.exit(-1)

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
