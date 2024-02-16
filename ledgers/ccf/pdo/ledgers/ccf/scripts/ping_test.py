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
import sys
import time

from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments

# -----------------------------------------------------------------
def ping_test(client, num_pings):
    start_time = time.time()

    for _ in range(num_pings):
        client.post("/app/ping", dict())

    end_time = time.time()

    total_time = end_time - start_time
    txn_throuput = num_pings/total_time

    LOG.warn("Performed {0} pings. Average throughput is {1} pings per second".format(num_pings, txn_throuput))

# -----------------------------------------------------------------
def Main() :
    (_, unprocessed_args, user_client) = parse_common_arguments(
        sys.argv[1:], 'Test the connection to a CCF server')

    # Parse the arguments that are unique to ping_test
    parser = argparse.ArgumentParser(description='Test the connection to a CCF server')
    parser.add_argument("--count", help="Number of ping operations to do", default = 1, type=int)
    local_options = parser.parse_args(unprocessed_args)

    try :
        ping_test(user_client, local_options.count)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        while e.__context__ : e = e.__context__
        LOG.error('ping test failed: {}', str(e))
        sys.exit(-1)

    sys.exit(0)
