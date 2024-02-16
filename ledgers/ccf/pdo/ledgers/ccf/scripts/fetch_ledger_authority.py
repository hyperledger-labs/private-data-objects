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

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments

# -----------------------------------------------------------------
def fetch_ledger_authority(client, output_file) :
    try :
        r = client.post("/app/get_ledger_verifying_key", dict())
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to contact ledger: {0}'.format(r.body))
            sys.exit(-1)

        if r.body is None :
            LOG.error('failed to generate ledger authority: {0}, '.format(r.error))
            sys.exit(-1)
    except :
        LOG.exception('invocation failed')
        sys.exit(-1)

    result = r.body.json()
    ledger_authority = result['verifying_key']
    LOG.info(ledger_authority)

    with open(output_file, "w") as of :
        of.write(ledger_authority)

# -----------------------------------------------------------------
def Main() :
    (options, unprocessed_args, user_client) = parse_common_arguments(
        sys.argv[1:], 'Fetch the ledger authority key from a CCF server')

    # Parse the arguments that are unique to fetch_ledger_authority
    parser = argparse.ArgumentParser(description='Fetch the ledger authority key from a CCF server')
    parser.add_argument(
        "--output-file",
        help="Name of the file where the key will be saved",
        default = os.path.join(options.key_dir, 'ledger_authority_pub.pem'),
        type=str)

    local_options = parser.parse_args(unprocessed_args)

    # -----------------------------------------------------------------
    try :
        fetch_ledger_authority(user_client, local_options.output_file)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        while e.__context__ : e = e.__context__
        LOG.error('fetch ledger authority failed: {}', str(e))
        sys.exit(-1)

    LOG.info('successfully fetched ledger authority')
    sys.exit(0)
