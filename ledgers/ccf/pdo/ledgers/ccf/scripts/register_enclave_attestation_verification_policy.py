#!/usr/bin/env python

# Copyright 2023 Intel Corporation
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
import sys

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments

# -----------------------------------------------------------------
def register_enclave_attestation_policy(client, options):
    try :
        params = {}
        params['check_attestation'] = options.check_attestation
        if options.check_attestation:
            params['mrenclave'] = options.mrenclave
            params['basename'] = options.basename
            params['ias_public_key'] = options.ias_public_key
        else:
            params['mrenclave'] = ""
            params['basename'] = ""
            params['ias_public_key'] = ""

        r = client.post("/app/set_contract_enclave_attestatation_verification_policy", params)
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to register enclave expected measurements: {}, code: {}'.format(
                r.body, r.status_code))
            sys.exit(-1)
    except Exception as e:
        LOG.error('failed to register enclave expected measurements: {}'.format(str(e)))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    (_, unprocessed_args, member_client) = parse_common_arguments(
        sys.argv[1:], 'Register enclave policy', True)

    parser = argparse.ArgumentParser(description='Register enclave policy')
    parser.add_argument(
        '--check-attestation',
        default=False,
        help="enable attestation verification",
        action='store_true')
    parser.add_argument(
        '--mrenclave',
        help="Expected MRENCLAVE of pdo enclaves",
        type=str)
    parser.add_argument(
        '--basename',
        help="PDO enclave basename",
        type=str)
    parser.add_argument(
        '--ias-public-key',
        help="IAS public key derived from cert used to verify report signatures",
        type=str)

    local_options = parser.parse_args(unprocessed_args)

    if local_options.check_attestation:
        if (not local_options.mrenclave) or (not local_options.basename) or (not local_options.ias_public_key):
            parser.print_help()
            sys.exit(-1)

    try :
        register_enclave_attestation_policy(member_client, local_options)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        while e.__context__ : e = e.__context__
        LOG.error('register enclave attestation policy failed: {}', str(e))
        sys.exit(-1)

    LOG.info('successfully registered enclave expected measurements')
    sys.exit(0)
