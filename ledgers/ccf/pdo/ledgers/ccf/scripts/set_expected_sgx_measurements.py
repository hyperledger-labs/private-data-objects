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

from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments


# -----------------------------------------------------------------
def set_contract_enclave_expected_sgx_measurements(client, options):

    params = {}
    params['mrenclave'] = options.mrenclave
    params['basename'] = options.basename
    params['ias_public_key'] = options.ias_public_key
    params['sgx_debug_flag'] = options.sgx_debug_flag

    r = client.post("/app/set_contract_enclave_expected_sgx_measurements", params)
    if r.status_code != http.HTTPStatus.OK.value:
        LOG.error('failed to set contract enclave expected sgx measurements: {}, code: {}'.format(
            r.body, r.status_code))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :

    (_, unprocessed_args, member_client) = parse_common_arguments(
        sys.argv[1:], 'Set contract enclave expected sgx measurements', True)

    # Parse the arguments that are unique to the script

    parser = argparse.ArgumentParser(description='Set contract enclave expected sgx measurements')
    parser.add_argument('--mrenclave', help="Expected MRENCLAVE of pdo enclaves", type=str)
    parser.add_argument('--basename', help="PDO enclave basename", type=str)
    parser.add_argument('--ias-public-key', 
                        help="IAS public key derived from cert used to verify report signatures", type=str)
    parser.add_argument('--sgx-debug-flag', help="PDO enclave sgx debug flag", action='store_true')

    local_options = parser.parse_args(unprocessed_args)

    if (not local_options.mrenclave) or \
            (not local_options.basename) or \
            (not local_options.ias_public_key):
        parser.print_help()
        sys.exit(-1)


     # -----------------------------------------------------------------
    try :
        set_contract_enclave_expected_sgx_measurements(member_client, local_options)
    except Exception as e:
        while e.__context__ : e = e.__context__
        LOG.error('failed to set contract enclave expected sgx measurements: {}', str(e))
        sys.exit(-1)

    LOG.info('successfully set contract enclave expected sgx measurements')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
