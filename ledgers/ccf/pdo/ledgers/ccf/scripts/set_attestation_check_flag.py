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
def set_contract_enclave_check_attestation_flag(client, options):

    params = {}
    params['check_attestation'] = options.attestation

    r = client.post("/app/set_contract_enclave_check_attestatation_flag", params)
    if r.status_code != http.HTTPStatus.OK.value:
        LOG.error('failed to set contract enclave check-attestation flag: {}, code: {}'.format(
            r.body, r.status_code))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :

    (_, unprocessed_args, member_client) = parse_common_arguments(
        sys.argv[1:], 'Set contract enclave attestation check flag', True)

    # Parse the arguments that are unique to the script
    parser = argparse.ArgumentParser(description='Set contract enclave attestation check flag')
    check_attestation_group = parser.add_mutually_exclusive_group(required=True)
    check_attestation_group.add_argument('--attestation', dest='attestation', 
                                         help="enable attestation verification", action='store_true')
    check_attestation_group.add_argument('--no-attestation', dest='attestation', 
                                         help="disable attestation verification", action='store_false')
    local_options = parser.parse_args(unprocessed_args)

    # -----------------------------------------------------------------
    try :
        
        set_contract_enclave_check_attestation_flag(member_client, local_options)
    except Exception as e:
        while e.__context__ : e = e.__context__
        LOG.error('failed to set contract enclave attestation check flag: {}', str(e))
        sys.exit(-1)

    LOG.info('successfully set contract enclave check-attestation flag ')
    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
Main()
