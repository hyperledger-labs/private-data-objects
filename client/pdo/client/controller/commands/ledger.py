# Copyright 2018 Intel Corporation
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

import os
import argparse
import json
import logging
import random

logger = logging.getLogger(__name__)

import pdo.common.crypto as pcrypto
from pdo.submitter.create import create_submitter
from pdo.client.controller.util import invocation_parameter

__all__ = ['command_ledger']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_ledger(state, bindings, pargs) :
    """controller command to fetch information from the ledger
    """
    default_ledger_url = state.get(['Ledger', 'LedgerURL'])

    parser = argparse.ArgumentParser(prog='ledger')
    parser.add_argument('--url', help='URL for the ledger', default=default_ledger_url)
    parser.add_argument('-q', '--quiet', help='Do not print the result', action='store_true')
    parser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('ledger-key')

    subparser = subparsers.add_parser('enclave-info')
    subparser.add_argument('-i', '--enclave-id', help='enclave identifier', type=str, required=True)
    subparser.add_argument('-p', '--path', help='path to retrieve within the expression', type=str)

    subparser = subparsers.add_parser('contract-info')
    subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
    subparser.add_argument('-p', '--path', help='path to retrieve within the expression', type=str)

    subparser = subparsers.add_parser('current-state')
    subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
    subparser.add_argument('-p', '--path', help='path to retrieve within the expression', type=str)

    subparser = subparsers.add_parser('state-info')
    subparser.add_argument('-a', '--state-hash', help='state hash', type=str, required=True)
    subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
    subparser.add_argument('-p', '--path', help='path to retrieve within the expression', type=str)

    options = parser.parse_args(pargs)

    ledger_config = { 'LedgerURL' : options.url }
    submitter = create_submitter(ledger_config)

    if options.command == 'ledger-key' :
        result = submitter.get_ledger_info()
        if result and not options.quiet :
            print(result)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'enclave-info' :

        result = submitter.get_enclave_info(options.enclave_id)
        if options.path :
            result = eval(options.path, None, result)
        if result and not options.quiet :
            print(result)
        if result and options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

    if options.command == 'contract-info' :
        result = submitter.get_contract_info(options.contract_id)
        if options.path :
            result = eval(options.path, None, result)
        if result and not options.quiet :
            print(result)
        if result and options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

    if options.command == 'current-state' :
        result = submitter.get_current_state_hash(options.contract_id)
        if options.path :
            result = eval(options.path, None, result)
        if result and not options.quiet :
            print(result)
        if result and options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

    if options.command == 'state-info' :
        result = submitter.get_state_details(options.contract_id, options.state_hash)
        if options.path :
            result = eval(options.path, None, result)
        if result and not options.quiet :
            print(result)
        if result and options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return
