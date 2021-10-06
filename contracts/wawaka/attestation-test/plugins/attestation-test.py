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

import argparse
import logging

logger = logging.getLogger(__name__)

from pdo.client.controller.commands.send import send_to_contract
from pdo.client.controller.util import *
from pdo.contract import invocation_request

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __command_attestation__(state, bindings, pargs) :
    """controller command to interact with an asset_type contract
    """

    parser = argparse.ArgumentParser(prog='attestation-test')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-l', '--ledger-key', help='ledger verifying key', type=str)

    subparser = subparsers.add_parser('get_contract_metadata')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('get_contract_code_metadata')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('add_endpoint')
    subparser.add_argument('-c', '--code-metadata',
                           help='contract code metadata', type=invocation_parameter, required=True)
    subparser.add_argument('-i', '--contract-id',
                           help='contract identifier', type=str, required=True)
    subparser.add_argument('-l', '--ledger-attestation',
                           help='attestation from the ledger', type=invocation_parameter, required=True)
    subparser.add_argument('-m', '--contract-metadata',
                           help='contract metadata', type=invocation_parameter, required=True)

    subparser = subparsers.add_parser('generate_secret')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('send_secret')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('recv_secret')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('reveal_secret')
    subparser.add_argument('-a', '--state-attestation',
                           help='ledger signature for current state attestation', type=invocation_parameter, required=True)
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'initialize' :
        message = invocation_request('initialize', ledger_verifying_key=options.ledger_key)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'get_contract_metadata' :
        extraparams['commit'] = False
        message = invocation_request('get_contract_metadata')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'get_contract_code_metadata' :
        extraparams['commit'] = False
        message = invocation_request('get_contract_code_metadata')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'add_endpoint' :
        message = invocation_request('add_endpoint',
                                     contract_id=options.contract_id,
                                     ledger_attestation=options.ledger_attestation,
                                     contract_metadata=options.contract_metadata,
                                     contract_code_metadata=options.code_metadata)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'generate_secret' :
        message = invocation_request('generate_secret')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'send_secret' :
        return

    # -------------------------------------------------------
    if options.command == 'recv_secret' :
        return

    # -------------------------------------------------------
    if options.command == 'reveal_secret' :
        extraparams['commit'] = False
        message = invocation_request('reveal_secret', ledger_signature=options.state_attestation)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_attestation(self, args) :
    """
    attestation -- methods on the attestation contract
    """

    if self.deferred > 0 : return False

    try :
        pargs = self.__arg_parse__(args)
        __command_attestation__(self.state, self.bindings, pargs)

    except SystemExit as se :
        return self.__arg_error__('attestation', args, se.code)
    except Exception as e :
        return self.__error__('attestation', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_attestation', do_attestation)
