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
import json

import logging
logger = logging.getLogger(__name__)

from pdo.client.controller.commands.send import send_to_contract
from pdo.client.controller.util import *
from pdo.contract import invocation_request

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __command_auction__(state, bindings, pargs) :
    """controller command to interact with an auction contract
    """

    parser = argparse.ArgumentParser(prog='auction')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get_signing_key')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-k', '--key', help='public key of the asset contract', type=str, required=True)

    subparser = subparsers.add_parser('prime')
    subparser.add_argument('-a', '--attestation', help='Escrow attestation from the asset ledger', type=invocation_parameter, required=True)

    subparser = subparsers.add_parser('submit_bid')
    subparser.add_argument('-a', '--attestation', help='Escrow attestation from the asset ledger', type=invocation_parameter, required=True)

    subparser = subparsers.add_parser('get_offered_asset')
    subparser = subparsers.add_parser('cancel_bid')
    subparser = subparsers.add_parser('check_bid')

    subparser = subparsers.add_parser('max_bid')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('close_bidding')

    subparser = subparsers.add_parser('exchange_attestation')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('cancel_attestation')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    if options.command == 'get_signing_key' :
        message = invocation_request('get-public-signing-key')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'initialize' :
        message = invocation_request('initialize', options.key)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'prime' :
        assert type(options.attestation) is list
        assert len(options.attestation) == 3

        bidinfo = options.attestation[0]
        dependencies = options.attestation[1]
        signature = options.attestation[2]
        message = invocation_request('prime-auction*', bidinfo, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'submit_bid' :
        assert type(options.attestation) is list
        assert len(options.attestation) == 3

        bidinfo = options.attestation[0]
        dependencies = options.attestation[1]
        signature = options.attestation[2]
        message = invocation_request('submit-bid*',bidinfo, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'get_offered_asset' :
        message = invocation_request('get-offered-asset')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'cancel_bid' :
        message = invocation_request('cancel-bid')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'check_bid' :
        message = invocation_request('check-bid')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'max_bid' :
        message = invocation_request('max-bid')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'close_bidding' :
        message = invocation_request('close-bidding')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'cancel_attestation' :
        message = invocation_request('cancel-attestation')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

    if options.command == 'exchange_attestation' :
        message = invocation_request('exchange-attestation')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_auction(self, args) :
    """
    auction -- invoke integer key commands
    """

    try :
        pargs = self.__arg_parse__(args)
        __command_auction__(self.state, self.bindings, pargs)
    except SystemExit as se :
        return self.__arg_error__('auction', args, se.code)
    except Exception as e :
        return self.__error__('auction', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_auction', do_auction)
