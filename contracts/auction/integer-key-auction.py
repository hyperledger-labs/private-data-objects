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
import shlex
import logging

logger = logging.getLogger(__name__)

from pdo.client.SchemeExpression import SchemeExpression
from pdo.client.controller.commands.send import send_to_contract

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
    subparser.add_argument('-a', '--attestation', help='Escrow attestation from the asset ledger', type=str, required=True)
    #subparser.add_argument('-b', '--bidinfo', help='information about the asset to auction', type=str, required=True)
    #subparser.add_argument('-d', '--dependencies', help='proof of escrow dependencies', type=str, nargs='*', default=[])
    #subparser.add_argument('-s', '--signature', help='signature from the asset contract', type=str, required=True)

    subparser = subparsers.add_parser('submit_bid')
    subparser.add_argument('-a', '--attestation', help='Escrow attestation from the asset ledger', type=str, required=True)
    #subparser.add_argument('-b', '--bidinfo', help='information about the asset to auction', type=str, required=True)
    #subparser.add_argument('-d', '--dependencies', help='proof of escrow dependencies', type=str, nargs='*', default=[])
    #subparser.add_argument('-s', '--signature', help='signature from the asset contract', type=str, required=True)

    subparser = subparsers.add_parser('get_offered_asset')
    subparser = subparsers.add_parser('cancel_bid')
    subparser = subparsers.add_parser('check_bid')
    subparser = subparsers.add_parser('max_bid')
    subparser = subparsers.add_parser('close_bidding')

    subparser = subparsers.add_parser('exchange_attestation')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('cancel_attestation')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    if options.command == 'get_signing_key' :
        message = "'(get-public-signing-key)"
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'initialize' :
        message = "'(initialize \"{0}\")".format(options.key)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'prime' :
        attestation = SchemeExpression.ParseExpression(options.attestation)
        bidinfo = str(attestation.nth(0))
        dependencies = str(attestation.nth(1))
        signature = str(attestation.nth(2))
        message = "'(prime-auction* {0} {1} {2})".format(bidinfo, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'submit_bid' :
        attestation = SchemeExpression.ParseExpression(options.attestation)
        bidinfo = str(attestation.nth(0))
        dependencies = str(attestation.nth(1))
        signature = str(attestation.nth(2))
        message = "'(submit-bid* {0} {1} {2})".format(bidinfo, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'get_offered_asset' :
        message = "'(get-offered-asset)"
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'cancel_bid' :
        message = "'(cancel-bid)"
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'check_bid' :
        message = "'(check-bid)"
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'max_bid' :
        message = "'(max-bid)"
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'close_bidding' :
        message = "'(close-bidding)"
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'cancel_attestation' :
        message = "'(cancel-attestation)"
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'exchange_attestation' :
        message = "'(exchange-attestation)"
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_auction(self, args) :
    """
    auction -- invoke integer key commands
    """

    pargs = shlex.split(self.bindings.expand(args))

    try :
        __command_auction__(self.state, self.bindings, pargs)

    except SystemExit as se :
        if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
        return

    except Exception as e :
        print('An error occurred processing {0}: {1}'.format(args, str(e)))
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_auction', do_auction)
