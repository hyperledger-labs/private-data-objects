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

from pdo.client.controller.commands.send import send_to_contract
from pdo.client.controller.util import *
from pdo.contract import invocation_request

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __command_exchange__(state, bindings, pargs) :
    """controller command to interact with an exchange contract
    """

    parser = argparse.ArgumentParser(prog='exchange')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get_verifying_key')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('get_offered_asset')
    subparser = subparsers.add_parser('get_requested_asset')

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-r', '--root', help='key for the root authority for requested issuer', type=str, required=True)
    subparser.add_argument('-t', '--type_id', help='contract identifier for the requested asset type', type=str, required=True)
    subparser.add_argument('-o', '--owner', help='identity of the asset owner; ECDSA key', type=str, default="")
    subparser.add_argument('-c', '--count', help='amount requested',  type=int, required=True)

    subparser = subparsers.add_parser('offer')
    subparser.add_argument('-a', '--asset', help='serialized escrowed asset', type=scheme_parameter, required=True)

    subparser = subparsers.add_parser('claim_offer')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('exchange')
    subparser.add_argument('-a', '--asset', help='serialized escrowed asset', type=scheme_parameter, required=True)

    subparser = subparsers.add_parser('claim_exchange')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('cancel')
    subparser = subparsers.add_parser('cancel_attestation')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'get_verifying_key' :
        extraparams['commit'] = False
        message = invocation_request('get-verifying-key')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'get_offered_asset' :
        extraparams['commit'] = False
        message = invocation_request('examine-offered-asset')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'get_requested_asset' :
        extraparams['commit'] = False
        message = invocation_request('examine-requested-asset')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'initialize' :
        asset_request = [options.type_id, options.count, options.owner]
        message = invocation_request('initialize', asset_request, options.root)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'offer' :
        message = invocation_request('offer-asset', options.asset)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'claim_offer' :
        extraparams['commit'] = False
        message = invocation_request('claim-offer')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'exchange' :
        message = invocation_request('exchange-asset', options.asset)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'claim_exchange' :
        extraparams['commit'] = False
        message = invocation_request('claim-exchange')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'cancel' :
        message = invocation_request('cancel')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'cancel_attestation' :
        extraparams['commit'] = False
        message = invocation_request('cancel-attestation')
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return


## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_exchange(self, args) :
    """
    exchange -- invoke methods from the exchange contract
    """

    try :
        pargs = self.__arg_parse__(args)
        __command_exchange__(self.state, self.bindings, pargs)
    except SystemExit as se :
        return self.__arg_error__('exchange', args, se.code)
    except Exception as e :
        return self.__error__('exchange', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_exchange', do_exchange)
