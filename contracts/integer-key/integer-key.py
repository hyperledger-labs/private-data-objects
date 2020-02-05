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
import hashlib
import json
import shlex

import logging
logger = logging.getLogger(__name__)

from pdo.client.controller.commands.send import send_to_contract
from pdo.client.controller.util import *
from pdo.contract import invocation_request

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __hashed_identity__(identity) :
    return hashlib.sha256(identity.encode('utf8')).hexdigest()[:16]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __dump_state__(expression) :

    print("{0:10}{1:10}{2:18}{3:8}{4:16}".format('key', 'value', 'owner', 'status', 'escrow'))
    for k, v in sorted(expression.items()) :
        key = v['key']
        val = v['value']
        owner_key = __hashed_identity__(v['owner'])
        active = v['active']
        escrow_key = __hashed_identity__(v['escrow-key']) if not active else ""
        print("{0:10}{1:10}{2:18}{3:8}{4:16}".format(key, str(val), owner_key, str(active), escrow_key))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __command_integer_key__(state, bindings, pargs) :
    """controller command to interact with an integer-key contract
    """

    parser = argparse.ArgumentParser(prog='integer_key')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get_state')

    subparser = subparsers.add_parser('get_signing_key')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('create')
    subparser.add_argument('-k', '--key', help='key to create', type=str, required=True)
    subparser.add_argument('-v', '--value', help='initial value to give to the key', type=int, default=0)

    subparser = subparsers.add_parser('inc')
    subparser.add_argument('-k', '--key', help='key to increment', type=str, required=True)
    subparser.add_argument('-v', '--value', help='initial value to give to the key', type=int, required=True)

    subparser = subparsers.add_parser('dec')
    subparser.add_argument('-k', '--key', help='key to decrement', type=str, required=True)
    subparser.add_argument('-v', '--value', help='initial value to give to the key', type=int, required=True)

    subparser = subparsers.add_parser('get')
    subparser.add_argument('-k', '--key', help='key to retrieve', type=str, required=True)
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('transfer')
    subparser.add_argument('-k', '--key', help='key to transfer', type=str, required=True)
    subparser.add_argument('-o', '--owner', help='identity to transfer ownership', type=str, required=True)

    subparser = subparsers.add_parser('escrow')
    subparser.add_argument('-k', '--key', help='key to escrow', type=str, required=True)
    subparser.add_argument('-a', '--agent', help='identity of the escrow agent', type=str, required=True)

    subparser = subparsers.add_parser('attestation')
    subparser.add_argument('-k', '--key', help='key to escrow', type=str, required=True)
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('disburse')
    subparser.add_argument('-a', '--attestation', help='disburse attestation from escrow agent', type=invocation_parameter, required=True)

    subparser = subparsers.add_parser('exchange')
    subparser.add_argument('-a', '--attestation', help='exchange attestation from escrow agent', type=invocation_parameter, required=True)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    if options.command == 'get_state' :
        extraparams['quiet'] = True
        message = invocation_request('get-state')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        __dump_state__(result)
        return

    if options.command == 'get_signing_key' :
        message = invocation_request('get-public-signing-key')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'create' :
        message = invocation_request('create', options.key, options.value)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'inc' :
        message = invocation_request('inc', options.key, options.value)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'dec' :
        message = invocation_request('dec', options.key, options.value)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'get' :
        extraparams['commit'] = False
        message = invocation_request('get-value', options.key)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, result)
        return

    if options.command == 'transfer' :
        message = invocation_request('transfer-ownership', options.key, options.owner)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'escrow' :
        message = invocation_request('escrow', options.key, options.agent)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'attestation' :
        message = invocation_request('escrow-attestation', options.key)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, json.dumps(result))
        return

    if options.command == 'disburse' :
        assert type(options.attestation) is list
        assert len(options.attestation) == 3

        bidinfo = dict(options.attestation[0])
        assetkey = bidinfo['key']
        dependencies = options.attestation[1]
        signature = options.attestation[2]
        message = invocation_request('disburse', assetkey, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    if options.command == 'exchange' :
        assert type(options.attestation) is list
        assert len(options.attestation) == 4

        offered = dict(options.attestation[0])['key']
        maxbid =  dict(options.attestation[1])['key']
        dependencies = options.attestation[2]
        signature = options.attestation[3]
        message = invocation_request('exchange-ownership', offered, maxbid, dependencies, signature)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_integer_key(self, args) :
    """
    integer_key -- invoke integer key commands
    """

    try :
        pargs = self.__arg_parse__(args)
        __command_integer_key__(self.state, self.bindings, pargs)
    except SystemExit as se :
        return self.__arg_error__('integer_key', args, se.code)
    except Exception as e :
        return self.__error__('integer_key', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_integer_key', do_integer_key)
