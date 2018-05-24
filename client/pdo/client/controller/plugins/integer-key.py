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
from controller.commands.SendMessage import send_to_contract

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

    create_parser = subparsers.add_parser('create')
    create_parser.add_argument('-k', '--key', help='key to create', type=str, required=True)
    create_parser.add_argument('-v', '--value', help='initial value to give to the key', type=int, default=0)

    inc_parser = subparsers.add_parser('inc')
    inc_parser.add_argument('-k', '--key', help='key to increment', type=str, required=True)
    inc_parser.add_argument('-v', '--value', help='initial value to give to the key', type=int, required=True)

    dec_parser = subparsers.add_parser('dec')
    dec_parser.add_argument('-k', '--key', help='key to decrement', type=str, required=True)
    dec_parser.add_argument('-v', '--value', help='initial value to give to the key', type=int, required=True)

    get_parser = subparsers.add_parser('get')
    get_parser.add_argument('-k', '--key', help='key to retrieve', type=str, required=True)

    transfer_parser = subparsers.add_parser('transfer')
    transfer_parser.add_argument('-k', '--key', help='key to transfer', type=str, required=True)
    transfer_parser.add_argument('-o', '--owner', help='identity to transfer ownership', type=str, required=True)

    escrow_parser = subparsers.add_parser('escrow')
    escrow_parser.add_argument('-k', '--key', help='key to escrow', type=str, required=True)
    escrow_parser.add_argument('-a', '--agent', help='identity of the escrow agent', type=str, required=True)

    attestation_parser = subparsers.add_parser('attestation')
    attestation_parser.add_argument('-k', '--key', help='key to escrow', type=str, required=True)
    attestation_parser.add_argument('-s', '--symbol', help='binding symbol for result', type=str, nargs=3)

    disburse_parser = subparsers.add_parser('disburse')
    disburse_parser.add_argument('-d', '--dependencies', help='list of dependencies', type=str, nargs='*', default=[])
    disburse_parser.add_argument('-k', '--key', help='key to disburse', type=str, required=True)
    disburse_parser.add_argument('-s', '--signature', help='signature from the escrow agent', type=str, required=True)

    exchange_parser = subparsers.add_parser('exchange')
    exchange_parser.add_argument('-d', '--dependencies', help='list of dependencies', type=str, nargs='*', default=[])
    exchange_parser.add_argument('--key1', help='source key', type=str, required=True)
    exchange_parser.add_argument('--key2', help='destination key', type=str, required=True)
    exchange_parser.add_argument('-s', '--signature', help='signature from the escrow agent', type=str, required=True)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    if options.command == 'create' :
        message = "'(create \"{0}\" {1})".format(options.key, options.value)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'inc' :
        message = "'(inc \"{0}\" {1})".format(options.key, options.value)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'dec' :
        message = "'(dec \"{0}\" {1})".format(options.key, options.value)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'get' :
        extraparams['commit'] = False
        message = "'(get-value \"{0}\")".format(options.key)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'transfer' :
        message = "'(transfer-ownership \"{0}\" \"{1}\")".format(options.key, options.owner)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'escrow' :
        message = "'(escrow \"{0}\" \"{1}\")".format(options.key, options.agent)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'attestation' :
        message = "'(escrow-attestation \"{0}\")".format(options.key)
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        if result and options.symbol :
            expression = SchemeExpression.ParseExpression(result)
            bindings.bind(options.symbol[0], str(expression.nth(0)))
            bindings.bind(options.symbol[1], str(expression.nth(1)))
            bindings.bind(options.symbol[2], str(expression.nth(2)))
        return

    if options.command == 'disburse' :
        dependencies = " ".join(options.dependencies)
        message = "'(disburse \"{0}\" ({1}) \"{2}\")".format(options.key, dependencies, options.signature)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    if options.command == 'exchange' :
        dependencies = " ".join(options.dependencies)
        message = "'(disburse \"{0}\" \"{1}\" ({2}) \"{3}\")".format(
            options.key1, options.key2, dependencies, options.signature)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_integer_key(self, args) :
    """
    integer_key -- invoke integer key commands
    """

    pargs = shlex.split(self.bindings.expand(args))

    try :
        __command_integer_key__(self.state, self.bindings, pargs)

    except SystemExit as se :
        if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
        return

    except Exception as e :
        print('An error occurred processing {0}: {1}'.format(args, str(e)))
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_integer_key', do_integer_key)
