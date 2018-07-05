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
def __command_issuer__(state, bindings, pargs) :
    """controller command to interact with an issuer contract
    """

    parser = argparse.ArgumentParser(prog='issuer')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get_verifying_key')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('get_balance')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-t', '--type_id', help='contract identifier for the issuer asset type', type=str, required=True)
    subparser.add_argument('-a', '--authority', help='serialized authority from the vetting organization', type=str, required=True)

    subparser = subparsers.add_parser('issue')
    subparser.add_argument('-o', '--owner', help='identity of the issuance owner; ECDSA key', type=str, required=True)
    subparser.add_argument('-c', '--count', help='amount of the issuance', type=int, required=True)

    subparser = subparsers.add_parser('transfer')
    subparser.add_argument('-n', '--new_owner', help='identity of the new owner; ECDSA key', type=str, required=True)
    subparser.add_argument('-c', '--count', help='amount to transfer', type=int, required=True)

    subparser = subparsers.add_parser('escrow')   # combine escrow & attestation
    subparser.add_argument('-a', '--agent', help='identity of the escrow agent', type=str, required=True)
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('disburse')
    subparser.add_argument('-a', '--attestation', help='Disburse attestation from the escrow agent', type=str, required=True)

    subparser = subparsers.add_parser('claim')
    subparser.add_argument('-a', '--attestation', help='Disburse attestation from the escrow agent', type=str, required=True)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'get_verifying_key' :
        extraparams['commit'] = False
        message = "'(get-verifying-key)"
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'get_balance' :
        extraparams['commit'] = False
        message = "'(get-balance)"
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'initialize' :
        message = "'(initialize \"{0}\" {1})".format(options.type_id, options.authority)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'issue' :
        message = "'(issue \"{0}\" {1})".format(options.owner, options.count)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'transfer' :
        message = "'(transfer \"{0}\" {1})".format(options.new_owner, options.count)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'escrow' :
        extraparams['commit'] = True
        extraparams['wait'] = True
        message = "'(escrow \"{0}\")".format(options.agent)
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)

        extraparams['commit'] = False
        extraparams['wait'] = False
        message = "'(escrow-attestation)"
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'disburse' :
        attestation = SchemeExpression.ParseExpression(options.attestation)
        dependencies = str(attestation.nth(0))
        signature = str(attestation.nth(1))
        message = "'(disburse {0} {1})".format(dependencies, signature)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'claim' :
        attestation = SchemeExpression.ParseExpression(options.attestation)
        old_owner_identity = str(attestation.nth(0))
        dependencies = str(attestation.nth(1))
        signature = str(attestation.nth(2))
        message = "'(claim {0} {1} {2})".format(old_owner_identity, dependencies, signature)
        send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_issuer(self, args) :
    """
    issuer -- invoke methods from the issuer contract
    """

    pargs = shlex.split(self.bindings.expand(args))

    try :
        __command_issuer__(self.state, self.bindings, pargs)

    except SystemExit as se :
        if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
        return

    except Exception as e :
        print('An error occurred processing {0}: {1}'.format(args, str(e)))
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_issuer', do_issuer)
