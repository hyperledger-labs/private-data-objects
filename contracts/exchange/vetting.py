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
def __command_vetting__(state, bindings, pargs) :
    """controller command to interact with an vetting contract
    """

    parser = argparse.ArgumentParser(prog='vetting')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get_verifying_key')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-t', '--type_id', help='contract identifier for the issuer asset type', type=str, required=True)

    subparser = subparsers.add_parser('approve')
    subparser.add_argument('-i', '--issuer', help='identity of the issuer; ECDSA key', type=str, required=True)

    subparser = subparsers.add_parser('get_authority')
    subparser.add_argument('-i', '--issuer', help='identity of the issuer; ECDSA key', type=str, required=True)
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'get_verifying_key' :
        extraparams['commit'] = False
        message = invocation_request('get-verifying-key')
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, result)
        return


    # -------------------------------------------------------
    if options.command == 'initialize' :
        message = invocation_request('initialize', options.type_id)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'approve' :
        message = invocation_request('add-approved-key', options.issuer)
        send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        return

   # -------------------------------------------------------
    if options.command == 'get_authority' :
        extraparams['commit'] = False
        message = invocation_request('get-authority', options.issuer)
        result = send_to_contract(state, options.save_file, message, eservice_url=options.enclave, **extraparams)
        if options.symbol :
            bindings.bind(options.symbol, result)
        return


## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_vetting(self, args) :
    """
    vetting -- invoke methods from the vetting contract
    """

    try :
        pargs = self.__arg_parse__(args)
        __command_vetting__(self.state, self.bindings, pargs)
    except SystemExit as se :
        return self.__arg_error__('vetting', args, se.code)
    except Exception as e :
        return self.__error__('vetting', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_vetting', do_vetting)
