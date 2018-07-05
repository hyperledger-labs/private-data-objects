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
def __command_asset_type__(state, bindings, pargs) :
    """controller command to interact with an asset_type contract
    """

    parser = argparse.ArgumentParser(prog='asset_type')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-q', '--quiet', help='Suppress printing the result', action='store_true')
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('initialize')
    subparser.add_argument('-d', '--description', help='human readable description', type=str, default='')
    subparser.add_argument('-n', '--name', help='human readable name', type=str, default='')
    subparser.add_argument('-l', '--link', help='URL where more information is located', type=str, default='')

    subparser = subparsers.add_parser('get_identifier')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('get_description')
    options = parser.parse_args(pargs)

    extraparams={'quiet' : options.quiet, 'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'initialize' :
        message = "'(initialize \"{0}\" \"{1}\" \"{2}\")".format(options.name, options.description, options.link)
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        return

    # -------------------------------------------------------
    if options.command == 'get_identifier' :
        extraparams['commit'] = False
        message = "'(get-identifier)"
        result = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        if result and options.symbol :
            bindings.bind(options.symbol, result)
        return

    # -------------------------------------------------------
    if options.command == 'get_description' :
        extraparams['quiet'] = True
        extraparams['commit'] = False
        message = "'(get-name)"
        name = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        message = "'(get-description)"
        description = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        message = "'(get-link)"
        link = send_to_contract(state, options.save_file, options.enclave, message, **extraparams)
        print("NAME: {0}".format(name))
        print("DESC: {1}".format(description))
        print("LINK: {2}".format(link))

        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_asset_type(self, args) :
    """
    asset_type -- invoke methods from the asset_type contract
    """

    pargs = shlex.split(self.bindings.expand(args))

    try :
        __command_asset_type__(self.state, self.bindings, pargs)

    except SystemExit as se :
        if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
        return

    except Exception as e :
        print('An error occurred processing {0}: {1}'.format(args, str(e)))
        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_asset_type', do_asset_type)
