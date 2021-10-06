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

from pdo.contract import Contract

__all__ = [
    'command_contract',
    'get_contract',
    'load_contract',
    ]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_contract(state, bindings, pargs) :
    """controller command to manage contracts
    """

    parser = argparse.ArgumentParser(prog='contract')
    parser.add_argument('-q', '--quiet', help='Do not print the result', action='store_true')
    parser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str, required=True)

    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('contract-id')
    subparsers.add_parser('creator')
    subparsers.add_parser('provisioned-enclaves')
    subparsers.add_parser('preferred-enclave')
    subparsers.add_parser('code-name')
    subparsers.add_parser('code-nonce')

    options = parser.parse_args(pargs)

    contract = load_contract(state, options.save_file)


    if options.command == 'contract-id' :
        result = contract.contract_id
    if options.command == 'creator' :
        result = contract.creator_id
    if options.command == 'provisioned-enclaves' :
        result = contract.provisioned_enclaves
    if options.command == 'preferred-enclave' :
        result = contract.extra_data.get('preferred-enclave', '')
    if options.command == 'code-name' :
        result = contract.contract_code.name
    if options.command == 'code-nonce' :
        result = contract.contract_code.nonce

    if result and not options.quiet :
        print(result)
    if result and options.symbol :
        bindings.bind(options.symbol, result)

    return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_contract(state, contract_file) :
    try :
        data_directory = state.get(['Contract', 'DataDirectory'])
        ledger_config = state.get(['Ledger'])

        return Contract.read_from_file(ledger_config, contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('unable to load the contract; {0}'.format(str(e)))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
__contract_cache__ = {}

def get_contract(state, save_file=None) :
    """ Get contract object using the save_file. If there is no save_file, try loading contract using config."""

    global __contract_cache__

    if save_file is None :
        current_contract = state.get(['Contract', 'Contract'], None)
        if current_contract is not None :
            return current_contract

        save_file = state.get(['Contract', 'SaveFile'], None)
        if save_file is None :
            raise Exception('no contract specified')

    if save_file not in __contract_cache__ :
        __contract_cache__[save_file] = load_contract(state, save_file)

    return __contract_cache__[save_file]
